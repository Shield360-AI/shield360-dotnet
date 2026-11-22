#pragma warning disable CA1861, CA1870 // netstandard2.0 has no SearchValues; the small literal arrays are on cold paths
using System;
using System.Collections.Generic;
using System.Linq;
using Shield360.Rasp;

namespace Shield360.Defend;

/// <summary>Defend's decision, weakest first.</summary>
public enum DefendVerdict
{
    /// <summary>Go on.</summary>
    Allow,

    /// <summary>Answer 401.</summary>
    RequireSignIn,

    /// <summary>Answer with a challenge (403).</summary>
    Challenge,

    /// <summary>Answer 403.</summary>
    Deny,
}

/// <summary>Enforce (the default) or monitor (never denies).</summary>
public enum DefendMode
{
    /// <summary>Decisions are enforced.</summary>
    Enforce,

    /// <summary>Decisions are reported, never enforced.</summary>
    Monitor,
}

/// <summary>Without a usable policy: open (allow, the default) or closed (deny).</summary>
public enum DefendFailMode
{
    /// <summary>Allow.</summary>
    Open,

    /// <summary>Deny.</summary>
    Closed,
}

/// <summary>Sensitive data in the content: monitor (the default; a reason only), block, or off.</summary>
public enum SensitiveDataMode
{
    /// <summary>Not checked.</summary>
    Off,

    /// <summary>A reason only.</summary>
    Monitor,

    /// <summary>Deny.</summary>
    Block,
}

/// <summary>The answer of an agent verifier.</summary>
public sealed class AgentCheck
{
    /// <summary>Creates an answer.</summary>
    public AgentCheck(bool verified, bool blocked, string? reason)
    {
        Verified = verified;
        Blocked = blocked;
        Reason = reason;
    }

    /// <summary>The agent proof verified.</summary>
    public bool Verified { get; }

    /// <summary>The agent policy refuses it.</summary>
    public bool Blocked { get; }

    /// <summary>A short code, or null.</summary>
    public string? Reason { get; }
}

/// <summary>What the content check found.</summary>
public sealed class ContentFindings
{
    /// <summary>Creates findings.</summary>
    public ContentFindings(bool promptInjection, bool sensitiveData)
    {
        PromptInjection = promptInjection;
        SensitiveData = sensitiveData;
    }

    /// <summary>Prompt injection.</summary>
    public bool PromptInjection { get; }

    /// <summary>A secret or PII shape.</summary>
    public bool SensitiveData { get; }
}

/// <summary>Defend's answer for a request.</summary>
public sealed class DefendResult
{
    internal DefendResult(DefendVerdict decision, IEnumerable<string> reasons, IEnumerable<string> ruleIds, int ttl)
    {
        Decision = decision;
        Reasons = new List<string>(reasons);
        RuleIds = new List<string>(ruleIds);
        Ttl = ttl;
    }

    /// <summary>The decision as enforced.</summary>
    public DefendVerdict Decision { get; internal set; }

    /// <summary>Reason codes, never request text.</summary>
    public List<string> Reasons { get; }

    /// <summary>The rules that matched.</summary>
    public List<string> RuleIds { get; }

    /// <summary>Seconds the decision may be cached (0: none).</summary>
    public int Ttl { get; internal set; }

    /// <summary>The decision monitor mode did not enforce (null: none).</summary>
    public DefendVerdict? WouldBe { get; internal set; }

    /// <summary>The client type, when known.</summary>
    public string? ClientType { get; internal set; }

    /// <summary>The honeypot's fake file to answer with (null: none).</summary>
    public HoneypotDecoy? Decoy { get; internal set; }

    /// <summary>The X-Debug-Trace value for an allowed response.</summary>
    public string? CrumbHeader { get; internal set; }

    /// <summary>The decision as enforced, or as it would be outside monitor mode.</summary>
    public DefendVerdict Effective => WouldBe ?? Decision;

    /// <summary>The wire code of a verdict (allow, require_sign_in, challenge, deny).</summary>
    public static string Code(DefendVerdict v) => v switch
    {
        DefendVerdict.RequireSignIn => "require_sign_in",
        DefendVerdict.Challenge => "challenge",
        DefendVerdict.Deny => "deny",
        _ => "allow",
    };
}

/// <summary>Per-process token buckets, the oldest dropped past the cap.</summary>
public sealed class DefendRateTable
{
    private readonly int _cap;
    private readonly Dictionary<string, LinkedListNode<KeyValuePair<string, double[]>>> _buckets = new(StringComparer.Ordinal);
    private readonly LinkedList<KeyValuePair<string, double[]>> _order = new();
    private readonly object _lock = new();

    /// <summary>At most 10,000 buckets.</summary>
    public DefendRateTable()
        : this(10_000)
    {
    }

    /// <summary>At most cap buckets.</summary>
    public DefendRateTable(int cap) => _cap = Math.Max(1, cap);

    /// <summary>Takes a token; false when the bucket is empty.</summary>
    public bool Take(string key, double rps, double burst, double nowMs)
    {
        var size = Math.Max(burst > 0 ? burst : Math.Ceiling(rps), 1);
        lock (_lock)
        {
            double[] b;
            if (!_buckets.TryGetValue(key, out var node))
            {
                if (_buckets.Count >= _cap && _order.First is { } oldest)
                {
                    _buckets.Remove(oldest.Value.Key);
                    _order.RemoveFirst();
                }

                b = new[] { size, nowMs };
                _buckets[key] = _order.AddLast(new KeyValuePair<string, double[]>(key, b));
            }
            else
            {
                b = node.Value.Value;
                b[0] = Math.Min(size, b[0] + ((nowMs - b[1]) / 1000.0 * rps));
                b[1] = nowMs;
            }

            if (b[0] >= 1)
            {
                b[0] -= 1;
                return true;
            }

            return false;
        }
    }
}

/// <summary>What one decision is made from.</summary>
internal sealed class DefendInput
{
    public DefendPolicy? Policy { get; set; }

    public CompiledPolicy? Compiled { get; set; }

    public DefendFacts Facts { get; set; } = new();

    public DefendMode Mode { get; set; } = DefendMode.Enforce;

    public DefendFailMode FailMode { get; set; } = DefendFailMode.Open;

    public AgentCheck? Agent { get; set; }

    public bool TrapHit { get; set; }

    public ClientClassification? Classification { get; set; }

    public ContentFindings Content { get; set; } = new(false, false);

    public SensitiveDataMode SensitiveData { get; set; } = SensitiveDataMode.Monitor;

    public DefendRateTable Rates { get; set; } = new();

    public double NowMs { get; set; }

    public Dictionary<string, bool>? SharedOver { get; set; }
}

/// <summary>
/// The decision order (docs/latest/shield360/defend.mdx): kill switch, deny list,
/// agent policy, trap hit, challenge list, rules in order (first match wins; allow
/// stops, monitor goes on), then sensitive data. Port of defend/engine.ts.
/// </summary>
internal static class DefendEngine
{
    public const int ListTtl = 60;

    public static bool InAny(string? ip, IReadOnlyList<RuleNet> nets)
    {
        if (string.IsNullOrEmpty(ip))
        {
            return false;
        }

        foreach (var n in nets)
        {
            if (RaspRuleExpr.InCidr(ip!, n))
            {
                return true;
            }
        }

        return false;
    }

    public static bool IsTrusted(CompiledPolicy? c, string? ip) => c is not null && InAny(ip, c.Allow);

    /// <summary>Whether path is prefix or below it on a segment boundary.</summary>
    public static bool PathUnder(string path, string prefix)
    {
        if (prefix == "/" || path == prefix)
        {
            return true;
        }

        if (prefix.EndsWith("/", StringComparison.Ordinal))
        {
            return path.StartsWith(prefix, StringComparison.Ordinal);
        }

        return path.Length > prefix.Length && path.StartsWith(prefix, StringComparison.Ordinal) && path[prefix.Length] == '/';
    }

    private static bool GeoMatches(DefendRule r, DefendFacts f)
    {
        if (r.Countries.Count == 0 && r.Asns.Count == 0)
        {
            return true;
        }

        if (f.Country is null && f.Asn is null)
        {
            return false;
        }

        var inside = (f.Country is not null && r.Countries.Contains(f.Country)) || (f.Asn is { } asn && r.Asns.Contains(asn));
        return r.Except != inside;
    }

    private static bool Matches(DefendRule r, DefendInput input, IReadOnlyList<RuleNet> nets)
    {
        var f = input.Facts;
        if (r.Cidrs.Count > 0 && !InAny(f.Ip, nets))
        {
            return false;
        }

        if (!GeoMatches(r, f))
        {
            return false;
        }

        if (r.Paths.Count > 0 && !r.Paths.Any(p => PathUnder(f.Path, p)))
        {
            return false;
        }

        if (r.Methods.Count > 0 && !r.Methods.Contains(f.Method))
        {
            return false;
        }

        // SHIELD: AI attack agents — scanner and ai_attack_agent are subtypes of unverified_automation.
        if (r.ClientTypes.Count > 0 && !ClientType.RuleMatches(r.ClientTypes, input.Classification?.ClientType))
        {
            return false;
        }

        return r.Attacks.Count == 0 || (r.Attacks.Contains("prompt_injection") && input.Content.PromptInjection);
    }

    public static List<DefendRule> RateRulesFor(DefendInput input)
    {
        var out_ = new List<DefendRule>();
        if (input.Policy is null || input.Compiled is null)
        {
            return out_;
        }

        for (var i = 0; i < input.Policy.Rules.Count; i++)
        {
            var r = input.Policy.Rules[i];
            if (r.Rate is not null && Matches(r, input, input.Compiled.Rules[i]))
            {
                out_.Add(r);
            }
        }

        return out_;
    }

    public static DefendResult FailResult(DefendFailMode fail, string reason, DefendMode mode) =>
        Finish(new DefendResult(fail == DefendFailMode.Closed ? DefendVerdict.Deny : DefendVerdict.Allow, new[] { reason }, Array.Empty<string>(), 0), mode);

    private static DefendResult Finish(DefendResult r, DefendMode mode)
    {
        if (mode == DefendMode.Monitor && r.Decision != DefendVerdict.Allow)
        {
            r.WouldBe = r.Decision;
            r.Decision = DefendVerdict.Allow;
        }

        return r;
    }

    public static DefendResult Decide(DefendInput input)
    {
        try
        {
            return DecideUnsafe(input);
        }
#pragma warning disable CA1031 // a decision never throws: the fail mode applies
        catch (Exception)
#pragma warning restore CA1031
        {
            return FailResult(input.FailMode, "error", input.Mode);
        }
    }

    private static DefendResult DecideUnsafe(DefendInput input)
    {
        var mode = input.Mode;
        var policy = input.Policy;
        var c = input.Compiled;
        if (policy is null || c is null)
        {
            return FailResult(input.FailMode, "policy_unavailable", mode);
        }

        if (policy.KillSwitch)
        {
            return new DefendResult(DefendVerdict.Allow, new[] { "kill_switch" }, Array.Empty<string>(), 0);
        }

        var f = input.Facts;
        var reasons = new List<string>();
        var ruleIds = new List<string>();
        var verified = input.Agent is { Verified: true };
        var clientType = verified ? ClientType.VerifiedAgent : input.TrapHit ? ClientType.SuspectedAiAgent : input.Classification?.ClientType;
        var ip = f.Ip;
        var trusted = InAny(ip, c.Allow);
        var exempt = trusted || verified;
        if (input.Classification is not null && !verified && !input.TrapHit)
        {
            for (var i = 0; i < Math.Min(8, input.Classification.Reasons.Count); i++)
            {
                reasons.Add("client:" + input.Classification.Reasons[i]);
            }
        }

        if (!trusted && InAny(ip, c.Deny))
        {
            reasons.Add("deny_list");
            return Out(DefendVerdict.Deny, ListTtl, reasons, ruleIds, clientType, mode);
        }

        if (input.Agent is { Blocked: true })
        {
            reasons.Add("agent_policy");
            if (!string.IsNullOrEmpty(input.Agent.Reason))
            {
                reasons.Add("agent:" + input.Agent.Reason);
            }

            return Out(DefendVerdict.Deny, 0, reasons, ruleIds, clientType, mode);
        }

        if (verified)
        {
            reasons.Add("agent_verified");
        }
        else if (input.Agent is not null && !string.IsNullOrEmpty(input.Agent.Reason))
        {
            reasons.Add("agent:" + input.Agent.Reason);
        }

        if (input.TrapHit && !exempt)
        {
            reasons.Add("trap_hit");
            if (policy.TrapAction != "monitor")
            {
                return Out(policy.TrapAction == "block" ? DefendVerdict.Deny : DefendVerdict.Challenge, policy.TrapTtlSeconds, reasons, ruleIds, clientType, mode);
            }
        }

        if (!exempt && InAny(ip, c.Challenge))
        {
            reasons.Add("challenge_list");
            return Out(DefendVerdict.Challenge, ListTtl, reasons, ruleIds, clientType, mode);
        }

        if (input.Content.PromptInjection)
        {
            reasons.Add("prompt_injection");
        }

        var decision = DefendVerdict.Allow;
        var ttl = 0;
        for (var i = 0; i < policy.Rules.Count; i++)
        {
            var rule = policy.Rules[i];
            if (!Matches(rule, input, c.Rules[i]))
            {
                continue;
            }

            if (rule.Rate is not null)
            {
                if (ip is null)
                {
                    continue;
                }

                bool over;
                if (input.SharedOver is not null && input.SharedOver.TryGetValue(rule.Id, out var shared))
                {
                    over = shared;
                }
                else
                {
                    over = !input.Rates.Take(rule.Id + "|" + ip, rule.Rate.Rps, rule.Rate.Burst, input.NowMs);
                }

                if (!over)
                {
                    continue;
                }

                reasons.Add("rate_limit");
                ttl = (int)Math.Max(Math.Ceiling(1.0 / rule.Rate.Rps), 1);
            }

            ruleIds.Add(rule.Id);
            if (rule.Action == DefendRuleAction.Allow)
            {
                reasons.Add("rule:allow");
                return Out(DefendVerdict.Allow, 0, reasons, ruleIds, clientType, mode);
            }

            if (rule.Action == DefendRuleAction.Monitor || exempt)
            {
                reasons.Add(exempt && rule.Action != DefendRuleAction.Monitor ? "rule:" + ActionCode(rule.Action) + ":exempt" : "rule:monitor");
                continue;
            }

            reasons.Add("rule:" + ActionCode(rule.Action));
            decision = rule.Action == DefendRuleAction.Block ? DefendVerdict.Deny : DefendVerdict.Challenge;
            break;
        }

        if (input.Content.SensitiveData)
        {
            reasons.Add("sensitive_data");
            if (input.SensitiveData == SensitiveDataMode.Block && !exempt && DefendVerdict.Deny > decision)
            {
                decision = DefendVerdict.Deny;
            }
        }

        return Out(decision, decision == DefendVerdict.Allow ? 0 : ttl, reasons, ruleIds, clientType, mode);
    }

    internal static string ActionCode(DefendRuleAction a) => a switch
    {
        DefendRuleAction.Block => "block",
        DefendRuleAction.Challenge => "challenge",
        DefendRuleAction.Allow => "allow",
        _ => "monitor",
    };

    private static DefendResult Out(DefendVerdict d, int ttl, List<string> reasons, List<string> ruleIds, string? clientType, DefendMode mode)
    {
        var r = new DefendResult(d, reasons, ruleIds, ttl) { ClientType = clientType };
        return Finish(r, mode);
    }
}
