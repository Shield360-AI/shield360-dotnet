#pragma warning disable CA1861, CA1870 // netstandard2.0 has no SearchValues; the small literal arrays are on cold paths
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Shield360.Rasp;

namespace Shield360.Defend;

/// <summary>What a rule does when it matches; Monitor only adds its reason.</summary>
public enum DefendRuleAction
{
    /// <summary>Deny.</summary>
    Block,

    /// <summary>Challenge.</summary>
    Challenge,

    /// <summary>Allow and stop.</summary>
    Allow,

    /// <summary>Add the reason and go on.</summary>
    Monitor,
}

/// <summary>At most Rps requests a second per client, with a burst (0: ceil(rps)).</summary>
public sealed class DefendRate
{
    /// <summary>Creates a rate.</summary>
    public DefendRate(double rps, long burst)
    {
        Rps = rps;
        Burst = burst;
    }

    /// <summary>Requests a second.</summary>
    public double Rps { get; }

    /// <summary>The burst (0: ceil(rps)).</summary>
    public long Burst { get; }
}

/// <summary>One rule: every condition set must match; an empty list is no condition.</summary>
public sealed class DefendRule
{
    /// <summary>The rule id.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>What it does.</summary>
    public DefendRuleAction Action { get; set; }

    /// <summary>Address ranges.</summary>
    public IReadOnlyList<string> Cidrs { get; set; } = Array.Empty<string>();

    /// <summary>Countries (ISO 3166 alpha-2).</summary>
    public IReadOnlyList<string> Countries { get; set; } = Array.Empty<string>();

    /// <summary>Networks (AS numbers).</summary>
    public IReadOnlyList<long> Asns { get; set; } = Array.Empty<long>();

    /// <summary>Everyone outside the countries and networks named.</summary>
    public bool Except { get; set; }

    /// <summary>Path prefixes, on a segment boundary.</summary>
    public IReadOnlyList<string> Paths { get; set; } = Array.Empty<string>();

    /// <summary>Methods.</summary>
    public IReadOnlyList<string> Methods { get; set; } = Array.Empty<string>();

    /// <summary>prompt_injection matches the content the caller passed.</summary>
    public IReadOnlyList<string> Attacks { get; set; } = Array.Empty<string>();

    /// <summary>Client types.</summary>
    public IReadOnlyList<string> ClientTypes { get; set; } = Array.Empty<string>();

    /// <summary>A rate limit, or null.</summary>
    public DefendRate? Rate { get; set; }
}

/// <summary>
/// The signed Defend policy (typ <c>shield360-defend+jws</c>). Anything malformed is
/// dropped, never widened: a rule whose condition cannot be read is left out entirely,
/// a list entry that is not an address is skipped. Port of defend/policy.ts.
/// </summary>
public sealed class DefendPolicy
{
    /// <summary>The policy's JWS typ.</summary>
    public const string JwsType = "shield360-defend+jws";

    /// <summary>Where the policy is fetched.</summary>
    public const string PolicyPath = "/api/defend/policy";

    /// <summary>The default trap TTL in seconds.</summary>
    public const int DefaultTrapTtl = 900;

    /// <summary>The longest trap TTL in seconds.</summary>
    public const int MaxTrapTtl = 86_400;

    private const int MaxRules = 200;
    private const int MaxList = 2000;

    /// <summary>The policy's version.</summary>
    public string Version { get; set; } = "v1";

    /// <summary>Expiry, seconds since the epoch.</summary>
    public double Exp { get; set; } = (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0) + 3600;

    /// <summary>The version of the deny, challenge and allow lists (the decisions feed).</summary>
    public string ListsVersion { get; set; } = "l1";

    /// <summary>Allow everything.</summary>
    public bool KillSwitch { get; set; }

    /// <summary>The rules, in order.</summary>
    public List<DefendRule> Rules { get; set; } = new();

    /// <summary>Denied address ranges.</summary>
    public List<string> Deny { get; set; } = new();

    /// <summary>Challenged address ranges.</summary>
    public List<string> Challenge { get; set; } = new();

    /// <summary>Trusted address ranges: never trapped or stopped.</summary>
    public List<string> Allow { get; set; } = new();

    /// <summary>block (the default), challenge or monitor.</summary>
    public string TrapAction { get; set; } = "block";

    /// <summary>Seconds a trapped client stays marked.</summary>
    public int TrapTtlSeconds { get; set; } = DefaultTrapTtl;

    /// <summary>Null: honeypots off.</summary>
    public HoneypotSettings? Honeypots { get; set; }

    internal IReadOnlyList<EdgeKey> EdgeKeys { get; set; } = Array.Empty<EdgeKey>();

    internal static bool IsRuleId(string s)
    {
        if (s.Length == 0 || s.Length > 48)
        {
            return false;
        }

        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && (c == '_' || c == '-'))))
            {
                return false;
            }
        }

        return true;
    }

    internal static bool IsCidr(string s) => s.Length <= 64 && RaspRuleExpr.ParseCidr(s) is not null;

    private static bool IsPath(string s)
    {
        if (s.Length > 256 || !s.StartsWith("/", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var c in s)
        {
            if (char.IsWhiteSpace(c) || "?#\"'\\".IndexOf(c) >= 0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Distinct strings each passing ok, at most max read; empty when absent or null, null when unreadable.</summary>
    private static List<string>? Strings(JsonElement m, string key, int max, Func<string, bool> ok)
    {
        if (!m.TryGetProperty(key, out var v) || v.ValueKind == JsonValueKind.Null)
        {
            return new List<string>();
        }

        if (v.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var out_ = new List<string>();
        var n = 0;
        foreach (var x in v.EnumerateArray())
        {
            if (n++ >= max)
            {
                break;
            }

            if (x.ValueKind != JsonValueKind.String || !ok(x.GetString()!))
            {
                return null;
            }

            if (!out_.Contains(x.GetString()!))
            {
                out_.Add(x.GetString()!);
            }
        }

        return out_;
    }

    private static bool Whole(JsonElement v, out double d)
    {
        d = 0;
        if (v.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        d = v.GetDouble();
        return !double.IsInfinity(d) && d == Math.Floor(d);
    }

    private static bool AllUpper(string s) => s.All(c => c >= 'A' && c <= 'Z');

    /// <summary>One rule, or null when any of its conditions cannot be read.</summary>
    public static DefendRule? ParseRule(JsonElement m)
    {
        if (m.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!m.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String || !IsRuleId(id.GetString()!))
        {
            return null;
        }

        DefendRuleAction action;
        switch (m.TryGetProperty("action", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() : null)
        {
            case "block":
                action = DefendRuleAction.Block;
                break;
            case "challenge":
                action = DefendRuleAction.Challenge;
                break;
            case "allow":
                action = DefendRuleAction.Allow;
                break;
            case "monitor":
                action = DefendRuleAction.Monitor;
                break;
            default:
                return null;
        }

        var cidrs = Strings(m, "cidrs", 50, IsCidr);
        var countries = Strings(m, "countries", 50, s => s.Length == 2 && AllUpper(s));
        var paths = Strings(m, "paths", 10, IsPath);
        var methods = Strings(m, "methods", 10, s => s.Length >= 3 && s.Length <= 10 && AllUpper(s));
        var attacks = Strings(m, "attacks", 16, s => s.Length > 0 && s.Length <= 32 && s.All(c => (c >= 'a' && c <= 'z') || c == '_'));
        var clientTypes = Strings(m, "clientTypes", ClientType.Types.Count, s => ClientType.Types.Contains(s));
        if (cidrs is null || countries is null || paths is null || methods is null || attacks is null || clientTypes is null)
        {
            return null;
        }

        var r = new DefendRule { Id = id.GetString()!, Action = action, Cidrs = cidrs, Countries = countries, Methods = methods, Attacks = attacks, ClientTypes = clientTypes };
        if (m.TryGetProperty("asns", out var asns) && asns.ValueKind != JsonValueKind.Null)
        {
            if (asns.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var out_ = new List<long>();
            foreach (var x in asns.EnumerateArray())
            {
                if (!Whole(x, out var d) || d <= 0 || d > 4_294_967_295.0)
                {
                    return null;
                }

                out_.Add((long)d);
            }

            r.Asns = out_.Count > 50 ? out_.GetRange(0, 50) : out_;
        }

        if (m.TryGetProperty("except", out var ex))
        {
            if (ex.ValueKind != JsonValueKind.True && ex.ValueKind != JsonValueKind.False)
            {
                return null;
            }

            r.Except = ex.GetBoolean();
        }

        if (r.Except && r.Countries.Count == 0 && r.Asns.Count == 0)
        {
            return null;
        }

        if (m.TryGetProperty("rate", out var rate))
        {
            if (rate.ValueKind != JsonValueKind.Object || !rate.TryGetProperty("rps", out var rpsEl) || rpsEl.ValueKind != JsonValueKind.Number)
            {
                return null;
            }

            var rps = rpsEl.GetDouble();
            if (double.IsNaN(rps) || rps <= 0 || rps > 100_000)
            {
                return null;
            }

            long burst = 0;
            if (rate.TryGetProperty("burst", out var b))
            {
                if (!Whole(b, out var bd) || bd < 0 || bd > 1_000_000)
                {
                    return null;
                }

                burst = (long)bd;
            }

            r.Rate = new DefendRate(rps, burst);
        }

        r.Paths = paths.Select(p => p.Length > 1 && p.EndsWith("/", StringComparison.Ordinal) ? p.Substring(0, p.Length - 1) : p).ToList();
        return r;
    }

    private static List<string> List(JsonElement m, string key)
    {
        var out_ = new List<string>();
        if (m.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in v.EnumerateArray())
            {
                if (out_.Count >= MaxList)
                {
                    break;
                }

                if (x.ValueKind == JsonValueKind.String && IsCidr(x.GetString()!) && !out_.Contains(x.GetString()!))
                {
                    out_.Add(x.GetString()!);
                }
            }
        }

        return out_;
    }

    /// <summary>The policy from verified claims; null when they hold no usable policy.</summary>
    public static DefendPolicy? Parse(JsonElement m)
    {
        if (m.ValueKind != JsonValueKind.Object || !m.TryGetProperty("version", out var ver) || ver.ValueKind != JsonValueKind.String
            || !m.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number)
        {
            return null;
        }

        var p = new DefendPolicy { Version = ver.GetString()!, Exp = exp.GetDouble() };
        if (m.TryGetProperty("rules", out var rules) && rules.ValueKind == JsonValueKind.Array)
        {
            var n = 0;
            foreach (var o in rules.EnumerateArray())
            {
                if (n++ >= MaxRules)
                {
                    break;
                }

                if (ParseRule(o) is { } r && !p.Rules.Any(x => x.Id == r.Id))
                {
                    p.Rules.Add(r);
                }
            }
        }

        if (m.TryGetProperty("traps", out var t) && t.ValueKind == JsonValueKind.Object)
        {
            var action = t.TryGetProperty("action", out var ta) && ta.ValueKind == JsonValueKind.String ? ta.GetString() : null;
            p.TrapAction = action == "monitor" || action == "challenge" ? action : "block";
            if (t.TryGetProperty("ttlSeconds", out var ttl) && ttl.ValueKind == JsonValueKind.Number && !double.IsInfinity(ttl.GetDouble()) && ttl.GetDouble() >= 1)
            {
                p.TrapTtlSeconds = (int)Math.Min(Math.Floor(ttl.GetDouble()), MaxTrapTtl);
            }
        }

        if (m.TryGetProperty("listsVersion", out var lv) && lv.ValueKind == JsonValueKind.String)
        {
            var s = lv.GetString()!;
            p.ListsVersion = DefendFacts.FirstCodePoints(s, 64);
        }
        else
        {
            p.ListsVersion = string.Empty;
        }

        p.KillSwitch = m.TryGetProperty("killSwitch", out var ks) && ks.ValueKind == JsonValueKind.True;
        p.Deny = List(m, "deny");
        p.Challenge = List(m, "challenge");
        p.Allow = List(m, "allow");
        p.Honeypots = m.TryGetProperty("honeypots", out var hp) ? HoneypotSettings.Parse(hp) : null;
        p.EdgeKeys = m.TryGetProperty("edgeContext", out var ec) ? EdgeContext.ParseKeys(ec) : Array.Empty<EdgeKey>();
        return p;
    }

    /// <summary>The policy from JSON text (tests, a hand-built policy); null when it holds none.</summary>
    public static DefendPolicy? Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return Parse(doc.RootElement);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>A policy's address lists, parsed once.</summary>
internal sealed class CompiledPolicy
{
    public CompiledPolicy(DefendPolicy p)
    {
        Deny = Ranges(p.Deny);
        Challenge = Ranges(p.Challenge);
        Allow = Ranges(p.Allow);
        foreach (var r in p.Rules)
        {
            Rules.Add(Ranges(r.Cidrs));
        }
    }

    public List<RuleNet> Deny { get; }

    public List<RuleNet> Challenge { get; }

    public List<RuleNet> Allow { get; }

    public List<List<RuleNet>> Rules { get; } = new();

    private static List<RuleNet> Ranges(IEnumerable<string> list)
    {
        var out_ = new List<RuleNet>();
        foreach (var s in list)
        {
            if (RaspRuleExpr.ParseCidr(s) is { } r)
            {
                out_.Add(r);
            }
        }

        return out_;
    }
}
