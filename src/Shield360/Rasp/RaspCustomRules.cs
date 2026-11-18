using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Shield360.Rasp;

/// <summary>When request rules are judged: head, body, or again once the client address is final.</summary>
internal enum RulePhase
{
    Head,
    Body,
    Ip,
}

/// <summary>A custom rule that applies to this app, compiled (sdk/rasp/README.md, "Custom rules").</summary>
internal sealed record CustomRule(string Id, string Name, string Action, IReadOnlyList<string>? Apps, CompiledRuleExpr Expr);

/// <summary>A rule left out of the signed config, and why.</summary>
internal sealed record SkippedRule(int Index, string? Id, string Reason);

/// <summary>A rule that matched, with the input that made it match (for <c>input.*</c> rules).</summary>
internal sealed record RuleMatch(CustomRule Rule, RuleInput? Input);

/// <summary>Per-request evaluation state, kept on the context: the rules matched so far and the work budget.</summary>
internal sealed class CustomRuleState
{
    public HashSet<string> Matched { get; } = new(StringComparer.Ordinal);

    public RuleBudget Budget { get; } = new();
}

/// <summary>
/// Custom rules (sdk/rasp/README.md, "Custom rules"): the organization's own rules, in the
/// expression language of <see cref="RaspRuleExpr"/>, delivered inside the signed config
/// (<c>customRules</c>). Each expression is parsed and type-checked when the config arrives
/// and evaluated as data. An invalid rule is skipped with one warning and never breaks the
/// config; evaluation fails open. Port of the TypeScript <c>custom-rules.ts</c>.
/// </summary>
internal static class RaspCustomRules
{
    public const int MaxRules = 64;
    public const int MaxApps = 32;
    public const string Prefix = "custom.";

    private static readonly object s_lock = new();
    private static readonly HashSet<string> s_warned = new(StringComparer.Ordinal);

    /// <summary>Tests only: lets the once-per-rule warnings fire again.</summary>
    internal static void ResetWarnings()
    {
        lock (s_lock)
        {
            s_warned.Clear();
        }
    }

    private static void DefaultWarn(SkippedRule s) =>
        RaspRuntime.Warn($"Shield360 RASP: custom rule {(s.Id is null ? "#" + (s.Index + 1) : "\"" + s.Id + "\"")} was skipped ({s.Reason}); the other rules apply.");

    /// <summary><c>^[a-z0-9][a-z0-9_-]{0,47}$</c>: lower-case, so the event rule <c>custom.&lt;id&gt;</c> fits the platform's rule shape.</summary>
    public static bool IsValidId(string id)
    {
        if (id.Length < 1 || id.Length > 48)
        {
            return false;
        }

        for (var i = 0; i < id.Length; i++)
        {
            var c = id[i];
            var ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && (c == '_' || c == '-'));
            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// The rules of a signed config that apply to this app: invalid rules are skipped (one
    /// warning per rule and reason, per process), disabled rules and rules scoped to other
    /// apps are left out silently. At most 64.
    /// </summary>
    public static IReadOnlyList<CustomRule> Parse(JsonElement? raw, string app, Action<SkippedRule>? warn = null)
    {
        var output = new List<CustomRule>();
        if (raw is not { ValueKind: JsonValueKind.Array } list)
        {
            return output;
        }

        var report = warn ?? DefaultWarn;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        void Skip(SkippedRule s, string? expression = null)
        {
            var key = (s.Id ?? s.Index.ToString(System.Globalization.CultureInfo.InvariantCulture)) + "\u0000" + s.Reason + "\u0000" + (expression ?? string.Empty);
            lock (s_lock)
            {
                if (s_warned.Contains(key))
                {
                    return;
                }

                if (s_warned.Count > 1024)
                {
                    s_warned.Clear();
                }

                s_warned.Add(key);
            }

            try
            {
                report(s);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // never
            }
        }

        var index = -1;
        foreach (var r in list.EnumerateArray())
        {
            index++;
            try
            {
                if (r.ValueKind != JsonValueKind.Object)
                {
                    Skip(new SkippedRule(index, null, "not an object"));
                    continue;
                }

                var id = r.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String && IsValidId(idEl.GetString()!) ? idEl.GetString()! : null;
                if (id is null)
                {
                    Skip(new SkippedRule(index, null, "invalid id"));
                    continue;
                }

                if (!ids.Add(id))
                {
                    Skip(new SkippedRule(index, id, "duplicate id"));
                    continue;
                }

                if (!r.TryGetProperty("enabled", out var enabledEl) || enabledEl.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    Skip(new SkippedRule(index, id, "invalid enabled flag"));
                    continue;
                }

                var action = r.TryGetProperty("action", out var actionEl) && actionEl.ValueKind == JsonValueKind.String ? actionEl.GetString() : null;
                if (action is not ("block" or "monitor" or "alert"))
                {
                    Skip(new SkippedRule(index, id, "invalid action"));
                    continue;
                }

                var hasName = r.TryGetProperty("name", out var nameEl);
                if (hasName && nameEl.ValueKind != JsonValueKind.String)
                {
                    Skip(new SkippedRule(index, id, "invalid name"));
                    continue;
                }

                List<string>? apps = null;
                if (r.TryGetProperty("apps", out var appsEl) && appsEl.ValueKind != JsonValueKind.Null)
                {
                    if (appsEl.ValueKind != JsonValueKind.Array || appsEl.GetArrayLength() > MaxApps || appsEl.EnumerateArray().Any(a => a.ValueKind != JsonValueKind.String))
                    {
                        Skip(new SkippedRule(index, id, "invalid apps"));
                        continue;
                    }

                    apps = appsEl.EnumerateArray().Select(a => a.GetString()!).ToList();
                }

                var expression = r.TryGetProperty("expression", out var exprEl) && exprEl.ValueKind == JsonValueKind.String ? exprEl.GetString() : null;
                var compiled = RaspRuleExpr.Compile(expression, out var error);
                if (compiled is null)
                {
                    Skip(new SkippedRule(index, id, "expression: " + error!.Code), expression);
                    continue;
                }

                if (enabledEl.ValueKind == JsonValueKind.False)
                {
                    continue;
                }

                if (apps is { Count: 0 })
                {
                    apps = null;
                }

                if (apps is not null && !apps.Contains(app, StringComparer.Ordinal))
                {
                    continue;
                }

                if (output.Count >= MaxRules)
                {
                    Skip(new SkippedRule(index, id, "more than 64 rules"));
                    continue;
                }

                output.Add(new CustomRule(id, hasName ? nameEl.GetString()! : id, action, apps, compiled));
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                Skip(new SkippedRule(index, null, "unreadable"));
            }
        }

        return output;
    }

    /// <summary>The most a rule does: <c>alert</c> reports like <c>monitor</c> (the platform raises the alert).</summary>
    public static RaspMode ActionMode(string action) => action == "block" ? RaspMode.Block : RaspMode.Monitor;

    /// <summary>The finding a matched rule reports (attack type <c>custom_rule</c>, rule <c>custom.&lt;id&gt;</c>).</summary>
    public static RaspFinding Finding(CustomRule rule, RaspInput? input) =>
        new(RaspAttackType.CustomRule, Prefix + rule.Id, input, Action: ActionMode(rule.Action));

    /// <summary>The SDK input behind a rule input, or a new one built from it.</summary>
    public static RaspInput? InputOf(RuleInput? input) =>
        input is null ? null : input.Origin ?? new RaspInput(input.Value, input.Key, input.Source == "model_output" ? RaspInputSource.ModelOutput : RaspInputSource.Request);

    /// <summary>
    /// The request as the language sees it (README "Custom rules: fields"). With
    /// <paramref name="head"/>, only the inputs known before the body: body inputs
    /// (<c>body</c>, <c>body.*</c>) join at the body phase even when the body was captured first.
    /// </summary>
    public static RuleSubject Subject(RaspContext? ctx, string app, bool head = false)
    {
        if (ctx is null)
        {
            return new RuleSubject { App = app, Inputs = Array.Empty<RuleInput>() };
        }

        IReadOnlyList<RaspInput> list = ctx.InputsSnapshot();
        if (head)
        {
            list = list.Where(i => !IsBodyInput(i)).ToArray();
        }

        var headers = new Dictionary<string, string>(StringComparer.Ordinal);
        if (ctx.Vp?.Req.Headers is { } raw)
        {
            foreach (var kv in raw)
            {
                if (kv.Value is not null)
                {
                    headers[kv.Key.ToLowerInvariant()] = kv.Value;
                }
            }
        }

        var query = new Dictionary<string, string>(StringComparer.Ordinal);
        var body = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var i in list)
        {
            if (i.Source != RaspInputSource.Request)
            {
                continue;
            }

            if (i.Key.StartsWith("query.", StringComparison.Ordinal))
            {
                var k = i.Key.Substring(6);
                if (!query.ContainsKey(k))
                {
                    query[k] = i.Value;
                }
            }
            else if (i.Key.StartsWith("body.", StringComparison.Ordinal))
            {
                var k = i.Key.Substring(5);
                if (!body.ContainsKey(k))
                {
                    body[k] = i.Value;
                }
            }
        }

        var path = ctx.Path;
        return new RuleSubject
        {
            App = app,
            Request = ctx.InRequest
                ? new RuleRequest
                {
                    Method = string.IsNullOrEmpty(ctx.Method) ? null : ctx.Method!.ToUpperInvariant(),
                    Path = path,
                    Route = ctx.ResolvedRoute() ?? (string.IsNullOrEmpty(path) ? null : RaspScope.RouteOf(path!)),
                    Ip = ctx.CurrentIp(),
                    Headers = headers,
                    Query = query,
                    Body = body,
                }
                : null,
            Inputs = list.Select(i => new RuleInput(i.Value, i.Key, RaspNames.Of(i.Source), i)).ToArray(),
        };
    }

    private static bool IsBodyInput(RaspInput i) =>
        i.Source == RaspInputSource.Request && (i.Key == "body" || i.Key.StartsWith("body.", StringComparison.Ordinal));

    /// <summary>The context's custom-rule state, created on first use.</summary>
    public static CustomRuleState StateOf(RaspContext ctx)
    {
        lock (ctx.SyncRoot)
        {
            return ctx.Rules ??= new CustomRuleState();
        }
    }

    /// <summary>
    /// The request rules to judge in a phase, matched in order. Head: every request rule that
    /// does not read the body. Body: rules that read the body, and rules reading <c>input.*</c>
    /// that did not match at head (the body added inputs). A rule matches at most once per request.
    /// </summary>
    /// <remarks>
    /// Rules that read <c>request.ip</c> are skipped while <see cref="RaspContext.IpPending"/>; the
    /// <see cref="RulePhase.Ip"/> phase judges every unmatched one of them whose inputs are known.
    /// </remarks>
    public static List<RuleMatch> MatchRequestRules(IReadOnlyList<CustomRule> rules, RaspContext ctx, RulePhase phase, RuleSubject subject)
    {
        var st = StateOf(ctx);
        var output = new List<RuleMatch>();

        // The budget is the lock: finding rules on other threads of the request share it.
        lock (st.Budget)
        {
            foreach (var rule in rules)
            {
                var e = rule.Expr;
                if (st.Budget.Steps < 0)
                {
                    break;
                }

                if (e.Phase != "request" || st.Matched.Contains(rule.Id))
                {
                    continue;
                }

                var wanted = phase switch
                {
                    RulePhase.Head => !e.UsesBody,
                    RulePhase.Body => e.UsesBody || e.UsesInput,
                    _ => e.UsesIp && (!e.UsesBody || ctx.Vp?.BodyKnown == true),
                };
                if (!wanted || (phase != RulePhase.Ip && e.UsesIp && ctx.IpPending))
                {
                    continue;
                }

                var r = RaspRuleExpr.Evaluate(e, subject, st.Budget);
                if (r.Exhausted)
                {
                    break;
                }

                if (!r.Matched)
                {
                    continue;
                }

                st.Matched.Add(rule.Id);
                output.Add(new RuleMatch(rule, r.Input));
            }
        }

        return output;
    }

    /// <summary>The finding rules a built-in finding matches, in order.</summary>
    public static List<RuleMatch> MatchFindingRules(IReadOnlyList<CustomRule> rules, RuleSubject subject, RuleBudget budget)
    {
        var output = new List<RuleMatch>();
        lock (budget)
        {
            foreach (var rule in rules)
            {
                if (budget.Steps < 0)
                {
                    break;
                }

                if (rule.Expr.Phase != "finding")
                {
                    continue;
                }

                var r = RaspRuleExpr.Evaluate(rule.Expr, subject, budget);
                if (r.Exhausted)
                {
                    break;
                }

                if (r.Matched)
                {
                    output.Add(new RuleMatch(rule, r.Input));
                }
            }
        }

        return output;
    }
}
