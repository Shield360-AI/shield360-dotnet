using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Shield360.Rasp;

/// <summary>One clause of a virtual patch's all-of <c>match</c>.</summary>
internal sealed record MatchClause(string Target, string Op, IReadOnlyList<string> Values, string? Value, bool IgnoreCase);

/// <summary>A virtual patch (sdk/rasp/README.md, "Virtual patches").</summary>
internal sealed class VirtualPatch
{
    public string Id { get; init; } = string.Empty;

    public string? Title { get; init; }

    public IReadOnlyList<string> Cves { get; init; } = Array.Empty<string>();

    public bool Example { get; init; }

    /// <summary>Null means every runtime.</summary>
    public IReadOnlyList<string>? Runtimes { get; init; }

    /// <summary>Half-open <c>[from, to)</c> ranges per runtime.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<(string From, string To)>?>? RuntimeVersions { get; init; }

    /// <summary>The rule's <c>action</c> as written (null when absent).</summary>
    public string? Action { get; init; }

    public IReadOnlyList<MatchClause> Match { get; init; } = Array.Empty<MatchClause>();

    /// <summary>
    /// Reads one rule. Null when it has no string <c>id</c> or no <c>match</c>
    /// array (the engine drops those); clauses that are not objects are kept as
    /// clauses that never match, so a rule with a broken clause never fires.
    /// </summary>
    public static VirtualPatch? FromJson(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.Object ||
            !e.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String ||
            !e.TryGetProperty("match", out var match) || match.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var clauses = new List<MatchClause>();
        foreach (var c in match.EnumerateArray())
        {
            clauses.Add(c.ValueKind == JsonValueKind.Object
                ? new MatchClause(
                    Str(c, "target") ?? string.Empty,
                    Str(c, "op") ?? string.Empty,
                    c.TryGetProperty("values", out var vs) && vs.ValueKind == JsonValueKind.Array
                        ? vs.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
                        : Array.Empty<string>(),
                    Str(c, "value"),
                    c.TryGetProperty("ignoreCase", out var ic) && ic.ValueKind == JsonValueKind.True)
                : new MatchClause(string.Empty, string.Empty, Array.Empty<string>(), null, false));
        }

        IReadOnlyList<string>? runtimes = null;
        if (e.TryGetProperty("runtimes", out var rt) && rt.ValueKind == JsonValueKind.Array)
        {
            runtimes = rt.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList();
        }

        Dictionary<string, IReadOnlyList<(string, string)>?>? versions = null;
        if (e.TryGetProperty("runtimeVersions", out var rv) && rv.ValueKind == JsonValueKind.Object)
        {
            versions = new Dictionary<string, IReadOnlyList<(string, string)>?>(StringComparer.Ordinal);
            foreach (var p in rv.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.Array)
                {
                    versions[p.Name] = null;
                    continue;
                }

                var ranges = new List<(string, string)>();
                foreach (var r in p.Value.EnumerateArray())
                {
                    // A malformed range never contains any version.
                    ranges.Add(r.ValueKind == JsonValueKind.Array && r.GetArrayLength() >= 2
                        ? (Text(r[0]), Text(r[1]))
                        : ("1", "0"));
                }

                versions[p.Name] = ranges;
            }
        }

        return new VirtualPatch
        {
            Id = id.GetString()!,
            Title = Str(e, "title"),
            Cves = e.TryGetProperty("cves", out var cves) && cves.ValueKind == JsonValueKind.Array
                ? cves.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
                : Array.Empty<string>(),
            Example = e.TryGetProperty("example", out var ex) && ex.ValueKind == JsonValueKind.True,
            Runtimes = runtimes,
            RuntimeVersions = versions?.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal),
            Action = Str(e, "action"),
            Match = clauses,
        };
    }

    /// <summary>Reads a rule list; entries that are not rules are left out.</summary>
    public static List<VirtualPatch> ListFromJson(JsonElement array) =>
        array.ValueKind == JsonValueKind.Array
            ? array.EnumerateArray().Select(FromJson).Where(r => r is not null).Select(r => r!).ToList()
            : new List<VirtualPatch>();

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    // JS String(x): numbers print as written, strings as they are.
    private static string Text(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString()! : e.GetRawText();
}

/// <summary>The request as the rules see it. Header names are lower-case.</summary>
internal sealed class VpRequest
{
    public string Method { get; set; } = "GET";

    public string Path { get; set; } = "/";

    /// <summary>The raw query string, without <c>?</c>.</summary>
    public string Query { get; set; } = string.Empty;

    /// <summary>Lower-case header names; repeated headers joined with <c>", "</c>.</summary>
    public Dictionary<string, string> Headers { get; set; } = new(StringComparer.Ordinal);

    /// <summary>The raw Cookie header.</summary>
    public string Cookie { get; set; } = string.Empty;

    /// <summary>The raw body text, or the JSON of a parsed body; empty when unknown.</summary>
    public string Body { get; set; } = string.Empty;
}

internal enum VpPhase
{
    All,
    Head,
    Body,
}

/// <summary>
/// Virtual patches: rules that match the documented request shape of a public
/// advisory, the one place RASP matches request signatures. Run once per
/// request when its input is captured, before the handler. The built-in list is
/// the embedded <c>Rasp/Data/default-rules.json</c>, a byte-identical copy of
/// <c>sdk/rasp/rules/default-rules.json</c>. Port of the TypeScript <c>vpatch.ts</c>.
/// </summary>
internal static class RaspVirtualPatches
{
    public const int MaxVpText = 64 * 1024;
    private const int MaxPattern = 1024;

    /// <summary>The runtime name rules use for .NET.</summary>
    public const string Runtime = "dotnet";

    private static readonly Regex s_refused = new(@"\\[1-9]|\\k<|\(\?<?[=!]", RegexOptions.CultureInvariant);
    private static readonly ConcurrentDictionary<string, Regex?> s_regexCache = new(StringComparer.Ordinal);

    /// <summary>The runtime version rules compare against: <see cref="Environment.Version"/>.</summary>
    public static string RuntimeVersion { get; } = Environment.Version.ToString();

    public static IReadOnlyList<VirtualPatch> BuiltIn => RaspData.BuiltInRules;

    private static int CompareVersions(string a, string b)
    {
        var pa = a.Split('.').Select(LeadingInt).ToArray();
        var pb = b.Split('.').Select(LeadingInt).ToArray();
        for (var i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            var d = (i < pa.Length ? pa[i] : 0) - (i < pb.Length ? pb[i] : 0);
            if (d != 0)
            {
                return d;
            }
        }

        return 0;
    }

    // JS parseInt(x, 10) || 0: the leading digits (after an optional sign), else 0.
    private static int LeadingInt(string s)
    {
        var t = JsText.Trim(s);
        var sign = 1;
        var i = 0;
        if (i < t.Length && (t[i] == '+' || t[i] == '-'))
        {
            sign = t[i] == '-' ? -1 : 1;
            i++;
        }

        var start = i;
        while (i < t.Length && t[i] >= '0' && t[i] <= '9' && i - start < 9)
        {
            i++;
        }

        return i == start ? 0 : sign * int.Parse(t.Substring(start, i - start), CultureInfo.InvariantCulture);
    }

    /// <summary>Whether the rule applies in this runtime and version (<c>[from, to)</c> ranges).</summary>
    public static bool RuleApplies(VirtualPatch rule, string runtime, string version)
    {
        if (rule.Runtimes is not null && !rule.Runtimes.Contains(runtime))
        {
            return false;
        }

        if (rule.RuntimeVersions is not null && rule.RuntimeVersions.TryGetValue(runtime, out var ranges) && ranges is not null)
        {
            return ranges.Any(r => CompareVersions(version, r.From) >= 0 && CompareVersions(version, r.To) < 0);
        }

        return true;
    }

    /// <summary>Whether a rule reads the body (it can only be judged once the body is known).</summary>
    public static bool NeedsBody(VirtualPatch rule) => rule.Match.Any(c => c.Target == "body" || c.Target == "request");

    private static string Cap(string s) => s.Length > MaxVpText ? s.Substring(0, MaxVpText) : s;

    private static string? TargetText(VpRequest req, string target)
    {
        switch (target)
        {
            case "method":
                return req.Method;
            case "path":
                return req.Path;
            case "query":
                return req.Query;
            case "cookie":
                return req.Cookie;
            case "body":
                return Cap(req.Body);
            case "request":
                return req.Path + "?" + req.Query + "\n" + req.Cookie + "\n" + Cap(req.Body);
        }

        if (JsText.Starts(target, "header:"))
        {
            return req.Headers.TryGetValue(JsText.Lower(target.Substring(7)), out var v) ? v : null;
        }

        return null;
    }

    /// <summary>Compiles a rule pattern; refuses backreferences, lookaround (contract) and overlong patterns.</summary>
    private static Regex? Compile(string pattern)
    {
        if (s_regexCache.TryGetValue(pattern, out var cached))
        {
            return cached;
        }

        Regex? re = null;
        if (pattern.Length <= MaxPattern && !s_refused.IsMatch(pattern))
        {
            try
            {
#if NET
                re = new Regex(pattern, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(100));
#else
                re = new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
#endif
            }
            catch (ArgumentException)
            {
                re = null;
            }
#if NET
            catch (NotSupportedException)
            {
                re = null;
            }
#endif
        }

        if (s_regexCache.Count > 512)
        {
            s_regexCache.Clear();
        }

        s_regexCache[pattern] = re;
        return re;
    }

    public static bool ClauseMatches(VpRequest req, MatchClause c)
    {
        var text = TargetText(req, c.Target);
        if (c.Op == "present")
        {
            return text is not null;
        }

        if (text is null)
        {
            return false;
        }

        switch (c.Op)
        {
            case "equals":
                return c.Values.Any(v => string.Equals(JsText.Lower(v), JsText.Lower(text), StringComparison.Ordinal));
            case "contains_any":
                if (c.IgnoreCase)
                {
                    var t = JsText.Lower(text);
                    return c.Values.Any(v => v.Length > 0 && JsText.Has(t, JsText.Lower(v)));
                }

                return c.Values.Any(v => v.Length > 0 && JsText.Has(text, v));
            case "regex" when c.Value is not null:
                var re = Compile(c.Value);
                if (re is null)
                {
                    return false;
                }

                try
                {
                    return re.IsMatch(Cap(text));
                }
                catch (RegexMatchTimeoutException)
                {
                    return false;
                }

            default:
                return false;
        }
    }

    /// <summary>
    /// The first rule the request matches, as a finding. <see cref="VpPhase.Head"/> judges only
    /// rules that do not read the body, <see cref="VpPhase.Body"/> only rules that do.
    /// </summary>
    public static RaspFinding? Match(VpRequest req, IReadOnlyList<VirtualPatch> rules, VpPhase phase = VpPhase.All, string runtime = Runtime, string? version = null)
    {
        var v = version ?? RuntimeVersion;
        foreach (var r in rules)
        {
            if (r.Match.Count == 0)
            {
                continue;
            }

            if (phase != VpPhase.All && NeedsBody(r) != (phase == VpPhase.Body))
            {
                continue;
            }

            if (!RuleApplies(r, runtime, v))
            {
                continue;
            }

            if (r.Match.All(c => ClauseMatches(req, c)))
            {
                var action = r.Action == "off" ? RaspMode.Off : r.Action == "monitor" ? RaspMode.Monitor : RaspMode.Block;
                return new RaspFinding(RaspAttackType.VirtualPatch, r.Id, Cve: r.Cves.Count > 0 ? r.Cves[0] : null, Action: action);
            }
        }

        return null;
    }
}

/// <summary>The data files embedded in the assembly (byte-identical copies of the contract's).</summary>
internal static class RaspData
{
    public const string RulesResource = "Shield360.Rasp.default-rules.json";
    public const string DnslogResource = "Shield360.Rasp.dnslog-domains.json";

    private static readonly Lazy<(IReadOnlyList<VirtualPatch> Rules, string Version)> s_rules = new(LoadRules);
    private static readonly Lazy<(HashSet<string> Hosts, string[] Suffixes)> s_dnslog = new(LoadDnslog);

    public static IReadOnlyList<VirtualPatch> BuiltInRules => s_rules.Value.Rules;

    public static string BuiltInVersion => s_rules.Value.Version;

    public static HashSet<string> DnslogHosts => s_dnslog.Value.Hosts;

    public static string[] DnslogSuffixes => s_dnslog.Value.Suffixes;

    public static byte[] Resource(string name)
    {
        using var stream = typeof(RaspData).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException("Missing embedded resource " + name);
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    private static (IReadOnlyList<VirtualPatch>, string) LoadRules()
    {
        try
        {
            using var doc = JsonDocument.Parse(Resource(RulesResource));
            var version = doc.RootElement.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : string.Empty;
            return (doc.RootElement.TryGetProperty("rules", out var rules) ? VirtualPatch.ListFromJson(rules) : new List<VirtualPatch>(), version);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            return (Array.Empty<VirtualPatch>(), string.Empty);
        }
    }

    private static (HashSet<string>, string[]) LoadDnslog()
    {
        try
        {
            using var doc = JsonDocument.Parse(Resource(DnslogResource));
            static IEnumerable<string> Strings(JsonElement root, string name) =>
                root.TryGetProperty(name, out var a) && a.ValueKind == JsonValueKind.Array
                    ? a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
                    : Enumerable.Empty<string>();
            return (new HashSet<string>(Strings(doc.RootElement, "hosts"), StringComparer.Ordinal), Strings(doc.RootElement, "domains").ToArray());
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            return (new HashSet<string>(StringComparer.Ordinal), Array.Empty<string>());
        }
    }
}
