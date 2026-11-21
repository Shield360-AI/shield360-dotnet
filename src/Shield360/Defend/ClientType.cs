#pragma warning disable CA1861, CA1870 // netstandard2.0 has no SearchValues; the small literal arrays are on cold paths
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Shield360.Defend;

/// <summary>What Edge's verified context says about the client.</summary>
public sealed class EdgeSignal
{
    /// <summary>Creates a signal.</summary>
    public EdgeSignal(string? clientType, int trap, bool flagged, int risk)
    {
        ClientType = clientType ?? string.Empty;
        Trap = trap;
        Flagged = flagged;
        Risk = risk;
    }

    /// <summary>Edge's client type (verified_agent, verified_crawler, suspected_agent, automation, ...).</summary>
    public string ClientType { get; }

    /// <summary>Edge's trap level (0 none, 1 recon to 4 exploit).</summary>
    public int Trap { get; }

    /// <summary>Whether Edge flagged the client.</summary>
    public bool Flagged { get; }

    /// <summary>Edge's risk score, 0 to 100.</summary>
    public int Risk { get; }
}

/// <summary>What the caller knows beyond the headers.</summary>
public sealed class ClientSignals
{
    /// <summary>An agent passport or Web Bot Auth signature verified.</summary>
    public bool VerifiedAgent { get; set; }

    /// <summary>The client hit a trap.</summary>
    public bool TrapHit { get; set; }

    /// <summary>Edge's verified context.</summary>
    public EdgeSignal? Edge { get; set; }

    /// <summary>Distinct path prefixes this client reached in the last minute (0: unknown).</summary>
    public int Breadth { get; set; }
}

/// <summary>A client type with its reasons and confidence (low, medium, high).</summary>
public sealed class ClientClassification
{
    /// <summary>Creates a classification.</summary>
    public ClientClassification(string clientType, IReadOnlyList<string> reasons, string confidence)
    {
        ClientType = clientType;
        Reasons = new List<string>(reasons);
        Confidence = confidence;
    }

    /// <summary>human, verified_agent, unverified_automation or suspected_ai_agent.</summary>
    public string ClientType { get; }

    /// <summary>Short codes (<c>ua_ai_agent:claude-user</c>), never a header value.</summary>
    public IReadOnlyList<string> Reasons { get; }

    /// <summary>low, medium or high.</summary>
    public string Confidence { get; }
}

/// <summary>
/// Client type: who is calling, with the reasons, deterministic and explainable
/// (docs/latest/shield360/client-type.mdx). The same signatures as the other SDKs
/// (an embedded byte-identical copy of sdk/client-type/signatures.json; a test says so).
/// Port of client-type/classify.ts by way of the Java and Go SDKs.
/// </summary>
public static class ClientType
{
    /// <summary>Nothing says it is automated.</summary>
    public const string Human = "human";

    /// <summary>An agent passport or Web Bot Auth signature verified, or Edge verified the client.</summary>
    public const string VerifiedAgent = "verified_agent";

    /// <summary>A script, library, headless browser, or a crawler that only claims to be one.</summary>
    public const string UnverifiedAutomation = "unverified_automation";

    /// <summary>A trap hit, an AI agent's own name, an agent framework, or automation that roams widely.</summary>
    public const string SuspectedAiAgent = "suspected_ai_agent";

    /// <summary>Distinct path prefixes in a minute that make automation an AI agent.</summary>
    public const int BreadthAgent = 30;

    /// <summary>Every client type.</summary>
    public static readonly IReadOnlyList<string> Types = new[] { Human, VerifiedAgent, UnverifiedAutomation, SuspectedAiAgent };

    private const string Resource = "Shield360.Defend.client-type-signatures.json";
    private static readonly Dictionary<string, List<KeyValuePair<string, string>>> s_sigs = Load(out s_version);
    private static readonly string s_version;

    /// <summary>The signatures' version.</summary>
    public static string SignaturesVersion => s_version;

    internal static byte[] SignaturesBytes()
    {
        using var stream = typeof(ClientType).Assembly.GetManifestResourceStream(Resource);
        if (stream is null)
        {
            return Array.Empty<byte>();
        }

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private static Dictionary<string, List<KeyValuePair<string, string>>> Load(out string version)
    {
        version = string.Empty;
        var sigs = new Dictionary<string, List<KeyValuePair<string, string>>>(StringComparer.Ordinal);
        try
        {
            using var doc = JsonDocument.Parse(SignaturesBytes());
            var root = doc.RootElement;
            if (root.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String)
            {
                version = v.GetString() ?? string.Empty;
            }

            foreach (var k in new[] { "aiAgents", "aiCrawlers", "agentFrameworks", "automation", "headless" })
            {
                var list = new List<KeyValuePair<string, string>>();
                if (root.TryGetProperty(k, out var arr) && arr.ValueKind == JsonValueKind.Array)
                {
                    foreach (var o in arr.EnumerateArray())
                    {
                        if (o.ValueKind == JsonValueKind.Object && o.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String
                            && o.TryGetProperty("match", out var m) && m.ValueKind == JsonValueKind.String)
                        {
                            list.Add(new KeyValuePair<string, string>(id.GetString()!, m.GetString()!));
                        }
                    }
                }

                sigs[k] = list;
            }
        }
        catch (JsonException)
        {
            // no signatures: everything without other signals is human
        }

        return sigs;
    }

    private static string? Find(string ua, string list)
    {
        if (!s_sigs.TryGetValue(list, out var sigs))
        {
            return null;
        }

        foreach (var s in sigs)
        {
            if (s.Value.Length > 0 && ua.IndexOf(s.Value, StringComparison.Ordinal) >= 0)
            {
                return s.Key;
            }
        }

        return null;
    }

    private static bool HasChromeVersion(string ua)
    {
        var i = 0;
        while ((i = ua.IndexOf("chrome/", i, StringComparison.Ordinal)) >= 0)
        {
            var k = i + 7;
            if (k < ua.Length && ua[k] >= '0' && ua[k] <= '9')
            {
                return true;
            }

            i++;
        }

        return false;
    }

    internal static string AsciiLower(string s)
    {
        var b = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            b.Append(c >= 'A' && c <= 'Z' ? (char)(c + 32) : c);
        }

        return b.ToString();
    }

    private static bool Empty(IReadOnlyDictionary<string, string> h, string k) => !h.TryGetValue(k, out var v) || string.IsNullOrEmpty(v);

    /// <summary>The client type from the request's headers (names lower-case) and the signals.</summary>
    public static ClientClassification Classify(IReadOnlyDictionary<string, string> headers, ClientSignals? signals = null)
    {
        var s = signals ?? new ClientSignals();
        var raw = headers.TryGetValue("user-agent", out var u) ? u ?? string.Empty : string.Empty;
        if (raw.Length > 512)
        {
            var cut = 512;
            if (char.IsLowSurrogate(raw[cut]))
            {
                cut--;
            }

            raw = raw.Substring(0, cut);
        }

        var ua = AsciiLower(raw);
        var edge = s.Edge ?? new EdgeSignal(string.Empty, 0, false, 0);
        var ct = edge.ClientType;
        if (s.VerifiedAgent)
        {
            return new ClientClassification(VerifiedAgent, new[] { "agent_verified" }, "high");
        }

        if (ct == "verified_agent" || ct == "verified_crawler")
        {
            return new ClientClassification(VerifiedAgent, new[] { "edge:" + ct }, "high");
        }

        if (s.TrapHit)
        {
            return new ClientClassification(SuspectedAiAgent, new[] { "trap_hit" }, "high");
        }

        if (edge.Trap >= 2)
        {
            return new ClientClassification(SuspectedAiAgent, new[] { "edge:trap_level_" + edge.Trap }, "high");
        }

        var reasons = new List<string>();
        if (ct == "suspected_agent")
        {
            reasons.Add("edge:suspected_agent");
        }

        if (Find(ua, "aiAgents") is { } a)
        {
            reasons.Add("ua_ai_agent:" + a);
        }

        if (Find(ua, "agentFrameworks") is { } f)
        {
            reasons.Add("ua_agent_framework:" + f);
        }

        if (reasons.Count > 0)
        {
            return new ClientClassification(SuspectedAiAgent, reasons, ct == "suspected_agent" ? "high" : "medium");
        }

        var crawler = Find(ua, "aiCrawlers");
        var automation = Find(ua, "automation");
        var headless = Find(ua, "headless");
        if (crawler is not null)
        {
            reasons.Add("ua_ai_crawler:" + crawler);
        }

        if (automation is not null)
        {
            reasons.Add("ua_automation:" + automation);
        }

        if (headless is not null)
        {
            reasons.Add("headless:" + headless);
        }

        if (ua.Length == 0)
        {
            reasons.Add("no_user_agent");
        }

        if (HasChromeVersion(ua) && headless is null && Empty(headers, "sec-ch-ua") && Empty(headers, "sec-fetch-mode") && Empty(headers, "accept-language"))
        {
            reasons.Add("browser_headers_missing");
        }

        if (ct == "automation")
        {
            reasons.Add("edge:automation");
        }

        if (reasons.Count > 0)
        {
            if (s.Breadth >= BreadthAgent)
            {
                reasons.Add("breadth");
                return new ClientClassification(SuspectedAiAgent, reasons, "medium");
            }

            var sure = crawler is not null || automation is not null || headless is not null;
            return new ClientClassification(UnverifiedAutomation, reasons, sure ? "high" : "medium");
        }

        if (edge.Flagged || edge.Risk >= 70)
        {
            return new ClientClassification(UnverifiedAutomation, new[] { edge.Flagged ? "edge:flagged" : "edge:risk" }, "medium");
        }

        return new ClientClassification(Human, Array.Empty<string>(), "low");
    }
}

/// <summary>Counts how many distinct path prefixes (the first three segments) each client reaches in a window.</summary>
public sealed class BreadthCounter
{
    private readonly long _windowMs;
    private readonly int _cap;
    private readonly Dictionary<string, LinkedListNode<Entry>> _clients = new(StringComparer.Ordinal);
    private readonly LinkedList<Entry> _order = new();
    private readonly object _lock = new();

    private sealed class Entry
    {
        public Entry(string client, long start)
        {
            Client = client;
            Start = start;
        }

        public string Client { get; }

        public long Start { get; }

        public HashSet<string> Keys { get; } = new(StringComparer.Ordinal);
    }

    /// <summary>A one-minute window, at most 10,000 clients.</summary>
    public BreadthCounter()
        : this(60_000, 10_000)
    {
    }

    /// <summary>A window and a client cap (the oldest dropped).</summary>
    public BreadthCounter(long windowMs, int cap)
    {
        _windowMs = windowMs;
        _cap = Math.Max(1, cap);
    }

    /// <summary>Records a request; how many distinct prefixes the client reached in its window.</summary>
    public int See(string client, string path, long nowMs)
    {
        var parts = path.Split('/');
        var key = string.Join("/", parts, 0, Math.Min(4, parts.Length));
        lock (_lock)
        {
            _clients.TryGetValue(client, out var node);
            if (node is null || nowMs - node.Value.Start > _windowMs)
            {
                if (node is null && _clients.Count >= _cap && _order.First is { } oldest)
                {
                    _clients.Remove(oldest.Value.Client);
                    _order.RemoveFirst();
                }

                if (node is not null)
                {
                    _order.Remove(node);
                }

                node = _order.AddLast(new Entry(client, nowMs));
                _clients[client] = node;
            }

            if (node.Value.Keys.Count < 64)
            {
                node.Value.Keys.Add(key);
            }

            return node.Value.Keys.Count;
        }
    }
}
