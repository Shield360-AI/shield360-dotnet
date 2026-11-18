using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace Shield360.Rasp;

/// <summary>
/// The signed config's <c>deception</c> block, normalized (sdk/rasp/README.md, "Deception").
/// Plain data: <see cref="RemoteConfig"/> holds it, so it carries no System.Text.Json type.
/// </summary>
internal sealed class DeceptionConfig
{
    public DeceptionConfig(IReadOnlyList<string> paths, bool block, int ttlSeconds)
    {
        Paths = paths;
        Block = block;
        TtlSeconds = ttlSeconds;
        var bytes = new byte[paths.Count][];
        for (var i = 0; i < paths.Count; i++)
        {
            bytes[i] = Encoding.UTF8.GetBytes(paths[i]);
        }

        PathBytes = bytes;
    }

    /// <summary>The decoys, in config order.</summary>
    public IReadOnlyList<string> Paths { get; }

    /// <summary>Each decoy's UTF-8 bytes, what a request path is compared with.</summary>
    public IReadOnlyList<byte[]> PathBytes { get; }

    /// <summary><c>action</c> is <c>block</c> (else monitor).</summary>
    public bool Block { get; }

    public int TtlSeconds { get; }
}

/// <summary>What the middleware does with a request after deception looked at it.</summary>
internal enum DeceptionVerdict
{
    /// <summary>Go on as if deception were off.</summary>
    Pass,

    /// <summary>A decoy: answer the app's own 404 and never call the next handler.</summary>
    NotFound,

    /// <summary>A suspicious client, blocked: the standard block response.</summary>
    Block,
}

/// <summary>
/// Decoy paths (sdk/rasp/README.md, "Deception"): reading the config, matching a request
/// target, the suspicious-address table and the decision. The middleware calls
/// <see cref="Evaluate"/> before anything else it does.
/// </summary>
internal static class RaspDeception
{
    public const string Sink = "http.deception";
    public const string HitRule = "deception.hit";
    public const string SuspiciousRule = "deception.suspicious";
    public const int MaxPaths = 64;
    public const int MaxPathChars = 256;
    public const int DefaultTtlSeconds = 900;
    public const int MaxTtlSeconds = 86400;

    private static RaspSuspiciousTable s_table = new();

    /// <summary>The process-wide suspicious addresses (tests replace it).</summary>
    internal static RaspSuspiciousTable Table
    {
        get => Volatile.Read(ref s_table);
        set => Volatile.Write(ref s_table, value ?? new RaspSuspiciousTable());
    }

    /// <summary>
    /// Reads the signed config's <c>deception</c> value (null when the key is absent).
    /// Null when deception is off: not an object, or no usable path.
    /// </summary>
    public static DeceptionConfig? Parse(JsonElement? value)
    {
        if (value is not { ValueKind: JsonValueKind.Object } d ||
            !d.TryGetProperty("paths", out var list) || list.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var paths = new List<string>();
        foreach (var p in list.EnumerateArray())
        {
            if (paths.Count == MaxPaths)
            {
                break;
            }

            if (p.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var s = p.GetString()!;
            if (CharCount(s) > MaxPathChars || !JsText.Starts(s, "/"))
            {
                continue;
            }

            if (s.EndsWith("/", StringComparison.Ordinal))
            {
                s = s.Substring(0, s.Length - 1);
            }

            if (s.Length == 0 || s == "/")
            {
                continue;
            }

            paths.Add(s);
        }

        if (paths.Count == 0)
        {
            return null;
        }

        var block = d.TryGetProperty("action", out var a) && a.ValueKind == JsonValueKind.String && a.GetString() == "block";
        var ttl = DefaultTtlSeconds;
        if (d.TryGetProperty("ttlSeconds", out var t) && t.ValueKind == JsonValueKind.Number)
        {
            // A number too large for a double (1e400) is still a number: capped, or below 1 when negative.
            var n = t.TryGetDouble(out var v) ? v : JsText.Starts(t.GetRawText(), "-") ? double.NegativeInfinity : double.PositiveInfinity;
            if (n >= 1)
            {
                ttl = n >= MaxTtlSeconds ? MaxTtlSeconds : (int)Math.Floor(n);
            }
        }

        return new DeceptionConfig(paths, block, ttl);
    }

    // "characters": Unicode code points, so a surrogate pair counts once.
    private static int CharCount(string s)
    {
        var count = 0;
        for (var i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                i++;
            }

            count++;
        }

        return count;
    }

    /// <summary>
    /// The path of a raw request target (everything before the first <c>?</c>) percent-decoded
    /// once (every <c>%XX</c>, <c>%2F</c> included), as bytes; other characters as UTF-8. Null when
    /// an escape is invalid: such a path hits nothing.
    /// </summary>
    public static byte[]? RawPathBytes(string target)
    {
        var q = target.IndexOf('?');
        var path = q >= 0 ? target.Substring(0, q) : target;
        var output = new List<byte>(path.Length);
        var literal = new StringBuilder();
        for (var i = 0; i < path.Length; i++)
        {
            if (path[i] != '%')
            {
                literal.Append(path[i]);
                continue;
            }

            if (i + 2 >= path.Length || Hex(path[i + 1]) is not { } hi || Hex(path[i + 2]) is not { } lo)
            {
                return null;
            }

            Flush(output, literal);
            output.Add((byte)((hi << 4) | lo));
            i += 2;
        }

        Flush(output, literal);
        return output.ToArray();
    }

    /// <summary>A path the server already decoded, as bytes; never decoded again.</summary>
    public static byte[] DecodedPathBytes(string path) => Encoding.UTF8.GetBytes(path);

    private static void Flush(List<byte> output, StringBuilder literal)
    {
        if (literal.Length > 0)
        {
            output.AddRange(Encoding.UTF8.GetBytes(literal.ToString()));
            literal.Clear();
        }
    }

    private static int? Hex(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => null,
    };

    /// <summary>
    /// The decoy a decoded path hits, or null (README "Matching"): byte for byte and
    /// case-sensitive, equal to the decoy or under it on a segment boundary; the first decoy in
    /// config order wins. Nothing is cleaned (dot segments, doubled slashes).
    /// </summary>
    public static string? Match(DeceptionConfig config, byte[]? path)
    {
        if (path is null)
        {
            return null;
        }

        for (var i = 0; i < config.PathBytes.Count; i++)
        {
            var d = config.PathBytes[i];
            if (path.Length < d.Length || (path.Length > d.Length && path[d.Length] != (byte)'/'))
            {
                continue;
            }

            var same = true;
            for (var k = 0; k < d.Length && same; k++)
            {
                same = path[k] == d[k];
            }

            if (same)
            {
                return config.Paths[i];
            }
        }

        return null;
    }

    /// <summary>
    /// The decision for one request. <paramref name="path"/> is the request path's bytes
    /// (<see cref="RawPathBytes"/> or <see cref="DecodedPathBytes"/>), <paramref name="eventPath"/>
    /// the path for the event route, <paramref name="ip"/> the SDK's client address (request.ip),
    /// empty or null when unknown. Never throws: any error passes the request (fail open).
    /// </summary>
    public static DeceptionVerdict Evaluate(
        Func<byte[]?> path,
        string? eventPath,
        Func<string?> ip,
        string? method,
        string framework,
        out Shield360RaspBlockedException? block)
    {
        block = null;
        try
        {
            // ModeFor is off while RASP is not active and for attacks.deception = off.
            var config = RaspEngine.Remote?.Deception;
            if (config is null || RaspEngine.ModeFor(RaspAttackType.Deception) == RaspMode.Off)
            {
                return DeceptionVerdict.Pass;
            }

            var action = config.Block ? RaspMode.Block : RaspMode.Monitor;
            var table = Table;
            var decoy = Match(config, path());
            var address = ip();
            if (decoy is not null)
            {
                if (!string.IsNullOrEmpty(address))
                {
                    table.Mark(address!, TimeSpan.FromSeconds(config.TtlSeconds));
                }

                try
                {
                    RaspEngine.HandleFinding(
                        new RaspFinding(RaspAttackType.Deception, HitRule, Action: action),
                        Sink,
                        new FindingExtra(framework, decoy, method));
                }
                catch (Shield360RaspBlockedException)
                {
                    // a decoy gets the 404 whatever the decision
                }

                return DeceptionVerdict.NotFound;
            }

            if (string.IsNullOrEmpty(address) || !table.IsSuspicious(address!))
            {
                return DeceptionVerdict.Pass;
            }

            try
            {
                RaspEngine.HandleFinding(
                    new RaspFinding(RaspAttackType.Deception, SuspiciousRule, Action: action),
                    Sink,
                    new FindingExtra(framework, null, method, eventPath ?? string.Empty));
            }
            catch (Shield360RaspBlockedException e)
            {
                block = e;
                return DeceptionVerdict.Block;
            }

            return DeceptionVerdict.Pass;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open: as if deception were off
            block = null;
            return DeceptionVerdict.Pass;
        }
    }
}

/// <summary>
/// Client addresses that touched a decoy (README "Suspicious addresses"): in memory, per
/// process, at most <see cref="Capacity"/> entries ordered by expiry, soonest first (equal
/// expiries in the order they were marked). Marking a new address when full drops every
/// expired mark, then the mark closest to expiring.
/// </summary>
internal sealed class RaspSuspiciousTable
{
    public const int DefaultCapacity = 10_000;

    private readonly object _lock = new();
    private readonly Dictionary<string, LinkedListNode<Entry>> _byAddress = new(StringComparer.Ordinal);
    private readonly LinkedList<Entry> _order = new();
    private readonly Func<DateTimeOffset> _now;

    public RaspSuspiciousTable(int capacity = DefaultCapacity, Func<DateTimeOffset>? now = null)
    {
        Capacity = capacity < 1 ? 1 : capacity;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public int Capacity { get; }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _byAddress.Count;
            }
        }
    }

    /// <summary>Marks an address until now + ttl; marking it again restarts the time.</summary>
    public void Mark(string address, TimeSpan ttl)
    {
        var now = _now();
        var until = now + ttl;
        lock (_lock)
        {
            if (_byAddress.TryGetValue(address, out var existing))
            {
                Drop(existing);
            }
            else if (_byAddress.Count >= Capacity)
            {
                // The front expires soonest, so this drops every expired mark.
                while (_order.First is { } first && first.Value.Until <= now)
                {
                    Drop(first);
                }

                while (_byAddress.Count >= Capacity && _order.First is { } soonest)
                {
                    Drop(soonest);
                }
            }

            // In expiry order, after every mark that expires at or before this one. With one
            // TTL that is the end; it only walks back after a TTL change.
            var after = _order.Last;
            while (after is not null && after.Value.Until > until)
            {
                after = after.Previous;
            }

            var entry = new Entry(address, until);
            _byAddress[address] = after is null ? _order.AddFirst(entry) : _order.AddAfter(after, entry);
        }
    }

    /// <summary>Whether an address is marked; an expired mark is dropped. Never extends a mark.</summary>
    public bool IsSuspicious(string address)
    {
        var now = _now();
        lock (_lock)
        {
            if (!_byAddress.TryGetValue(address, out var node))
            {
                return false;
            }

            if (node.Value.Until <= now)
            {
                Drop(node);
                return false;
            }

            return true;
        }
    }

    /// <summary>The marked addresses, soonest to expire first (tests).</summary>
    internal List<string> Addresses()
    {
        lock (_lock)
        {
            var list = new List<string>(_order.Count);
            foreach (var m in _order)
            {
                list.Add(m.Address);
            }

            return list;
        }
    }

    private void Drop(LinkedListNode<Entry> node)
    {
        _order.Remove(node);
        _byAddress.Remove(node.Value.Address);
    }

    private readonly record struct Entry(string Address, DateTimeOffset Until);
}
