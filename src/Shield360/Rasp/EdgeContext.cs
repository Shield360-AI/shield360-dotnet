using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Shield360.Rasp;

/// <summary>A key of the signed config's <c>edgeContext</c> (protection triangle).</summary>
internal sealed class EdgeKey
{
    public EdgeKey(string kid, byte[] secret)
    {
        Kid = kid;
        Secret = secret;
    }

    public string Kid { get; }

    public byte[] Secret { get; }
}

/// <summary>Edge's verified context for a request (protection triangle).</summary>
internal sealed record EdgeRequestContext(
    string Rid, long Iat, long Exp, string Method, string PathHash, string ClientType, int Risk, int Trap, bool Flagged, IReadOnlyList<string>? Waf, string? Traceparent);

/// <summary>
/// SHIELD: the protection triangle (agent-guides/edge-deception-spec.md, "Protection triangle").
/// Shield360 Edge in front of the app sends a signed, short-lived <c>X-Shield360-Edge-Context</c>
/// header; RASP verifies it and may tighten on it. A detection in a request that came through
/// Edge is answered with a signed <c>X-Shield360-Verdict</c> response header so Edge blocks the
/// client on its next request. Both are <c>v1.&lt;kid&gt;.&lt;base64url payload&gt;.&lt;base64url
/// HMAC-SHA-256&gt;</c> with the environment's key from the signed config (<c>edgeContext</c>).
/// A header that does not verify is ignored. Never throws. Port of
/// sdk/typescript/src/rasp/edge-context.ts; passes sdk/rasp/testdata/triangle.json.
/// </summary>
internal static class EdgeContext
{
    public const string ContextHeader = "x-shield360-edge-context";
    public const string VerdictHeader = "X-Shield360-Verdict";

    private const int ContextTtl = 30;
    private const int Skew = 5;
    private const int MaxHeader = 4096;
    private static readonly TimeSpan s_rx = TimeSpan.FromMilliseconds(100);
    private static readonly Regex s_kid = new("^[0-9a-f]{8}\\z", RegexOptions.CultureInvariant, s_rx);
    private static readonly Regex s_rid = new("^[A-Za-z0-9_-]{8,64}\\z", RegexOptions.CultureInvariant, s_rx);
    private static readonly Regex s_cat = new("^[a-z][a-z0-9_]{0,39}\\z", RegexOptions.CultureInvariant, s_rx);
    private static readonly Regex s_key = new("^[A-Za-z0-9_-]{43}\\z", RegexOptions.CultureInvariant, s_rx);
    private static readonly Regex s_b64 = new("^[A-Za-z0-9_-]*\\z", RegexOptions.CultureInvariant, s_rx);
    private static readonly HashSet<string> s_clients = new(StringComparer.Ordinal) { "human", "verified_crawler", "verified_agent", "automation", "suspected_agent", "unknown" };
    private static readonly HashSet<string> s_contextKeys = new(StringComparer.Ordinal) { "rid", "iat", "exp", "m", "ph", "ct", "risk", "waf", "trap", "fl", "tp" };
    private static readonly EdgeReplayCache s_replay = new();

    /// <summary>The signed config's <c>edgeContext</c>: <c>{"keys": [{"kid", "key"}]}</c>, at most two; anything malformed: none.</summary>
    public static IReadOnlyList<EdgeKey> ParseKeys(JsonElement? raw)
    {
        try
        {
            if (raw is not { ValueKind: JsonValueKind.Object } o || !o.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array)
            {
                return Array.Empty<EdgeKey>();
            }

            var output = new List<EdgeKey>();
            foreach (var k in keys.EnumerateArray().Take(2))
            {
                if (k.ValueKind != JsonValueKind.Object || !k.TryGetProperty("kid", out var kid) || kid.ValueKind != JsonValueKind.String
                    || !k.TryGetProperty("key", out var key) || key.ValueKind != JsonValueKind.String
                    || !s_kid.IsMatch(kid.GetString()!) || !s_key.IsMatch(key.GetString()!))
                {
                    return Array.Empty<EdgeKey>();
                }

                var secret = B64Decode(key.GetString()!);
                if (secret.Length != 32)
                {
                    return Array.Empty<EdgeKey>();
                }

                output.Add(new EdgeKey(kid.GetString()!, secret));
            }

            return output;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return Array.Empty<EdgeKey>();
        }
    }

    /// <summary><c>hex(SHA-256(path)[0:8])</c>.</summary>
    public static string PathHash(string path)
    {
#if NET8_0_OR_GREATER
        return Hex(SHA256.HashData(Encoding.UTF8.GetBytes(path)), 8);
#else
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(path)), 8);
#endif
    }

    private static string Hex(byte[] b, int n)
    {
        var sb = new StringBuilder(n * 2);
        for (var i = 0; i < n; i++)
        {
            sb.Append(b[i].ToString("x2", CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }

    private static byte[] Mac(byte[] secret, string label, string payload)
    {
#if NET8_0_OR_GREATER
        return HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(label + payload));
#else
        using var h = new HMACSHA256(secret);
        return h.ComputeHash(Encoding.UTF8.GetBytes(label + payload));
#endif
    }

    private static string B64Encode(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] B64Decode(string s)
    {
        if (!s_b64.IsMatch(s) || s.Length % 4 == 1)
        {
            throw new FormatException("base64url");
        }

        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t + new string('=', (4 - (t.Length % 4)) % 4));
    }

    private static bool FixedEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        var d = 0;
        for (var i = 0; i < a.Length; i++)
        {
            d |= a[i] ^ b[i];
        }

        return d == 0;
    }

    private static JsonElement? Open(IReadOnlyList<EdgeKey> keys, string label, string? value, HashSet<string> allowed)
    {
        try
        {
            if (string.IsNullOrEmpty(value) || value!.Length > MaxHeader)
            {
                return null;
            }

            var parts = value.Split('.');
            if (parts.Length != 4 || parts[0] != "v1" || !s_kid.IsMatch(parts[1]))
            {
                return null;
            }

            var key = keys.FirstOrDefault(k => k.Kid == parts[1]);
            if (key is null || !FixedEquals(B64Decode(parts[3]), Mac(key.Secret, label, parts[2])))
            {
                return null;
            }

            using var doc = JsonDocument.Parse(B64Decode(parts[2]));
            var root = doc.RootElement.Clone();
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Any(p => !allowed.Contains(p.Name)))
            {
                return null;
            }

            return root;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    private static bool Int(JsonElement o, string name, out long v)
    {
        v = 0;
        if (!o.TryGetProperty(name, out var p) || p.ValueKind != JsonValueKind.Number || !p.TryGetDouble(out var d) || Math.Floor(d) != d || double.IsInfinity(d))
        {
            return false;
        }

        v = (long)d;
        return true;
    }

    private static string? Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    /// <summary>The verified context for this request (process replay cache, the clock), or null.</summary>
    public static EdgeRequestContext? Verify(IReadOnlyList<EdgeKey> keys, string? value, string method, string path, string? requestId) =>
        Verify(keys, value, method, path, requestId, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), s_replay);

    /// <summary>The verified context for this request, or null (<paramref name="cache"/> null: no replay check).</summary>
    public static EdgeRequestContext? Verify(IReadOnlyList<EdgeKey> keys, string? value, string method, string path, string? requestId, long now, EdgeReplayCache? cache)
    {
        try
        {
            if (value is null || keys.Count == 0 || Open(keys, "s360-ctx|v1|", value, s_contextKeys) is not { } c)
            {
                return null;
            }

            var rid = Str(c, "rid");
            var ct = Str(c, "ct");
            if (rid is null || !s_rid.IsMatch(rid) || ct is null || !s_clients.Contains(ct))
            {
                return null;
            }

            if (!Int(c, "iat", out var iat) || !Int(c, "exp", out var exp) || iat > now + Skew || exp < now - Skew || exp - iat > ContextTtl)
            {
                return null;
            }

            var m = Str(c, "m");
            if (m != method || Str(c, "ph") != PathHash(path) || requestId != rid)
            {
                return null;
            }

            if (!Int(c, "risk", out var risk) || !Int(c, "trap", out var trap) || risk < 0 || risk > 100 || trap < 0 || trap > 4)
            {
                return null;
            }

            List<string>? waf = null;
            if (c.TryGetProperty("waf", out var w) && w.ValueKind != JsonValueKind.Null)
            {
                if (w.ValueKind != JsonValueKind.Array || w.GetArrayLength() > 16)
                {
                    return null;
                }

                waf = new List<string>();
                foreach (var x in w.EnumerateArray())
                {
                    if (x.ValueKind != JsonValueKind.String || !s_cat.IsMatch(x.GetString()!))
                    {
                        return null;
                    }

                    waf.Add(x.GetString()!);
                }
            }

            if (cache is not null && !cache.First("c:" + rid, exp + Skew, now))
            {
                return null;
            }

            var fl = c.TryGetProperty("fl", out var f) && f.ValueKind == JsonValueKind.True;
            return new EdgeRequestContext(rid, iat, exp, m!, Str(c, "ph")!, ct, (int)risk, (int)trap, fl, waf, Str(c, "tp"));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    /// <summary>A signed verdict for Edge with the current (first) key, or null.</summary>
    public static string? SignVerdict(IReadOnlyList<EdgeKey> keys, string rid, string act, string cat, string src, long ttl, long iat)
    {
        try
        {
            if (keys.Count == 0 || !s_rid.IsMatch(rid) || (act != "block" && act != "flag") || !s_cat.IsMatch(cat)
                || (src != "rasp" && src != "sdk" && src != "defend") || ttl < 0 || ttl > 86400)
            {
                return null;
            }

            // rid and cat are plain [A-Za-z0-9_-]: no JSON escaping needed.
            var json = "{\"rid\":\"" + rid + "\",\"iat\":" + iat.ToString(CultureInfo.InvariantCulture) + ",\"act\":\"" + act + "\",\"cat\":\"" + cat
                + "\",\"src\":\"" + src + "\",\"ttl\":" + ttl.ToString(CultureInfo.InvariantCulture) + "}";
            var payload = B64Encode(Encoding.UTF8.GetBytes(json));
            return "v1." + keys[0].Kid + "." + payload + "." + B64Encode(Mac(keys[0].Secret, "s360-verdict|v1|", payload));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    /// <summary>Edge already marked this client: injection-class attacks tighten from monitor to block.</summary>
    public static bool SaysSuspect(EdgeRequestContext? c) =>
        c is not null && c.ClientType != "verified_crawler" && c.ClientType != "verified_agent" && (c.Flagged || c.Trap >= 2 || c.Risk >= 70);

    /// <summary>Test hook: forgets the process replay cache.</summary>
    internal static void ResetReplay() => s_replay.Clear();
}

/// <summary>Remembers ids until they expire; bounded.</summary>
internal sealed class EdgeReplayCache
{
    private readonly object _lock = new();
    private readonly Dictionary<string, long> _seen = new(StringComparer.Ordinal);
    private readonly LinkedList<string> _order = new();
    private readonly int _max;

    public EdgeReplayCache(int max = 10000)
    {
        _max = max;
    }

    public bool First(string key, long exp, long now)
    {
        lock (_lock)
        {
            if (_seen.TryGetValue(key, out var t) && t > now)
            {
                return false;
            }

            if (_seen.Count >= _max)
            {
                foreach (var k in _seen.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList())
                {
                    _seen.Remove(k);
                    _order.Remove(k);
                }

                while (_seen.Count >= _max && _order.First is { } oldest)
                {
                    _seen.Remove(oldest.Value);
                    _order.RemoveFirst();
                }
            }

            if (!_seen.ContainsKey(key))
            {
                _order.AddLast(key);
            }

            _seen[key] = exp;
            return true;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _seen.Clear();
            _order.Clear();
        }
    }
}
