#pragma warning disable CA1861, CA1870 // netstandard2.0 has no SearchValues; the small literal arrays are on cold paths
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Shield360.Rasp;

namespace Shield360.Defend;

/// <summary>The request Defend decides on.</summary>
public sealed class DefendRequest
{
    /// <summary>The HTTP method.</summary>
    public string Method { get; set; } = "GET";

    /// <summary>Path and query, or an absolute URL.</summary>
    public string Target { get; set; } = "/";

    /// <summary>Header names in any case; several values joined with ", ".</summary>
    public IDictionary<string, string> Headers { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The connection's peer address.</summary>
    public string? RemoteAddr { get; set; }
}

/// <summary>What the caller adds for one decision.</summary>
public sealed class DefendCall
{
    /// <summary>Text to check for prompt injection and sensitive data.</summary>
    public IReadOnlyList<string> Content { get; set; } = Array.Empty<string>();

    /// <summary>Overrides the client address read from the request.</summary>
    public string? Ip { get; set; }

    /// <summary>Overrides the country (ISO 3166 alpha-2).</summary>
    public string? Country { get; set; }

    /// <summary>Overrides the network (ASN).</summary>
    public long? Asn { get; set; }

    /// <summary>A call with content to check.</summary>
    public static DefendCall WithContent(params string[] text) => new() { Content = text };
}

/// <summary>How the client address and its location are read.</summary>
public sealed class DefendFactsOptions
{
    /// <summary>How many proxies in front append to X-Forwarded-For (0: not read).</summary>
    public int TrustProxy { get; set; }

    /// <summary>A header holding the client's country (set by a proxy you trust).</summary>
    public string? CountryHeader { get; set; }

    /// <summary>A header holding the client's network (AS number).</summary>
    public string? AsnHeader { get; set; }
}

/// <summary>
/// What Defend reads from a request. Header values stay in memory for the one
/// decision; nothing here is logged or sent. Port of defend/request.ts.
/// </summary>
public sealed class DefendFacts
{
    /// <summary>At most this many content items are read.</summary>
    public const int MaxContentItems = 16;

    /// <summary>Each content item is cut to this many characters.</summary>
    public const int MaxContentItem = 8192;

    private const int MaxHeader = 4096;

    /// <summary>The upper-case method.</summary>
    public string Method { get; set; } = "GET";

    /// <summary>Percent-decoded; <see cref="RawPath"/> is as sent (Edge signs it).</summary>
    public string Path { get; set; } = "/";

    /// <summary>The path as sent.</summary>
    public string RawPath { get; set; } = "/";

    /// <summary>The query string, or null.</summary>
    public string? Query { get; set; }

    /// <summary>The client address, or null.</summary>
    public string? Ip { get; set; }

    /// <summary>The client's country, or null.</summary>
    public string? Country { get; set; }

    /// <summary>The client's network, or null.</summary>
    public long? Asn { get; set; }

    /// <summary>Lower-case names.</summary>
    public Dictionary<string, string> Headers { get; } = new(StringComparer.Ordinal);

    /// <summary>The content to check.</summary>
    public List<string> Content { get; } = new();

    /// <summary>Edge's verified context, when the request came through Edge.</summary>
    public EdgeSignal? Edge { get; set; }

    internal string Header(string name) => Headers.TryGetValue(name, out var v) ? v : string.Empty;

    internal static string Cut(string s, int max)
    {
        if (s.Length <= max)
        {
            return s;
        }

        var n = max;
        if (char.IsLowSurrogate(s[n]))
        {
            n--;
        }

        return s.Substring(0, n);
    }

    internal static string FirstCodePoints(string s, int n)
    {
        var i = 0;
        for (var k = 0; k < n && i < s.Length; k++)
        {
            i += char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]) ? 2 : 1;
        }

        return s.Substring(0, i);
    }

    internal static int CodePointCount(string s) => Injection.CodePoints(s).Length;

    private static bool AsciiAlnum(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');

    private static string StripTarget(string? target)
    {
        var p = string.IsNullOrEmpty(target) ? "/" : target!;
        var i = p.IndexOf("://", StringComparison.Ordinal);
        if (i > 0)
        {
            var scheme = p.Substring(0, i);
            var ok = (scheme[0] >= 'a' && scheme[0] <= 'z') || (scheme[0] >= 'A' && scheme[0] <= 'Z');
            for (var j = 0; ok && j < scheme.Length; j++)
            {
                var c = scheme[j];
                ok = AsciiAlnum(c) || c == '+' || c == '.' || c == '-';
            }

            if (ok)
            {
                var rest = p.Substring(i + 3);
                var j = rest.IndexOfAny(new[] { '/', '?', '#' });
                p = j >= 0 && rest[j] == '/' ? rest.Substring(j) : "/";
            }
        }

        var q = p.IndexOfAny(new[] { '?', '#' });
        return q >= 0 ? p.Substring(0, q) : p;
    }

    private static int HexDigit(byte b) => b >= '0' && b <= '9' ? b - '0' : b >= 'a' && b <= 'f' ? b - 'a' + 10 : b >= 'A' && b <= 'F' ? b - 'A' + 10 : -1;

    /// <summary>The target's path, percent-decoded (as sent when it does not decode to UTF-8).</summary>
    public static string PathOf(string? target)
    {
        var stripped = StripTarget(target);
        var p = stripped.StartsWith("/", StringComparison.Ordinal) ? stripped : "/" + stripped;
        var b = Encoding.UTF8.GetBytes(p);
        var out_ = new List<byte>(b.Length);
        for (var i = 0; i < b.Length; i++)
        {
            if (b[i] == '%')
            {
                var h = i + 1 < b.Length ? HexDigit(b[i + 1]) : -1;
                var l = i + 2 < b.Length ? HexDigit(b[i + 2]) : -1;
                if (h < 0 || l < 0)
                {
                    return p;
                }

                out_.Add((byte)((h * 16) + l));
                i += 2;
                continue;
            }

            out_.Add(b[i]);
        }

        return Injection.Utf8(out_.ToArray()) ?? p;
    }

    /// <summary>The target's path as sent.</summary>
    public static string RawPathOf(string? target) => StripTarget(target);

    /// <summary>An address ([v6], ::ffff:v4), or null when it is not one.</summary>
    public static string? UsableIp(string? v)
    {
        if (v is null)
        {
            return null;
        }

        var s = v.Trim();
        if (s.StartsWith("[", StringComparison.Ordinal))
        {
            var e = s.IndexOf(']');
            if (e >= 0)
            {
                s = s.Substring(1, e - 1);
            }
        }

        if (s.StartsWith("::ffff:", StringComparison.Ordinal) && s.IndexOf('.') >= 0)
        {
            s = s.Substring(7);
        }

        return RaspRuleExpr.ParseIpBytes(s) is not null ? s : null;
    }

    private static string? RemoteIp(string? addr)
    {
        var ip = UsableIp(addr);
        if (ip is null && addr is not null)
        {
            var i = addr.LastIndexOf(':');
            if (i > 0)
            {
                ip = UsableIp(addr.Substring(0, i));
            }
        }

        return ip;
    }

    /// <summary>The address <paramref name="hops"/> entries from the right of an X-Forwarded-For value.</summary>
    public static string? ForwardedIp(string? header, int hops)
    {
        if (string.IsNullOrEmpty(header) || hops < 1)
        {
            return null;
        }

        var parts = new List<string>();
        foreach (var p in header!.Split(','))
        {
            if (p.Trim().Length > 0)
            {
                parts.Add(p.Trim());
            }
        }

        var i = parts.Count - hops;
        return i < 0 ? null : UsableIp(parts[i]);
    }

    /// <summary>The facts of a request.</summary>
    public static DefendFacts Of(DefendRequest req, DefendCall? call = null, DefendFactsOptions? options = null)
    {
        var c = call ?? new DefendCall();
        var o = options ?? new DefendFactsOptions();
        var f = new DefendFacts();
        foreach (var e in req.Headers)
        {
            if (e.Key is not null && e.Value is not null)
            {
                f.Headers[e.Key.ToLowerInvariant()] = Cut(e.Value, MaxHeader);
            }
        }

        f.Method = string.IsNullOrEmpty(req.Method) ? "GET" : Cut(req.Method.ToUpperInvariant(), 16);
        var target = string.IsNullOrEmpty(req.Target) ? "/" : req.Target;
        f.Ip = UsableIp(c.Ip) ?? ForwardedIp(f.Headers.TryGetValue("x-forwarded-for", out var xff) ? xff : null, o.TrustProxy) ?? RemoteIp(req.RemoteAddr);
        f.Path = PathOf(target);
        f.RawPath = RawPathOf(target);
        var q = target.IndexOf('?');
        f.Query = q >= 0 ? Cut(target.Substring(q + 1), 2048) : null;
        var country = c.Country ?? (o.CountryHeader is not null && f.Headers.TryGetValue(o.CountryHeader.ToLowerInvariant(), out var ch) ? ch : null);
        if (country is not null)
        {
            var t = country.Trim();
            if (t.Length == 2 && char.IsLetter(t[0]) && char.IsLetter(t[1]) && t[0] < 128 && t[1] < 128)
            {
                f.Country = t.ToUpperInvariant();
            }
        }

        var asn = c.Asn;
        if (asn is null && o.AsnHeader is not null && f.Headers.TryGetValue(o.AsnHeader.ToLowerInvariant(), out var a))
        {
            var t = a.Trim();
            var digits = t.Length > 2 && string.Equals(t.Substring(0, 2), "as", StringComparison.OrdinalIgnoreCase) ? t.Substring(2) : t;
            var allDigits = digits.Length > 0 && digits.Length <= 10;
            foreach (var d in digits)
            {
                allDigits &= d >= '0' && d <= '9';
            }

            if (allDigits)
            {
                asn = long.Parse(digits, CultureInfo.InvariantCulture);
            }
        }

        f.Asn = asn is > 0 and <= 4_294_967_295L ? asn : null;
        foreach (var item in c.Content ?? Array.Empty<string>())
        {
            if (string.IsNullOrEmpty(item))
            {
                continue;
            }

            if (f.Content.Count >= MaxContentItems)
            {
                break;
            }

            f.Content.Add(FirstCodePoints(item, MaxContentItem));
        }

        return f;
    }

    /// <summary>Whether the request carries an agent passport or a Web Bot Auth signature.</summary>
    public static bool CarriesAgentProof(IReadOnlyDictionary<string, string> headers)
    {
        static string Get(IReadOnlyDictionary<string, string> h, string k) => h.TryGetValue(k, out var v) ? v : string.Empty;
        return Get(headers, "shield360-agent").Length > 0 || (Get(headers, "signature").Length > 0 && Get(headers, "signature-input").Length > 0);
    }
}
