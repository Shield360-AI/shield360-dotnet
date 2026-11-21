#pragma warning disable CA1861, CA1870 // netstandard2.0 has no SearchValues; the small literal arrays are on cold paths
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Shield360.Defend;

/// <summary>
/// Prompt injection (<see cref="Injection"/>) and sensitive data in the text the app
/// passes to Defend: the high-precision PII and secret shapes of the AI security
/// pack's output check. Deterministic and local; never throws.
/// </summary>
public static class DefendContent
{
    /// <summary>At most this many characters of content are checked per decision.</summary>
    public const int MaxContentChars = 20_000;

    private const string W = "[A-Za-z0-9_]";
    private const string B = "(?:(?<=" + W + ")(?!" + W + ")|(?<!" + W + ")(?=" + W + "))";
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(1);

    private sealed class Shape
    {
        public Shape(string p, Func<string, bool>? check)
        {
            Re = new Regex(p, RegexOptions.CultureInvariant, s_timeout);
            Check = check;
        }

        public Regex Re { get; }

        public Func<string, bool>? Check { get; }
    }

    private static readonly Shape[] s_shapes =
    {
        new("(" + B + "sk-(?:proj-)?[A-Za-z0-9_-]{20,})", null),
        new("(" + B + "sk-ant-[A-Za-z0-9_-]{20,})", null),
        new("(?:^|[^A-Za-z0-9/+=])((?:AKIA|ASIA)[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)", null),
        new("(" + B + "AIza[0-9A-Za-z_-]{35})", null),
        new("(" + B + "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,})", null),
        new("(" + B + "github_pat_[A-Za-z0-9_]{22,})", null),
        new("(" + B + "(?:sk|rk)_live_[A-Za-z0-9]{24,})", null),
        new("(" + B + "xox[bpoas]-[A-Za-z0-9-]{10,})", null),
        new("(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)", null),
        new("(" + B + "(?:mongodb(?:\\+srv)?|postgres(?:ql)?|mysql|redis|amqps?)://[^\\t\\n\\x0B\\f\\r :@/]+:[^\\t\\n\\x0B\\f\\r @/]+@[^\\t\\n\\x0B\\f\\r ]+)", null),
        new("(" + B + "eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,})", null),
        new("(" + B + "[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}" + B + ")", null),
        new("(?:^|[^0-9-])([0-9]{3}-[0-9]{2}-[0-9]{4})(?:[^0-9-]|$)", IssuableSsn),
        new("(?:^|[^0-9])((?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))(?:[ -]?[0-9]{4}){2}[ -]?[0-9]{3,4})(?:[^0-9]|$)", Luhn),
        new("(?:^|[^0-9])((?:\\+1[ .-]?)?\\(?[2-9][0-9]{2}\\)?[ .-][0-9]{3}[ .-][0-9]{4})(?:[^0-9]|$)", null),
    };

    internal static bool Luhn(string v)
    {
        var d = new List<int>();
        foreach (var c in v)
        {
            if (c >= '0' && c <= '9')
            {
                d.Add(c - '0');
            }
        }

        if (d.Count < 13 || d.Count > 19)
        {
            return false;
        }

        var sum = 0;
        for (var i = 0; i < d.Count; i++)
        {
            var n = d[d.Count - 1 - i];
            if (i % 2 == 1)
            {
                n *= 2;
                if (n > 9)
                {
                    n -= 9;
                }
            }

            sum += n;
        }

        return sum % 10 == 0;
    }

    internal static bool IssuableSsn(string v)
    {
        var p = v.Split('-');
        return p[0] != "000" && p[0] != "666" && !p[0].StartsWith("9", StringComparison.Ordinal) && p[1] != "00" && p[2] != "0000";
    }

    /// <summary>Whether text holds a secret or PII shape.</summary>
    public static bool Sensitive(string text)
    {
        var t = DefendFacts.Cut(text, 200_000);
        foreach (var s in s_shapes)
        {
            try
            {
                var at = 0;
                while (at <= t.Length)
                {
                    var m = s.Re.Match(t, at);
                    if (!m.Success || !m.Groups[1].Success)
                    {
                        break;
                    }

                    var g = m.Groups[1];
                    if (s.Check is null || s.Check(g.Value))
                    {
                        return true;
                    }

                    var end = g.Index + g.Length;
                    at = end > at ? end : at + 1;
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // too slow: not this shape
            }
        }

        return false;
    }

    /// <summary>Prompt injection and, unless off, sensitive data in the content.</summary>
    public static ContentFindings Check(IReadOnlyList<string> content, SensitiveDataMode mode)
    {
        bool pi = false, sd = false;
        var left = MaxContentChars;
        foreach (var raw in content)
        {
            if (left <= 0)
            {
                break;
            }

            if (string.IsNullOrEmpty(raw))
            {
                continue;
            }

            var cps = Injection.CodePoints(raw);
            var text = cps.Length > left ? DefendFacts.FirstCodePoints(raw, left) : raw;
            left -= Math.Min(cps.Length, left);
            if (!pi)
            {
                try
                {
                    pi = Injection.Score(text, "prompt") >= Injection.Threshold;
                }
                catch (Exception e) when (e is ArgumentException or InvalidOperationException or RegexMatchTimeoutException)
                {
                    pi = false;
                }
            }

            if (mode != SensitiveDataMode.Off && !sd)
            {
                sd = Sensitive(text);
            }
        }

        return new ContentFindings(pi, sd);
    }
}
