using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Shield360.Rasp;

/// <summary>A vulnerability a passive IAST rule found: the rule, the input and where in the sink argument it sits.</summary>
internal sealed record RaspVuln(string Rule, RaspInput Input, string Position);

/// <summary>
/// The slot a check's detectors write a vulnerability into (sdk/rasp/README.md, "Passive
/// IAST"). <see cref="RaspEngine.Check"/> arms a slot for one check when passive IAST is on
/// and the check is sampled; the detectors in <see cref="RaspDetect"/> call
/// <see cref="Note"/> with a rule from <see cref="RaspIastRules"/>, which runs only while a
/// slot is armed. Checks run synchronously on the calling thread, so the slot is per thread.
/// Unarmed, the cost is one read per detector call. Port of the TypeScript <c>iast-scope.ts</c>.
/// </summary>
internal static class RaspIastScope
{
    internal sealed class Slot
    {
        public Slot(Slot? prev)
        {
            Prev = prev;
        }

        public Slot? Prev { get; }

        public RaspVuln? Vuln { get; set; }

        public bool Closed { get; set; }
    }

    [ThreadStatic]
    private static Slot? t_current;

    /// <summary>Whether a slot is armed for the running check.</summary>
    public static bool Armed => t_current is not null;

    /// <summary>Arms a slot for the check about to run (nested checks keep their own).</summary>
    public static Slot Arm()
    {
        var slot = new Slot(t_current);
        t_current = slot;
        return slot;
    }

    /// <summary>Disarms a slot; returns the vulnerability noted in it, once. Idempotent.</summary>
    public static RaspVuln? Close(Slot slot)
    {
        if (slot.Closed)
        {
            return null;
        }

        slot.Closed = true;
        if (ReferenceEquals(t_current, slot))
        {
            t_current = slot.Prev;
        }

        return slot.Vuln;
    }

    /// <summary>Runs a vulnerability rule when a slot is armed and keeps its first result. Never throws.</summary>
    public static void Note(Func<RaspVuln?> rule)
    {
        var slot = t_current;
        if (slot is null || slot.Vuln is not null)
        {
            return;
        }

        try
        {
            slot.Vuln = rule();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // passive IAST never breaks a check
        }
    }

    /// <summary>Runs <paramref name="fn"/> with a slot armed; returns its result and the vulnerability noted (tests, conformance).</summary>
    public static (T Result, RaspVuln? Vuln) Capture<T>(Func<T> fn)
    {
        var slot = Arm();
        try
        {
            var result = fn();
            return (result, Close(slot));
        }
        finally
        {
            Close(slot);
        }
    }
}

/// <summary>
/// Passive IAST rules (sdk/rasp/README.md, "Passive IAST"). Pure: each takes what a detector
/// already computed (the sink text, its tokens, the inputs) and says whether a request input
/// reaches the sink verbatim in a place the app did not parameterize, though the value is
/// harmless and the attack check found nothing. Port of the TypeScript <c>iast-rules.ts</c>.
/// </summary>
internal static class RaspIastRules
{
    public static readonly string[] Rules =
    {
        "vuln.sql_concat", "vuln.cmd_shell", "vuln.cmd_arg", "vuln.path_from_input", "vuln.ssrf_host",
        "vuln.code_eval", "vuln.include_from_input", "vuln.deser_input", "vuln.xml_external",
    };

    /// <summary>Shortest input considered.</summary>
    public const int MinLength = 3;

    /// <summary>Letters-only inputs shorter than this are common words that also appear hard-coded.</summary>
    public const int MinWordLength = 8;

    /// <summary>Digits-only inputs shorter than this are small numbers that also appear hard-coded.</summary>
    public const int MinNumberLength = 4;

    private static readonly HashSet<string> s_boring = new("true false null none nil undefined yes no on off asc desc".Split(' '), StringComparer.Ordinal);

    /// <summary>
    /// Whether an input is specific enough that finding it verbatim in a sink means it came
    /// from the request, not a coincidence with a literal the app wrote (README "Thresholds").
    /// </summary>
    public static bool Qualifies(string v)
    {
        if (v.Length < MinLength || s_boring.Contains(v.ToLowerInvariant()))
        {
            return false;
        }

        if (v.All(c => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) && v.Length < MinWordLength)
        {
            return false;
        }

        if (v.All(c => (c >= '0' && c <= '9') || c == '.' || c == '+' || c == '-') && v.Length < MinNumberLength)
        {
            return false;
        }

        if (v.All(c => c == v[0]))
        {
            return false;
        }

        // Only spaces and punctuation: no letter or digit (Unicode).
        for (var i = 0; i < v.Length; i += char.IsSurrogatePair(v, i) ? 2 : 1)
        {
            switch (CharUnicodeInfo.GetUnicodeCategory(v, i))
            {
                case UnicodeCategory.UppercaseLetter:
                case UnicodeCategory.LowercaseLetter:
                case UnicodeCategory.TitlecaseLetter:
                case UnicodeCategory.ModifierLetter:
                case UnicodeCategory.OtherLetter:
                case UnicodeCategory.DecimalDigitNumber:
                case UnicodeCategory.LetterNumber:
                case UnicodeCategory.OtherNumber:
                    return true;
            }
        }

        return false;
    }

    private static IEnumerable<RaspInput> Candidates(IReadOnlyList<RaspInput> inputs) =>
        inputs.Where(i => i.Source == RaspInputSource.Request && Qualifies(i.Value));

    private static bool IsComment(RaspToken t) => t.Kind == "comment" || t.Kind == "version_comment";

    /// <summary>
    /// <c>vuln.sql_concat</c>: an input sits inside a string literal, as a whole number, as a
    /// whole identifier (not a keyword), or as a run of whole tokens the attack check let
    /// through. Never inside a comment, never when the input is the whole query.
    /// </summary>
    public static RaspVuln? Sql(string query, IReadOnlyList<RaspInput> inputs, Func<List<RaspToken>> tokens)
    {
        var trimmed = JsText.Trim(query);
        foreach (var inp in Candidates(inputs))
        {
            var v = inp.Value;
            if (v == query || JsText.Trim(v) == trimmed)
            {
                continue;
            }

            foreach (var idx in RaspLexers.Occurrences(query, v))
            {
                var over = RaspLexers.Overlapping(tokens(), idx, v.Length);
                if (over.Count == 0 || over.Any(IsComment))
                {
                    continue;
                }

                var end = idx + v.Length;
                if (over.Count == 1)
                {
                    var t = over[0];
                    if (t.Kind == "string" && idx > t.S && end <= t.E)
                    {
                        return new RaspVuln("vuln.sql_concat", inp, "string");
                    }

                    var whole = t.S == idx && t.E == end;
                    if (whole && t.Kind == "number")
                    {
                        return new RaspVuln("vuln.sql_concat", inp, "number");
                    }

                    if (whole && (t.Kind == "name" || (t.Kind == "word" && !RaspDetect.IsSqlKeyword(JsText.Lower(t.Text)))))
                    {
                        return new RaspVuln("vuln.sql_concat", inp, "identifier");
                    }

                    continue;
                }

                if (over[0].S == idx && over[over.Count - 1].E == end)
                {
                    return new RaspVuln("vuln.sql_concat", inp, "tokens");
                }
            }
        }

        return null;
    }

    /// <summary><c>vuln.cmd_shell</c>: an input sits inside one word of a shell-interpreted command.</summary>
    public static RaspVuln? Shell(string command, IReadOnlyList<RaspInput> inputs, List<RaspToken> tokens)
    {
        var trimmed = JsText.Trim(command);
        foreach (var inp in Candidates(inputs))
        {
            var v = inp.Value;
            if (JsText.Trim(v) == trimmed)
            {
                continue;
            }

            foreach (var idx in RaspLexers.Occurrences(command, v))
            {
                var over = RaspLexers.Overlapping(tokens, idx, v.Length);
                if (over.Count == 1 && over[0].Kind == "word")
                {
                    return new RaspVuln("vuln.cmd_shell", inp, "word");
                }
            }
        }

        return null;
    }

    /// <summary><c>vuln.cmd_arg</c>: an argument (not the executable) of an argv spawn without a shell contains an input.</summary>
    public static RaspVuln? Argv(IReadOnlyList<string> argv, IReadOnlyList<RaspInput> inputs)
    {
        foreach (var inp in Candidates(inputs))
        {
            for (var k = 1; k < argv.Count; k++)
            {
                if (argv[k] is { } a && JsText.Has(a, inp.Value))
                {
                    return new RaspVuln("vuln.cmd_arg", inp, "argument");
                }
            }
        }

        return null;
    }

    /// <summary>
    /// <c>vuln.path_from_input</c>: an input (normalized like the path) forms whole path
    /// segments: it starts at a segment start and ends at a segment end, or before a <c>.</c>.
    /// </summary>
    public static RaspVuln? Path(string normalizedPath, IReadOnlyList<RaspInput> inputs, Func<string, string> norm)
    {
        var np = normalizedPath;
        foreach (var inp in Candidates(inputs))
        {
            var ni = norm(inp.Value);
            if (ni.Length == 0 || ni == "/")
            {
                continue;
            }

            foreach (var idx in RaspLexers.Occurrences(np, ni))
            {
                var end = idx + ni.Length;
                var startOk = idx == 0 || np[idx - 1] == '/' || ni[0] == '/';
                var endOk = end == np.Length || np[end] == '/' || np[end] == '.' || ni[ni.Length - 1] == '/';
                if (startOk && endOk)
                {
                    return new RaspVuln("vuln.path_from_input", inp, "segment");
                }
            }
        }

        return null;
    }

    private static readonly char[] s_authorityEnd = { '/', '?', '#', '\\' };

    private static int SchemeLength(string url)
    {
        // ^[A-Za-z][A-Za-z0-9+.-]*://
        if (url.Length == 0 || !((url[0] >= 'A' && url[0] <= 'Z') || (url[0] >= 'a' && url[0] <= 'z')))
        {
            return -1;
        }

        var i = 1;
        while (i < url.Length && ((url[i] >= 'A' && url[i] <= 'Z') || (url[i] >= 'a' && url[i] <= 'z') || (url[i] >= '0' && url[i] <= '9') || url[i] is '+' or '.' or '-'))
        {
            i++;
        }

        return JsText.StartsAt(url, "://", i) ? i + 3 : -1;
    }

    /// <summary>The <c>host[:port]</c> of a URL as written (lower-cased) and the offset just past the host (after any userinfo); null without an authority.</summary>
    private static (string Authority, int HostEnd)? AuthorityOf(string url, string host)
    {
        var start = SchemeLength(url);
        if (start < 0)
        {
            return null;
        }

        var rest = url.Substring(start);
        var end = rest.IndexOfAny(s_authorityEnd);
        var auth = end < 0 ? rest : rest.Substring(0, end);
        var at = auth.LastIndexOf('@');
        var hostStart = start + at + 1;
        var bracket = JsText.At(url, hostStart) == '[' ? 2 : 0;
        return (JsText.Lower(auth.Substring(at + 1)), hostStart + host.Length + bracket);
    }

    /// <summary>
    /// <c>vuln.ssrf_host</c>: the URL's host is an input (the host, <c>host:port</c> or
    /// <c>[host]</c>), or an input is a prefix of the URL that covers its scheme and host.
    /// </summary>
    public static RaspVuln? Ssrf(string url, string host, IReadOnlyList<RaspInput> inputs)
    {
        var auth = host.Length > 0 ? AuthorityOf(url, host) : null;
        var authority = auth?.Authority ?? string.Empty;

        // The prefix must reach past the destination host itself, not a copy of it in the userinfo.
        var hostEnd = host.Length > 0 ? (auth?.HostEnd ?? url.Length + 1) : url.IndexOf(':') + 1;
        foreach (var inp in Candidates(inputs))
        {
            var v = JsText.Lower(inp.Value);
            if (host.Length > 0 && (v == host || v == authority || v == "[" + host + "]"))
            {
                return new RaspVuln("vuln.ssrf_host", inp, "host");
            }

            if (JsText.Starts(url, inp.Value) && inp.Value.Length >= hostEnd && (host.Length > 0 || inp.Value.Length > hostEnd))
            {
                return new RaspVuln("vuln.ssrf_host", inp, "url");
            }
        }

        return null;
    }

    /// <summary><c>vuln.code_eval</c>: an input sits inside a string literal of evaluated code, or is a whole identifier or number in it.</summary>
    public static RaspVuln? Code(string code, IReadOnlyList<RaspInput> inputs, Func<List<RaspToken>> tokens)
    {
        foreach (var inp in Candidates(inputs))
        {
            var v = inp.Value;
            if (v == code)
            {
                continue;
            }

            foreach (var idx in RaspLexers.Occurrences(code, v))
            {
                var over = RaspLexers.Overlapping(tokens(), idx, v.Length);
                if (over.Count != 1)
                {
                    continue;
                }

                var t = over[0];
                var end = idx + v.Length;
                if (t.Kind == "string" && idx > t.S && end <= t.E)
                {
                    return new RaspVuln("vuln.code_eval", inp, "string");
                }

                if (t.S == idx && t.E == end && (t.Kind == "word" || t.Kind == "number"))
                {
                    return new RaspVuln("vuln.code_eval", inp, t.Kind == "word" ? "identifier" : "number");
                }
            }
        }

        return null;
    }

    /// <summary><c>vuln.include_from_input</c>: a module specifier contains an input (equal and path-like inputs are <c>code.include</c>).</summary>
    public static RaspVuln? Include(string specifier, IReadOnlyList<RaspInput> inputs)
    {
        foreach (var inp in Candidates(inputs))
        {
            if (inp.Value != specifier && JsText.Has(specifier, inp.Value))
            {
                return new RaspVuln("vuln.include_from_input", inp, "specifier");
            }
        }

        return null;
    }

    /// <summary>
    /// <c>vuln.deser_input</c> / <c>vuln.xml_external</c>: the data handed to an unsafe
    /// deserializer, or to an XML parser that resolves external entities, is tainted (the
    /// caller decides) by a request input that qualifies, and is at least 3 characters.
    /// </summary>
    public static RaspVuln? Data(string rule, string data, RaspInput? inp)
    {
        if (inp is null || inp.Source != RaspInputSource.Request || data.Length < MinLength || !Qualifies(inp.Value))
        {
            return null;
        }

        return new RaspVuln(rule, inp, "data");
    }
}
