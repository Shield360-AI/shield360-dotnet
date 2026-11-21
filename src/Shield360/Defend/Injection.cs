#pragma warning disable CA1861, CA1870 // netstandard2.0 has no SearchValues; the small literal arrays are on cold paths
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Shield360.Defend;

/// <summary>A prompt-injection score and the rules that matched.</summary>
public sealed class InjectionScan
{
    internal InjectionScan(double score, SortedSet<string> rules)
    {
        Score = score;
        Rules = rules;
    }

    /// <summary>0 to 1; at or above <see cref="Injection.Threshold"/> is prompt injection.</summary>
    public double Score { get; }

    /// <summary>The rule ids that matched, sorted.</summary>
    public IReadOnlyCollection<string> Rules { get; }
}

/// <summary>
/// Prompt injection: the shared rule set (an embedded byte-identical copy of
/// cli/internal/coding/injection/rules.json) run as the shared detector runs it: on
/// the text as written (whitespace made uniform), cleaned (invisible characters
/// removed, fullwidth letters narrowed), on the invisible characters themselves (tag
/// characters, zero-width runs, bidi controls, ASCII smuggled in tag characters), in
/// encoded blobs (base64, hex) and respelled (look-alike letters, leetspeak, ROT13),
/// scored as the shared detector scores. The golden corpus
/// (cli/internal/coding/injection/testdata) holds it to the Go detector's answers.
/// Port of the Java, Rust and Go detectors.
/// </summary>
public static class Injection
{
    private const string Resource = "Shield360.Defend.injection-rules.json";
    private const int MaxBlobs = 20;
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(2);

    private sealed class Rule
    {
        public string Id { get; set; } = string.Empty;

        public string? Kind { get; set; }

        public double Weight { get; set; }

        public Dictionary<string, double> Weights { get; } = new(StringComparer.Ordinal);

        public List<string> Sources { get; } = new();

        public List<string> Any { get; } = new();

        public List<Regex> Patterns { get; } = new();

        public List<Regex> Within { get; } = new();

        public bool Decoded { get; set; }

        public int Min { get; set; }

        public bool AppliesTo(string source) => Sources.Count == 0 || Sources.Contains(source);

        public double WeightFor(string source) => Weights.TryGetValue(source, out var w) ? w : Weight;

        public bool AnyIn(string folded)
        {
            foreach (var a in Any)
            {
                if (folded.IndexOf(a, StringComparison.Ordinal) >= 0)
                {
                    return true;
                }
            }

            return false;
        }
    }

    private static readonly List<Rule> s_rules = new();
    private static readonly Dictionary<string, Rule> s_byId = new(StringComparer.Ordinal);
    private static double s_threshold = 1.0;
    private static int s_maxScanChars = 200_000;

#pragma warning disable CA1810 // the rules load once, in order
    static Injection()
#pragma warning restore CA1810
    {
        try
        {
            using var doc = JsonDocument.Parse(RulesBytes());
            var d = doc.RootElement;
            if (d.TryGetProperty("threshold", out var t) && t.ValueKind == JsonValueKind.Number)
            {
                s_threshold = t.GetDouble();
            }

            if (d.TryGetProperty("maxScanChars", out var mx) && mx.ValueKind == JsonValueKind.Number)
            {
                s_maxScanChars = (int)mx.GetDouble();
            }

            if (!d.TryGetProperty("rules", out var rules) || rules.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            foreach (var m in rules.EnumerateArray())
            {
                if (m.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var r = new Rule
                {
                    Id = Str(m, "id") ?? string.Empty,
                    Kind = Str(m, "kind") is { Length: > 0 } k ? k : null,
                    Weight = Num(m, "weight") ?? 0,
                    Decoded = m.TryGetProperty("decoded", out var dec) && dec.ValueKind == JsonValueKind.True,
                    Min = (int)(Num(m, "min") ?? 0),
                };
                if (m.TryGetProperty("weights", out var ws) && ws.ValueKind == JsonValueKind.Object)
                {
                    foreach (var p in ws.EnumerateObject())
                    {
                        if (p.Value.ValueKind == JsonValueKind.Number)
                        {
                            r.Weights[p.Name] = p.Value.GetDouble();
                        }
                    }
                }

                r.Sources.AddRange(Strings(m, "sources"));
                foreach (var a in Strings(m, "any"))
                {
                    r.Any.Add(Fold(a));
                }

                foreach (var p in Strings(m, "patterns"))
                {
                    if (Compile(p) is { } re)
                    {
                        r.Patterns.Add(re);
                    }
                }

                foreach (var p in Strings(m, "within"))
                {
                    if (Compile(p) is { } re)
                    {
                        r.Within.Add(re);
                    }
                }

                s_rules.Add(r);
                if (!s_byId.ContainsKey(r.Id))
                {
                    s_byId[r.Id] = r;
                }
            }
        }
        catch (JsonException)
        {
            // no rules: nothing is prompt injection
        }
    }

    /// <summary>The score at which text is prompt injection.</summary>
    public static double Threshold => s_threshold;

    internal static byte[] RulesBytes()
    {
        using var stream = typeof(Injection).Assembly.GetManifestResourceStream(Resource);
        if (stream is null)
        {
            return Array.Empty<byte>();
        }

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private static string? Str(JsonElement m, string k) => m.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static double? Num(JsonElement m, string k) => m.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : null;

    private static IEnumerable<string> Strings(JsonElement m, string k)
    {
        if (m.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in v.EnumerateArray())
            {
                if (x.ValueKind == JsonValueKind.String)
                {
                    yield return x.GetString()!;
                }
            }
        }
    }

    internal static int[] CodePoints(string s)
    {
        var out_ = new List<int>(s.Length);
        for (var i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                out_.Add(char.ConvertToUtf32(s[i], s[i + 1]));
                i++;
            }
            else
            {
                out_.Add(s[i]);
            }
        }

        return out_.ToArray();
    }

    internal static void AppendCodePoint(StringBuilder b, int c)
    {
        if (c >= 0x10000 && c <= 0x10ffff)
        {
            b.Append(char.ConvertFromUtf32(c));
        }
        else
        {
            b.Append((char)c);
        }
    }

    private static string Str(int[] cps)
    {
        var b = new StringBuilder(cps.Length);
        foreach (var c in cps)
        {
            AppendCodePoint(b, c);
        }

        return b.ToString();
    }

    internal static string Fold(string s)
    {
        var b = new StringBuilder(s.Length);
        foreach (var c in CodePoints(s))
        {
            if (c == 0x017f)
            {
                b.Append('s');
            }
            else if (c == 0x212a)
            {
                b.Append('k');
            }
            else if (c >= 'A' && c <= 'Z')
            {
                b.Append((char)(c + 32));
            }
            else
            {
                AppendCodePoint(b, c);
            }
        }

        return b.ToString();
    }

    private const string Word = "[A-Za-z0-9_]";
    private const string AsciiB = "(?:(?<=" + Word + ")(?!" + Word + ")|(?<!" + Word + ")(?=" + Word + "))";
    private const string AsciiNb = "(?:(?<=" + Word + ")(?=" + Word + ")|(?<!" + Word + ")(?!" + Word + "))";

    /// <summary>The RE2 pattern in .NET's dialect: ASCII \b, \d, \s and \w, as the Go detector reads them.</summary>
    private static Regex? Compile(string p)
    {
        var out_ = new StringBuilder(p.Length + 16);
        var inClass = false;
        for (var i = 0; i < p.Length; i++)
        {
            var c = p[i];
            if (c == '\\' && i + 1 < p.Length)
            {
                var n = p[++i];
                switch (n)
                {
                    case 'b' when !inClass:
                        out_.Append(AsciiB);
                        break;
                    case 'B' when !inClass:
                        out_.Append(AsciiNb);
                        break;
                    case 'd':
                        out_.Append(inClass ? "0-9" : "[0-9]");
                        break;
                    case 'w':
                        out_.Append(inClass ? "A-Za-z0-9_" : "[A-Za-z0-9_]");
                        break;
                    case 's':
                        out_.Append(inClass ? "\\t\\n\\x0B\\f\\r " : "[\\t\\n\\x0B\\f\\r ]");
                        break;
                    case 'D' when !inClass:
                        out_.Append("[^0-9]");
                        break;
                    case 'W' when !inClass:
                        out_.Append("[^A-Za-z0-9_]");
                        break;
                    case 'S' when !inClass:
                        out_.Append("[^\\t\\n\\x0B\\f\\r ]");
                        break;
                    default:
                        out_.Append('\\').Append(n);
                        break;
                }

                continue;
            }

            if (c == '[' && !inClass)
            {
                inClass = true;
                out_.Append(c);
                if (i + 1 < p.Length && p[i + 1] == '^')
                {
                    out_.Append('^');
                    i++;
                }

                if (i + 1 < p.Length && p[i + 1] == ']')
                {
                    out_.Append("\\]");
                    i++;
                }

                continue;
            }

            if (inClass && c == '[')
            {
                out_.Append("\\[");
                continue;
            }

            if (c == ']' && inClass)
            {
                inClass = false;
            }

            if (c == '(' && string.CompareOrdinal(p, i, "(?P<", 0, 4) == 0)
            {
                out_.Append("(?<");
                i += 3;
                continue;
            }

            out_.Append(c);
        }

        try
        {
            return new Regex(out_.ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, s_timeout);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static bool IsJsWhitespace(int r) =>
        r == 0x09 || r == 0x0a || r == 0x0b || r == 0x0c || r == 0x0d || r == 0x20 || r == 0xa0 || r == 0x1680 || r == 0x2028 || r == 0x2029
        || r == 0x202f || r == 0x205f || r == 0x3000 || r == 0xfeff || (r >= 0x2000 && r <= 0x200a);

    private static int Normalise(int c)
    {
        if (c == 0x0a || c == 0x0d || c == 0x2028 || c == 0x2029)
        {
            return '\n';
        }

        return IsJsWhitespace(c) ? ' ' : c;
    }

    private static bool IsTag(int r) => r >= 0xe0000 && r <= 0xe007f;

    private static bool IsBidi(int r) => (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069);

    private static bool IsZeroWidth(int r) => r == 0x200b || r == 0x2060 || r == 0x2061 || r == 0x2062 || r == 0x2063 || r == 0x2064 || r == 0x180e || r == 0xfeff;

    private static bool IsInvisible(int r) => IsZeroWidth(r) || r == 0x200c || r == 0x200d || IsTag(r) || IsBidi(r) || r == 0xad || r == 0x200e || r == 0x200f;

    private static bool IsAsciiLetter(int c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

    private static SortedSet<string> RegexMatches(string text, bool decodedOnly, string source)
    {
        var found = new SortedSet<string>(StringComparer.Ordinal);
        var folded = Fold(text);
        foreach (var rule in s_rules)
        {
            if (rule.Kind is not null || !rule.AppliesTo(source) || (decodedOnly && !rule.Decoded))
            {
                continue;
            }

            if (rule.Any.Count > 0 && !rule.AnyIn(folded))
            {
                continue;
            }

            if (RuleMatches(rule, text))
            {
                found.Add(rule.Id);
            }
        }

        return found;
    }

    private static bool RuleMatches(Rule rule, string text)
    {
        foreach (var re in rule.Patterns)
        {
            try
            {
                var m = re.Match(text);
                for (var n = 0; n < 20 && m.Success; n++, m = m.NextMatch())
                {
                    var s = m.Value;
                    if (s.Length == 0)
                    {
                        continue;
                    }

                    var all = true;
                    foreach (var w in rule.Within)
                    {
                        if (!w.IsMatch(s))
                        {
                            all = false;
                            break;
                        }
                    }

                    if (all)
                    {
                        return true;
                    }
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // too slow: no match
            }
        }

        return false;
    }

    /// <summary>The shared detector's score for text from source (prompt, tool_result, ...).</summary>
    public static double Score(string text, string source) => Scan(text, source).Score;

    /// <summary>The shared detector's score and the rules that matched.</summary>
    public static InjectionScan Scan(string text, string source)
    {
        var original = CodePoints(text ?? string.Empty);
        if (s_maxScanChars > 0 && original.Length > s_maxScanChars)
        {
            Array.Resize(ref original, s_maxScanChars);
        }

        var norm = new int[original.Length];
        for (var i = 0; i < original.Length; i++)
        {
            norm[i] = Normalise(original[i]);
        }

        var normText = Str(norm);
        var direct = RegexMatches(normText, false, source);
        var hits = new SortedSet<string>(direct, StringComparer.Ordinal);
        var cleaned = new StringBuilder();
        var changed = false;
        foreach (var c in original)
        {
            var r = c;
            if (IsInvisible(r))
            {
                changed = true;
                continue;
            }

            if (r >= 0xff01 && r <= 0xff5e)
            {
                r -= 0xfee0;
                changed = true;
            }

            AppendCodePoint(cleaned, Normalise(r));
        }

        if (changed)
        {
            foreach (var id in RegexMatches(cleaned.ToString(), false, source))
            {
                if (direct.Contains(id))
                {
                    continue;
                }

                hits.Add(id);
                foreach (var split in s_rules)
                {
                    if (split.Kind == "invisible_split" && split.AppliesTo(source))
                    {
                        hits.Add(split.Id);
                    }
                }
            }
        }

        hits.UnionWith(Invisible(original, source));
        hits.UnionWith(Encoded(normText, source));
        foreach (var rule in s_rules)
        {
            if (!rule.AppliesTo(source) || rule.Kind is null)
            {
                continue;
            }

            int[]? mapped;
            var rot = false;
            switch (rule.Kind)
            {
                case "homoglyph":
                    mapped = RespellHomoglyphs(norm);
                    break;
                case "leetspeak":
                    mapped = RespellLeet(norm);
                    break;
                case "rot13":
                    if (rule.Any.Count > 0 && !rule.AnyIn(Fold(normText)))
                    {
                        continue;
                    }

                    mapped = Rot13(norm);
                    rot = true;
                    break;
                default:
                    continue;
            }

            if (mapped is null)
            {
                continue;
            }

            var fresh = false;
            foreach (var id in RegexMatches(Str(mapped), true, source))
            {
                if (direct.Contains(id) || (hits.Contains(id) && !rot))
                {
                    continue;
                }

                hits.Add(id);
                fresh = true;
            }

            if (fresh)
            {
                hits.Add(rule.Id);
            }
        }

        var keep = 1.0;
        foreach (var id in hits)
        {
            var w = s_byId.TryGetValue(id, out var r) ? r.WeightFor(source) : 0;
            if (w > 0)
            {
                keep *= 1.0 - w;
            }
        }

        var score = hits.Count == 0 ? 0.0 : Math.Round((1.0 - keep) * 1000.0, MidpointRounding.AwayFromZero) / 1000.0;
        return new InjectionScan(score, hits);
    }

    private static SortedSet<string> Invisible(int[] original, string source)
    {
        int tag = 0, zw = 0, bidi = 0;
        var smuggled = new StringBuilder();
        var n = original.Length;
        var i = 0;
        while (i < n)
        {
            var r = original[i];
            if (IsTag(r))
            {
                var j = i;
                while (j < n && IsTag(original[j]))
                {
                    j++;
                }

                var flag = i > 0 && original[i - 1] == 0x1f3f4 && original[j - 1] == 0xe007f && j - i <= 8;
                if (!flag)
                {
                    tag += j - i;
                    for (var k = i; k < j; k++)
                    {
                        var v = original[k];
                        if (v >= 0xe0020 && v <= 0xe007e)
                        {
                            smuggled.Append((char)(v - 0xe0000));
                        }
                    }

                    smuggled.Append(' ');
                }

                i = j;
                continue;
            }

            var joiner = (r == 0x200c || r == 0x200d) && i > 0 && i + 1 < n && IsAsciiLetter(original[i - 1]) && IsAsciiLetter(original[i + 1]);
            if ((IsZeroWidth(r) && !(r == 0xfeff && i == 0)) || joiner)
            {
                zw++;
            }
            else if (IsBidi(r))
            {
                bidi++;
            }

            i++;
        }

        var hits = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var rule in s_rules)
        {
            if (!rule.AppliesTo(source) || rule.Kind is null)
            {
                continue;
            }

            int count;
            switch (rule.Kind)
            {
                case "tag":
                    count = tag;
                    break;
                case "zero_width":
                    count = zw;
                    break;
                case "bidi":
                    count = bidi;
                    break;
                default:
                    continue;
            }

            if (count == 0 || count < Math.Max(rule.Min, 1))
            {
                continue;
            }

            hits.Add(rule.Id);
        }

        if (smuggled.Length > 0)
        {
            hits.UnionWith(RegexMatches(smuggled.ToString(), true, source));
        }

        return hits;
    }

    private static readonly Dictionary<int, char> s_homoglyphs = BuildHomoglyphs();

    private static Dictionary<int, char> BuildHomoglyphs()
    {
        var pairs = new[]
        {
            "0430a", "0435e", "043eo", "0440p", "0441c", "0443y", "0445x", "0456i", "0458j", "0455s", "0501d", "0261g", "04bbh", "051bq", "051dw",
            "0410A", "0412B", "0415E", "041aK", "041cM", "041dH", "041eO", "0420P", "0421C", "0422T", "0425X", "0406I", "0408J", "0405S", "03bfo",
            "03b1a", "03bdv", "03b9i", "03bak", "03c1p", "03c5u", "039fO", "0391A", "0392B", "0395E", "0397H", "0399I", "039aK", "039cM", "039dN",
            "03a1P", "03a4T", "03a7X", "03a5Y", "0396Z",
        };
        var m = new Dictionary<int, char>();
        foreach (var p in pairs)
        {
            m[int.Parse(p.Substring(0, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture)] = p[4];
        }

        return m;
    }

    private static int Leet(int c) => c switch
    {
        '0' => 'o',
        '1' => 'i',
        '3' => 'e',
        '4' or '@' => 'a',
        '5' or '$' => 's',
        '7' => 't',
        _ => -1,
    };

    private static int StyledLetter(int r)
    {
        if (r >= 0x1d400 && r <= 0x1d6a3)
        {
            var i = (r - 0x1d400) % 52;
            return i < 26 ? 0x41 + i : 0x61 + i - 26;
        }

        if (r >= 0x24b6 && r <= 0x24cf)
        {
            return 0x41 + r - 0x24b6;
        }

        if (r >= 0x24d0 && r <= 0x24e9)
        {
            return 0x61 + r - 0x24d0;
        }

        return -1;
    }

    private static int[]? RespellHomoglyphs(int[] norm)
    {
        var out_ = (int[])norm.Clone();
        var changed = false;
        var n = norm.Length;
        var i = 0;
        while (i < n)
        {
            if (!(IsAsciiLetter(norm[i]) || s_homoglyphs.ContainsKey(norm[i])))
            {
                var r = StyledLetter(norm[i]);
                if (r >= 0)
                {
                    out_[i] = r;
                    changed = true;
                }

                i++;
                continue;
            }

            var j = i;
            var ascii = false;
            while (j < n && (IsAsciiLetter(norm[j]) || s_homoglyphs.ContainsKey(norm[j])))
            {
                ascii = ascii || IsAsciiLetter(norm[j]);
                j++;
            }

            if (ascii)
            {
                for (var k = i; k < j; k++)
                {
                    if (s_homoglyphs.TryGetValue(norm[k], out var h))
                    {
                        out_[k] = h;
                        changed = true;
                    }
                }
            }

            i = j;
        }

        return changed ? out_ : null;
    }

    private static bool IsLeetWord(int c) => IsAsciiLetter(c) || (c >= '0' && c <= '9') || Leet(c) >= 0;

    private static int[]? RespellLeet(int[] norm)
    {
        var out_ = (int[])norm.Clone();
        var changed = false;
        var n = norm.Length;
        var i = 0;
        while (i < n)
        {
            if (!IsLeetWord(norm[i]))
            {
                i++;
                continue;
            }

            var j = i;
            int letters = 0, digits = 0;
            while (j < n && IsLeetWord(norm[j]))
            {
                if (IsAsciiLetter(norm[j]))
                {
                    letters++;
                }
                else if (Leet(norm[j]) >= 0)
                {
                    digits++;
                }

                j++;
            }

            if (letters > 0 && digits > 0)
            {
                for (var k = i; k < j; k++)
                {
                    var l = Leet(norm[k]);
                    if (l >= 0)
                    {
                        out_[k] = l;
                        changed = true;
                    }
                }
            }

            i = j;
        }

        return changed ? out_ : null;
    }

    private static int[] Rot13(int[] norm)
    {
        var out_ = new int[norm.Length];
        for (var i = 0; i < norm.Length; i++)
        {
            var c = norm[i];
            out_[i] = c >= 'a' && c <= 'z' ? 'a' + ((c - 'a' + 13) % 26) : c >= 'A' && c <= 'Z' ? 'A' + ((c - 'A' + 13) % 26) : c;
        }

        return out_;
    }

    private static readonly Regex s_hexBlob = new("(?:[0-9A-Fa-f]{2}){8,}", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_b64Blob = new("[A-Za-z0-9+/_-]{16,}={0,2}", RegexOptions.CultureInvariant, s_timeout);

    private static SortedSet<string> Encoded(string text, string source)
    {
        var hits = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var rule in s_rules)
        {
            bool hex;
            if (rule.Kind == "hex")
            {
                hex = true;
            }
            else if (rule.Kind == "base64")
            {
                hex = false;
            }
            else
            {
                continue;
            }

            if (!rule.AppliesTo(source))
            {
                continue;
            }

            var seen = 0;
            try
            {
                for (var m = (hex ? s_hexBlob : s_b64Blob).Match(text); m.Success; m = m.NextMatch())
                {
                    var blob = m.Value;
                    if (blob.Length < rule.Min)
                    {
                        continue;
                    }

                    if (seen >= MaxBlobs)
                    {
                        break;
                    }

                    seen++;
                    var plain = hex ? DecodeHex(blob) : DecodeBase64(blob);
                    if (plain is null)
                    {
                        continue;
                    }

                    var normalised = new StringBuilder();
                    foreach (var c in CodePoints(plain))
                    {
                        AppendCodePoint(normalised, Normalise(c));
                    }

                    var inner = RegexMatches(normalised.ToString(), true, source);
                    if (inner.Count == 0)
                    {
                        continue;
                    }

                    hits.UnionWith(inner);
                    hits.Add(rule.Id);
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // too slow: stop here
            }
        }

        return hits;
    }

    private static bool Printable(byte[] b)
    {
        if (b.Length < 12)
        {
            return false;
        }

        var ok = 0;
        foreach (var x in b)
        {
            if ((x >= 0x20 && x <= 0x7e) || x == 0x0a || x == 0x0d || x == 0x09)
            {
                ok++;
            }
        }

        return ok * 10 >= b.Length * 9;
    }

    private static readonly UTF8Encoding s_strictUtf8 = new(false, true);

    internal static string? Utf8(byte[] b)
    {
        try
        {
            return s_strictUtf8.GetString(b);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static string? DecodeBase64(string input)
    {
        var s = input.TrimEnd('=');
        if (s.Length % 4 == 1)
        {
            return null;
        }

        var out_ = new List<byte>(s.Length);
        int acc = 0, bits = 0;
        foreach (var ch in s)
        {
            int v;
            if (ch >= 'A' && ch <= 'Z')
            {
                v = ch - 'A';
            }
            else if (ch >= 'a' && ch <= 'z')
            {
                v = ch - 'a' + 26;
            }
            else if (ch >= '0' && ch <= '9')
            {
                v = ch - '0' + 52;
            }
            else if (ch == '+' || ch == '-')
            {
                v = 62;
            }
            else if (ch == '/' || ch == '_')
            {
                v = 63;
            }
            else
            {
                return null;
            }

            acc = ((acc << 6) | v) & 0xffff;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                out_.Add((byte)((acc >> bits) & 0xff));
                acc &= (1 << bits) - 1;
            }
        }

        var b = out_.ToArray();
        return Printable(b) ? Utf8(b) : null;
    }

    private static string? DecodeHex(string s)
    {
        if (s.Length % 2 != 0)
        {
            return null;
        }

        var b = new byte[s.Length / 2];
        for (var i = 0; i < b.Length; i++)
        {
            b[i] = byte.Parse(s.Substring(2 * i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return Printable(b) ? Utf8(b) : null;
    }
}
