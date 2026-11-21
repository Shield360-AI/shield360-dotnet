#pragma warning disable CA1861 // small literal arrays on cold paths
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Shield360.Rasp;

/// <summary>Why an upload signature was refused (the contract's codes).</summary>
public sealed class UploadSignatureException : Exception
{
    /// <summary>Creates the error.</summary>
    public UploadSignatureException()
        : this("shape", null, 0, false)
    {
    }

    /// <summary>Creates the error.</summary>
    public UploadSignatureException(string message)
        : this(message, null, 0, false)
    {
    }

    /// <summary>Creates the error.</summary>
    public UploadSignatureException(string message, Exception innerException)
        : base("upload signature: " + message, innerException)
    {
        Code = message;
    }

    private UploadSignatureException(string code, string? stringId, int rule, bool _)
        : base("upload signature: " + code)
    {
        Code = code;
        StringId = stringId;
        Rule = rule;
    }

    internal static UploadSignatureException Of(string code, string? stringId = null, int rule = 0) => new(code, stringId, rule, false);

    /// <summary>The contract's code (shape, id, title, strings, string_id, text, hex, regex, anchor, condition, ...).</summary>
    public string Code { get; }

    /// <summary>The string id the error is about, when it is about one.</summary>
    public string? StringId { get; }

    /// <summary>The index of the refused rule in the list.</summary>
    public int Rule { get; internal set; }
}

/// <summary>A compiled upload signature.</summary>
public sealed class UploadSignature
{
    internal UploadSignature(string id, string title)
    {
        Id = id;
        Title = title;
    }

    /// <summary>The rule id.</summary>
    public string Id { get; }

    /// <summary>The title.</summary>
    public string Title { get; }

    internal List<UploadSignatures.Str> Strings { get; } = new();

    internal UploadSignatures.Cond Cond { get; set; } = new("atLeast", 0, 1, null);
}

/// <summary>
/// Upload signatures (sdk/rasp/README.md "Signatures"): the YARA-like rules of the
/// built-in web-shell set and the organization's own. A port of the Go SDK's compiler
/// and matcher, held to the same answers by testdata/uploads.json. Regex strings use
/// the custom rules' safe subset and its step-counting VM, run only in a window
/// around their anchor.
/// </summary>
public static class UploadSignatures
{
    internal const int Overlap = 2048;
    internal const int Piece = 1 << 20;
    private const int WindowBefore = 256;
    private const int WindowAfter = 1024;
    private const int AnchorsPerPiece = 8;
    private const long RegexSteps = 1_000_000;
    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);
    private static readonly Regex s_ruleId = new("^[a-z0-9][a-z0-9_.-]{0,47}\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_stringId = new("^[a-z][a-z0-9_]{0,15}\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_hex = new("^[0-9a-fA-F]{2}( ?[0-9a-fA-F]{2})*\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_token = new("\\(|\\)|[A-Za-z_][A-Za-z0-9_]*|[^\\t\\n\\f\\r ]", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_count = new("^[0-9]{1,2}\\z", RegexOptions.CultureInvariant, s_timeout);

    internal sealed class Str
    {
        public Str(string id, string kind, byte[] bytes, bool nocase, RegexInst[]? prog)
        {
            Id = id;
            Kind = kind;
            Bytes = bytes;
            NoCase = nocase;
            Prog = prog;
        }

        public string Id { get; }

        public string Kind { get; }

        public byte[] Bytes { get; }

        public bool NoCase { get; }

        public RegexInst[]? Prog { get; }
    }

    internal sealed class Cond
    {
        public Cond(string op, int i, int n, List<Cond>? xs)
        {
            Op = op;
            I = i;
            N = n;
            Xs = xs ?? new List<Cond>();
        }

        public string Op { get; }

        public int I { get; }

        public int N { get; }

        public List<Cond> Xs { get; }

        public bool Holds(bool[] found) => Op switch
        {
            "id" => found[I],
            "not" => !Xs[0].Holds(found),
            "and" => Xs.All(x => x.Holds(found)),
            "or" => Xs.Any(x => x.Holds(found)),
            _ => found.Count(f => f) >= N,
        };
    }

    internal static byte[] Fold(byte[] b, int from, int to)
    {
        var out_ = new byte[to - from];
        for (var i = from; i < to; i++)
        {
            var c = b[i];
            out_[i - from] = c >= 'A' && c <= 'Z' ? (byte)(c + 32) : c;
        }

        return out_;
    }

    internal static byte[] Fold(byte[] b) => Fold(b, 0, b.Length);

    /// <summary>The first index of needle in hay[from, to), or -1.</summary>
    internal static int IndexOf(byte[] hay, int from, int to, byte[] needle)
    {
        var n = needle.Length;
        if (n == 0)
        {
            return from;
        }

        var first = needle[0];
        for (var i = from; i <= to - n; i++)
        {
            if (hay[i] != first)
            {
                continue;
            }

            var k = 1;
            while (k < n && hay[i + k] == needle[k])
            {
                k++;
            }

            if (k == n)
            {
                return i;
            }
        }

        return -1;
    }

    internal static bool Contains(byte[] hay, byte[] needle) => IndexOf(hay, 0, hay.Length, needle) >= 0;

    private static bool Reserved(string id) => id is "and" or "or" or "not" or "any" or "all";

    private static string? Str_(JsonElement m, string k) => m.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool Present(JsonElement m, string k) => m.TryGetProperty(k, out var v) && v.ValueKind != JsonValueKind.Null;

    private static Str CompileString(JsonElement raw)
    {
        var id = Str_(raw, "id") ?? string.Empty;
        if (!s_stringId.IsMatch(id) || Reserved(id))
        {
            throw UploadSignatureException.Of("string_id", id);
        }

        var n = new[] { "text", "hex", "regex" }.Count(k => Present(raw, k));
        if (n != 1)
        {
            throw UploadSignatureException.Of("string_kind", id);
        }

        var nocase = raw.TryGetProperty("nocase", out var nc) && nc.ValueKind == JsonValueKind.True;
        if (Str_(raw, "text") is { } t)
        {
            var b = Encoding.UTF8.GetBytes(t);
            if (b.Length < 3 || b.Length > 256)
            {
                throw UploadSignatureException.Of("text", id);
            }

            return new Str(id, "text", nocase ? Fold(b) : b, nocase, null);
        }

        if (Str_(raw, "hex") is { } h)
        {
            var hs = h.Trim();
            if (!s_hex.IsMatch(hs))
            {
                throw UploadSignatureException.Of("hex", id);
            }

            var digits = hs.Replace(" ", string.Empty);
            var b = new byte[digits.Length / 2];
            for (var i = 0; i < b.Length; i++)
            {
                b[i] = byte.Parse(digits.Substring(2 * i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            if (b.Length < 3 || b.Length > 256)
            {
                throw UploadSignatureException.Of("hex", id);
            }

            return new Str(id, "hex", b, false, null);
        }

        if (Str_(raw, "regex") is { } r)
        {
            var prog = RaspRuleExpr.CompileRegex(r) ?? throw UploadSignatureException.Of("regex", id);
            var a = Str_(raw, "anchor");
            if (a is null || Encoding.UTF8.GetByteCount(a) < 3 || Encoding.UTF8.GetByteCount(a) > 64)
            {
                throw UploadSignatureException.Of("anchor", id);
            }

            return new Str(id, "regex", Encoding.UTF8.GetBytes(a), false, prog);
        }

        throw UploadSignatureException.Of("string_kind", id);
    }

    private sealed class CondParser
    {
        private readonly List<string> _toks;
        private readonly Dictionary<string, int> _ids;
        private int _depth;

        public CondParser(List<string> toks, Dictionary<string, int> ids)
        {
            _toks = toks;
            _ids = ids;
        }

        public int Pos { get; private set; }

        public bool Unknown { get; private set; }

        private string Peek() => Pos < _toks.Count ? _toks[Pos] : string.Empty;

        public Cond? Or()
        {
            var x = And();
            if (x is null)
            {
                return null;
            }

            var xs = new List<Cond> { x };
            while (Peek() == "or")
            {
                Pos++;
                var y = And();
                if (y is null)
                {
                    return null;
                }

                xs.Add(y);
            }

            return xs.Count == 1 ? xs[0] : new Cond("or", 0, 0, xs);
        }

        private Cond? And()
        {
            var x = Unary();
            if (x is null)
            {
                return null;
            }

            var xs = new List<Cond> { x };
            while (Peek() == "and")
            {
                Pos++;
                var y = Unary();
                if (y is null)
                {
                    return null;
                }

                xs.Add(y);
            }

            return xs.Count == 1 ? xs[0] : new Cond("and", 0, 0, xs);
        }

        private Cond? Unary()
        {
            var t = Peek();
            if (t == "not" || t == "(")
            {
                Pos++;
                _depth++;
                if (_depth > 8)
                {
                    return null;
                }

                if (t == "not")
                {
                    var x = Unary();
                    _depth--;
                    return x is null ? null : new Cond("not", 0, 0, new List<Cond> { x });
                }

                var inner = Or();
                _depth--;
                if (inner is null || Peek() != ")")
                {
                    return null;
                }

                Pos++;
                return inner;
            }

            if (t.Length > 0 && s_stringId.IsMatch(t) && t != "and" && t != "or")
            {
                Pos++;
                if (!_ids.TryGetValue(t, out var i))
                {
                    Unknown = true;
                    return null;
                }

                return new Cond("id", i, 0, null);
            }

            return null;
        }
    }

    private static Cond ParseCondition(string src, Dictionary<string, int> ids)
    {
        var text = src.Trim();
        if (text.Length == 0 || text.Length > 256)
        {
            throw UploadSignatureException.Of("condition", null);
        }

        if (text == "any")
        {
            return new Cond("atLeast", 0, 1, null);
        }

        if (text == "all")
        {
            return new Cond("atLeast", 0, ids.Count, null);
        }

        if (s_count.IsMatch(text))
        {
            var n = int.Parse(text, CultureInfo.InvariantCulture);
            return n >= 1 && n <= ids.Count ? new Cond("atLeast", 0, n, null) : throw UploadSignatureException.Of("condition", null);
        }

        var toks = s_token.Matches(text).Cast<Match>().Select(m => m.Value).ToList();
        var p = new CondParser(toks, ids);
        var c = p.Or();
        if (p.Unknown)
        {
            throw UploadSignatureException.Of("unknown_string", null);
        }

        if (c is null || p.Pos != toks.Count)
        {
            throw UploadSignatureException.Of("condition", null);
        }

        return c;
    }

    /// <summary>Checks one rule (decoded JSON) and compiles it; throws <see cref="UploadSignatureException"/>.</summary>
    public static UploadSignature Compile(JsonElement m)
    {
        if (m.ValueKind != JsonValueKind.Object)
        {
            throw UploadSignatureException.Of("shape", null);
        }

        var id = Str_(m, "id") ?? string.Empty;
        if (!s_ruleId.IsMatch(id))
        {
            throw UploadSignatureException.Of("id", null);
        }

        var title = Str_(m, "title") ?? string.Empty;
        if (title.Trim().Length == 0 || Encoding.UTF32.GetByteCount(title) / 4 > 120)
        {
            throw UploadSignatureException.Of("title", null);
        }

        if (!m.TryGetProperty("strings", out var list) || list.ValueKind != JsonValueKind.Array || list.GetArrayLength() < 1 || list.GetArrayLength() > 16)
        {
            throw UploadSignatureException.Of("strings", null);
        }

        var sig = new UploadSignature(id, title.Trim());
        var ids = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var s in list.EnumerateArray())
        {
            if (s.ValueKind != JsonValueKind.Object)
            {
                throw UploadSignatureException.Of("string_kind", null);
            }

            var spec = CompileString(s);
            if (ids.ContainsKey(spec.Id))
            {
                throw UploadSignatureException.Of("duplicate_string", spec.Id);
            }

            ids[spec.Id] = sig.Strings.Count;
            sig.Strings.Add(spec);
        }

        string condText;
        if (!m.TryGetProperty("condition", out var cv))
        {
            throw UploadSignatureException.Of("condition", null);
        }

        if (cv.ValueKind == JsonValueKind.String)
        {
            condText = cv.GetString()!;
        }
        else if (cv.ValueKind == JsonValueKind.Number)
        {
            condText = cv.GetDouble().ToString("R", CultureInfo.InvariantCulture);
        }
        else
        {
            throw UploadSignatureException.Of("condition", null);
        }

        sig.Cond = ParseCondition(condText, ids);
        return sig;
    }

    /// <summary>Compiles the organization's rules: every valid one, in order, and the errors of the others; more than 64 or 64 KiB is refused whole.</summary>
    public static (IReadOnlyList<UploadSignature> Signatures, IReadOnlyList<UploadSignatureException> Errors) CompileAll(JsonElement raw)
    {
        var sigs = new List<UploadSignature>();
        var errs = new List<UploadSignatureException>();
        if (raw.ValueKind != JsonValueKind.Array)
        {
            return (sigs, errs);
        }

        if (raw.GetArrayLength() > 64)
        {
            errs.Add(UploadSignatureException.Of("too_many", null));
            return (sigs, errs);
        }

        long total = 2;
        foreach (var r in raw.EnumerateArray())
        {
            total += Encoding.UTF8.GetByteCount(r.GetRawText()) + 1;
        }

        if (total > 65536)
        {
            errs.Add(UploadSignatureException.Of("too_large", null));
            return (sigs, errs);
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var i = 0;
        foreach (var r in raw.EnumerateArray())
        {
            try
            {
                var s = Compile(r);
                if (!seen.Add(s.Id))
                {
                    errs.Add(UploadSignatureException.Of("duplicate_id", null, i));
                }
                else
                {
                    sigs.Add(s);
                }
            }
            catch (UploadSignatureException e)
            {
                e.Rule = i;
                errs.Add(e);
            }

            i++;
        }

        return (sigs, errs);
    }

    /// <summary>The contract's web-shell signatures (a byte-identical copy of sdk/rasp/rules/upload-signatures.json).</summary>
    public static IReadOnlyList<UploadSignature> BuiltIn { get; } = LoadBuiltIn();

    internal static byte[] BuiltInJson()
    {
        using var stream = typeof(UploadSignatures).Assembly.GetManifestResourceStream("Shield360.Rasp.upload-signatures.json");
        if (stream is null)
        {
            return Array.Empty<byte>();
        }

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private static IReadOnlyList<UploadSignature> LoadBuiltIn()
    {
        try
        {
            using var doc = JsonDocument.Parse(BuiltInJson());
            return doc.RootElement.TryGetProperty("rules", out var rules) ? CompileAll(rules).Signatures : Array.Empty<UploadSignature>();
        }
        catch (JsonException)
        {
            return Array.Empty<UploadSignature>();
        }
    }

    /// <summary>Runs signatures over pieces of a file as they pass, with one regex budget for the whole file.</summary>
    internal sealed class Matcher
    {
        private readonly IReadOnlyList<UploadSignature> _sigs;
        private readonly bool[][] _found;
        private readonly RuleBudget _budget = new(RegexSteps);

        public Matcher(IReadOnlyList<UploadSignature> sigs)
        {
            _sigs = sigs;
            _found = sigs.Select(s => new bool[s.Strings.Count]).ToArray();
        }

        public void Feed(byte[] piece, byte[] folded, bool last)
        {
            for (var r = 0; r < _sigs.Count; r++)
            {
                var sig = _sigs[r];
                for (var i = 0; i < sig.Strings.Count; i++)
                {
                    if (_found[r][i])
                    {
                        continue;
                    }

                    var s = sig.Strings[i];
                    if (s.Kind != "regex")
                    {
                        if (Contains(s.NoCase ? folded : piece, s.Bytes))
                        {
                            _found[r][i] = true;
                        }

                        continue;
                    }

                    if (_budget.Steps < 0)
                    {
                        continue;
                    }

                    var from = 0;
                    for (var n = 0; n < AnchorsPerPiece; n++)
                    {
                        var at = IndexOf(piece, from, piece.Length, s.Bytes);
                        if (at < 0)
                        {
                            break;
                        }

                        var end = at + s.Bytes.Length + WindowAfter;
                        if (end > piece.Length && !last)
                        {
                            break;
                        }

                        var lo = Math.Max(0, at - WindowBefore);
                        end = Math.Min(end, piece.Length);
                        var subject = new int[end - lo];
                        for (var k = lo; k < end; k++)
                        {
                            subject[k - lo] = piece[k];
                        }

                        if (RaspRuleExpr.UploadRegexMatch(s.Prog!, subject, _budget))
                        {
                            _found[r][i] = true;
                            break;
                        }

                        if (_budget.Steps < 0)
                        {
                            break;
                        }

                        from = at + 1;
                    }
                }
            }
        }

        public List<UploadSignature> Matched()
        {
            var out_ = new List<UploadSignature>();
            for (var r = 0; r < _sigs.Count; r++)
            {
                if (_sigs[r].Cond.Holds(_found[r]))
                {
                    out_.Add(_sigs[r]);
                }
            }

            return out_;
        }
    }

    /// <summary>Runs signatures over a whole sample; the ids that match.</summary>
    public static IReadOnlyList<string> MatchSample(IReadOnlyList<UploadSignature> sigs, byte[] data)
    {
        var m = new Matcher(sigs);
        for (var start = 0; ; start += Piece)
        {
            var lo = Math.Max(0, start - Overlap);
            var end = Math.Min(start + Piece, data.Length);
            var piece = new byte[end - lo];
            Buffer.BlockCopy(data, lo, piece, 0, piece.Length);
            m.Feed(piece, Fold(piece), end >= data.Length);
            if (end >= data.Length)
            {
                break;
            }
        }

        return m.Matched().Select(s => s.Id).ToList();
    }
}
