using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Shield360.Rasp;

/// <summary>Why an expression did not compile (sdk/rasp/README.md, "Custom rules: limits"); the corpus's error codes.</summary>
internal sealed record RuleExprError(string Code, int Pos);

/// <summary>One untrusted input as the expression language sees it. <see cref="Origin"/> is the SDK's input, when there is one.</summary>
internal sealed record RuleInput(string Value, string Key, string Source, RaspInput? Origin = null);

/// <summary>The request as the expression language sees it. Missing parts read as null.</summary>
internal sealed class RuleRequest
{
    public string? Method { get; init; }

    public string? Path { get; init; }

    public string? Route { get; init; }

    public string? Ip { get; init; }

    /// <summary>Lower-case header names.</summary>
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    /// <summary>Query parameter name to its first value.</summary>
    public IReadOnlyDictionary<string, string>? Query { get; init; }

    /// <summary>Flattened body path (<c>user.name</c>) to its first string leaf.</summary>
    public IReadOnlyDictionary<string, string>? Body { get; init; }
}

/// <summary>What an expression is evaluated against. Missing parts read as null.</summary>
internal sealed class RuleSubject
{
    public string? App { get; set; }

    public RuleRequest? Request { get; set; }

    public IReadOnlyList<RuleInput>? Inputs { get; set; }

    public string? Sink { get; set; }

    public string? AttackType { get; set; }

    public string? AttackRule { get; set; }
}

/// <summary>Work left for one evaluation (regex VM steps); running out ends the evaluation as no match.</summary>
internal sealed class RuleBudget
{
    public RuleBudget(long steps = RaspRuleExpr.DefaultBudget)
    {
        Steps = steps;
    }

    public long Steps { get; set; }
}

/// <summary>A parsed, type-checked expression.</summary>
internal sealed class CompiledRuleExpr
{
    public CompiledRuleExpr(RuleNode ast, IReadOnlyList<string> fields)
    {
        Ast = ast;
        Fields = fields;
        Phase = fields.Any(f => f.StartsWith("sink.", StringComparison.Ordinal) || f.StartsWith("attack.", StringComparison.Ordinal)) ? "finding" : "request";
        UsesInput = fields.Any(f => f.StartsWith("input.", StringComparison.Ordinal));
        UsesBody = fields.Contains("request.body");
        UsesIp = fields.Contains("request.ip");
    }

    public RuleNode Ast { get; }

    /// <summary>Field names read (without map keys), sorted.</summary>
    public IReadOnlyList<string> Fields { get; }

    /// <summary><c>finding</c> when the expression reads <c>sink.*</c> or <c>attack.*</c>, else <c>request</c>.</summary>
    public string Phase { get; }

    /// <summary>Reads <c>input.*</c>: evaluated once per input, true when any input makes it true.</summary>
    public bool UsesInput { get; }

    /// <summary>Reads <c>request.body[...]</c>.</summary>
    public bool UsesBody { get; }

    /// <summary>Reads <c>request.ip</c> (judged again when the framework rewrites the client address).</summary>
    public bool UsesIp { get; }
}

/// <summary>The result of evaluating an expression.</summary>
internal readonly record struct RuleEvalResult(bool Matched, RuleInput? Input = null, bool Exhausted = false);

internal enum RuleNodeKind
{
    Str,
    Bool,
    Null,
    Field,
    Not,
    And,
    Or,
    Cmp,
    In,
    StrMethod,
    Lower,
    Matches,
    Cidr,
}

/// <summary>An expression node. Which members are set depends on <see cref="Kind"/>.</summary>
internal sealed class RuleNode
{
    public RuleNode(RuleNodeKind kind)
    {
        Kind = kind;
    }

    public RuleNodeKind Kind { get; }

    /// <summary>A string literal's value, a field's name, a comparison operator, or a string method's name.</summary>
    public string? Text { get; init; }

    public bool Flag { get; init; }

    /// <summary>A map field's key, or a string method's argument.</summary>
    public string? Key { get; init; }

    /// <summary>The operand of <c>!</c>, the target of a method, or a comparison's left side.</summary>
    public RuleNode? X { get; init; }

    /// <summary>A comparison's right side.</summary>
    public RuleNode? Y { get; init; }

    public RuleNode[]? Xs { get; init; }

    public string[]? Items { get; init; }

    internal RegexInst[]? Prog { get; init; }

    internal RuleNet? Net { get; init; }
}

internal enum RegexOp
{
    Char,
    Any,
    Class,
    Split,
    Jmp,
    Bol,
    Eol,
    Match,
}

/// <summary>One instruction of a regular-expression program (Pike VM).</summary>
internal sealed class RegexInst
{
    public RegexInst(RegexOp op)
    {
        Op = op;
    }

    public RegexOp Op { get; }

    public int C { get; set; }

    public int X { get; set; }

    public int Y { get; set; }

    public int[] R { get; set; } = Array.Empty<int>();

    public bool Neg { get; set; }
}

/// <summary>A network: 16 address bytes and a prefix length in bits (IPv4 as <c>::ffff:a.b.c.d/(96+n)</c>).</summary>
internal sealed record RuleNet(byte[] Bytes, int Prefix);

/// <summary>
/// Custom RASP rule expressions (sdk/rasp/README.md, "Custom rules"): a small, sandboxed,
/// CEL-style language of a fixed set of fields, string literals, comparison, <c>in</c>, a
/// few string methods, a safe regular-expression subset matched in linear time by a Pike
/// VM, and CIDR matching. Expressions are parsed and type-checked once and evaluated as
/// data; nothing downloaded is ever run as code. Port of the TypeScript <c>rule-expr.ts</c>,
/// which the platform shares byte for byte, with the same limits, error codes and semantics
/// (strings are UTF-16 as in JavaScript; regexes and comparisons read code points).
/// </summary>
/// <remarks>
/// The regex subset is matched by a port of the reference Pike VM on every target, not
/// <c>RegexOptions.NonBacktracking</c>: netstandard2.0 has no NonBacktracking, and the
/// contract's per-request step budget (4,000,000 VM steps, after which the rule is no
/// match) can only be counted in an engine the SDK runs itself. One engine on both
/// targets gives the same answer and the same budget everywhere.
/// </remarks>
internal static class RaspRuleExpr
{
    public const int ExpressionBytes = 2048;
    public const int MaxDepth = 12;
    public const int MaxNodes = 128;
    public const int StringBytes = 1024;
    public const int ListItems = 64;
    public const int Regexes = 8;
    public const int RegexBytes = 256;
    public const int RegexAtoms = 256;
    public const int RegexRepeat = 100;
    public const int MatchCodePoints = 4096;
    public const long DefaultBudget = 4_000_000;

    /// <summary>The fields an expression may read: <c>string</c> or <c>map</c>.</summary>
    public static readonly IReadOnlyDictionary<string, string> Fields = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["request.method"] = "string",
        ["request.path"] = "string",
        ["request.route"] = "string",
        ["request.ip"] = "string",
        ["request.headers"] = "map",
        ["request.query"] = "map",
        ["request.body"] = "map",
        ["input.value"] = "string",
        ["input.key"] = "string",
        ["input.source"] = "string",
        ["sink.name"] = "string",
        ["attack.type"] = "string",
        ["attack.rule"] = "string",
        ["app.name"] = "string",
    };

    private sealed class ExprException : Exception
    {
        public ExprException(string code, int pos)
            : base(code)
        {
            Code = code;
            Pos = pos;
        }

        public string Code { get; }

        public int Pos { get; }
    }

    private sealed class BudgetExhaustedException : Exception
    {
    }

    private sealed class RegexRefusedException : Exception
    {
    }

    /// <summary>UTF-8 length of a UTF-16 string (a lone surrogate counts 3, as its U+FFFD replacement).</summary>
    public static int Utf8Length(string s)
    {
        var n = 0;
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c < 0x80)
            {
                n += 1;
            }
            else if (c < 0x800)
            {
                n += 2;
            }
            else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.Length && s[i + 1] >= 0xdc00 && s[i + 1] <= 0xdfff)
            {
                n += 4;
                i++;
            }
            else
            {
                n += 3;
            }
        }

        return n;
    }

    /// <summary>The code points of a string, at most <paramref name="max"/> (a lone surrogate is its own code point, as in JS).</summary>
    private static int[] CodePoints(string s, int max)
    {
        var output = new List<int>(Math.Min(s.Length, max));
        for (var i = 0; i < s.Length && output.Count < max;)
        {
            var c = (int)s[i];
            if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.Length && s[i + 1] >= 0xdc00 && s[i + 1] <= 0xdfff)
            {
                output.Add(char.ConvertToUtf32(s[i], s[i + 1]));
                i += 2;
            }
            else
            {
                output.Add(c);
                i++;
            }
        }

        return output.ToArray();
    }

    /// <summary>JavaScript's <c>trim()</c> white space (WhiteSpace and LineTerminator).</summary>
    private static bool IsJsSpace(char c) =>
        c is '\t' or '\n' or '\v' or '\f' or '\r' or ' ' or '\u00a0' or '\u1680' or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000' or '\ufeff'
        || (c >= '\u2000' && c <= '\u200a');

    private static string AsciiLower(string s)
    {
        var chars = s.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            if (chars[i] >= 'A' && chars[i] <= 'Z')
            {
                chars[i] = (char)(chars[i] + 32);
            }
        }

        return new string(chars);
    }

    // ---- lexer ------------------------------------------------------------------

    private enum TokKind
    {
        Ident,
        Str,
        Op,
        Eof,
    }

    private readonly record struct Tok(TokKind T, string V, int Pos);

    private static bool IsIdentStart(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';

    private static bool IsIdentPart(char c) => IsIdentStart(c) || (c >= '0' && c <= '9');

    private static bool IsHex(char c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

    private static List<Tok> Lex(string src)
    {
        var toks = new List<Tok>();
        var i = 0;
        while (i < src.Length)
        {
            var c = src[i];
            if (c is ' ' or '\t' or '\n' or '\r')
            {
                i++;
                continue;
            }

            var start = i;
            var raw = (c == 'r' || c == 'R') && i + 1 < src.Length && (src[i + 1] == '"' || src[i + 1] == '\'');
            if (c == '"' || c == '\'' || raw)
            {
                if (raw)
                {
                    i++;
                }

                var quote = src[i];
                i++;
                var v = new StringBuilder();
                for (; ; )
                {
                    if (i >= src.Length)
                    {
                        throw new ExprException("syntax", start);
                    }

                    var d = src[i];
                    if (d == quote)
                    {
                        i++;
                        break;
                    }

                    if (d < 0x20)
                    {
                        throw new ExprException("syntax", i);
                    }

                    if (d == '\\' && !raw)
                    {
                        var e = i + 1 < src.Length ? src[i + 1] : '\0';
                        if (e is '\\' or '"' or '\'')
                        {
                            v.Append(e);
                        }
                        else if (e == 'n')
                        {
                            v.Append('\n');
                        }
                        else if (e == 'r')
                        {
                            v.Append('\r');
                        }
                        else if (e == 't')
                        {
                            v.Append('\t');
                        }
                        else if (e == 'u')
                        {
                            if (i + 6 > src.Length || !IsHex(src[i + 2]) || !IsHex(src[i + 3]) || !IsHex(src[i + 4]) || !IsHex(src[i + 5]))
                            {
                                throw new ExprException("syntax", i);
                            }

                            var code = Convert.ToInt32(src.Substring(i + 2, 4), 16);
                            if (code >= 0xd800 && code <= 0xdfff)
                            {
                                throw new ExprException("syntax", i);
                            }

                            v.Append((char)code);
                            i += 4;
                        }
                        else
                        {
                            throw new ExprException("syntax", i);
                        }

                        i += 2;
                        continue;
                    }

                    v.Append(d);
                    i++;
                }

                var value = v.ToString();
                if (Utf8Length(value) > StringBytes)
                {
                    throw new ExprException("string_too_long", start);
                }

                toks.Add(new Tok(TokKind.Str, value, start));
                continue;
            }

            if (IsIdentStart(c))
            {
                while (i < src.Length && IsIdentPart(src[i]))
                {
                    i++;
                }

                toks.Add(new Tok(TokKind.Ident, src.Substring(start, i - start), start));
                continue;
            }

            if (i + 1 < src.Length)
            {
                var two = src.Substring(i, 2);
                if (two is "==" or "!=" or "<=" or ">=" or "&&" or "||")
                {
                    toks.Add(new Tok(TokKind.Op, two, start));
                    i += 2;
                    continue;
                }
            }

            if ("()[],.<>!".IndexOf(c) >= 0)
            {
                toks.Add(new Tok(TokKind.Op, c.ToString(), start));
                i++;
                continue;
            }

            throw new ExprException("syntax", i);
        }

        toks.Add(new Tok(TokKind.Eof, string.Empty, src.Length));
        return toks;
    }

    // ---- parser -----------------------------------------------------------------

    private static readonly HashSet<string> s_methods = new(new[] { "startsWith", "endsWith", "contains", "lowerAscii", "matches", "inCidr" }, StringComparer.Ordinal);

    private sealed class Parser
    {
        private readonly List<Tok> _toks;
        private int _i;
        private int _nodes;
        private int _parens;
        private int _nots;
        private int _regexes;

        public Parser(List<Tok> toks)
        {
            _toks = toks;
        }

        private Tok Peek(int o = 0) => _toks[Math.Min(_i + o, _toks.Count - 1)];

        private Tok Next()
        {
            var t = Peek();
            if (_i < _toks.Count - 1)
            {
                _i++;
            }

            return t;
        }

        private bool IsOp(string v, int o = 0)
        {
            var t = Peek(o);
            return t.T == TokKind.Op && t.V == v;
        }

        private void ExpectOp(string v)
        {
            var t = Next();
            if (t.T != TokKind.Op || t.V != v)
            {
                throw new ExprException("syntax", t.Pos);
            }
        }

        private void Count(int n, int pos)
        {
            _nodes += n;
            if (_nodes > MaxNodes)
            {
                throw new ExprException("nodes", pos);
            }
        }

        public RuleNode Parse()
        {
            var n = Or();
            var t = Peek();
            if (t.T != TokKind.Eof)
            {
                throw new ExprException("syntax", t.Pos);
            }

            return n;
        }

        private RuleNode Or()
        {
            var pos = Peek().Pos;
            var xs = new List<RuleNode> { And() };
            while (IsOp("||"))
            {
                Next();
                xs.Add(And());
            }

            if (xs.Count == 1)
            {
                return xs[0];
            }

            Count(1, pos);
            return new RuleNode(RuleNodeKind.Or) { Xs = xs.ToArray() };
        }

        private RuleNode And()
        {
            var pos = Peek().Pos;
            var xs = new List<RuleNode> { Relation() };
            while (IsOp("&&"))
            {
                Next();
                xs.Add(Relation());
            }

            if (xs.Count == 1)
            {
                return xs[0];
            }

            Count(1, pos);
            return new RuleNode(RuleNodeKind.And) { Xs = xs.ToArray() };
        }

        private RuleNode Relation()
        {
            var l = Unary();
            var t = Peek();
            if (t.T == TokKind.Op && t.V is "==" or "!=" or "<" or "<=" or ">" or ">=")
            {
                Next();
                var r = Unary();
                Count(1, t.Pos);
                return new RuleNode(RuleNodeKind.Cmp) { Text = t.V, X = l, Y = r };
            }

            if (t.T == TokKind.Ident && t.V == "in")
            {
                Next();
                ExpectOp("[");
                var items = new List<string>();
                while (!IsOp("]"))
                {
                    var s = Next();
                    if (s.T != TokKind.Str)
                    {
                        throw new ExprException("syntax", s.Pos);
                    }

                    items.Add(s.V);
                    if (items.Count > ListItems)
                    {
                        throw new ExprException("list_too_long", s.Pos);
                    }

                    if (IsOp(","))
                    {
                        Next();
                    }
                    else if (!IsOp("]"))
                    {
                        throw new ExprException("syntax", Peek().Pos);
                    }
                }

                Next();
                Count(2 + items.Count, t.Pos);
                return new RuleNode(RuleNodeKind.In) { X = l, Items = items.ToArray() };
            }

            return l;
        }

        private RuleNode Unary()
        {
            var t = Peek();
            if (IsOp("!"))
            {
                Next();
                if (++_nots > MaxDepth)
                {
                    throw new ExprException("depth", t.Pos);
                }

                var x = Unary();
                _nots--;
                Count(1, t.Pos);
                return new RuleNode(RuleNodeKind.Not) { X = x };
            }

            return Member();
        }

        private RuleNode Member()
        {
            var n = Primary();
            while (IsOp("."))
            {
                Next();
                var name = Next();
                if (name.T != TokKind.Ident)
                {
                    throw new ExprException("syntax", name.Pos);
                }

                if (!IsOp("("))
                {
                    throw new ExprException("syntax", Peek().Pos);
                }

                Next();
                string? arg = null;
                if (Peek().T == TokKind.Str)
                {
                    arg = Next().V;
                }

                ExpectOp(")");
                if (!s_methods.Contains(name.V))
                {
                    throw new ExprException("unknown_method", name.Pos);
                }

                if (name.V == "lowerAscii")
                {
                    if (arg is not null)
                    {
                        throw new ExprException("type", name.Pos);
                    }

                    Count(1, name.Pos);
                    n = new RuleNode(RuleNodeKind.Lower) { X = n };
                    continue;
                }

                if (arg is null)
                {
                    throw new ExprException("type", name.Pos);
                }

                Count(2, name.Pos);
                if (name.V is "startsWith" or "endsWith" or "contains")
                {
                    n = new RuleNode(RuleNodeKind.StrMethod) { Text = name.V, X = n, Key = arg };
                }
                else if (name.V == "matches")
                {
                    _regexes++;
                    if (_regexes > Regexes)
                    {
                        throw new ExprException("too_many_regexes", name.Pos);
                    }

                    var prog = CompileRegex(arg) ?? throw new ExprException("regex", name.Pos);
                    n = new RuleNode(RuleNodeKind.Matches) { X = n, Prog = prog };
                }
                else
                {
                    var net = ParseCidr(arg) ?? throw new ExprException("cidr", name.Pos);
                    n = new RuleNode(RuleNodeKind.Cidr) { X = n, Net = net };
                }
            }

            return n;
        }

        private RuleNode Primary()
        {
            var t = Next();
            if (t.T == TokKind.Str)
            {
                Count(1, t.Pos);
                return new RuleNode(RuleNodeKind.Str) { Text = t.V };
            }

            if (t.T == TokKind.Op && t.V == "(")
            {
                if (++_parens > MaxDepth)
                {
                    throw new ExprException("depth", t.Pos);
                }

                var n = Or();
                _parens--;
                ExpectOp(")");
                return n;
            }

            if (t.T == TokKind.Ident)
            {
                if (t.V is "true" or "false")
                {
                    Count(1, t.Pos);
                    return new RuleNode(RuleNodeKind.Bool) { Flag = t.V == "true" };
                }

                if (t.V == "null")
                {
                    Count(1, t.Pos);
                    return new RuleNode(RuleNodeKind.Null);
                }

                if (t.V == "in")
                {
                    throw new ExprException("syntax", t.Pos);
                }

                // A dotted field name; a segment followed by `(` is a method call.
                var name = t.V;
                while (IsOp(".") && Peek(1).T == TokKind.Ident && !IsOp("(", 2))
                {
                    Next();
                    name += "." + Next().V;
                }

                if (!Fields.TryGetValue(name, out var type))
                {
                    throw new ExprException("unknown_field", t.Pos);
                }

                string? key = null;
                if (IsOp("["))
                {
                    var open = Next();
                    var s = Next();
                    if (s.T != TokKind.Str)
                    {
                        throw new ExprException("syntax", s.Pos);
                    }

                    ExpectOp("]");
                    if (type != "map")
                    {
                        throw new ExprException("type", open.Pos);
                    }

                    // Header names are case-insensitive: ASCII lower-cased here, as the SDKs record them.
                    key = name == "request.headers" ? AsciiLower(s.V) : s.V;
                }
                else if (type == "map")
                {
                    throw new ExprException("type", t.Pos);
                }

                Count(1, t.Pos);
                return new RuleNode(RuleNodeKind.Field) { Text = name, Key = key };
            }

            throw new ExprException("syntax", t.Pos);
        }
    }

    // ---- types ------------------------------------------------------------------

    private enum Ty
    {
        String,
        Bool,
        Null,
    }

    private static Ty TypeOf(RuleNode n)
    {
        switch (n.Kind)
        {
            case RuleNodeKind.Str:
            case RuleNodeKind.Field:
                return Ty.String;
            case RuleNodeKind.Bool:
                return Ty.Bool;
            case RuleNodeKind.Null:
                return Ty.Null;
            case RuleNodeKind.Not:
                return TypeOf(n.X!) == Ty.Bool ? Ty.Bool : throw new ExprException("type", 0);
            case RuleNodeKind.And:
            case RuleNodeKind.Or:
                foreach (var x in n.Xs!)
                {
                    if (TypeOf(x) != Ty.Bool)
                    {
                        throw new ExprException("type", 0);
                    }
                }

                return Ty.Bool;
            case RuleNodeKind.Cmp:
            {
                var l = TypeOf(n.X!);
                var r = TypeOf(n.Y!);
                if (n.Text is "==" or "!=")
                {
                    static bool Strish(Ty t) => t is Ty.String or Ty.Null;
                    if (!((Strish(l) && Strish(r)) || (l == Ty.Bool && r == Ty.Bool)))
                    {
                        throw new ExprException("type", 0);
                    }
                }
                else if (l != Ty.String || r != Ty.String)
                {
                    throw new ExprException("type", 0);
                }

                return Ty.Bool;
            }

            case RuleNodeKind.In:
            case RuleNodeKind.StrMethod:
            case RuleNodeKind.Matches:
            case RuleNodeKind.Cidr:
                return TypeOf(n.X!) == Ty.String ? Ty.Bool : throw new ExprException("type", 0);
            default:
                return TypeOf(n.X!) == Ty.String ? Ty.String : throw new ExprException("type", 0);
        }
    }

    private static int DepthOf(RuleNode n) => n.Kind switch
    {
        RuleNodeKind.Not or RuleNodeKind.Lower => 1 + DepthOf(n.X!),
        RuleNodeKind.And or RuleNodeKind.Or => 1 + n.Xs!.Max(DepthOf),
        RuleNodeKind.Cmp => 1 + Math.Max(DepthOf(n.X!), DepthOf(n.Y!)),
        RuleNodeKind.In => 1 + Math.Max(DepthOf(n.X!), 2),
        RuleNodeKind.StrMethod or RuleNodeKind.Matches or RuleNodeKind.Cidr => 1 + Math.Max(DepthOf(n.X!), 1),
        _ => 1,
    };

    private static void CollectFields(RuleNode n, SortedSet<string> output)
    {
        if (n.Kind == RuleNodeKind.Field)
        {
            output.Add(n.Text!);
            return;
        }

        if (n.Xs is not null)
        {
            foreach (var x in n.Xs)
            {
                CollectFields(x, output);
            }
        }

        if (n.X is not null)
        {
            CollectFields(n.X, output);
        }

        if (n.Y is not null)
        {
            CollectFields(n.Y, output);
        }
    }

    /// <summary>
    /// Parses and type-checks an expression (anything but a string is <c>empty</c>). Every
    /// limit is checked here; an expression that compiles is safe to evaluate on any input.
    /// </summary>
    public static CompiledRuleExpr? Compile(object? src, out RuleExprError? error)
    {
        error = null;
        try
        {
            if (src is not string s || s.All(IsJsSpace))
            {
                error = new RuleExprError("empty", 0);
                return null;
            }

            if (Utf8Length(s) > ExpressionBytes)
            {
                error = new RuleExprError("too_long", 0);
                return null;
            }

            var ast = new Parser(Lex(s)).Parse();
            if (TypeOf(ast) != Ty.Bool)
            {
                throw new ExprException("type", 0);
            }

            if (DepthOf(ast) > MaxDepth)
            {
                throw new ExprException("depth", 0);
            }

            var fields = new SortedSet<string>(StringComparer.Ordinal);
            CollectFields(ast, fields);
            return new CompiledRuleExpr(ast, fields.ToArray());
        }
        catch (ExprException e)
        {
            error = new RuleExprError(e.Code, e.Pos);
            return null;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            error = new RuleExprError("syntax", 0);
            return null;
        }
    }

    // ---- evaluation -------------------------------------------------------------

    private static string? Own(IReadOnlyDictionary<string, string>? map, string key) =>
        map is not null && map.TryGetValue(key, out var v) ? v : null;

    /// <summary>Compares two strings by Unicode code point (not UTF-16 code unit).</summary>
    private static int CompareCodePoints(string a, string b)
    {
        int i = 0, j = 0;
        while (i < a.Length && j < b.Length)
        {
            var x = CodePointAt(a, i);
            var y = CodePointAt(b, j);
            if (x != y)
            {
                return x < y ? -1 : 1;
            }

            i += x > 0xffff ? 2 : 1;
            j += y > 0xffff ? 2 : 1;
        }

        return i < a.Length ? 1 : j < b.Length ? -1 : 0;
    }

    private static int CodePointAt(string s, int i) =>
        char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]) ? char.ConvertToUtf32(s[i], s[i + 1]) : s[i];

    private static string? Field(RuleNode n, RuleSubject s, RuleInput? input)
    {
        var r = s.Request;
        return n.Text switch
        {
            "request.method" => r?.Method,
            "request.path" => r?.Path,
            "request.route" => r?.Route,
            "request.ip" => r?.Ip,
            "request.headers" => Own(r?.Headers, n.Key!),
            "request.query" => Own(r?.Query, n.Key!),
            "request.body" => Own(r?.Body, n.Key!),
            "input.value" => input?.Value,
            "input.key" => input?.Key,
            "input.source" => input?.Source,
            "sink.name" => s.Sink,
            "attack.type" => s.AttackType,
            "attack.rule" => s.AttackRule,
            "app.name" => s.App,
            _ => null,
        };
    }

    private static bool StrictEquals(object? a, object? b) => a switch
    {
        null => b is null,
        string x => b is string y && string.Equals(x, y, StringComparison.Ordinal),
        bool x => b is bool y && x == y,
        _ => false,
    };

    private static bool Truthy(object? v) => v is true;

    private static object? Ev(RuleNode n, RuleSubject s, RuleInput? input, RuleBudget budget)
    {
        switch (n.Kind)
        {
            case RuleNodeKind.Str:
                return n.Text;
            case RuleNodeKind.Bool:
                return n.Flag;
            case RuleNodeKind.Null:
                return null;
            case RuleNodeKind.Field:
                return Field(n, s, input);
            case RuleNodeKind.Not:
                return !Truthy(Ev(n.X!, s, input, budget));
            case RuleNodeKind.And:
                foreach (var x in n.Xs!)
                {
                    if (!Truthy(Ev(x, s, input, budget)))
                    {
                        return false;
                    }
                }

                return true;
            case RuleNodeKind.Or:
                foreach (var x in n.Xs!)
                {
                    if (Truthy(Ev(x, s, input, budget)))
                    {
                        return true;
                    }
                }

                return false;
            case RuleNodeKind.Cmp:
            {
                var l = Ev(n.X!, s, input, budget);
                var r = Ev(n.Y!, s, input, budget);
                if (n.Text == "==")
                {
                    return StrictEquals(l, r);
                }

                if (n.Text == "!=")
                {
                    return !StrictEquals(l, r);
                }

                if (l is not string ls || r is not string rs)
                {
                    return false;
                }

                var c = CompareCodePoints(ls, rs);
                return n.Text switch
                {
                    "<" => c < 0,
                    "<=" => c <= 0,
                    ">" => c > 0,
                    _ => c >= 0,
                };
            }

            case RuleNodeKind.In:
                return Ev(n.X!, s, input, budget) is string v && n.Items!.Contains(v, StringComparer.Ordinal);
            case RuleNodeKind.StrMethod:
            {
                if (Ev(n.X!, s, input, budget) is not string t)
                {
                    return false;
                }

                return n.Text switch
                {
                    "startsWith" => t.StartsWith(n.Key!, StringComparison.Ordinal),
                    "endsWith" => t.EndsWith(n.Key!, StringComparison.Ordinal),
                    _ => t.IndexOf(n.Key!, StringComparison.Ordinal) >= 0,
                };
            }

            case RuleNodeKind.Lower:
                return Ev(n.X!, s, input, budget) is string lt ? AsciiLower(lt) : null;
            case RuleNodeKind.Matches:
                return Ev(n.X!, s, input, budget) is string mt && RunRegex(n.Prog!, CodePoints(mt, MatchCodePoints), budget);
            default:
                return Ev(n.X!, s, input, budget) is string ct && InCidr(ct, n.Net!);
        }
    }

    /// <summary>
    /// Evaluates a compiled expression. One that reads <c>input.*</c> is evaluated once per
    /// input, in order, and matches when any input makes it true (with no inputs, once with
    /// the input fields null). Never throws: an evaluation that runs out of budget, or fails
    /// in any way, is no match.
    /// </summary>
    public static RuleEvalResult Evaluate(CompiledRuleExpr expr, RuleSubject subject, RuleBudget? budget = null)
    {
        var b = budget ?? new RuleBudget();
        try
        {
            var inputs = expr.UsesInput ? subject.Inputs : null;
            if (inputs is null || inputs.Count == 0)
            {
                return new RuleEvalResult(Truthy(Ev(expr.Ast, subject, null, b)));
            }

            foreach (var input in inputs)
            {
                if (input is not null && Truthy(Ev(expr.Ast, subject, input, b)))
                {
                    return new RuleEvalResult(true, input);
                }
            }

            return new RuleEvalResult(false);
        }
        catch (BudgetExhaustedException)
        {
            return new RuleEvalResult(false, null, true);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return new RuleEvalResult(false);
        }
    }

    // ---- regular expressions ----------------------------------------------------

    private enum RKind
    {
        Char,
        Any,
        Class,
        Bol,
        Eol,
        Cat,
        Alt,
        Rep,
    }

    private sealed class RNode
    {
        public RNode(RKind t)
        {
            T = t;
        }

        public RKind T { get; }

        public int C { get; init; }

        public int[] R { get; init; } = Array.Empty<int>();

        public bool Neg { get; init; }

        public List<RNode> Xs { get; init; } = new();

        public RNode? X { get; init; }

        public int Min { get; init; }

        /// <summary>-1 = unbounded.</summary>
        public int Max { get; init; }
    }

    private const int MaxCodePoint = 0x10ffff;
    private static readonly int[] s_digit = { 0x30, 0x39 };
    private static readonly int[] s_word = { 0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a };
    private static readonly int[] s_space = { 0x09, 0x0d, 0x20, 0x20 };
    private const string Meta = "\\.^$|?*+()[]{}";
    private const string Escapable = "\\.^$|?*+()[]{}/-";

    private static int[] Complement(int[] r)
    {
        var sorted = new List<(int Lo, int Hi)>();
        for (var i = 0; i < r.Length; i += 2)
        {
            sorted.Add((r[i], r[i + 1]));
        }

        sorted.Sort((a, b) => a.Lo.CompareTo(b.Lo));
        var output = new List<int>();
        var next = 0;
        foreach (var (lo, hi) in sorted)
        {
            if (lo > next)
            {
                output.Add(next);
                output.Add(lo - 1);
            }

            next = Math.Max(next, hi + 1);
        }

        if (next <= MaxCodePoint)
        {
            output.Add(next);
            output.Add(MaxCodePoint);
        }

        return output.ToArray();
    }

    private sealed class RegexParser
    {
        private readonly int[] _cp;
        private int _i;

        public RegexParser(int[] cp)
        {
            _cp = cp;
        }

        private int Peek() => _i < _cp.Length ? _cp[_i] : -1;

        private int At(int i) => i < _cp.Length ? _cp[i] : -1;

        private bool Ch(char c) => _i < _cp.Length && _cp[_i] == c;

        public RNode Parse()
        {
            var n = Alt();
            if (_i < _cp.Length)
            {
                throw new RegexRefusedException();
            }

            return n;
        }

        private RNode Alt()
        {
            var xs = new List<RNode> { Cat() };
            while (Ch('|'))
            {
                _i++;
                xs.Add(Cat());
            }

            return xs.Count == 1 ? xs[0] : new RNode(RKind.Alt) { Xs = xs };
        }

        private RNode Cat()
        {
            var xs = new List<RNode>();
            while (_i < _cp.Length && !Ch('|') && !Ch(')'))
            {
                xs.Add(Piece());
            }

            return xs.Count == 1 ? xs[0] : new RNode(RKind.Cat) { Xs = xs };
        }

        private RNode Piece()
        {
            var atom = Atom();
            var q = Quant();
            if (q is null)
            {
                return atom;
            }

            if (atom.T is RKind.Bol or RKind.Eol || HasRep(atom) || AtomsOf(atom) == 0)
            {
                throw new RegexRefusedException(); // anchor, nested quantifier, or nothing to repeat
            }

            return new RNode(RKind.Rep) { X = atom, Min = q.Value.Min, Max = q.Value.Max };
        }

        private int? Num()
        {
            var digits = 0;
            var n = 0;
            while (Peek() >= 0x30 && Peek() <= 0x39)
            {
                n = (n * 10) + (Peek() - 0x30);
                _i++;
                if (++digits > 3)
                {
                    throw new RegexRefusedException();
                }
            }

            return digits > 0 ? n : null;
        }

        private (int Min, int Max)? Quant()
        {
            (int Min, int Max)? q = null;
            if (Ch('*'))
            {
                q = (0, -1);
            }
            else if (Ch('+'))
            {
                q = (1, -1);
            }
            else if (Ch('?'))
            {
                q = (0, 1);
            }

            if (q is not null)
            {
                _i++;
            }
            else if (Ch('{'))
            {
                _i++;
                var min = Num() ?? throw new RegexRefusedException();
                var max = min;
                if (Ch(','))
                {
                    _i++;
                    max = Num() ?? -1;
                }

                if (!Ch('}'))
                {
                    throw new RegexRefusedException();
                }

                _i++;
                if (min > RegexRepeat || max > RegexRepeat || (max != -1 && max < min))
                {
                    throw new RegexRefusedException();
                }

                q = (min, max);
            }
            else
            {
                return null;
            }

            if (Ch('?'))
            {
                _i++; // lazy: the same language, so the same answer
            }

            if (Ch('*') || Ch('+') || Ch('?') || Ch('{'))
            {
                throw new RegexRefusedException();
            }

            return q;
        }

        private RNode Escape()
        {
            _i++; // the backslash
            var c = Peek();
            if (c < 0)
            {
                throw new RegexRefusedException();
            }

            _i++;

            // Only ASCII has meaning after a backslash; a code point above U+FFFF must never alias one.
            var e = c < 0x80 ? (char)c : '\0';
            switch (e)
            {
                case 'd':
                case 'D':
                    return new RNode(RKind.Class) { R = (int[])s_digit.Clone(), Neg = e == 'D' };
                case 'w':
                case 'W':
                    return new RNode(RKind.Class) { R = (int[])s_word.Clone(), Neg = e == 'W' };
                case 's':
                case 'S':
                    return new RNode(RKind.Class) { R = (int[])s_space.Clone(), Neg = e == 'S' };
                case 'n':
                    return new RNode(RKind.Char) { C = 0x0a };
                case 'r':
                    return new RNode(RKind.Char) { C = 0x0d };
                case 't':
                    return new RNode(RKind.Char) { C = 0x09 };
                case 'f':
                    return new RNode(RKind.Char) { C = 0x0c };
                case 'v':
                    return new RNode(RKind.Char) { C = 0x0b };
                case 'x':
                case 'u':
                {
                    var n = e == 'x' ? 2 : 4;
                    if (_i + n > _cp.Length)
                    {
                        throw new RegexRefusedException();
                    }

                    var code = 0;
                    for (var k = 0; k < n; k++)
                    {
                        var d = _cp[_i + k];
                        if (d >= 0x80 || !IsHex((char)d))
                        {
                            throw new RegexRefusedException();
                        }

                        code = (code * 16) + Convert.ToInt32(((char)d).ToString(), 16);
                    }

                    if (code >= 0xd800 && code <= 0xdfff)
                    {
                        throw new RegexRefusedException();
                    }

                    _i += n;
                    return new RNode(RKind.Char) { C = code };
                }
            }

            if (e != '\0' && Escapable.IndexOf(e) >= 0)
            {
                return new RNode(RKind.Char) { C = c };
            }

            throw new RegexRefusedException();
        }

        private RNode Atom()
        {
            var c = Peek();

            // Operators are ASCII; any other code point (U+1002E included) is a literal.
            var s = c >= 0 && c < 0x80 ? (char)c : '\0';
            switch (s)
            {
                case '(':
                {
                    _i++;
                    if (Ch('?'))
                    {
                        _i++;
                        if (!Ch(':'))
                        {
                            throw new RegexRefusedException(); // lookaround, named groups, flags
                        }

                        _i++;
                    }

                    var inner = Alt();
                    if (!Ch(')'))
                    {
                        throw new RegexRefusedException();
                    }

                    _i++;
                    return inner;
                }

                case '[':
                    return Cls();
                case '.':
                    _i++;
                    return new RNode(RKind.Any);
                case '^':
                    _i++;
                    return new RNode(RKind.Bol);
                case '$':
                    _i++;
                    return new RNode(RKind.Eol);
                case '\\':
                    return Escape();
            }

            if (s != '\0' && Meta.IndexOf(s) >= 0)
            {
                throw new RegexRefusedException();
            }

            _i++;
            return new RNode(RKind.Char) { C = c };
        }

        private RNode ClsItem()
        {
            var c = Peek();
            if (c < 0)
            {
                throw new RegexRefusedException();
            }

            if (c == 0x5c)
            {
                return Escape();
            }

            if (c == 0x5b)
            {
                throw new RegexRefusedException(); // unescaped [ inside a class
            }

            _i++;
            return new RNode(RKind.Char) { C = c };
        }

        private RNode Cls()
        {
            _i++; // [
            var neg = false;
            if (Ch('^'))
            {
                neg = true;
                _i++;
            }

            var r = new List<int>();
            while (!Ch(']'))
            {
                if (_i >= _cp.Length)
                {
                    throw new RegexRefusedException();
                }

                var a = ClsItem();

                // `-` between two items is a range; at the start or right before `]` it is literal.
                if (Ch('-') && At(_i + 1) != -1 && At(_i + 1) != 0x5d)
                {
                    _i++; // -
                    var b = ClsItem();
                    if (a.T != RKind.Char || b.T != RKind.Char || a.C > b.C)
                    {
                        throw new RegexRefusedException();
                    }

                    r.Add(a.C);
                    r.Add(b.C);
                }
                else if (a.T == RKind.Char)
                {
                    r.Add(a.C);
                    r.Add(a.C);
                }
                else if (a.T == RKind.Class)
                {
                    r.AddRange(a.Neg ? Complement(a.R) : a.R);
                }
                else
                {
                    throw new RegexRefusedException();
                }
            }

            _i++; // ]
            if (r.Count == 0)
            {
                throw new RegexRefusedException();
            }

            return new RNode(RKind.Class) { R = r.ToArray(), Neg = neg };
        }
    }

    private static bool HasRep(RNode n) => n.T == RKind.Rep || (n.T is RKind.Cat or RKind.Alt && n.Xs.Any(HasRep));

    /// <summary>Atoms once counted repetitions are expanded (README "Regular expressions").</summary>
    private static int AtomsOf(RNode n) => n.T switch
    {
        RKind.Char or RKind.Any or RKind.Class => 1,
        RKind.Bol or RKind.Eol => 0,
        RKind.Cat or RKind.Alt => n.Xs.Sum(AtomsOf),

        // The copies the program holds: min, then one loop (unbounded) or max - min optional ones.
        _ => AtomsOf(n.X!) * (n.Max == -1 ? n.Min + 1 : n.Max),
    };

    private static void Emit(RNode n, List<RegexInst> prog)
    {
        switch (n.T)
        {
            case RKind.Char:
                prog.Add(new RegexInst(RegexOp.Char) { C = n.C });
                return;
            case RKind.Any:
                prog.Add(new RegexInst(RegexOp.Any));
                return;
            case RKind.Class:
                prog.Add(new RegexInst(RegexOp.Class) { R = n.R, Neg = n.Neg });
                return;
            case RKind.Bol:
                prog.Add(new RegexInst(RegexOp.Bol));
                return;
            case RKind.Eol:
                prog.Add(new RegexInst(RegexOp.Eol));
                return;
            case RKind.Cat:
                foreach (var x in n.Xs)
                {
                    Emit(x, prog);
                }

                return;
            case RKind.Alt:
            {
                // split L1, next; L1: x0; jmp end; next: split ... ; last
                var jumps = new List<RegexInst>();
                for (var k = 0; k < n.Xs.Count; k++)
                {
                    if (k < n.Xs.Count - 1)
                    {
                        var split = new RegexInst(RegexOp.Split) { X = prog.Count + 1, Y = -1 };
                        prog.Add(split);
                        Emit(n.Xs[k], prog);
                        var j = new RegexInst(RegexOp.Jmp) { X = -1 };
                        prog.Add(j);
                        jumps.Add(j);
                        split.Y = prog.Count;
                    }
                    else
                    {
                        Emit(n.Xs[k], prog);
                    }
                }

                foreach (var j in jumps)
                {
                    j.X = prog.Count;
                }

                return;
            }

            default:
            {
                for (var k = 0; k < n.Min; k++)
                {
                    Emit(n.X!, prog);
                }

                if (n.Max == -1)
                {
                    // L: split body, end; body; jmp L
                    var l = prog.Count;
                    var split = new RegexInst(RegexOp.Split) { X = l + 1, Y = -1 };
                    prog.Add(split);
                    Emit(n.X!, prog);
                    prog.Add(new RegexInst(RegexOp.Jmp) { X = l });
                    split.Y = prog.Count;
                }
                else
                {
                    for (var k = n.Min; k < n.Max; k++)
                    {
                        var split = new RegexInst(RegexOp.Split) { X = prog.Count + 1, Y = -1 };
                        prog.Add(split);
                        Emit(n.X!, prog);
                        split.Y = prog.Count;
                    }
                }

                return;
            }
        }
    }

    /// <summary>Checks a pattern against the safe subset and compiles it; null when refused.</summary>
    internal static RegexInst[]? CompileRegex(string pattern)
    {
        try
        {
            if (Utf8Length(pattern) > RegexBytes)
            {
                return null;
            }

            var ast = new RegexParser(CodePoints(pattern, int.MaxValue)).Parse();
            if (AtomsOf(ast) > RegexAtoms)
            {
                return null;
            }

            var prog = new List<RegexInst>();
            Emit(ast, prog);
            prog.Add(new RegexInst(RegexOp.Match));
            return prog.ToArray();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    /// <summary>Whether a pattern is in the safe subset.</summary>
    public static bool IsSafeRegex(string pattern) => CompileRegex(pattern) is not null;

    /// <summary>
    /// SHIELD: upload signatures — runs a compiled program over code points; an exhausted
    /// budget is left negative and the run is no match.
    /// </summary>
    internal static bool UploadRegexMatch(RegexInst[] prog, int[] subject, RuleBudget budget)
    {
        try
        {
            return RunRegex(prog, subject, budget);
        }
        catch (BudgetExhaustedException)
        {
            budget.Steps = -1;
            return false;
        }
    }

    private static bool ClassHas(int[] r, int c)
    {
        for (var k = 0; k < r.Length; k += 2)
        {
            if (c >= r[k] && c <= r[k + 1])
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Pike VM: every thread advances in lock step, one code point at a time, so the work is
    /// at most (subject length + 1) x (program size). True when some substring of the subject
    /// (respecting <c>^</c> and <c>$</c>) is in the pattern's language. Each instruction a
    /// thread visits costs one step of <paramref name="budget"/>.
    /// </summary>
    private static bool RunRegex(RegexInst[] prog, int[] subject, RuleBudget budget)
    {
        var size = prog.Length;
        var mark = new int[size];
        for (var k = 0; k < size; k++)
        {
            mark[k] = -1;
        }

        var gen = 0;
        var clist = new List<int>();
        var stack = new Stack<int>();
        var len = subject.Length;

        bool Add(List<int> list, int pc0, int pos)
        {
            stack.Clear();
            stack.Push(pc0);
            while (stack.Count > 0)
            {
                var pc = stack.Pop();
                if (mark[pc] == gen)
                {
                    continue;
                }

                mark[pc] = gen;
                if (--budget.Steps < 0)
                {
                    throw new BudgetExhaustedException();
                }

                var inst = prog[pc];
                switch (inst.Op)
                {
                    case RegexOp.Jmp:
                        stack.Push(inst.X);
                        break;
                    case RegexOp.Split:
                        stack.Push(inst.Y);
                        stack.Push(inst.X);
                        break;
                    case RegexOp.Bol:
                        if (pos == 0)
                        {
                            stack.Push(pc + 1);
                        }

                        break;
                    case RegexOp.Eol:
                        if (pos == len)
                        {
                            stack.Push(pc + 1);
                        }

                        break;
                    case RegexOp.Match:
                        return true;
                    default:
                        list.Add(pc);
                        break;
                }
            }

            return false;
        }

        for (var pos = 0; ; pos++)
        {
            // Threads already in clist were marked with this generation when added.
            if (Add(clist, 0, pos))
            {
                return true;
            }

            if (pos == len)
            {
                return false;
            }

            var c = subject[pos];
            gen++;
            var nlist = new List<int>();
            foreach (var pc in clist)
            {
                var inst = prog[pc];
                var ok = inst.Op == RegexOp.Any || (inst.Op == RegexOp.Char && inst.C == c) || (inst.Op == RegexOp.Class && ClassHas(inst.R, c) != inst.Neg);
                if (ok && Add(nlist, pc + 1, pos + 1))
                {
                    return true;
                }
            }

            clist = nlist;
        }
    }

    // ---- CIDR -------------------------------------------------------------------

    /// <summary><c>^(0|[1-9][0-9]{0,2})$</c>, ASCII digits only.</summary>
    private static bool IsDecimalPart(string p)
    {
        if (p.Length == 0 || p.Length > 3 || (p.Length > 1 && p[0] == '0'))
        {
            return false;
        }

        foreach (var c in p)
        {
            if (c < '0' || c > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static int[]? ParseV4(string s)
    {
        var parts = s.Split('.');
        if (parts.Length != 4)
        {
            return null;
        }

        var output = new int[4];
        for (var k = 0; k < 4; k++)
        {
            if (!IsDecimalPart(parts[k]))
            {
                return null;
            }

            var n = int.Parse(parts[k], System.Globalization.CultureInfo.InvariantCulture);
            if (n > 255)
            {
                return null;
            }

            output[k] = n;
        }

        return output;
    }

    private static readonly string[] s_doubleColon = { "::" };

    private static List<int>? Groups(string h)
    {
        var output = new List<int>();
        if (h.Length == 0)
        {
            return output;
        }

        var parts = h.Split(':');
        for (var k = 0; k < parts.Length; k++)
        {
            var p = parts[k];
            if (k == parts.Length - 1 && p.IndexOf('.') >= 0)
            {
                var t = ParseV4(p);
                if (t is null)
                {
                    return null;
                }

                output.Add((t[0] << 8) | t[1]);
                output.Add((t[2] << 8) | t[3]);
            }
            else
            {
                if (p.Length < 1 || p.Length > 4 || !p.All(IsHex))
                {
                    return null;
                }

                output.Add(Convert.ToInt32(p, 16));
            }
        }

        return output;
    }

    /// <summary>An IPv4 or IPv6 address as 16 bytes (IPv4 as <c>::ffff:a.b.c.d</c>); null when not an address.</summary>
    internal static byte[]? ParseIpBytes(string s)
    {
        if (s.Length > 64)
        {
            return null;
        }

        var v4 = ParseV4(s);
        if (v4 is not null)
        {
            return new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, (byte)v4[0], (byte)v4[1], (byte)v4[2], (byte)v4[3] };
        }

        if (s.IndexOf(':') < 0)
        {
            return null;
        }

        var halves = s.Split(s_doubleColon, StringSplitOptions.None);
        if (halves.Length > 2)
        {
            return null;
        }

        var head = Groups(halves[0]);
        var tail = halves.Length == 2 ? Groups(halves[1]) : new List<int>();
        if (head is null || tail is null)
        {
            return null;
        }

        if (halves.Length == 2 && halves[0].Length > 0 && halves[0].IndexOf('.') >= 0)
        {
            return null;
        }

        var words = new List<int>(8);
        if (halves.Length == 2)
        {
            if (head.Count + tail.Count > 7)
            {
                return null;
            }

            words.AddRange(head);
            words.AddRange(Enumerable.Repeat(0, 8 - head.Count - tail.Count));
            words.AddRange(tail);
        }
        else
        {
            if (head.Count != 8)
            {
                return null;
            }

            words = head;
        }

        var bytes = new byte[16];
        for (var k = 0; k < 8; k++)
        {
            bytes[2 * k] = (byte)(words[k] >> 8);
            bytes[(2 * k) + 1] = (byte)(words[k] & 0xff);
        }

        return bytes;
    }

    /// <summary><c>a.b.c.d/n</c>, <c>x:y::z/n</c>, or a bare address (all bits). Null when malformed.</summary>
    internal static RuleNet? ParseCidr(string s)
    {
        var slash = s.IndexOf('/');
        var addr = slash == -1 ? s : s.Substring(0, slash);
        if (addr.IndexOf('%') >= 0)
        {
            return null;
        }

        var bytes = ParseIpBytes(addr);
        if (bytes is null)
        {
            return null;
        }

        var v4 = ParseV4(addr) is not null;
        var prefix = 128;
        if (slash != -1)
        {
            var p = s.Substring(slash + 1);
            if (!IsDecimalPart(p))
            {
                return null;
            }

            var n = int.Parse(p, System.Globalization.CultureInfo.InvariantCulture);
            if (n > (v4 ? 32 : 128))
            {
                return null;
            }

            prefix = v4 ? n + 96 : n;
        }

        return new RuleNet(bytes, prefix);
    }

    internal static bool InCidr(string ip, RuleNet net)
    {
        var pct = ip.IndexOf('%');
        var bytes = ParseIpBytes(pct == -1 ? ip : ip.Substring(0, pct));
        if (bytes is null)
        {
            return false;
        }

        var bits = net.Prefix;
        for (var k = 0; k < 16 && bits > 0; k++, bits -= 8)
        {
            var mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
            if ((bytes[k] & mask) != (net.Bytes[k] & mask))
            {
                return false;
            }
        }

        return true;
    }
}
