using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Shield360.Rasp;

/// <summary>How a pair's region ends (sdk/rasp/README.md, "Template source", Engine table).</summary>
internal enum TemplateCloseMode
{
    /// <summary>At the first close, quoted or not.</summary>
    First,

    /// <summary>At the first close outside <c>"</c>/<c>'</c> strings.</summary>
    Quoted,

    /// <summary>At the bracket closing depth zero.</summary>
    Bracket,
}

/// <summary>One engine's syntax. Order inside each list matters: the first match wins.</summary>
internal sealed class TemplateSyntax
{
    public (string Open, string Close, TemplateCloseMode Mode)[] Pairs { get; init; } = Array.Empty<(string, string, TemplateCloseMode)>();

    /// <summary>Comments and raw/verbatim blocks: literal text to the close. A space matches any run of whitespace and <c>-</c>, <c>+</c>, <c>~</c>.</summary>
    public (string Open, string Close)[] Literal { get; init; } = Array.Empty<(string, string)>();

    /// <summary>Prefix + identifier start, ending at the first close outside quotes (<c>&lt;#if x&gt;</c>).</summary>
    public (string Prefix, string Close)[] Tags { get; init; } = Array.Empty<(string, string)>();

    /// <summary>Prefix + identifier (dots allowed), optionally followed by <c>(args)</c>; not after a word character.</summary>
    public string[] Directives { get; init; } = Array.Empty<string>();

    public string[] LineComment { get; init; } = Array.Empty<string>();

    public string[] LineCode { get; init; } = Array.Empty<string>();

    /// <summary>After whitespace: prefix + attribute name + <c>=</c> + quoted value; the value is a region.</summary>
    public string[] Attrs { get; init; } = Array.Empty<string>();

    /// <summary>An opener right after this character (itself not escaped) is literal; empty for none.</summary>
    public string Escape { get; init; } = string.Empty;

    /// <summary>A pair opener followed by whitespace is literal (Smarty auto_literal).</summary>
    public bool SpaceLiteral { get; init; }

    /// <summary>Pug line code, buffered expressions and tag attributes.</summary>
    public bool Pug { get; init; }
}

/// <summary>
/// The structural template-source check (<c>code.template_injection</c>), ported from
/// sdk/typescript/src/rasp/template.ts. Data arguments are never inspected.
/// </summary>
internal static class RaspTemplate
{
    private const TemplateCloseMode First = TemplateCloseMode.First;
    private const TemplateCloseMode Quoted = TemplateCloseMode.Quoted;
    private const TemplateCloseMode Bracket = TemplateCloseMode.Bracket;

    private static readonly (string, string, TemplateCloseMode)[] s_jinja = { ("{{", "}}", Quoted), ("{%", "%}", Quoted) };

    // The contract table sdk/rasp/rules/template-engines.json, in its order (a test compares).
    public static readonly IReadOnlyList<(string Name, TemplateSyntax Syntax)> Engines = new (string, TemplateSyntax)[]
    {
        ("handlebars", new TemplateSyntax { Pairs = new[] { ("{{{", "}}}", Quoted), ("{{", "}}", Quoted) }, Literal = new[] { ("{{!--", "--}}"), ("{{!", "}}") }, Escape = "\\" }),
        ("ejs", new TemplateSyntax { Pairs = new[] { ("<%", "%>", First) }, Literal = new[] { ("<%#", "%>") } }),
        ("lodash", new TemplateSyntax { Pairs = new[] { ("<%", "%>", First), ("${", "}", First) }, Literal = new[] { ("<%#", "%>") } }),
        ("pug", new TemplateSyntax { Pairs = new[] { ("#{", "}", Bracket), ("!{", "}", Bracket) }, Pug = true }),
        ("nunjucks", new TemplateSyntax { Pairs = s_jinja, Literal = new[] { ("{#", "#}"), ("{% raw %}", "{% endraw %}") } }),
        ("jinja2", new TemplateSyntax { Pairs = s_jinja, Literal = new[] { ("{#", "#}"), ("{% raw %}", "{% endraw %}") } }),
        ("minijinja", new TemplateSyntax { Pairs = s_jinja, Literal = new[] { ("{#", "#}"), ("{% raw %}", "{% endraw %}") } }),
        ("tera", new TemplateSyntax { Pairs = s_jinja, Literal = new[] { ("{#", "#}"), ("{% raw %}", "{% endraw %}") } }),
        ("twig", new TemplateSyntax { Pairs = s_jinja, Literal = new[] { ("{#", "#}"), ("{% verbatim %}", "{% endverbatim %}") } }),
        ("pebble", new TemplateSyntax { Pairs = s_jinja, Literal = new[] { ("{#", "#}"), ("{% verbatim %}", "{% endverbatim %}") } }),
        ("django", new TemplateSyntax
        {
            Pairs = new[] { ("{{", "}}", First), ("{%", "%}", First) },
            Literal = new[] { ("{#", "#}"), ("{% comment %}", "{% endcomment %}"), ("{% verbatim %}", "{% endverbatim %}") },
        }),
        ("liquid", new TemplateSyntax { Pairs = s_jinja, Literal = new[] { ("{% comment %}", "{% endcomment %}"), ("{% raw %}", "{% endraw %}") } }),
        ("scriban", new TemplateSyntax { Pairs = new[] { ("{{", "}}", Quoted) }, Literal = new[] { ("{%{", "}%}") } }),
        ("gotemplate", new TemplateSyntax { Pairs = new[] { ("{{", "}}", Quoted) }, Literal = new[] { ("{{/*", "*/"), ("{{- /*", "*/") } }),
        ("mako", new TemplateSyntax
        {
            Pairs = new[] { ("${", "}", Bracket), ("<%", "%>", First) },
            Literal = new[] { ("<%doc>", "</%doc>"), ("<%text>", "</%text>") },
            Tags = new[] { ("<%", ">"), ("</%", ">") },
            LineComment = new[] { "##" },
            LineCode = new[] { "%" },
        }),
        ("freemarker", new TemplateSyntax
        {
            Pairs = new[] { ("${", "}", Bracket), ("#{", "}", Bracket) },
            Literal = new[] { ("<#--", "-->"), ("<#noparse>", "</#noparse>") },
            Tags = new[] { ("<#", ">"), ("</#", ">"), ("<@", ">"), ("</@", ">") },
        }),
        ("velocity", new TemplateSyntax
        {
            Pairs = new[] { ("$!{", "}", Bracket), ("${", "}", Bracket) },
            Literal = new[] { ("#*", "*#"), ("##", "\n"), ("#[[", "]]#") },
            Directives = new[] { "$!", "$", "#" },
            Escape = "\\",
        }),
        ("thymeleaf", new TemplateSyntax
        {
            Pairs = new[] { ("[[", "]]", Quoted), ("[(", ")]", Quoted) },
            Literal = new[] { ("<!--/*", "*/-->") },
            Attrs = new[] { "th:", "data-th-" },
        }),
        ("smarty", new TemplateSyntax { Pairs = new[] { ("{", "}", Quoted) }, Literal = new[] { ("{*", "*}"), ("{literal}", "{/literal}") }, SpaceLiteral = true }),
        ("blade", new TemplateSyntax
        {
            Pairs = new[] { ("{!!", "!!}", First), ("{{", "}}", First), ("@php", "@endphp", First) },
            Literal = new[] { ("{{--", "--}}"), ("@verbatim", "@endverbatim") },
            Directives = new[] { "@" },
            Escape = "@",
        }),
    };

    private static readonly Dictionary<string, TemplateSyntax> s_byName = BuildIndex();

    // Pug line regexes with ASCII \w and \s (the contract's semantics).
    private static readonly Regex s_pugMarker = new(@"^[ \t\n\r\f\v]*(?:-[ \t\n\r\f\v]*|(?:[A-Za-z0-9_.#-]+[ \t\n\r\f\v]*)?!?=[ \t\n\r\f\v]*)", RegexOptions.CultureInvariant);
    private static readonly Regex s_pugTag = new(@"^[ \t\n\r\f\v]*\+?[A-Za-z0-9_.#:-]+", RegexOptions.CultureInvariant);
    private static readonly Regex s_pugRest = new(@"^!?=[ \t\n\r\f\v]*", RegexOptions.CultureInvariant);

    private static Dictionary<string, TemplateSyntax> BuildIndex()
    {
        var map = new Dictionary<string, TemplateSyntax>(StringComparer.Ordinal);
        foreach (var (name, syntax) in Engines)
        {
            map[name] = syntax;
        }

        return map;
    }

    /// <summary>Whether <paramref name="engine"/> is in the shared table.</summary>
    public static bool Knows(string? engine) => engine is not null && s_byName.ContainsKey(engine);

    private static char At(string s, int i) => i >= 0 && i < s.Length ? s[i] : '\0';

    private static bool StartsAt(string s, string p, int i) =>
        i >= 0 && i + p.Length <= s.Length && string.CompareOrdinal(s, i, p, 0, p.Length) == 0;

    private static bool IsSpace(char c) => c is ' ' or '\t' or '\n' or '\r' or '\f' or '\v';

    private static bool IsIdStart(char c) => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or '_';

    private static bool IsWord(char c) => IsIdStart(c) || c is >= '0' and <= '9';

    private static bool IsAttrChar(char c) => IsWord(c) || c is ':' or '-';

    /// <summary>Index just past a quoted run starting at <paramref name="i"/> (source[i] is the quote).</summary>
    private static int SkipQuoted(string source, int i)
    {
        var quote = source[i];
        var k = i + 1;
        while (k < source.Length && source[k] != quote)
        {
            k += source[k] == '\\' ? 2 : 1;
        }

        return Math.Min(source.Length, k + 1);
    }

    /// <summary>First <paramref name="close"/> outside quoted strings.</summary>
    private static int QuotedClose(string source, int from, string close)
    {
        for (var i = from; i < source.Length;)
        {
            var c = source[i];
            if (c is '"' or '\'')
            {
                i = SkipQuoted(source, i);
                continue;
            }

            if (StartsAt(source, close, i))
            {
                return i;
            }

            i++;
        }

        return -1;
    }

    /// <summary>The bracket closing depth zero, skipping quoted strings and nested brackets.</summary>
    private static int BracketClose(string source, int from)
    {
        var depth = 0;
        for (var i = from; i < source.Length;)
        {
            var c = source[i];
            if (c is '"' or '\'' or '`')
            {
                i = SkipQuoted(source, i);
                continue;
            }

            if (c is '(' or '[' or '{')
            {
                depth++;
            }
            else if (c is ')' or ']' or '}')
            {
                if (depth == 0)
                {
                    return i;
                }

                depth--;
            }

            i++;
        }

        return -1;
    }

    /// <summary>End of literal-block <paramref name="pattern"/> matched at <paramref name="i"/>, or -1; a space matches any run of whitespace, <c>-</c>, <c>+</c> and <c>~</c>.</summary>
    private static int LiteralAt(string source, int i, string pattern)
    {
        var k = i;
        foreach (var c in pattern)
        {
            if (c == ' ')
            {
                while (k < source.Length && (IsSpace(source[k]) || source[k] is '-' or '+' or '~'))
                {
                    k++;
                }
            }
            else if (At(source, k) == c && k < source.Length)
            {
                k++;
            }
            else
            {
                return -1;
            }
        }

        return k;
    }

    /// <summary>Code tokens of a region body. Template expressions have no <c>//</c> or <c>/*</c> comments: both are operators.</summary>
    private static List<RaspToken> RegionCode(string body)
    {
        var output = new List<RaspToken>();
        for (var pos = 0; pos < body.Length;)
        {
            var resume = -1;
            foreach (var t in RaspLexers.CodeTokens(body.Substring(pos)))
            {
                var start = pos + t.S;
                if (t.Kind == "comment")
                {
                    output.Add(new RaspToken(start, start + 1, "op", "/", output.Count));
                    output.Add(new RaspToken(start + 1, start + 2, "op", body.Substring(start + 1, 1), output.Count));
                    resume = start + 2;
                    break;
                }

                output.Add(t with { S = start, E = pos + t.E, Index = output.Count });
            }

            if (resume < 0)
            {
                break;
            }

            pos = resume;
        }

        return output;
    }

    /// <summary>A dotted property path (<c>user.name</c>) is one reference, like a single variable name.</summary>
    private static List<RaspToken> MergePaths(List<RaspToken> tokens)
    {
        var output = new List<RaspToken>(tokens.Count);
        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            while (token.Kind == "word" && i + 2 < tokens.Count
                && tokens[i + 1].Text == "." && tokens[i + 1].S == token.E
                && tokens[i + 2].Kind == "word" && tokens[i + 2].S == tokens[i + 1].E)
            {
                token = token with { E = tokens[i + 2].E, Text = token.Text + "." + tokens[i + 2].Text };
                i += 2;
            }

            output.Add(token);
        }

        return output;
    }

    /// <summary>Template tokens: boundary delimiters plus code tokens of each expression region; literal text yields nothing.</summary>
    public static List<RaspToken> Tokens(string source, string engine)
    {
        var s = s_byName[engine];
        var tokens = new List<RaspToken>();
        void Push(int start, int end, string kind, string text) => tokens.Add(new RaspToken(start, end, kind, text, tokens.Count));
        void Region(int start, int open, int end, int close)
        {
            Push(start, start + open, "delimiter", string.Empty);
            var offset = start + open;
            foreach (var t in MergePaths(RegionCode(source.Substring(offset, end - offset))))
            {
                Push(t.S + offset, t.E + offset, t.Kind, t.Text);
            }

            if (close > 0)
            {
                Push(end, end + close, "delimiter", string.Empty);
            }
        }

        int LineEndAt(int i)
        {
            var end = source.IndexOf('\n', i);
            return end < 0 ? source.Length : end;
        }

        var n = source.Length;
        for (var i = 0; i < n;)
        {
            var lineStart = i == 0 || source[i - 1] == '\n';
            if (s.Pug && lineStart)
            {
                var lineEnd = LineEndAt(i);
                var line = source.Substring(i, lineEnd - i);

                // Pug's line code and buffered expressions; ordinary tag/text lines stay literal.
                var marker = s_pugMarker.Match(line);
                if (marker.Success)
                {
                    Region(i, marker.Length, lineEnd, 0);
                    i = lineEnd;
                    continue;
                }

                // Tag or mixin attributes are JavaScript expressions: `a(href=url)`, `+card(item)`.
                var tag = s_pugTag.Match(line);
                if (tag.Success && At(source, i + tag.Length) == '(')
                {
                    var open = i + tag.Length;
                    var close = BracketClose(source, open + 1);
                    if (close >= 0)
                    {
                        Region(open, 1, close, 1);
                        i = close + 1;
                        var restEnd = i < n ? LineEndAt(i) : n;
                        var rest = s_pugRest.Match(source.Substring(i, restEnd - i));
                        if (rest.Success)
                        {
                            Region(i, rest.Length, restEnd, 0);
                            i = restEnd;
                        }

                        continue;
                    }
                }
            }

            if (lineStart && (s.LineComment.Length > 0 || s.LineCode.Length > 0))
            {
                var j = i;
                while (At(source, j) is ' ' or '\t')
                {
                    j++;
                }

                var lineEnd = LineEndAt(i);
                if (Array.Exists(s.LineComment, p => StartsAt(source, p, j)))
                {
                    i = lineEnd;
                    continue;
                }

                var coded = false;
                foreach (var p in s.LineCode)
                {
                    if (StartsAt(source, p, j) && !StartsAt(source, p, j + p.Length))
                    {
                        Region(i, j + p.Length - i, lineEnd, 0);
                        i = lineEnd;
                        coded = true;
                        break;
                    }
                }

                if (coded)
                {
                    continue;
                }
            }

            // First match wins: literal blocks, tags, attributes, pairs, directives.
            string? opener = null;
            int kind = 0; // 1 literal, 2 tag, 3 attr, 4 pair, 5 directive
            string close2 = string.Empty;
            var mode = First;
            var quote = -1;
            var literalEnd = -1;
            foreach (var (open, close) in s.Literal)
            {
                literalEnd = LiteralAt(source, i, open);
                if (literalEnd >= 0)
                {
                    (opener, kind, close2) = (open, 1, close);
                    break;
                }
            }

            if (opener is null)
            {
                foreach (var (prefix, close) in s.Tags)
                {
                    if (StartsAt(source, prefix, i) && IsIdStart(At(source, i + prefix.Length)))
                    {
                        (opener, kind, close2) = (prefix, 2, close);
                        break;
                    }
                }
            }

            if (opener is null && (i == 0 || IsSpace(source[i - 1])))
            {
                foreach (var p in s.Attrs)
                {
                    if (!StartsAt(source, p, i))
                    {
                        continue;
                    }

                    var k = i + p.Length;
                    while (IsAttrChar(At(source, k)))
                    {
                        k++;
                    }

                    if (k == i + p.Length)
                    {
                        continue;
                    }

                    while (IsSpace(At(source, k)))
                    {
                        k++;
                    }

                    if (At(source, k) != '=')
                    {
                        continue;
                    }

                    k++;
                    while (IsSpace(At(source, k)))
                    {
                        k++;
                    }

                    if (At(source, k) is '"' or '\'')
                    {
                        (opener, kind, quote) = (p, 3, k);
                        break;
                    }
                }
            }

            if (opener is null)
            {
                foreach (var (open, close, m) in s.Pairs)
                {
                    if (StartsAt(source, open, i))
                    {
                        (opener, kind, close2, mode) = (open, 4, close, m);
                        break;
                    }
                }
            }

            if (opener is null)
            {
                foreach (var p in s.Directives)
                {
                    if (StartsAt(source, p, i) && IsIdStart(At(source, i + p.Length)) && !IsWord(At(source, i - 1)))
                    {
                        (opener, kind) = (p, 5);
                        break;
                    }
                }
            }

            if (opener is null)
            {
                i++;
                continue;
            }

            var from = kind == 1 ? literalEnd : i + opener.Length;

            // An escaped opener (`\{{`, `@{{`) is literal; a doubled escape (`\\{{`) leaves it live.
            if (s.Escape.Length > 0 && At(source, i - 1) == s.Escape[0] && At(source, i - 2) != s.Escape[0])
            {
                i = from;
                continue;
            }

            switch (kind)
            {
                case 1:
                {
                    i = n;
                    for (var j = from; j < n; j++)
                    {
                        var end = LiteralAt(source, j, close2);
                        if (end >= 0)
                        {
                            i = end;
                            break;
                        }
                    }

                    continue;
                }

                case 2:
                {
                    var end = QuotedClose(source, from, close2);
                    if (end < 0)
                    {
                        i = from;
                        continue;
                    }

                    Region(i, opener.Length, end, close2.Length);
                    i = end + close2.Length;
                    continue;
                }

                case 3:
                {
                    var end = source.IndexOf(source[quote], quote + 1);
                    if (end < 0)
                    {
                        i = from;
                        continue;
                    }

                    Region(quote, 1, end, 1);
                    i = end + 1;
                    continue;
                }

                case 5:
                {
                    Push(i, from, "delimiter", string.Empty);
                    var k = from;
                    while (IsWord(At(source, k)) || At(source, k) == '.')
                    {
                        k++;
                    }

                    while (At(source, k - 1) == '.')
                    {
                        k--;
                    }

                    Push(from, k, "word", source.Substring(from, k - from));
                    i = k;
                    if (At(source, k) == '(')
                    {
                        var close = BracketClose(source, k + 1);
                        if (close >= 0)
                        {
                            Region(k, 1, close, 1);
                            i = close + 1;
                        }
                    }

                    continue;
                }
            }

            // A pair.
            if (s.SpaceLiteral && IsSpace(At(source, from)))
            {
                i = from;
                continue;
            }

            // Closing delimiters inside quotes end an expression only where the engine itself ignores quotes.
            var pairEnd = mode switch
            {
                TemplateCloseMode.Bracket => BracketClose(source, from),
                TemplateCloseMode.Quoted => QuotedClose(source, from, close2),
                _ => source.IndexOf(close2, from, StringComparison.Ordinal),
            };
            if (pairEnd < 0)
            {
                i = from;
                continue;
            }

            Region(i, opener.Length, pairEnd, close2.Length);
            i = pairEnd + close2.Length;
        }

        return tokens;
    }

    /// <summary>Input must introduce a template boundary or span multiple expression tokens. An unknown engine is not checked.</summary>
    public static RaspFinding? Detect(string? source, IReadOnlyList<RaspInput> inputs, string? engine)
    {
        if (string.IsNullOrEmpty(source) || !Knows(engine))
        {
            return null;
        }

        List<RaspToken>? tokens = null;
        foreach (var input in inputs)
        {
            if (input.Value.Length < 3)
            {
                continue;
            }

            foreach (var idx in RaspLexers.Occurrences(source!, input.Value))
            {
                tokens ??= Tokens(source!, engine!);
                var span = RaspLexers.Overlapping(tokens, idx, input.Value.Length);
                if (span.Count >= 2 || span.Exists(t => t.Kind == "delimiter"))
                {
                    return new RaspFinding(RaspAttackType.CodeInjection, "code.template_injection", input);
                }
            }
        }

        return null;
    }
}
