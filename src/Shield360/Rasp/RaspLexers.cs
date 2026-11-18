using System.Collections.Generic;
using static Shield360.Rasp.JsText;

namespace Shield360.Rasp;

/// <summary>A lexer token: <c>[S, E)</c> in the source, its kind and text. <see cref="Index"/> is its position in the token list.</summary>
internal readonly record struct RaspToken(int S, int E, string Kind, string Text, int Index);

/// <summary>The SQL dialects the lexer knows (chosen from the driver).</summary>
internal enum SqlDialect
{
    Generic,
    MySql,
    Postgres,
    Sqlite,
    MsSql,
    Oracle,
    Db2,
}

/// <summary>
/// One-pass lexers used by the structural checks: SQL, shell and a generic
/// C-like lexer for code. No regex backtracking; every loop advances.
/// Port of the TypeScript <c>lexers.ts</c>.
/// </summary>
internal static class RaspLexers
{
    private static readonly string[] s_sqlOps = { "->>", "<=", ">=", "<>", "!=", "||", "&&", "::", ":=", "->", "<<", ">>" };
    private static readonly string[] s_shellOps = { "&&", "||", ">>", "<<", "$(", ";", "&", "|", ">", "<", "(", ")", "`", "\n" };

    public static SqlDialect Dialect(string? name) => name switch
    {
        "mysql" => SqlDialect.MySql,
        "postgres" => SqlDialect.Postgres,
        "sqlite" => SqlDialect.Sqlite,
        "mssql" => SqlDialect.MsSql,
        "oracle" => SqlDialect.Oracle,
        "db2" => SqlDialect.Db2,
        _ => SqlDialect.Generic,
    };

    /// <summary>The contract's name of a dialect (<c>shield360.rasp.sql.dialect</c>).</summary>
    public static string DialectName(SqlDialect d) => d switch
    {
        SqlDialect.MySql => "mysql",
        SqlDialect.Postgres => "postgres",
        SqlDialect.Sqlite => "sqlite",
        SqlDialect.MsSql => "mssql",
        SqlDialect.Oracle => "oracle",
        SqlDialect.Db2 => "db2",
        _ => "generic",
    };

    private static bool IsSpace(char c) => c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';

    private static bool IsDigit(char c) => c >= '0' && c <= '9';

    private static bool IsIdStart(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';

    private static bool IsIdChar(char c) => IsIdStart(c) || IsDigit(c) || c == '$';

    private static bool IsX(char c) => c == 'X' || c == 'x';

    private static bool IsHex(char c) => IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

    /// <summary>Tokenizes SQL per the contract's lexer.</summary>
    public static List<RaspToken> SqlTokens(string q, SqlDialect dialect = SqlDialect.Generic)
    {
        var output = new List<RaspToken>();
        var n = q.Length;
        var hashComment = dialect == SqlDialect.MySql || dialect == SqlDialect.Generic;
        var bracketIdent = dialect == SqlDialect.MsSql || dialect == SqlDialect.Generic;
        var dollarQuote = dialect == SqlDialect.Postgres || dialect == SqlDialect.Generic;
        var oracle = dialect == SqlDialect.Oracle;
        var db2 = dialect == SqlDialect.Db2;

        // E'' (backslash escapes) is not a prefix in Oracle or DB2.
        var ePrefix = !oracle && !db2;

        // Oracle and DB2 identifiers may contain '#' after the first character.
        var hashIdent = oracle || db2;
        var i = 0;
        bool IdChar(char c) => IsIdChar(c) || (hashIdent && c == '#');
        void Push(int s, int e, string kind) => output.Add(new RaspToken(s, e, kind, q.Substring(s, e - s), output.Count));

        // Reads a quoted run starting at start (q[start] is the quote); returns the end index.
        int Quoted(int start, char close, bool backslash)
        {
            var j = start + 1;
            while (j < n)
            {
                var c = q[j];
                if (backslash && c == '\\')
                {
                    j += 2;
                    continue;
                }

                if (c == close)
                {
                    if (At(q, j + 1) == close)
                    {
                        j += 2;
                        continue;
                    }

                    return j + 1;
                }

                j++;
            }

            return n;
        }

        // A name part: identifier or quoted identifier; returns its end or -1.
        int NamePart(int j)
        {
            var c = At(q, j);
            if (IsIdStart(c))
            {
                var k = j + 1;
                while (k < n && IdChar(q[k]))
                {
                    k++;
                }

                return k;
            }

            if (c == '"' || c == '`')
            {
                return Quoted(j, c, false);
            }

            if (c == '[' && bracketIdent)
            {
                return Quoted(j, ']', false);
            }

            return -1;
        }

        // Oracle alternative quoting q'X…X' (also nq'…'), the quote at j; returns its end or -1.
        // The delimiter X is one character (a surrogate pair counts as one) other than whitespace.
        int AltQuoted(int j)
        {
            if (j + 1 >= n || IsSpace(q[j + 1]))
            {
                return -1;
            }

            var width = char.IsHighSurrogate(q[j + 1]) && char.IsLowSurrogate(At(q, j + 2)) ? 2 : 1;
            var open = q.Substring(j + 1, width);
            var close = open switch
            {
                "[" => "]",
                "{" => "}",
                "(" => ")",
                "<" => ">",
                _ => open,
            };
            var k = IndexOf(q, close + "'", j + 1 + width);
            return k < 0 ? n : k + close.Length + 1;
        }

        // A block comment starting at i; nests in db2, postgres and mssql.
        var nestedComments = dialect == SqlDialect.Db2 || dialect == SqlDialect.Postgres || dialect == SqlDialect.MsSql;
        int BlockComment(int i)
        {
            if (!nestedComments)
            {
                var e = IndexOf(q, "*/", i + 2);
                return e < 0 ? n : e + 2;
            }

            var depth = 1;
            var k = i + 2;
            while (k < n)
            {
                if (q[k] == '/' && At(q, k + 1) == '*')
                {
                    depth++;
                    k += 2;
                }
                else if (q[k] == '*' && At(q, k + 1) == '/')
                {
                    k += 2;
                    if (--depth == 0)
                    {
                        return k;
                    }
                }
                else
                {
                    k++;
                }
            }

            return n;
        }

        while (i < n)
        {
            var c = q[i];
            if (IsSpace(c))
            {
                i++;
                continue;
            }

            var start = i;

            // comments
            if (c == '-' && At(q, i + 1) == '-')
            {
                var k = IndexOf(q, '\n', i);
                i = k < 0 ? n : k;
                Push(start, i, "comment");
                continue;
            }

            if (c == '#' && hashComment)
            {
                var k = IndexOf(q, '\n', i);
                i = k < 0 ? n : k;
                Push(start, i, "comment");
                continue;
            }

            if (c == '/' && At(q, i + 1) == '*')
            {
                i = BlockComment(i);
                Push(start, i, At(q, start + 2) == '!' ? "version_comment" : "comment");
                continue;
            }

            // strings, with E'' / N'' prefixes
            if (c == '\'')
            {
                i = Quoted(i, '\'', dialect == SqlDialect.MySql);
                Push(start, i, "string");
                continue;
            }

            if (oracle)
            {
                // q'…' / nq'…' alternative quoting
                var p = c == 'N' || c == 'n' ? i + 1 : i;
                if ((At(q, p) == 'q' || At(q, p) == 'Q') && At(q, p + 1) == '\'')
                {
                    var k = AltQuoted(p + 1);
                    if (k > 0)
                    {
                        i = k;
                        Push(start, i, "string");
                        continue;
                    }
                }
            }

            if (db2)
            {
                // X'' hex, G'' graphic, GX'' / UX'' / BX'' hex strings
                var g = c == 'G' || c == 'g';
                var p = (g || c == 'U' || c == 'u' || c == 'B' || c == 'b') && IsX(At(q, i + 1)) ? i + 1 : i;
                if ((p > i || g || IsX(c)) && At(q, p + 1) == '\'')
                {
                    i = Quoted(p + 1, '\'', false);
                    Push(start, i, "string");
                    continue;
                }
            }

            if ((((c == 'E' || c == 'e') && ePrefix) || c == 'N' || c == 'n') && At(q, i + 1) == '\'')
            {
                i = Quoted(i + 1, '\'', dialect == SqlDialect.MySql || c == 'E' || c == 'e');
                Push(start, i, "string");
                continue;
            }

            // dollar quotes and $n placeholders
            if (c == '$')
            {
                if (IsDigit(At(q, i + 1)))
                {
                    var k = i + 1;
                    while (k < n && IsDigit(q[k]))
                    {
                        k++;
                    }

                    i = k;
                    Push(start, i, "placeholder");
                    continue;
                }

                if (dollarQuote)
                {
                    var k = i + 1;
                    while (k < n && (IsIdStart(q[k]) || IsDigit(q[k])))
                    {
                        k++;
                    }

                    if (At(q, k) == '$')
                    {
                        var tag = q.Substring(i, k + 1 - i);
                        var end = IndexOf(q, tag, k + 1);
                        i = end < 0 ? n : end + tag.Length;
                        Push(start, i, "string");
                        continue;
                    }
                }
            }

            // placeholders
            if (c == '?')
            {
                i++;
                Push(start, i, "placeholder");
                continue;
            }

            if ((c == ':' || c == '@') && IsIdStart(At(q, i + 1)) && !(c == ':' && At(q, i - 1) == ':'))
            {
                var k = i + 1;
                while (k < n && IdChar(q[k]))
                {
                    k++;
                }

                i = k;
                Push(start, i, "placeholder");
                continue;
            }

            if (oracle && c == ':' && IsDigit(At(q, i + 1)) && At(q, i - 1) != ':')
            {
                // Oracle positional bind :1
                var k = i + 1;
                while (k < n && IsDigit(q[k]))
                {
                    k++;
                }

                i = k;
                Push(start, i, "placeholder");
                continue;
            }

            if (c == '@' && At(q, i + 1) == '@' && IsIdStart(At(q, i + 2)))
            {
                var k = i + 2;
                while (k < n && IsIdChar(q[k]))
                {
                    k++;
                }

                i = k;
                Push(start, i, "word");
                continue;
            }

            if (c == '%' && At(q, i + 1) == 's')
            {
                i += 2;
                Push(start, i, "placeholder");
                continue;
            }

            if (c == '%' && At(q, i + 1) == '(')
            {
                var k = IndexOf(q, ')', i + 2);
                if (k > 0 && At(q, k + 1) == 's')
                {
                    i = k + 2;
                    Push(start, i, "placeholder");
                    continue;
                }
            }

            // numbers
            if (IsDigit(c) || (c == '.' && IsDigit(At(q, i + 1))))
            {
                var k = i;
                if (c == '0' && (At(q, i + 1) == 'x' || At(q, i + 1) == 'X'))
                {
                    k = i + 2;
                    while (k < n && IsHex(q[k]))
                    {
                        k++;
                    }
                }
                else
                {
                    while (k < n && IsDigit(q[k]))
                    {
                        k++;
                    }

                    if (At(q, k) == '.')
                    {
                        k++;
                        while (k < n && IsDigit(q[k]))
                        {
                            k++;
                        }
                    }

                    if ((At(q, k) == 'e' || At(q, k) == 'E') &&
                        (IsDigit(At(q, k + 1)) || ((At(q, k + 1) == '+' || At(q, k + 1) == '-') && IsDigit(At(q, k + 2)))))
                    {
                        k += 2;
                        while (k < n && IsDigit(q[k]))
                        {
                            k++;
                        }
                    }
                }

                i = k;
                Push(start, i, "number");
                continue;
            }

            // identifiers and qualified names (one token)
            var first = NamePart(i);
            if (first > 0)
            {
                var k = first;
                while (At(q, k) == '.')
                {
                    var next = NamePart(k + 1);
                    if (next < 0)
                    {
                        break;
                    }

                    k = next;
                }

                i = k;
                Push(start, i, IsIdStart(c) && k == first ? "word" : "name");
                continue;
            }

            // operators
            string? op = null;
            foreach (var o in s_sqlOps)
            {
                if (StartsAt(q, o, i))
                {
                    op = o;
                    break;
                }
            }

            i += op?.Length ?? 1;
            Push(start, i, "op");
        }

        return output;
    }

    /// <summary>Shell tokens; <c>InSingle[i]</c> marks characters inside single quotes.</summary>
    public static (List<RaspToken> Tokens, bool[] InSingle) ShellTokens(string cmd)
    {
        var output = new List<RaspToken>();
        var inSingle = new bool[cmd.Length];
        var n = cmd.Length;
        var i = 0;
        var wordStart = -1;
        var dq = false;
        void EndWord(int e)
        {
            if (wordStart >= 0 && e > wordStart)
            {
                output.Add(new RaspToken(wordStart, e, "word", cmd.Substring(wordStart, e - wordStart), output.Count));
            }

            wordStart = -1;
        }

        void PushOp(int s, int len) => output.Add(new RaspToken(s, s + len, "op", cmd.Substring(s, len), output.Count));

        while (i < n)
        {
            var c = cmd[i];
            if (!dq)
            {
                if (c == ' ' || c == '\t')
                {
                    EndWord(i);
                    i++;
                    continue;
                }

                string? op = null;
                foreach (var o in s_shellOps)
                {
                    if (StartsAt(cmd, o, i))
                    {
                        op = o;
                        break;
                    }
                }

                if (op is not null)
                {
                    EndWord(i);
                    PushOp(i, op.Length);
                    i += op.Length;
                    continue;
                }

                if (wordStart < 0)
                {
                    wordStart = i;
                }

                if (c == '\\')
                {
                    i += 2;
                    continue;
                }

                if (c == '\'')
                {
                    var k = IndexOf(cmd, '\'', i + 1);
                    var end = k < 0 ? n : k + 1;
                    for (var x = i; x < end; x++)
                    {
                        inSingle[x] = true;
                    }

                    i = end;
                    continue;
                }

                if (c == '"')
                {
                    dq = true;
                    i++;
                    continue;
                }

                i++;
                continue;
            }

            // inside double quotes
            if (c == '\\')
            {
                if (wordStart < 0)
                {
                    wordStart = i;
                }

                i += 2;
                continue;
            }

            if (c == '"')
            {
                if (wordStart < 0)
                {
                    wordStart = i;
                }

                dq = false;
                i++;
                continue;
            }

            if (c == '`' || (c == '$' && At(cmd, i + 1) == '('))
            {
                EndWord(i);
                var len = c == '`' ? 1 : 2;
                PushOp(i, len);
                i += len;
                continue;
            }

            if (wordStart < 0)
            {
                wordStart = i;
            }

            i++;
        }

        EndWord(System.Math.Min(n, i));
        return (output, inSingle);
    }

    /// <summary>A generic C-like lexer: identifiers, numbers, quoted strings, comments, punctuation.</summary>
    public static List<RaspToken> CodeTokens(string src)
    {
        var output = new List<RaspToken>();
        var n = src.Length;
        var i = 0;
        void Push(int s, int e, string kind) => output.Add(new RaspToken(s, e, kind, src.Substring(s, e - s), output.Count));
        while (i < n)
        {
            var c = src[i];
            if (IsSpace(c))
            {
                i++;
                continue;
            }

            var s = i;
            if (c == '/' && At(src, i + 1) == '/')
            {
                var k = IndexOf(src, '\n', i);
                i = k < 0 ? n : k;
                Push(s, i, "comment");
                continue;
            }

            if (c == '/' && At(src, i + 1) == '*')
            {
                var k = IndexOf(src, "*/", i + 2);
                i = k < 0 ? n : k + 2;
                Push(s, i, "comment");
                continue;
            }

            if (c == '"' || c == '\'' || c == '`')
            {
                var k = i + 1;
                while (k < n && src[k] != c)
                {
                    k += src[k] == '\\' ? 2 : 1;
                }

                i = System.Math.Min(n, k + 1);
                Push(s, i, "string");
                continue;
            }

            if (IsDigit(c))
            {
                var k = i + 1;
                while (k < n && (IsIdChar(src[k]) || src[k] == '.'))
                {
                    k++;
                }

                i = k;
                Push(s, i, "number");
                continue;
            }

            if (IsIdStart(c) || c == '$' || c > 127)
            {
                var k = i + 1;
                while (k < n && (IsIdChar(src[k]) || src[k] > 127))
                {
                    k++;
                }

                i = k;
                Push(s, i, "word");
                continue;
            }

            i++;
            Push(s, i, "op");
        }

        return output;
    }

    /// <summary>Tokens overlapping <c>[idx, idx+len)</c> (half-open).</summary>
    public static List<RaspToken> Overlapping(List<RaspToken> tokens, int idx, int len)
    {
        var end = idx + len;
        var output = new List<RaspToken>();
        foreach (var t in tokens)
        {
            if (t.S >= end)
            {
                break;
            }

            if (t.E > idx)
            {
                output.Add(t);
            }
        }

        return output;
    }

    /// <summary>Start offsets of <paramref name="needle"/> in <paramref name="hay"/>, at most <paramref name="max"/>.</summary>
    public static List<int> Occurrences(string hay, string needle, int max = 8)
    {
        var output = new List<int>();
        if (needle.Length == 0)
        {
            return output;
        }

        var from = 0;
        while (output.Count < max)
        {
            var i = IndexOf(hay, needle, from);
            if (i < 0)
            {
                break;
            }

            output.Add(i);
            from = i + 1;
        }

        return output;
    }
}
