using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Shield360.Rasp.JsText;

namespace Shield360.Rasp;

/// <summary>The file operations the path checks know.</summary>
internal enum FileOp
{
    Read,
    Write,
    Append,
    Delete,
    Rename,
    List,
    Open,
}

/// <summary>The deserialization formats (sdk/rasp/README.md, "Deserialization").</summary>
internal enum DeserFormat
{
    Pickle,
    Marshal,
    Yaml,
    JsonPickle,
    NodeSerialize,
    Funcster,
    BinaryFormatter,
    TypeName,

    /// <summary>Java serialization (<c>ObjectInputStream.readObject</c>): tainted data always fires.</summary>
    Java,

    /// <summary>SnakeYAML with a constructor that builds arbitrary classes: a global tag naming a Java class fires.</summary>
    SnakeYaml,
}

/// <summary>
/// Pure structural detectors (sdk/rasp/README.md, "Detection algorithms").
/// Each takes the sink's argument and the inputs in scope and returns a finding
/// or null. No I/O, no state: the engine decides what a finding does. Port of
/// the TypeScript <c>detect.ts</c>, with the same rule ids.
/// </summary>
internal static class RaspDetect
{
    // Regular expressions use the reference's JavaScript semantics: ASCII
    // classes for \d, \w and \b, and \z (JS $ never matches before a final newline).
    private const RegexOptions Opts = RegexOptions.CultureInvariant;
    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);

    private static Regex Re(string pattern, RegexOptions extra = RegexOptions.None) => new(pattern, Opts | extra, s_timeout);

    private static IEnumerable<RaspInput> ReqInputs(IReadOnlyList<RaspInput> inputs, int min) =>
        inputs.Where(i => i.Source == RaspInputSource.Request && i.Value.Length >= min);

    private static IEnumerable<RaspInput> ModelInputs(IReadOnlyList<RaspInput> inputs, int min) =>
        inputs.Where(i => i.Source == RaspInputSource.ModelOutput && i.Value.Length >= min);

    // ---- SQL ----------------------------------------------------------------

    private static readonly HashSet<string> s_antiDetect = new(
        ("add all alter analyze and any as asc avg begin between by case create count delete desc do dumpfile else elseif end exists false file " +
         "float flush follows from group having identified if in insert interval into join last like limit loop not null on or order procedure " +
         "regexp return rlike select then true union update values xor").Split(' '),
        StringComparer.Ordinal);

    /// <summary>The contract's SQL keyword list (lower-case): the anti-detect words of <c>sqli.userinput</c>.</summary>
    internal static bool IsSqlKeyword(string lower) => s_antiDetect.Contains(lower);

    private static List<RaspInput> RequestOnly(IReadOnlyList<RaspInput> inputs) => inputs.Where(i => i.Source == RaspInputSource.Request).ToList();

    private static readonly Regex s_commaList =
        Re(@"^(, *)?(([a-zA-Z_][A-Za-z0-9_]*|[0-9+\-x.]+) *, *)+([a-zA-Z_][A-Za-z0-9_]*|[0-9+\-x.]+)\z");

    private static readonly HashSet<string> s_writeStatements = new(
        "insert update delete drop alter create truncate grant revoke merge replace".Split(' '), StringComparer.Ordinal);

    private static bool IsComment(RaspToken t) => t.Kind == "comment" || t.Kind == "version_comment";

    private static bool HasStackedAfter(List<RaspToken> tokens, List<RaspToken> from)
    {
        foreach (var t in from)
        {
            if (t.Kind != "op" || t.Text != ";")
            {
                continue;
            }

            for (var k = t.Index + 1; k < tokens.Count; k++)
            {
                if (!IsComment(tokens[k]))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool SqlWholeIsDangerous(List<RaspToken> tokens)
    {
        var code = tokens.Where(t => !IsComment(t)).ToList();
        if (code.Count == 0)
        {
            return false;
        }

        if (code[0].Kind == "word" && s_writeStatements.Contains(Lower(code[0].Text)))
        {
            return true;
        }

        for (var i = 0; i < code.Count - 1; i++)
        {
            if (code[i].Kind == "op" && code[i].Text == ";")
            {
                return true;
            }
        }

        return false;
    }

    /// <summary><c>sql_injection</c>; every finding carries the dialect the lexer used.</summary>
    public static RaspFinding? Sql(string? query, IReadOnlyList<RaspInput> inputs, SqlDialect dialect = SqlDialect.Generic) =>
        SqlCheck(query, inputs, dialect) is { } f ? f with { Dialect = RaspLexers.DialectName(dialect) } : null;

    private static RaspFinding? SqlCheck(string? query, IReadOnlyList<RaspInput> inputs, SqlDialect dialect)
    {
        if (string.IsNullOrEmpty(query) || inputs.Count == 0)
        {
            return null;
        }

        List<RaspToken>? tokens = null;
        List<RaspToken> Toks() => tokens ??= RaspLexers.SqlTokens(query!, dialect);
        var trimmed = Trim(query!);
        foreach (var inp in ReqInputs(inputs, 3))
        {
            var v = inp.Value;
            if (v == query || Trim(v) == trimmed)
            {
                continue; // allow_full: a SQL console
            }

            var occ = RaspLexers.Occurrences(query!, v);
            if (occ.Count == 0)
            {
                continue;
            }

            var commaList = s_commaList.IsMatch(v);
            foreach (var idx in occ)
            {
                var over = RaspLexers.Overlapping(Toks(), idx, v.Length);
                if (!commaList && over.Count >= 2)
                {
                    if (over.Count >= 10)
                    {
                        return new RaspFinding(RaspAttackType.SqlInjection, "sqli.userinput", inp);
                    }

                    var plain = over.Count(t => !(t.Kind == "word" && s_antiDetect.Contains(Lower(t.Text))));
                    if (plain >= 2)
                    {
                        return new RaspFinding(RaspAttackType.SqlInjection, "sqli.userinput", inp);
                    }
                }

                if (HasStackedAfter(Toks(), over))
                {
                    return new RaspFinding(RaspAttackType.SqlInjection, "sqli.stacked", inp);
                }
            }
        }

        foreach (var inp in ModelInputs(inputs, 3))
        {
            if (Trim(inp.Value) == trimmed)
            {
                if (SqlWholeIsDangerous(Toks()))
                {
                    return new RaspFinding(RaspAttackType.SqlInjection, "sqli.model_output", inp);
                }

                continue;
            }

            foreach (var idx in RaspLexers.Occurrences(query!, inp.Value))
            {
                if (RaspLexers.Overlapping(Toks(), idx, inp.Value.Length).Count >= 2)
                {
                    return new RaspFinding(RaspAttackType.SqlInjection, "sqli.model_output", inp);
                }
            }
        }

        if (RaspIastScope.Armed)
        {
            RaspIastScope.Note(() => RaspIastRules.Sql(query!, inputs, Toks)); // passive IAST
        }

        return null;
    }

    // ---- NoSQL ----------------------------------------------------------------

    /// <summary>Deep equality of two JSON trees (objects by key set, arrays by position, values by JSON text).</summary>
    internal static bool DeepEqual(JsonNode? a, JsonNode? b, int depth = 0)
    {
        if (ReferenceEquals(a, b))
        {
            return true;
        }

        if (a is null || b is null || depth > 32)
        {
            return false;
        }

        switch (a)
        {
            case JsonObject oa when b is JsonObject ob:
                if (oa.Count != ob.Count)
                {
                    return false;
                }

                foreach (var kv in oa)
                {
                    if (!ob.TryGetPropertyValue(kv.Key, out var other) || !DeepEqual(kv.Value, other, depth + 1))
                    {
                        return false;
                    }
                }

                return true;
            case JsonArray aa when b is JsonArray ab:
                if (aa.Count != ab.Count)
                {
                    return false;
                }

                for (var i = 0; i < aa.Count; i++)
                {
                    if (!DeepEqual(aa[i], ab[i], depth + 1))
                    {
                        return false;
                    }
                }

                return true;
            case JsonValue va when b is JsonValue vb:
                return va.ToJsonString() == vb.ToJsonString();
            default:
                return false;
        }
    }

    private static IEnumerable<KeyValuePair<string, JsonNode?>> Entries(JsonNode node)
    {
        if (node is JsonObject o)
        {
            foreach (var kv in o)
            {
                yield return kv;
            }
        }
        else if (node is JsonArray a)
        {
            for (var i = 0; i < a.Count; i++)
            {
                yield return new KeyValuePair<string, JsonNode?>(i.ToString(CultureInfo.InvariantCulture), a[i]);
            }
        }
    }

    private static bool TreeContains(JsonNode? tree, JsonNode obj, int depth = 0)
    {
        if (tree is null or JsonValue || depth > 32)
        {
            return false;
        }

        if (ReferenceEquals(tree, obj) || DeepEqual(tree, obj))
        {
            return true;
        }

        return Entries(tree).Any(kv => TreeContains(kv.Value, obj, depth + 1));
    }

    /// <summary>
    /// <c>nosqli.operator</c>: an operator object (a key starting with <c>$</c>) that also
    /// appears in the request's parsed trees; <c>nosqli.where</c>: tainted code in
    /// <c>$where</c> / <c>$function</c>.
    /// </summary>
    public static RaspFinding? NoSql(JsonNode? doc, IReadOnlyList<JsonNode?> trees, IReadOnlyList<RaspInput> inputs)
    {
        RaspFinding? found = null;
        void Walk(JsonNode? node, int depth)
        {
            if (found is not null || node is null or JsonValue || depth > 32)
            {
                return;
            }

            var entries = Entries(node!).ToList();
            if (node is JsonObject && entries.Any(kv => Starts(kv.Key, "$")) && trees.Any(t => TreeContains(t, node!)))
            {
                found = new RaspFinding(RaspAttackType.NoSqlInjection, "nosqli.operator");
                return;
            }

            foreach (var kv in entries)
            {
                if ((kv.Key == "$where" || kv.Key == "$function") && found is null)
                {
                    var code = kv.Value is JsonValue v && v.TryGetValue<string>(out var s)
                        ? s
                        : kv.Value is JsonObject fo && fo["body"] is JsonValue bv && bv.TryGetValue<string>(out var body) ? body : string.Empty;
                    var hit = code.Length > 0 ? Code(code, inputs) : null;
                    if (hit is not null)
                    {
                        found = new RaspFinding(RaspAttackType.NoSqlInjection, "nosqli.where", hit.Input);
                    }
                }

                Walk(kv.Value, depth + 1);
            }
        }

        Walk(doc, 0);
        return found;
    }

    // ---- Command ----------------------------------------------------------------

    public static readonly HashSet<string> Shells = new("sh bash zsh dash ksh fish csh tcsh cmd powershell pwsh".Split(' '), StringComparer.Ordinal);
    public static readonly HashSet<string> Downloaders = new(new[] { "curl", "wget" }, StringComparer.Ordinal);
    private static readonly HashSet<string> s_multiOps = new(new[] { ";", "&&", "||", "|", "`", "$(" }, StringComparer.Ordinal);

    /// <summary>An executable's basename, lower-case, without <c>.exe</c>.</summary>
    public static string ExeName(string p)
    {
        var parts = p.Replace('\\', '/').Split('/');
        var b = Lower(parts[parts.Length - 1]);
        return Ends(b, ".exe") ? b.Substring(0, b.Length - 4) : b;
    }

    private static string UnquoteWord(string w)
    {
        if (w.Length > 0 && (w[0] == '\'' || w[0] == '"'))
        {
            w = w.Substring(1);
        }

        if (w.Length > 0 && (w[w.Length - 1] == '\'' || w[w.Length - 1] == '"'))
        {
            w = w.Substring(0, w.Length - 1);
        }

        return w;
    }

    public static RaspFinding? Command(string? command, IReadOnlyList<RaspInput> inputs)
    {
        if (string.IsNullOrEmpty(command) || inputs.Count == 0)
        {
            return null;
        }

        var (tokens, inSingle) = RaspLexers.ShellTokens(command!);
        var trimmed = Trim(command!);
        foreach (var inp in ReqInputs(inputs, 3))
        {
            foreach (var idx in RaspLexers.Occurrences(command!, inp.Value))
            {
                if (RaspLexers.Overlapping(tokens, idx, inp.Value.Length).Count >= 2)
                {
                    return new RaspFinding(RaspAttackType.CommandInjection, "cmdi.userinput", inp);
                }
            }
        }

        foreach (var inp in ReqInputs(inputs, 3))
        {
            var v = inp.Value;
            if (Has(v, "${IFS}") || Has(v, "$IFS"))
            {
                if (Has(command!, v))
                {
                    return new RaspFinding(RaspAttackType.CommandInjection, "cmdi.substitution", inp);
                }
            }

            if (Has(v, '`') || Has(v, "$("))
            {
                foreach (var idx in RaspLexers.Occurrences(command!, v))
                {
                    for (var k = idx; k < idx + v.Length; k++)
                    {
                        var sub = command![k] == '`' || (command[k] == '$' && At(command, k + 1) == '(');
                        if (sub && !inSingle[k])
                        {
                            return new RaspFinding(RaspAttackType.CommandInjection, "cmdi.substitution", inp);
                        }
                    }
                }
            }
        }

        foreach (var inp in ReqInputs(inputs, 1))
        {
            if (Trim(inp.Value) == trimmed)
            {
                return new RaspFinding(RaspAttackType.CommandInjection, "cmdi.full", inp);
            }
        }

        foreach (var inp in ModelInputs(inputs, 3))
        {
            if (Trim(inp.Value) == trimmed)
            {
                if (tokens.Any(t => t.Kind == "op" && s_multiOps.Contains(t.Text)))
                {
                    return new RaspFinding(RaspAttackType.CommandInjection, "cmdi.model_output", inp);
                }

                continue;
            }

            foreach (var idx in RaspLexers.Occurrences(command!, inp.Value))
            {
                if (RaspLexers.Overlapping(tokens, idx, inp.Value.Length).Count >= 2)
                {
                    return new RaspFinding(RaspAttackType.CommandInjection, "cmdi.model_output", inp);
                }
            }
        }

        if (RaspIastScope.Armed)
        {
            RaspIastScope.Note(() => RaspIastRules.Shell(command!, inputs, tokens)); // passive IAST
        }

        return null;
    }

    /// <summary><c>cmdi.executable</c> (argv spawns): the executable equals an input.</summary>
    public static RaspFinding? Argv(IReadOnlyList<string> argv, IReadOnlyList<RaspInput> inputs)
    {
        if (argv.Count == 0)
        {
            return null;
        }

        foreach (var inp in inputs)
        {
            if (inp.Value.Length >= 1 && inp.Value == argv[0])
            {
                return new RaspFinding(RaspAttackType.CommandInjection, "cmdi.executable", inp);
            }
        }

        // Passive IAST: a `sh -c <script>` spawn's script is checked as shell text instead.
        if (RaspIastScope.Armed)
        {
            RaspIastScope.Note(() => ShellScriptOf(argv) is null ? RaspIastRules.Argv(argv, inputs) : null);
        }

        return null;
    }

    /// <summary><c>shell_spawn</c>: a shell or downloader started during a request, or <c>curl | sh</c> at any time.</summary>
    public static RaspFinding? ShellSpawn(string? argv0, string? command, bool inRequest, IReadOnlyList<string> allow)
    {
        var allowed = new HashSet<string>(allow.Select(ExeName), StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(command))
        {
            var words = RaspLexers.ShellTokens(command!).Tokens;
            for (var i = 0; i < words.Count; i++)
            {
                if (words[i].Kind != "word" || !Downloaders.Contains(ExeName(UnquoteWord(words[i].Text))))
                {
                    continue;
                }

                for (var k = i + 1; k < words.Count - 1; k++)
                {
                    if (words[k].Kind == "op" && words[k].Text == "|" && words[k + 1].Kind == "word" &&
                        Shells.Contains(ExeName(UnquoteWord(words[k + 1].Text))))
                    {
                        return new RaspFinding(RaspAttackType.ShellSpawn, "shell_spawn.download_exec");
                    }
                }
            }
        }

        if (!inRequest)
        {
            return null;
        }

        var name = string.IsNullOrEmpty(argv0) ? string.Empty : ExeName(argv0!);
        if (name.Length == 0 && !string.IsNullOrEmpty(command))
        {
            var firstWord = RaspLexers.ShellTokens(command!).Tokens.FirstOrDefault(t => t.Kind == "word");
            name = firstWord.Text is null ? string.Empty : ExeName(UnquoteWord(firstWord.Text));
        }

        if (name.Length > 0 && (Shells.Contains(name) || Downloaders.Contains(name)) && !allowed.Contains(name))
        {
            return new RaspFinding(RaspAttackType.ShellSpawn, "shell_spawn.shell", Target: name);
        }

        return null;
    }

    /// <summary>The script of <c>sh -c &lt;script&gt;</c> style argv, if any.</summary>
    public static string? ShellScriptOf(IReadOnlyList<string> argv)
    {
        if (argv.Count < 3 || !Shells.Contains(ExeName(argv[0])))
        {
            return null;
        }

        var i = -1;
        for (var k = 1; k < argv.Count; k++)
        {
            var a = argv[k];
            if (a == "-c" || Lower(a) == "/c" || Lower(a) == "-command")
            {
                i = k;
                break;
            }
        }

        return i > 0 && i + 1 < argv.Count ? string.Join(" ", argv.Skip(i + 1)) : null;
    }

    // ---- Path ----------------------------------------------------------------

    private static readonly Regex s_multiSlash = Re("/{2,}");
    private static readonly Regex s_drive = Re("^[A-Za-z]:/");
    private static readonly Regex s_driveOnly = Re("^[A-Za-z]:");

    /// <summary><c>\</c> to <c>/</c>, <c>/./</c> and repeated slashes collapsed; a UNC prefix kept.</summary>
    public static string NormPath(string p)
    {
        var s = p.Replace('\\', '/');
        var unc = Starts(s, "//");
        while (Has(s, "/./"))
        {
            s = ReplaceFirst(s, "/./", "/");
        }

        s = s_multiSlash.Replace(s, "/");
        return unc ? "/" + s : s;
    }

    /// <summary>The path joined to the working directory when relative, <c>.</c> and <c>..</c> removed lexically.</summary>
    public static string ResolvePath(string p, string? cwd = null)
    {
        var s = p.Replace('\\', '/');
        var abs = Starts(s, "/") || s_drive.IsMatch(s) ? s : (cwd ?? Directory.GetCurrentDirectory()).Replace('\\', '/') + "/" + s;
        var drive = s_driveOnly.IsMatch(abs) ? abs.Substring(0, 2) : string.Empty;
        var normalized = PosixNormalize("/" + abs.Substring(drive.Length));
        if (Ends(normalized, "/"))
        {
            normalized = normalized.Substring(0, normalized.Length - 1);
        }

        var result = drive + normalized;
        return result.Length == 0 ? "/" : result;
    }

    /// <summary>Node's <c>path.posix.normalize</c> for an absolute path.</summary>
    private static string PosixNormalize(string path)
    {
        var trailing = Ends(path, "/");
        var stack = new List<string>();
        foreach (var seg in path.Split('/'))
        {
            if (seg.Length == 0 || seg == ".")
            {
                continue;
            }

            if (seg == "..")
            {
                if (stack.Count > 0)
                {
                    stack.RemoveAt(stack.Count - 1);
                }

                continue;
            }

            stack.Add(seg);
        }

        var joined = "/" + string.Join("/", stack);
        return trailing && stack.Count > 0 ? joined + "/" : joined;
    }

    private static readonly string[] s_sensitive =
    {
        "/etc/passwd", "/etc/shadow", "/proc/self/environ", "/root/.bash_history", "/var/run/secrets/kubernetes.io/serviceaccount/token",
    };

    private static readonly Regex s_scriptFile =
        Re(@"\.(aspx?|jspx?|php[3-7]?|phar|phtml|sh|bash|py|pyc|pl|rb|so|dll|dylib|exe|cgi|js|mjs|cjs)\.?\z", RegexOptions.IgnoreCase);

    private static readonly Regex s_ntfs = Re(@"::\$(DATA|INDEX)\z", RegexOptions.IgnoreCase);

    /// <summary>
    /// The directory <c>path.outside_root</c> reports: everything before the resolved path's last <c>/</c>,
    /// or <c>/</c> (<c>X:/</c> for a drive) when that is empty or a drive letter. Never the file name.
    /// </summary>
    public static string TargetDirectory(string resolved)
    {
        var i = resolved.LastIndexOf('/');
        var d = i < 0 ? string.Empty : resolved.Substring(0, i);
        if (d.Length == 0)
        {
            return "/";
        }

        return d.Length == 2 && d[1] == ':' && ((d[0] >= 'A' && d[0] <= 'Z') || (d[0] >= 'a' && d[0] <= 'z')) ? d + "/" : d;
    }

    /// <summary>Equal to the root or under <c>root/</c>.</summary>
    public static bool UnderRoot(string resolved, string root)
    {
        var r = ResolvePath(root);
        return resolved == r || Starts(resolved, Ends(r, "/") ? r : r + "/");
    }

    private static string TempDir() => Path.GetTempPath();

    private static string HomeDir()
    {
        try
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).Replace('\\', '/');
        }
        catch (PlatformNotSupportedException)
        {
            return string.Empty;
        }
    }

    public static RaspFinding? FilePath(string? path, FileOp op, IReadOnlyList<RaspInput> inputs, IReadOnlyList<string>? fileRoots = null, bool inRequest = true)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        var roots = fileRoots ?? Array.Empty<string>();
        var np = NormPath(path!);
        var resolved = ResolvePath(path!);
        var writes = op is FileOp.Write or FileOp.Append or FileOp.Rename or FileOp.Open;
        if (writes && s_ntfs.IsMatch(path!))
        {
            return new RaspFinding(RaspAttackType.FileWrite, "file_write.ntfs");
        }

        var cands = ReqInputs(inputs, 3).Concat(ModelInputs(inputs, 3)).ToList();
        foreach (var inp in cands)
        {
            var ni = NormPath(inp.Value);
            if (Has(ni, "../") && (Ends(np, ni) || Has(np, ni)))
            {
                return new RaspFinding(RaspAttackType.PathTraversal, "path.traversal", inp);
            }

            var absolute = Starts(ni, "/") || s_drive.IsMatch(ni) || Starts(inp.Value, "file://");
            if (absolute)
            {
                var target = Starts(inp.Value, "file://") ? NormPath(inp.Value.Substring(7)) : ni;
                if (np == target || Ends(np, target))
                {
                    return new RaspFinding(RaspAttackType.PathTraversal, "path.absolute", inp);
                }
            }

            var nul = inp.Value.IndexOf('\0');
            if (nul > 0 && Has(path!, inp.Value.Substring(0, nul)))
            {
                return new RaspFinding(RaspAttackType.PathTraversal, "path.nullbyte", inp);
            }
        }

        var contained = cands.FirstOrDefault(i => Has(path!, i.Value) || Has(np, NormPath(i.Value)));
        if (contained is not null && roots.Count > 0 && !roots.Any(r => UnderRoot(resolved, r)))
        {
            return new RaspFinding(RaspAttackType.PathTraversal, "path.outside_root", contained, Target: TargetDirectory(resolved));
        }

        if (contained is not null)
        {
            var home = HomeDir();
            if (s_sensitive.Contains(resolved) || (home.Length > 0 && resolved == home + "/.ssh/id_rsa") || Ends(resolved, "/.ssh/id_rsa"))
            {
                return new RaspFinding(RaspAttackType.PathTraversal, "path.sensitive", contained);
            }
        }

        if (writes && inRequest)
        {
            var parts = resolved.Split('/');
            if (s_scriptFile.IsMatch(parts[parts.Length - 1]) &&
                (contained is not null || roots.Any(r => UnderRoot(resolved, r)) || UnderRoot(resolved, TempDir())))
            {
                return new RaspFinding(RaspAttackType.FileWrite, "file_write.script", contained);
            }
        }

        if (RaspIastScope.Armed)
        {
            RaspIastScope.Note(() => RaspIastRules.Path(np, inputs, NormPath)); // passive IAST
        }

        return null;
    }

    /// <summary><c>file_write.upload</c>: an uploaded file whose name (its last path segment) is a script (README "Path").</summary>
    public static RaspFinding? Upload(RaspInput input)
    {
        var v = input.Value;
        var cut = Math.Max(v.LastIndexOf('/'), v.LastIndexOf('\\'));
        var name = cut >= 0 ? v.Substring(cut + 1) : v;
        return s_scriptFile.IsMatch(name) ? new RaspFinding(RaspAttackType.FileWrite, "file_write.upload", input) : null;
    }

    private static readonly Regex s_includePathLike = Re(@"[/\\]|\.\.");
    private static readonly Regex s_includeAbsolute = Re(@"^(?:/|[A-Za-z]:[\\/]|\\\\|file:)", RegexOptions.IgnoreCase);

    /// <summary>
    /// <c>code.include</c>: an assembly name or path that is an input, or carries one that is
    /// an absolute path or holds <c>/</c>, <c>\</c>, <c>..</c> or a NUL (README "Code").
    /// </summary>
    public static RaspFinding? Include(string? specifier, IReadOnlyList<RaspInput> inputs)
    {
        if (string.IsNullOrEmpty(specifier))
        {
            return null;
        }

        foreach (var inp in inputs)
        {
            if (inp.Value.Length == 0)
            {
                continue;
            }

            if (inp.Value == specifier)
            {
                return new RaspFinding(RaspAttackType.CodeInjection, "code.include", inp);
            }

            if (inp.Value.Length >= 3 && Has(specifier!, inp.Value) &&
                (s_includeAbsolute.IsMatch(inp.Value) || s_includePathLike.IsMatch(inp.Value) || Has(inp.Value, '\0')))
            {
                return new RaspFinding(RaspAttackType.CodeInjection, "code.include", inp);
            }
        }

        if (RaspIastScope.Armed)
        {
            RaspIastScope.Note(() => RaspIastRules.Include(specifier!, inputs)); // passive IAST
        }

        return null;
    }

    // ---- SSRF ----------------------------------------------------------------

    private static readonly HashSet<string> s_ssrfProtocols = new(
        "file gopher dict ftp jar netdoc ldap ldaps php phar expect tftp".Split(' '), StringComparer.Ordinal);

    public static readonly string[] MetadataHosts =
    {
        "169.254.169.254", "fd00:ec2::254", "100.100.100.200", "168.63.129.16", "169.254.170.2", "metadata.google.internal", "metadata",
    };

    private static readonly Regex s_scheme = Re("^([A-Za-z][A-Za-z0-9+.-]*):");
    private static readonly Regex s_hostEnd = Re(@"[/?#\\]");

    /// <summary>Scheme and raw host as written (a URL parser would rewrite numeric hosts).</summary>
    public static (string Scheme, string Host)? RawUrl(string url)
    {
        var m = s_scheme.Match(url);
        if (!m.Success)
        {
            return null;
        }

        var scheme = Lower(m.Groups[1].Value);
        var rest = url.Substring(m.Length);
        if (!Starts(rest, "//"))
        {
            return (scheme, string.Empty);
        }

        rest = rest.Substring(2);
        var end = s_hostEnd.Match(rest);
        var auth = end.Success ? rest.Substring(0, end.Index) : rest;
        var at = auth.LastIndexOf('@');
        if (at >= 0)
        {
            auth = auth.Substring(at + 1);
        }

        var host = auth;
        if (Starts(host, "["))
        {
            var close = host.IndexOf(']');
            host = close < 0 ? host.Substring(1) : Slice(host, 1, close);
        }
        else if (Has(host, ':'))
        {
            host = host.Substring(0, host.IndexOf(':'));
        }

        return (scheme, Lower(host));
    }

    private static readonly Regex s_v4Part = Re("^(0|[1-9][0-9]{0,2})\\z");
    private static readonly Regex s_v6Word = Re("^[0-9a-f]{1,4}\\z", RegexOptions.IgnoreCase);

    private static int[]? ParseV4(string s)
    {
        var p = s.Split('.');
        if (p.Length != 4)
        {
            return null;
        }

        var n = new int[4];
        for (var i = 0; i < 4; i++)
        {
            if (!s_v4Part.IsMatch(p[i]))
            {
                return null;
            }

            n[i] = int.Parse(p[i], CultureInfo.InvariantCulture);
            if (n[i] > 255)
            {
                return null;
            }
        }

        return n;
    }

    private static readonly string[] s_doubleColon = { "::" };

    /// <summary>16 bytes, or null.</summary>
    private static int[]? ParseV6(string s)
    {
        if (!Has(s, ':'))
        {
            return null;
        }

        int[] tail = Array.Empty<int>();
        var str = s;
        var lastColon = str.LastIndexOf(':');
        var v4 = ParseV4(str.Substring(lastColon + 1));
        if (v4 is not null)
        {
            tail = v4;
            str = str.Substring(0, lastColon) + ":0:0";
        }

        var halves = str.Split(s_doubleColon, StringSplitOptions.None);
        if (halves.Length > 2)
        {
            return null;
        }

        static List<int>? Parse(string h)
        {
            var output = new List<int>();
            if (h.Length == 0)
            {
                return output;
            }

            foreach (var x in h.Split(':'))
            {
                if (!s_v6Word.IsMatch(x))
                {
                    return null;
                }

                output.Add(int.Parse(x, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            }

            return output;
        }

        var a = Parse(halves[0]);
        var b = halves.Length == 2 ? Parse(halves[1]) : new List<int>();
        if (a is null || b is null)
        {
            return null;
        }

        var fill = halves.Length == 2 ? 8 - a.Count - b.Count : 0;
        if (fill < 0 || (halves.Length == 1 && a.Count != 8))
        {
            return null;
        }

        var words = a.Concat(Enumerable.Repeat(0, fill)).Concat(b).ToList();
        var bytes = new List<int>();
        foreach (var w in words)
        {
            bytes.Add(w >> 8);
            bytes.Add(w & 255);
        }

        if (tail.Length > 0)
        {
            bytes.RemoveRange(12, Math.Min(4, bytes.Count - 12));
            bytes.InsertRange(12, tail);
        }

        return bytes.ToArray();
    }

    private static bool V4Private(int a, int c) =>
        a == 0 || a == 10 || a == 127 || (a == 100 && c >= 64 && c < 128) || (a == 169 && c == 254) ||
        (a == 172 && c >= 16 && c < 32) || (a == 192 && c == 168) || (a == 198 && (c == 18 || c == 19));

    /// <summary>Private, loopback, link-local or unique-local; IPv4-mapped and IPv4-compatible IPv6 decoded first.</summary>
    public static bool IsPrivateAddress(string addr)
    {
        var a = Lower(addr);
        if (Starts(a, "["))
        {
            a = a.Substring(1);
        }

        if (Ends(a, "]"))
        {
            a = a.Substring(0, a.Length - 1);
        }

        a = a.Split('%')[0];
        var v4 = ParseV4(a);
        if (v4 is not null)
        {
            return V4Private(v4[0], v4[1]);
        }

        var v6 = ParseV6(a);
        if (v6 is null)
        {
            return false;
        }

        var zero10 = v6.Take(10).All(x => x == 0);
        if (zero10 && v6[10] == 0xff && v6[11] == 0xff)
        {
            return V4Private(v6[12], v6[13]);
        }

        var zero12 = zero10 && v6[10] == 0 && v6[11] == 0;
        var loopOrAny = v6[12] == 0 && v6[13] == 0 && v6[14] == 0 && v6[15] <= 1;
        if (zero12 && !loopOrAny)
        {
            return V4Private(v6[12], v6[13]);
        }

        if (v6.All(x => x == 0))
        {
            return true;
        }

        if (v6.Take(15).All(x => x == 0) && v6[15] == 1)
        {
            return true;
        }

        if ((v6[0] & 0xfe) == 0xfc)
        {
            return true;
        }

        return v6[0] == 0xfe && (v6[1] & 0xc0) == 0x80;
    }

    public static bool IsIpLiteral(string host) => ParseV4(host) is not null || ParseV6(host) is not null;

    private static readonly Regex s_allDigits = Re("^[0-9]+\\z");
    private static readonly Regex s_hexNumber = Re("^0x[0-9a-f]+\\z", RegexOptions.IgnoreCase);
    private static readonly Regex s_numericPart = Re("^(0x[0-9a-f]+|[0-9]+)\\z", RegexOptions.IgnoreCase);
    private static readonly Regex s_leadingZero = Re("^0[0-9]");
    private static readonly Regex s_hexPrefix = Re("^0x", RegexOptions.IgnoreCase);

    private static bool IsObfuscatedV4(string host)
    {
        if (host.Length == 0 || ParseV4(host) is not null)
        {
            return false;
        }

        if (s_allDigits.IsMatch(host) || s_hexNumber.IsMatch(host))
        {
            return true;
        }

        var parts = host.Split('.');
        if (parts.Length > 4 || parts.Length < 2)
        {
            return false;
        }

        if (!parts.All(p => s_numericPart.IsMatch(p)))
        {
            return false;
        }

        return parts.Length < 4 || parts.Any(p => s_leadingZero.IsMatch(p) || s_hexPrefix.IsMatch(p));
    }

    public static bool HostMatches(string host, string pattern)
    {
        var p = Lower(pattern);
        if (Starts(p, "*."))
        {
            return Ends(host, p.Substring(1)) && host.Length > p.Length - 1;
        }

        return host == p;
    }

    /// <summary>The input that taints the URL's host, if any.</summary>
    public static RaspInput? TaintOf(string url, string host, IReadOnlyList<RaspInput> inputs)
    {
        var cands = inputs.Where(i => i.Value.Length >= 3).ToList();
        if (host.Length > 0)
        {
            var hostEnd = IndexOf(Lower(url), host) + host.Length;
            return cands.FirstOrDefault(i => Has(Lower(i.Value), host) || (Starts(url, i.Value) && i.Value.Length >= hostEnd));
        }

        // No host (file:, gopher: without //): an input that is a prefix past the scheme.
        var schemeEnd = url.IndexOf(':') + 1;
        return cands.FirstOrDefault(i => Starts(url, i.Value) && i.Value.Length > schemeEnd);
    }

    public static RaspFinding? Ssrf(string? url, IReadOnlyList<RaspInput> inputs, IReadOnlyList<string>? resolved = null)
    {
        if (string.IsNullOrEmpty(url))
        {
            return null;
        }

        var raw = RawUrl(url!);
        if (raw is null)
        {
            return null;
        }

        var addresses = resolved ?? Array.Empty<string>();
        var (scheme, host) = raw.Value;
        var inp = TaintOf(url!, host, inputs);
        if (inp is null)
        {
            return null;
        }

        if (s_ssrfProtocols.Contains(scheme))
        {
            return new RaspFinding(RaspAttackType.Ssrf, "ssrf.protocol", inp);
        }

        if (MetadataHosts.Contains(host) || addresses.Any(a => MetadataHosts.Contains(Lower(a))))
        {
            return new RaspFinding(RaspAttackType.Ssrf, "ssrf.metadata", inp);
        }

        if (IsObfuscatedV4(host))
        {
            return new RaspFinding(RaspAttackType.Ssrf, "ssrf.obfuscated", inp);
        }

        if (host == "localhost" || Ends(host, ".localhost") || (IsIpLiteral(host) && IsPrivateAddress(host)) || addresses.Any(IsPrivateAddress))
        {
            return new RaspFinding(RaspAttackType.Ssrf, "ssrf.internal", inp);
        }

        if (RaspData.DnslogHosts.Contains(host) || RaspData.DnslogSuffixes.Any(s => Ends(host, s)))
        {
            return new RaspFinding(RaspAttackType.Ssrf, "ssrf.dnslog", inp);
        }

        if (RaspIastScope.Armed)
        {
            RaspIastScope.Note(() => RaspIastRules.Ssrf(url!, host, inputs)); // passive IAST
        }

        return null;
    }

    /// <summary><c>outbound.not_allowed</c>: the host matches none of the allow-list (always-allowed hosts aside).</summary>
    public static RaspFinding? Outbound(string? url, IReadOnlyList<string> allow, IReadOnlyList<string>? alwaysAllowed = null)
    {
        if (allow.Count == 0 || string.IsNullOrEmpty(url))
        {
            return null;
        }

        var raw = RawUrl(url!);
        if (raw is null || raw.Value.Host.Length == 0)
        {
            return null;
        }

        var host = raw.Value.Host;
        if ((alwaysAllowed ?? Array.Empty<string>()).Contains(host) || allow.Any(p => HostMatches(host, p)))
        {
            return null;
        }

        return new RaspFinding(RaspAttackType.Outbound, "outbound.not_allowed", Target: host);
    }

    // ---- Deserialization, code, XML, XSS ------------------------------------------

    private static readonly Regex s_base64ish = Re("^[A-Za-z0-9+/=_-]+\\z");

    /// <summary>Data is tainted when equal to an input, contained in one, or containing one of length 8 or more (base64-decoded inputs too).</summary>
    public static RaspInput? TaintedData(string? data, IReadOnlyList<RaspInput> inputs)
    {
        if (string.IsNullOrEmpty(data))
        {
            return null;
        }

        foreach (var i in inputs)
        {
            if (i.Value.Length == 0)
            {
                continue;
            }

            if (i.Value == data || Has(i.Value, data!) || (i.Value.Length >= 8 && Has(data!, i.Value)))
            {
                return i;
            }

            if (i.Value.Length >= 8 && s_base64ish.IsMatch(i.Value))
            {
                var dec = Latin1(LenientBase64(i.Value));
                if (dec.Length > 0 && (dec == data || (dec.Length >= 8 && (Has(dec, data!) || Has(data!, dec)))))
                {
                    return i;
                }
            }
        }

        return null;
    }

    /// <summary>Base64 or base64url, as Node's <c>Buffer.from(s, 'base64')</c> reads it: stops at <c>=</c>, drops trailing bits.</summary>
    internal static byte[] LenientBase64(string s)
    {
        var output = new List<byte>(s.Length * 3 / 4);
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
            else if (ch == '=')
            {
                break;
            }
            else
            {
                continue;
            }

            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)((acc >> bits) & 0xff));
            }
        }

        return output.ToArray();
    }

    /// <summary>Bytes as a latin-1 string (each byte one character).</summary>
    internal static string Latin1(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length);
        foreach (var b in bytes)
        {
            sb.Append((char)b);
        }

        return sb.ToString();
    }

    public static DeserFormat? Format(string? name) => name switch
    {
        "pickle" => DeserFormat.Pickle,
        "marshal" => DeserFormat.Marshal,
        "yaml" => DeserFormat.Yaml,
        "jsonpickle" => DeserFormat.JsonPickle,
        "node_serialize" => DeserFormat.NodeSerialize,
        "funcster" => DeserFormat.Funcster,
        "binaryformatter" => DeserFormat.BinaryFormatter,
        "typename" => DeserFormat.TypeName,
        "java" => DeserFormat.Java,
        "snakeyaml" => DeserFormat.SnakeYaml,
        _ => null,
    };

    private static readonly string[] s_jsonPickleMarks =
    {
        "\"py/reduce\"", "\"py/object\"", "\"py/type\"", "\"py/function\"", "\"py/repr\"", "\"py/newargs\"",
    };

    // A SnakeYAML global tag naming a Java class; standard tags such as !!str have no dot and never match.
    private static readonly Regex s_snakeYamlClassTag =
        Re(@"(?:^|[\s\[{,])(?:!!|!<tag:yaml\.org,2002:)[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$]");

    public static RaspFinding? Deserialization(DeserFormat format, string? data, IReadOnlyList<RaspInput> inputs)
    {
        var inp = TaintedData(data, inputs);
        if (inp is null)
        {
            return null;
        }

        var d = data!;

        // Passive IAST: tainted data reaching an unsafe deserializer, whatever the format check says.
        if (RaspIastScope.Armed)
        {
            RaspIastScope.Note(() => RaspIastRules.Data("vuln.deser_input", d, TaintedData(d, RequestOnly(inputs))));
        }

        RaspFinding Hit(string rule) => new(RaspAttackType.Deserialization, rule, inp);
        return format switch
        {
            DeserFormat.Pickle => Hit("deser.pickle"),
            DeserFormat.Marshal => Hit("deser.marshal"),
            DeserFormat.BinaryFormatter => Hit("deser.binaryformatter"),
            DeserFormat.Java => Hit("deser.java"),
            DeserFormat.SnakeYaml => s_snakeYamlClassTag.IsMatch(d) ? Hit("deser.yaml") : null,
            DeserFormat.Yaml => Has(d, "!!python/") || Has(d, "!!js/") ? Hit("deser.yaml") : null,
            DeserFormat.JsonPickle => s_jsonPickleMarks.Any(m => Has(d, m)) ? Hit("deser.jsonpickle") : null,
            DeserFormat.NodeSerialize => Has(d, "_$$ND_FUNC$$_") ? Hit("deser.node_serialize") : null,
            DeserFormat.Funcster => Has(d, "__js_function") ? Hit("deser.funcster") : null,
            DeserFormat.TypeName => Has(d, "\"$type\"") || Has(d, "\"__type\"") ? Hit("deser.typename") : null,
            _ => null,
        };
    }

    public static RaspFinding? Code(string? code, IReadOnlyList<RaspInput> inputs)
    {
        if (string.IsNullOrEmpty(code))
        {
            return null;
        }

        List<RaspToken>? tokens = null;
        foreach (var inp in inputs)
        {
            if (inp.Value.Length < 3)
            {
                continue;
            }

            if (inp.Value == code)
            {
                return new RaspFinding(RaspAttackType.CodeInjection, "code.eval", inp);
            }

            foreach (var idx in RaspLexers.Occurrences(code!, inp.Value))
            {
                tokens ??= RaspLexers.CodeTokens(code!);
                if (RaspLexers.Overlapping(tokens, idx, inp.Value.Length).Count >= 2)
                {
                    return new RaspFinding(RaspAttackType.CodeInjection, "code.eval", inp);
                }
            }
        }

        if (RaspIastScope.Armed)
        {
            RaspIastScope.Note(() => RaspIastRules.Code(code!, inputs, () => tokens ??= RaspLexers.CodeTokens(code!))); // passive IAST
        }

        return null;
    }

    internal sealed record EntityDecl(string Name, bool External, string Uri, string Value);

    private static readonly Regex s_doctypeExt = Re(@"\s(SYSTEM|PUBLIC)\s");
    private static readonly Regex s_literal = Re("\"[^\"]*\"|'[^']*'");
    private static readonly Regex s_entityBody = Re(@"^(%\s+)?([^\s]+)\s+(.*)\z", RegexOptions.Singleline);
    private static readonly Regex s_externalId = Re("^(SYSTEM|PUBLIC)(?![A-Za-z0-9_])");

    private static List<string> Literals(string s) => s_literal.Matches(s).Cast<Match>().Select(m => m.Value).ToList();

    /// <summary>Reads the DOCTYPE: the external DTD id and the entity declarations.</summary>
    public static (bool HasDoctype, string? ExternalDtd, List<EntityDecl> Entities) ParseDoctype(string xml)
    {
        var at = IndexOf(xml, "<!DOCTYPE");
        var entities = new List<EntityDecl>();
        if (at < 0)
        {
            return (false, null, entities);
        }

        var head = Slice(xml, at, at + (64 * 1024));
        var bracket = head.IndexOf('[');
        var close = head.IndexOf('>');
        var decl = Slice(head, 0, bracket >= 0 && bracket < close ? bracket : close);
        var ext = s_doctypeExt.Match(decl);
        string? externalDtd = null;
        if (ext.Success)
        {
            var lits = Literals(decl.Substring(ext.Index));
            var pick = ext.Groups[1].Value == "PUBLIC" && lits.Count > 1 ? lits[1] : lits.Count > 0 ? lits[0] : string.Empty;
            externalDtd = Slice(pick, 1, -1);
        }

        var from = 0;
        while (entities.Count < 1000)
        {
            var i = IndexOf(head, "<!ENTITY", from);
            if (i < 0)
            {
                break;
            }

            var end = IndexOf(head, '>', i);
            var body = Trim(Slice(head, i + 8, end < 0 ? null : end));
            from = end < 0 ? head.Length : end + 1;
            var m = s_entityBody.Match(body);
            if (!m.Success)
            {
                continue;
            }

            var rest = Trim(m.Groups[3].Value);
            var lits = Literals(rest);
            var external = s_externalId.IsMatch(rest);
            var uriIndex = Starts(rest, "PUBLIC") ? 1 : 0;
            var uri = external ? Slice(lits.Count > uriIndex ? lits[uriIndex] : string.Empty, 1, -1) : string.Empty;
            var value = external ? string.Empty : Slice(lits.Count > 0 ? lits[0] : string.Empty, 1, -1);
            entities.Add(new EntityDecl(m.Groups[2].Value, external, uri, value));
        }

        return (true, externalDtd, entities);
    }

    private static readonly HashSet<string> s_xxeProtocols = new("ftp dict gopher netdoc mailto jar php expect".Split(' '), StringComparer.Ordinal);
    private static readonly Regex s_uriScheme = Re("^([a-z][a-z0-9+.-]*):", RegexOptions.IgnoreCase);
    private static readonly Regex s_fileScheme = Re("^file:(//)?", RegexOptions.IgnoreCase);
    private static readonly Regex s_schemaFile = Re(@"\.(dtd|xsd|xml)\z", RegexOptions.IgnoreCase);
    private static readonly Regex s_entityRef = Re(@"[&%][^\s;]+;");

    public static RaspFinding? Xml(string? xml, IReadOnlyList<RaspInput> inputs, bool resolvesExternal)
    {
        // Passive IAST: request data parsed by a parser that resolves external entities, DOCTYPE or not.
        if (RaspIastScope.Armed && !string.IsNullOrEmpty(xml) && resolvesExternal)
        {
            RaspIastScope.Note(() => RaspIastRules.Data("vuln.xml_external", xml!, TaintedData(xml, RequestOnly(inputs))));
        }

        if (string.IsNullOrEmpty(xml) || !Has(xml!, "<!DOCTYPE"))
        {
            return null;
        }

        var inp = TaintedData(xml, inputs);
        if (inp is null)
        {
            return null;
        }

        var d = ParseDoctype(xml!);
        var uris = d.Entities.Where(e => e.External).Select(e => e.Uri).ToList();
        if (d.ExternalDtd is not null)
        {
            uris.Add(d.ExternalDtd);
        }

        foreach (var u in uris)
        {
            var sm = s_uriScheme.Match(u);
            var scheme = sm.Success ? Lower(sm.Groups[1].Value) : null;
            if ((scheme is not null && s_xxeProtocols.Contains(scheme)) || Starts(u, "\\\\"))
            {
                return new RaspFinding(RaspAttackType.Xxe, "xxe.protocol", inp);
            }

            if (scheme == "file")
            {
                var p = s_fileScheme.Replace(u, string.Empty, 1);
                if ((Starts(p, "/") || s_driveOnly.IsMatch(p) || Has(p, "../")) && !s_schemaFile.IsMatch(p))
                {
                    return new RaspFinding(RaspAttackType.Xxe, "xxe.file", inp);
                }
            }
        }

        if (uris.Count > 0)
        {
            return new RaspFinding(RaspAttackType.Xxe, resolvesExternal ? "xxe.external_entity" : "xxe.doctype", inp);
        }

        var referencing = d.Entities.Count(e => !e.External && s_entityRef.IsMatch(e.Value));
        return referencing >= 3 ? new RaspFinding(RaspAttackType.Xxe, "xxe.billion_laughs", inp) : null;
    }

    // The contract's tag pattern (OpenRASP xss_userinput) includes control characters on purpose.
    private static readonly Regex s_xssTag = Re(@"<![\-\[A-Za-z]|<([A-Za-z]{1,12})[/>\x00-\x20]");
    private static readonly Regex s_xssHandler = Re(@"(?<![A-Za-z0-9_])on[a-z]{3,}\s*=", RegexOptions.IgnoreCase);
    public const int MaxXssBody = 1024 * 1024;

    /// <summary>An input <c>xss.reflected</c> looks for: 15 characters or more, with a tag, <c>javascript:</c> or an <c>on…=</c> handler.</summary>
    public static bool IsXssCandidate(RaspInput input)
    {
        var v = input.Value;
        return v.Length >= 15 && (s_xssTag.IsMatch(v) || Has(Lower(v), "javascript:") || s_xssHandler.IsMatch(v));
    }

    public static RaspFinding? Xss(string? contentType, string? body, IReadOnlyList<RaspInput> inputs)
    {
        if (string.IsNullOrEmpty(contentType) || !Has(Lower(contentType!), "html") || string.IsNullOrEmpty(body) || body!.Length > MaxXssBody)
        {
            return null;
        }

        foreach (var inp in inputs)
        {
            if (!IsXssCandidate(inp))
            {
                continue;
            }

            if (Has(body, inp.Value))
            {
                return new RaspFinding(RaspAttackType.Xss, "xss.reflected", inp);
            }
        }

        return null;
    }
}
