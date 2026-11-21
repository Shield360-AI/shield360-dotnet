using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Shield360.Rasp;

/// <summary>
/// Backdoor checks (sdk/rasp/README.md "Uploads", "Backdoor checks"): where uploaded
/// files were saved, per process and in memory only (resolved paths, at most 10,000,
/// each kept 24 hours), and the checks that fire when the app saves one somewhere
/// executable or served, loads it, runs it or makes it executable. The file and process
/// wrappers (<see cref="RaspFile"/>, <see cref="Shield360Rasp.StartProcess(System.Diagnostics.ProcessStartInfo)"/>,
/// <see cref="Shield360Rasp.CheckCommand"/>) call in; <see cref="Shield360Rasp.CheckChmod"/>,
/// <see cref="Shield360Rasp.CheckLoad"/> and <see cref="Shield360Rasp.CheckExtract"/>
/// cover permission changes, plugin loads and archive extraction. A port of the Go
/// SDK's upload_backdoor.go.
/// </summary>
internal static class RaspUploadBackdoor
{
    internal const int MaxLocations = 10_000;
    private static readonly TimeSpan s_ttl = TimeSpan.FromHours(24);
    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);
    private static readonly Regex s_interpreter = new("^(sh|bash|zsh|dash|ksh|python[0-9.]*|node|nodejs|perl|php[0-9.]*|ruby|cmd|powershell|pwsh)(\\.exe)?\\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_shell = new("^(sh|bash|zsh|dash|ksh|cmd|powershell|pwsh)(\\.exe)?\\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_sanitize = new("[^a-z0-9._-]", RegexOptions.CultureInvariant, s_timeout);
    private static readonly HashSet<string> s_servedSegs = new(StringComparer.Ordinal) { "public", "static", "www", "wwwroot", "htdocs", "webroot", "public_html" };

    private static readonly object s_lock = new();
    private static readonly Dictionary<string, LinkedListNode<(string Key, UploadVerdict V, DateTime Until)>> s_locations = new(StringComparer.Ordinal);
    private static readonly LinkedList<(string Key, UploadVerdict V, DateTime Until)> s_order = new();

    internal static Func<DateTime> Now { get; set; } = () => DateTime.UtcNow;

    /// <summary>Tests only.</summary>
    internal static void Reset()
    {
        lock (s_lock)
        {
            s_locations.Clear();
            s_order.Clear();
        }

        Now = () => DateTime.UtcNow;
    }

    internal static int Count
    {
        get
        {
            lock (s_lock)
            {
                return s_locations.Count;
            }
        }
    }

    private static string StripScheme(string p) => p.StartsWith("file://", StringComparison.Ordinal) ? p.Substring(7) : p;

    /// <summary>The resolved path and, when different, its real path.</summary>
    internal static List<string> KeysOf(string p)
    {
        var resolved = RaspDetect.ResolvePath(StripScheme(p));
        var keys = new List<string> { resolved };
        try
        {
#if NET8_0_OR_GREATER
            var info = new FileInfo(resolved);
            var target = info.Exists ? info.ResolveLinkTarget(returnFinalTarget: true)?.FullName : null;
            var dir = info.Directory?.ResolveLinkTarget(returnFinalTarget: true)?.FullName;
            var real = target ?? (dir is null ? null : Path.Combine(dir, info.Name));
            if (real is not null)
            {
                real = real.Replace('\\', '/');
                if (real != resolved)
                {
                    keys.Add(real);
                }
            }
#endif
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // not there (yet)
        }

        return keys;
    }

    /// <summary>Records a saved location; returns the resolved path.</summary>
    internal static string Remember(string p, UploadVerdict v)
    {
        var keys = KeysOf(p);
        lock (s_lock)
        {
            var now = Now();
            foreach (var k in keys)
            {
                if (s_locations.TryGetValue(k, out var old))
                {
                    s_order.Remove(old);
                    s_locations.Remove(k);
                }

                if (s_locations.Count >= MaxLocations)
                {
                    for (var n = s_order.First; n is not null;)
                    {
                        var next = n.Next;
                        if (n.Value.Until <= now)
                        {
                            s_locations.Remove(n.Value.Key);
                            s_order.Remove(n);
                        }

                        n = next;
                    }

                    while (s_locations.Count >= MaxLocations && s_order.First is { } first)
                    {
                        s_locations.Remove(first.Value.Key);
                        s_order.RemoveFirst();
                    }
                }

                s_locations[k] = s_order.AddLast((k, v, now + s_ttl));
            }
        }

        return keys[0];
    }

    /// <summary>The verdict of the upload saved at a path, or null.</summary>
    internal static UploadVerdict? At(string? p)
    {
        if (string.IsNullOrEmpty(p) || Count == 0)
        {
            return null;
        }

        foreach (var k in KeysOf(p!))
        {
            lock (s_lock)
            {
                if (!s_locations.TryGetValue(k, out var n))
                {
                    continue;
                }

                if (n.Value.Until <= Now())
                {
                    s_order.Remove(n);
                    s_locations.Remove(k);
                    continue;
                }

                return n.Value.V;
            }
        }

        return null;
    }

    internal static void Forget(IEnumerable<string> keys)
    {
        lock (s_lock)
        {
            foreach (var k in keys)
            {
                if (s_locations.TryGetValue(k, out var n))
                {
                    s_order.Remove(n);
                    s_locations.Remove(k);
                }
            }
        }
    }

    /// <summary>The known locations of an upload (the same hash).</summary>
    internal static List<string> LocationsOf(UploadVerdict v)
    {
        if (v.Sha256.Length == 0)
        {
            return new List<string>();
        }

        lock (s_lock)
        {
            return s_order.Where(x => x.V.Sha256 == v.Sha256).Select(x => x.Key).ToList();
        }
    }

    // ---- the request's uploads ---------------------------------------------------

    internal sealed record RequestUpload(string Name, UploadVerdict V);

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<RaspContext, List<RequestUpload>> s_requests = new();

    internal static void AddRequestUpload(RaspContext? ctx, string? name, UploadVerdict v)
    {
        if (ctx is null)
        {
            return;
        }

        var list = s_requests.GetValue(ctx, _ => new List<RequestUpload>());
        lock (list)
        {
            if (list.Count < RaspUploads.MaxRequestUploads)
            {
                list.Add(new RequestUpload(name ?? string.Empty, v));
            }
        }
    }

    internal static List<RequestUpload> RequestUploads()
    {
        var ctx = RaspScope.Current;
        if (ctx is null || !s_requests.TryGetValue(ctx, out var list))
        {
            return new List<RequestUpload>();
        }

        lock (list)
        {
            return new List<RequestUpload>(list);
        }
    }

    private static string BaseName(string p)
    {
        var s = p.Replace('\\', '/');
        var i = s.LastIndexOf('/');
        return i >= 0 ? s.Substring(i + 1) : s;
    }

    /// <summary>A file opened for writing named after one of the request's uploads (as sent, or sanitized).</summary>
    internal static UploadVerdict? Named(string p)
    {
        var ups = RequestUploads();
        if (ups.Count == 0)
        {
            return null;
        }

        var name = BaseName(p);
        foreach (var u in ups)
        {
            var n = BaseName(u.Name);
            if (n.Length > 0 && (n == name || s_sanitize.Replace(n.ToLowerInvariant(), "_") == name))
            {
                return u.V;
            }
        }

        return null;
    }

    /// <summary>A write whose data is one of the request's uploads (same size and SHA-256).</summary>
    internal static UploadVerdict? WithData(byte[] data)
    {
        string? sha = null;
        foreach (var u in RequestUploads())
        {
            if (u.V.Size == data.Length && u.V.Sha256.Length > 0)
            {
                if (sha is null)
                {
#if NET8_0_OR_GREATER
                    var digest = SHA256.HashData(data);
#else
                    using var h = SHA256.Create();
                    var digest = h.ComputeHash(data);
#endif
                    sha = string.Concat(digest.Select(b => b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture)));
                }

                if (sha == u.V.Sha256)
                {
                    return u.V;
                }
            }
        }

        return null;
    }

    // ---- the checks ------------------------------------------------------------------

    /// <summary>A server-script extension (file_write.script) or a server config name.</summary>
    internal static bool IsExecutableName(string p) => RaspDetect.s_scriptFile.IsMatch(BaseName(p)) || UploadScanner.IsServerConfigName(p);

    /// <summary>Kind script, html, svg or executable, or any finding other than the capped and policy ones.</summary>
    internal static bool IsActiveContent(UploadVerdict v) =>
        v.Kind is "script" or "html" or "svg" or "executable"
        || v.Findings.Any(f => !f.Capped && f.Rule != "upload.too_large" && f.Rule != "upload.type_not_allowed");

    /// <summary>Under one of servedDirs, or, without them, with a served directory segment.</summary>
    internal static bool IsServed(string resolved, IReadOnlyList<string> servedDirs)
    {
        var p = resolved.Replace('\\', '/');
        if (servedDirs.Count > 0)
        {
            foreach (var d in servedDirs)
            {
                var root = d.Replace('\\', '/').TrimEnd('/');
                if (p == root || p.StartsWith(root + "/", StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        var segs = p.Split('/');
        for (var i = 0; i < segs.Length - 1; i++)
        {
            if (s_servedSegs.Contains(segs[i].ToLowerInvariant()))
            {
                return true;
            }
        }

        return false;
    }

    internal static RaspFinding Finding(string rule, UploadVerdict v, string dest) =>
        new(RaspAttackType.UploadBackdoor, rule) { Upload = new UploadAttrs(v, null, null, dest) };

    /// <summary>Records a location and checks it.</summary>
    internal static RaspFinding? CheckNewLocation(string p, UploadVerdict v)
    {
        var resolved = Remember(p, v);
        var dest = RaspDetect.TargetDirectory(resolved);
        if (IsExecutableName(resolved))
        {
            return Finding("backdoor.write_executable", v, dest);
        }

        return IsServed(resolved, RaspUploads.ServedDirs()) && IsActiveContent(v) ? Finding("backdoor.write_served", v, dest) : null;
    }

    internal static RaspFinding? DetectWrite(string? p, string? source, byte[]? data)
    {
        if (string.IsNullOrEmpty(p))
        {
            return null;
        }

        var v = string.IsNullOrEmpty(source) ? null : At(source);
        v ??= Named(p!);
        if (v is null && data is not null)
        {
            v = WithData(data);
        }

        return v is null ? null : CheckNewLocation(p!, v);
    }

    private static RaspFinding? ExecWords(IReadOnlyList<string> words)
    {
        if (words.Count == 0)
        {
            return null;
        }

        var candidates = new List<string> { words[0] };
        if (s_interpreter.IsMatch(BaseName(words[0])))
        {
            var a = words.Skip(1).FirstOrDefault(x => !x.StartsWith("-", StringComparison.Ordinal));
            if (a is not null)
            {
                candidates.Add(a);
            }
        }

        foreach (var c in candidates)
        {
            if (At(c) is { } v)
            {
                return Finding("backdoor.exec", v, RaspDetect.TargetDirectory(RaspDetect.ResolvePath(c)));
            }
        }

        return null;
    }

    internal static RaspFinding? DetectExec(IReadOnlyList<string>? argv)
    {
        if (argv is null || argv.Count == 0)
        {
            return null;
        }

        if (ExecWords(argv) is { } f)
        {
            return f;
        }

        // sh -c "<command line>": each command of the line.
        if (s_shell.IsMatch(BaseName(argv[0])))
        {
            for (var i = 1; i + 1 < argv.Count; i++)
            {
                if (argv[i] is "-c" or "/c" or "-Command")
                {
                    return DetectShell(argv[i + 1]);
                }
            }
        }

        return null;
    }

    internal static RaspFinding? DetectShell(string command)
    {
        foreach (var seg in CommandSegments(command))
        {
            if (ExecWords(seg) is { } f)
            {
                return f;
            }
        }

        return null;
    }

    /// <summary>Splits a shell command line into the words of each command (quotes and backslashes honored; ; &amp; | and newlines split).</summary>
    internal static List<List<string>> CommandSegments(string command)
    {
        var segments = new List<List<string>>();
        var words = new List<string>();
        var cur = new StringBuilder();
        var has = false;
        var q = '\0';
        void End()
        {
            if (has || cur.Length > 0)
            {
                words.Add(cur.ToString());
            }

            cur.Clear();
            has = false;
        }

        var n = command.Length;
        for (var i = 0; i < n; i++)
        {
            var c = command[i];
            if (q == '\'')
            {
                if (c == '\'')
                {
                    q = '\0';
                }
                else
                {
                    cur.Append(c);
                }
            }
            else if (q == '"')
            {
                if (c == '"')
                {
                    q = '\0';
                }
                else if (c == '\\' && i + 1 < n && "\"\\$`".IndexOf(command[i + 1]) >= 0)
                {
                    cur.Append(command[++i]);
                }
                else
                {
                    cur.Append(c);
                }
            }
            else if (c == '\'' || c == '"')
            {
                q = c;
                has = true;
            }
            else if (c == '\\' && i + 1 < n)
            {
                cur.Append(command[++i]);
                has = true;
            }
            else if (c is ';' or '&' or '|' or '\n')
            {
                End();
                if (words.Count > 0)
                {
                    segments.Add(words);
                }

                words = new List<string>();
            }
            else if (c is ' ' or '\t' or '\r' or '\v' or '\f')
            {
                End();
            }
            else
            {
                cur.Append(c);
            }
        }

        End();
        if (words.Count > 0)
        {
            segments.Add(words);
        }

        return segments;
    }

    internal static RaspFinding? PathFinding(string rule, string p) =>
        At(p) is { } v ? Finding(rule, v, RaspDetect.TargetDirectory(RaspDetect.ResolvePath(StripScheme(p)))) : null;

    internal static RaspFinding? ExtractFinding(string archive)
    {
        var v = At(archive);
        return v is not null && v.Findings.Any(f => f.Rule is "upload.archive_traversal" or "upload.archive_symlink")
            ? Finding("backdoor.extract", v, RaspDetect.TargetDirectory(RaspDetect.ResolvePath(StripScheme(archive))))
            : null;
    }

    /// <summary>Nothing to do while no upload location is known and the request inspected none.</summary>
    internal static bool AnyKnown() => Count > 0 || RequestUploads().Count > 0;

    /// <summary>Runs a backdoor check through the sink (fail open, the block error thrown).</summary>
    internal static RaspDecision? Check(string sink, Func<RaspFinding?> detect) => RaspEngine.IsActive ? RaspEngine.Check(sink, detect) : null;

    internal static void CheckWrite(string sink, string? path, string? source = null, byte[]? data = null)
    {
        if (RaspEngine.IsActive && AnyKnown())
        {
            Check(sink, () => DetectWrite(path, source, data));
        }
    }

    internal static void CheckExec(string sink, IReadOnlyList<string> argv)
    {
        if (RaspEngine.IsActive && AnyKnown())
        {
            Check(sink, () => DetectExec(argv));
        }
    }

    internal static void CheckShell(string sink, string command)
    {
        if (RaspEngine.IsActive && AnyKnown())
        {
            Check(sink, () => DetectShell(command));
        }
    }
}
