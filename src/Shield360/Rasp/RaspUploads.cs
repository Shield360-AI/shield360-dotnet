#pragma warning disable CA1861 // small literal arrays on cold paths
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Shield360.Rasp;

/// <summary>One inspection finding (a malicious_upload rule).</summary>
public sealed class UploadFileFinding
{
    /// <summary>Creates a finding.</summary>
    public UploadFileFinding(string rule, string engine, string? signature = null)
    {
        Rule = rule;
        Engine = engine;
        Signature = signature ?? string.Empty;
        Capped = UploadScanner.Capped.Contains(rule);
    }

    /// <summary>The rule (upload.webshell, ...).</summary>
    public string Rule { get; }

    /// <summary>builtin, custom, policy, clamav or reputation.</summary>
    public string Engine { get; }

    /// <summary>The signature that matched, or "".</summary>
    public string Signature { get; }

    /// <summary>A rule that never blocks (monitor at most).</summary>
    public bool Capped { get; }
}

/// <summary>What a file is.</summary>
public sealed class UploadVerdict
{
    /// <summary>Creates a verdict.</summary>
    public UploadVerdict(string type, string kind, long size, string sha256, string ext, IReadOnlyList<UploadFileFinding> findings)
    {
        Type = type;
        Kind = kind;
        Size = size;
        Sha256 = sha256 ?? string.Empty;
        Ext = ext ?? string.Empty;
        Findings = findings;
    }

    /// <summary>The real type (jpeg, zip, php, ...).</summary>
    public string Type { get; }

    /// <summary>The kind (image, archive, script, ...).</summary>
    public string Kind { get; }

    /// <summary>Bytes.</summary>
    public long Size { get; }

    /// <summary>Only when the inspector saw every byte; "" otherwise.</summary>
    public string Sha256 { get; }

    /// <summary>The name's extension.</summary>
    public string Ext { get; }

    /// <summary>The findings, in README "Inspection rules" order.</summary>
    public IReadOnlyList<UploadFileFinding> Findings { get; }
}

/// <summary>README "Upload event attributes".</summary>
internal sealed class UploadAttrs
{
    public UploadAttrs(UploadVerdict v, string? signature, string? engine, string? dest)
    {
        Type = v.Type;
        Kind = v.Kind;
        Ext = v.Ext;
        Size = v.Size;
        Sha256 = v.Sha256;
        Signature = signature ?? string.Empty;
        Engine = engine ?? string.Empty;
        Dest = dest ?? string.Empty;
    }

    public string Type { get; }

    public string Kind { get; }

    public string Ext { get; }

    public long Size { get; }

    public string Sha256 { get; }

    public string Signature { get; }

    public string Engine { get; }

    public string Dest { get; }

    public string? Action { get; set; }
}

/// <summary>What <see cref="RaspUploads.Inspect(Stream, string?, string?, UploadOptions?)"/> applies: the policy (README "Upload policy and deep scan"). The defaults are no policy.</summary>
public sealed class UploadOptions
{
    /// <summary>The form field (the event's input key body.&lt;field&gt;.filename); "file" when empty.</summary>
    public string Field { get; set; } = string.Empty;

    /// <summary>Types or kinds; empty is any type. A type listed by name gets past the type checks.</summary>
    public IReadOnlyList<string> Allow { get; set; } = Array.Empty<string>();

    /// <summary>0 is no limit.</summary>
    public long MaxBytes { get; set; }

    /// <summary>When set, decides the built-in findings instead of malicious_upload's mode.</summary>
    public RaspMode? Mode { get; set; }

    /// <summary>The organization's own signatures (decided by <see cref="DeepScanMode"/>).</summary>
    public IReadOnlyList<UploadSignature> Signatures { get; set; } = Array.Empty<UploadSignature>();

    /// <summary>The deep scan's mode.</summary>
    public RaspMode? DeepScanMode { get; set; }

    /// <summary>The deep scan engines (ClamAV, reputation) and how they run.</summary>
    public DeepScanOptions DeepScan { get; set; } = new();

    /// <summary>SHA-256 hashes marked safe.</summary>
    public IReadOnlyCollection<string> Trusted { get; set; } = Array.Empty<string>();

    /// <summary>How many bytes the signatures read (0: 8 MiB).</summary>
    public long ScanBytes { get; set; }

    /// <summary>Starts an inspection with these options.</summary>
    public UploadScanner NewScanner(string? name, string? contentType) =>
        new(name, contentType, ScanBytes, DeepScanMode is RaspMode m && m != RaspMode.Off ? Signatures : null, Trusted);

    internal bool IsTrusted(string sha) => sha.Length > 0 && Trusted.Contains(sha);

    internal UploadOptions Copy() => new()
    {
        Field = Field, Allow = Allow, MaxBytes = MaxBytes, Mode = Mode, Signatures = Signatures, DeepScanMode = DeepScanMode,
        DeepScan = DeepScan.Copy(), Trusted = Trusted, ScanBytes = ScanBytes,
    };
}

/// <summary>One route's upload policy.</summary>
public sealed class UploadRoutePolicy
{
    /// <summary>The route (a prefix when it ends in *).</summary>
    public string Route { get; init; } = "/";

    /// <summary>Null keeps the app's list.</summary>
    public IReadOnlyList<string>? Allow { get; init; }

    /// <summary>0 keeps the app's.</summary>
    public long MaxBytes { get; init; }

    /// <summary>The built-in findings' mode, or null.</summary>
    public RaspMode? Mode { get; init; }

    /// <summary>The deep scan's mode, or null.</summary>
    public RaspMode? DeepScan { get; init; }

    /// <summary>"sync", "async" or null.</summary>
    public string? Scan { get; init; }

    /// <summary>0 keeps the deep scan's.</summary>
    public long TimeoutMs { get; init; }

    /// <summary>"open", "closed" or null.</summary>
    public string? FailMode { get; init; }
}

/// <summary>The signed config's uploads block (or the local options).</summary>
public sealed class UploadPolicy
{
    /// <summary>Types or kinds; empty is any.</summary>
    public IReadOnlyList<string> Allow { get; init; } = Array.Empty<string>();

    /// <summary>0 is no limit.</summary>
    public long MaxBytes { get; init; }

    /// <summary>Directories the web server serves (the backdoor checks).</summary>
    public IReadOnlyList<string> ServedDirs { get; init; } = Array.Empty<string>();

    /// <summary>SHA-256 hashes marked safe.</summary>
    public IReadOnlyCollection<string> Trusted { get; init; } = Array.Empty<string>();

    /// <summary>The organization's own signatures.</summary>
    public IReadOnlyList<UploadSignature> Signatures { get; init; } = Array.Empty<UploadSignature>();

    /// <summary>The deep scan's mode.</summary>
    public RaspMode DeepScanMode { get; init; } = RaspMode.Off;

    /// <summary>The deep scan engines.</summary>
    public DeepScanOptions DeepScan { get; init; } = new();

    /// <summary>Per-route policies.</summary>
    public IReadOnlyList<UploadRoutePolicy> Routes { get; init; } = Array.Empty<UploadRoutePolicy>();

    private static RaspMode? Mode(JsonElement m, string k) => m.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? RaspNames.Mode(v.GetString()) : null;

    private static long PositiveInt(JsonElement m, string k)
    {
        if (m.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number)
        {
            var d = v.GetDouble();
            if (d >= 1 && d == Math.Floor(d) && d < 9.0e18)
            {
                return (long)d;
            }
        }

        return 0;
    }

    internal static long TimeoutMs(JsonElement m, string k)
    {
        if (!m.TryGetProperty(k, out var v) || v.ValueKind != JsonValueKind.Number)
        {
            return 0;
        }

        var d = v.GetDouble();
        return double.IsNaN(d) || double.IsInfinity(d) ? 0 : Math.Min(60000, Math.Max(100, (long)d));
    }

    private static List<string> Strings(JsonElement m, string k, int max, Func<string, bool> keep)
    {
        var out_ = new List<string>();
        if (m.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in v.EnumerateArray())
            {
                if (x.ValueKind == JsonValueKind.String && keep(x.GetString()!) && out_.Count < max)
                {
                    out_.Add(x.GetString()!);
                }
            }
        }

        return out_;
    }

    private static readonly HashSet<string> s_kinds = new(StringComparer.Ordinal) { "image", "document", "text", "archive", "media", "executable", "script", "html", "svg", "other" };

    private static bool AllowedName(string s) => UploadScanner.KnownType(s) || s_kinds.Contains(s);

    /// <summary>Reads the signed config's uploads block; null when absent or not an object.</summary>
    public static UploadPolicy? Parse(JsonElement? raw)
    {
        if (raw is not { ValueKind: JsonValueKind.Object } m)
        {
            return null;
        }

        var deep = m.TryGetProperty("deepScan", out var d) ? d : default;
        var routes = new List<UploadRoutePolicy>();
        if (m.TryGetProperty("routes", out var rs) && rs.ValueKind == JsonValueKind.Array)
        {
            foreach (var r in rs.EnumerateArray())
            {
                if (r.ValueKind != JsonValueKind.Object || !r.TryGetProperty("route", out var rv) || rv.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                var route = rv.GetString()!;
                if (!route.StartsWith("/", StringComparison.Ordinal) || route.Length > 256 || routes.Count >= 64)
                {
                    continue;
                }

                var sc = r.TryGetProperty("scan", out var scv) && scv.ValueKind == JsonValueKind.String ? scv.GetString() : null;
                var fm = r.TryGetProperty("failMode", out var fmv) && fmv.ValueKind == JsonValueKind.String ? fmv.GetString() : null;
                routes.Add(new UploadRoutePolicy
                {
                    Route = route,
                    Allow = r.TryGetProperty("allow", out _) ? Strings(r, "allow", 64, AllowedName) : null,
                    MaxBytes = PositiveInt(r, "maxBytes"),
                    Mode = Mode(r, "mode"),
                    DeepScan = Mode(r, "deepScan"),
                    Scan = sc is "sync" or "async" ? sc : null,
                    TimeoutMs = TimeoutMs(r, "timeoutMs"),
                    FailMode = fm is "open" or "closed" ? fm : null,
                });
            }
        }

        return new UploadPolicy
        {
            Allow = Strings(m, "allow", 64, AllowedName),
            MaxBytes = PositiveInt(m, "maxBytes"),
            Trusted = new HashSet<string>(Strings(m, "trusted", 1000, s => RaspUploads.ShaShape.IsMatch(s)), StringComparer.Ordinal),
            Signatures = m.TryGetProperty("rules", out var rules) ? UploadSignatures.CompileAll(rules).Signatures : Array.Empty<UploadSignature>(),
            DeepScan = DeepScanOptions.Parse(deep),
            DeepScanMode = deep.ValueKind == JsonValueKind.Object ? Mode(deep, "mode") ?? RaspMode.Off : RaspMode.Off,
            ServedDirs = Strings(m, "servedDirs", 32, s => RaspUploads.IsAbsPath(s) && s.Length <= 512),
            Routes = routes,
        };
    }

    /// <summary>The block from JSON text; null when it is not an object.</summary>
    public static UploadPolicy? Parse(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(json!);
            return Parse(doc.RootElement);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>
/// Upload protection (sdk/rasp/README.md "Uploads"): inspect each uploaded file, apply
/// the signed upload policy, run the deep scan and remember where uploads were saved
/// for the backdoor checks. A port of the Go SDK's <c>InspectUpload</c>,
/// <c>UploadOptionsFor</c> and <c>UploadSaved</c>. The ASP.NET Core middleware
/// inspects every multipart file part; apps that read uploads themselves call
/// <see cref="Inspect(Stream, string?, string?, UploadOptions?)"/> (or
/// <see cref="InspectAsync"/>) for each file with <see cref="OptionsFor"/> the route,
/// and <see cref="Saved"/> once they store it.
/// </summary>
public static class RaspUploads
{
    /// <summary>The request sink of the inspection's event.</summary>
    public const string Sink = "request.upload";

    internal const int MaxRequestUploads = 64;
    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);
    internal static readonly Regex ShaShape = new("^[0-9a-f]{64}\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_word = new("^[a-z0-9_]{1,16}\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_sig = new("^[A-Za-z0-9._:/-]{1,128}\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_drive = new("^[A-Za-z]:/", RegexOptions.CultureInvariant, s_timeout);
    private static readonly HashSet<string> s_engines = new(StringComparer.Ordinal) { "builtin", "custom", "clamav", "reputation", "policy" };
    private static readonly HashSet<string> s_typeRules = new(StringComparer.Ordinal) { "upload.executable", "upload.script", "upload.type_mismatch" };

    internal static bool IsAbsPath(string? p) => p is not null && (p.StartsWith("/", StringComparison.Ordinal) || s_drive.IsMatch(p));

    /// <summary>
    /// Reads an uploaded file (bounded memory), reports what it is (README "Inspection
    /// rules": one event a file, the strongest decision) and returns the verdict. Throws
    /// <see cref="Shield360RaspBlockedException"/> when it must be refused. With a sync
    /// deep scan the engines read the same bytes as they pass.
    /// </summary>
    public static UploadVerdict Inspect(Stream stream, string? name, string? contentType, UploadOptions? options = null)
    {
        var o = options ?? new UploadOptions();
        var (v, blocked) = InspectCore(stream, name, contentType, o, !o.DeepScan.Async, null);
        return blocked is null ? v : throw blocked;
    }

    /// <summary>Inspects bytes in memory with these options (reporting as <see cref="Inspect(Stream, string?, string?, UploadOptions?)"/> does).</summary>
    public static UploadVerdict Inspect(byte[] data, string? name, string? contentType, UploadOptions? options = null)
    {
        using var ms = new MemoryStream(data ?? Array.Empty<byte>(), writable: false);
        return Inspect(ms, name, contentType, options);
    }

    /// <summary><see cref="Inspect(Stream, string?, string?, UploadOptions?)"/> reading the stream asynchronously (an ASP.NET Core request body).</summary>
    public static async Task<UploadVerdict> InspectAsync(Stream stream, string? name, string? contentType, UploadOptions? options = null, CancellationToken cancellationToken = default)
    {
        var o = options ?? new UploadOptions();
        var (v, blocked) = await InspectCoreAsync(stream, name, contentType, o, null, cancellationToken).ConfigureAwait(false);
        return blocked is null ? v : throw blocked;
    }

    internal static async Task<(UploadVerdict Verdict, Shield360RaspBlockedException? Blocked)> InspectCoreAsync(
        Stream stream, string? name, string? contentType, UploadOptions o, RaspContext? ctx, CancellationToken cancellationToken)
    {
        using var s = o.NewScanner(name, contentType);
        var run = !o.DeepScan.Async && RaspEngine.IsActive ? RaspDeepScan.Start(o) : null;
        var buf = new byte[64 * 1024];
        try
        {
            int n;
#if NET8_0_OR_GREATER
            while ((n = await stream.ReadAsync(buf.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
#else
            while ((n = await stream.ReadAsync(buf, 0, buf.Length, cancellationToken).ConfigureAwait(false)) > 0)
#endif
            {
                s.Push(buf, 0, n);
                run?.Write(buf, 0, n);
            }
        }
        catch (IOException)
        {
            RaspDeepScan.Abort(run);
            return (s.Finish(false), null);
        }

        return Decide(s.Finish(true), name, o, run, ctx);
    }

    internal static (UploadVerdict Verdict, Shield360RaspBlockedException? Blocked) InspectCore(Stream stream, string? name, string? contentType, UploadOptions o, bool deep, RaspContext? ctx)
    {
        using var s = o.NewScanner(name, contentType);
        var run = deep && RaspEngine.IsActive ? RaspDeepScan.Start(o) : null;
        var buf = new byte[64 * 1024];
        try
        {
            int n;
            while ((n = stream.Read(buf, 0, buf.Length)) > 0)
            {
                s.Push(buf, 0, n);
                run?.Write(buf, 0, n);
            }
        }
        catch (IOException)
        {
            RaspDeepScan.Abort(run);
            return (s.Finish(false), null);
        }

        return Decide(s.Finish(true), name, o, run, ctx);
    }

    private static (UploadVerdict, Shield360RaspBlockedException?) Decide(UploadVerdict v, string? name, UploadOptions o, RaspDeepScan.Run? run, RaspContext? ctx)
    {
        if (!RaspEngine.IsActive)
        {
            RaspDeepScan.Abort(run);
            return (v, null);
        }

        var context = ctx ?? RaspScope.Current;
        RaspUploadBackdoor.AddRequestUpload(context, name, v);
        var extra = context is null ? null : new FindingExtra(context.Framework, context.ResolvedRoute(), context.Method, context.Path, context);
        if (Strongest(Findings(v, o)) is { } best)
        {
            try
            {
                RaspEngine.HandleFinding(best, Sink, extra);
            }
            catch (Shield360RaspBlockedException e)
            {
                RaspDeepScan.Abort(run);
                return (v, e);
            }
        }

        if (run is null)
        {
            return (v, null);
        }

        if (o.IsTrusted(v.Sha256))
        {
            RaspDeepScan.Abort(run);
            return (v, null);
        }

        if (run.Finish(v.Sha256, true) is { } f)
        {
            try
            {
                RaspEngine.HandleFinding(RaspDeepScan.Finding(f, v, o), RaspDeepScan.Sink, extra);
            }
            catch (Shield360RaspBlockedException e)
            {
                return (v, e);
            }
        }

        return (v, null);
    }

    /// <summary>
    /// Inspects an upload already on disk (a temp file): the built-in checks, then, with
    /// a sync deep scan, the engines on the file. The location is remembered. A blocked
    /// file is moved to quarantine and the block error thrown.
    /// </summary>
    public static UploadVerdict InspectFile(string path, string? name, string? contentType, UploadOptions? options = null)
    {
        var o = options ?? new UploadOptions();
        UploadVerdict v;
        Shield360RaspBlockedException? blocked;
        using (var f = File.OpenRead(path))
        {
            (v, blocked) = InspectCore(f, name, contentType, o, !o.DeepScan.Async, null);
        }

        if (RaspEngine.IsActive)
        {
            RaspUploadBackdoor.Remember(path, v);
        }

        if (blocked is not null)
        {
            var keys = RaspUploadBackdoor.KeysOf(path);
            if (RaspDeepScan.Quarantine(path, v.Sha256))
            {
                RaspUploadBackdoor.Forget(keys);
            }

            throw blocked;
        }

        if (o.DeepScan.Async && RaspEngine.IsActive && RaspDeepScan.On(o) && !o.IsTrusted(v.Sha256))
        {
            RaspDeepScan.Async(path, v, o);
        }

        return v;
    }

    /// <summary>
    /// Tells RASP where the app saved an upload it inspected: the location is remembered
    /// for the backdoor checks and checked now (backdoor.write_executable,
    /// backdoor.write_served; a blocked one is moved to quarantine and the block error
    /// thrown), and with an async deep scan the engines scan the saved file in the background.
    /// </summary>
    public static void Saved(string path, UploadVerdict verdict, UploadOptions? options = null)
    {
        if (!RaspEngine.IsActive || string.IsNullOrEmpty(path) || verdict is null)
        {
            return;
        }

        try
        {
            RaspUploadBackdoor.Check("upload.save", () => RaspUploadBackdoor.CheckNewLocation(path, verdict));
        }
        catch (Shield360RaspBlockedException)
        {
            var keys = RaspUploadBackdoor.KeysOf(path);
            if (RaspDeepScan.Quarantine(path, verdict.Sha256))
            {
                RaspUploadBackdoor.Forget(keys);
            }

            throw;
        }

        var o = options ?? new UploadOptions();
        if (o.DeepScan.Async && RaspDeepScan.On(o) && !o.IsTrusted(verdict.Sha256))
        {
            RaspDeepScan.Async(path, verdict, o);
        }
    }

    /// <summary>
    /// Applies the policy (allow list, maxBytes, a listed type passing the type checks) to
    /// a verdict: one malicious_upload finding per rule, in README "Inspection rules"
    /// order, each carrying the mode that decides it.
    /// </summary>
    internal static List<RaspFinding> Findings(UploadVerdict v, UploadOptions o)
    {
        var fs = new List<UploadFileFinding>(v.Findings);
        var listed = o.Allow.Contains(v.Type) || o.Allow.Contains(v.Kind);
        if (o.Allow.Count > 0 && !listed)
        {
            fs.Add(new UploadFileFinding("upload.type_not_allowed", "policy"));
        }

        if (o.MaxBytes > 0 && v.Size > o.MaxBytes)
        {
            fs.Add(new UploadFileFinding("upload.too_large", "policy"));
        }

        if (listed)
        {
            fs.RemoveAll(f => s_typeRules.Contains(f.Rule));
        }

        var input = Input(o);
        return UploadScanner.Sorted(fs).Select(f => new RaspFinding(RaspAttackType.MaliciousUpload, f.Rule, input, Action: f.Capped ? RaspMode.Monitor : null)
        {
            Mode = f.Engine == "custom" ? o.DeepScanMode : o.Mode,
            Upload = new UploadAttrs(v, f.Signature, f.Engine, null),
        }).ToList();
    }

    internal static RaspInput Input(UploadOptions o) => new(string.Empty, "body." + (string.IsNullOrEmpty(o.Field) ? "file" : o.Field) + ".filename");

    /// <summary>The finding with the strongest decision, the rule order breaking ties; null when none decides more than off.</summary>
    internal static RaspFinding? Strongest(IEnumerable<RaspFinding> findings)
    {
        RaspFinding? best = null;
        var bestRank = 0;
        foreach (var f in findings)
        {
            var r = RaspNames.Rank(RaspEngine.EffectiveUploadMode(f));
            if (r > bestRank)
            {
                best = f;
                bestRank = r;
            }
        }

        return best;
    }

    /// <summary>README "Upload event attributes", each only when it has its shape.</summary>
    internal static void AddAttrs(IDictionary<string, string> attrs, RaspFinding f)
    {
        var u = f.Upload;
        if (u is null || (f.Attack != RaspAttackType.MaliciousUpload && f.Attack != RaspAttackType.UploadBackdoor))
        {
            return;
        }

        const string P = "shield360.rasp.upload.";
        if (s_word.IsMatch(u.Type))
        {
            attrs[P + "type"] = u.Type;
        }

        if (s_word.IsMatch(u.Kind))
        {
            attrs[P + "kind"] = u.Kind;
        }

        if (UploadScanner.ExtShape.IsMatch(u.Ext))
        {
            attrs[P + "ext"] = u.Ext;
        }

        if (u.Size >= 0)
        {
            attrs[P + "size"] = u.Size.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        if (ShaShape.IsMatch(u.Sha256))
        {
            attrs[P + "sha256"] = u.Sha256;
        }

        if (s_sig.IsMatch(u.Signature))
        {
            attrs[P + "signature"] = u.Signature;
        }

        if (s_engines.Contains(u.Engine))
        {
            attrs[P + "engine"] = u.Engine;
        }

        if (u.Dest.Length > 0 && RaspEngine.MaskTarget(u.Dest) is { Length: > 0 } d)
        {
            attrs[P + "dest"] = d;
        }

        if (u.Action == "quarantined")
        {
            attrs[P + "action"] = "quarantined";
        }
    }

    // ---- policy for a route -------------------------------------------------

    private sealed record Local(UploadPolicy? Policy, long ScanBytes);

    private static Local s_local = new(null, 0);

    /// <summary>
    /// Sets the local upload options, used without a signed config: the uploads block as
    /// JSON (the signed config's shape), the scan size and the quarantine directory.
    /// </summary>
    internal static void SetLocal(string? policyJson, long scanBytes, string? quarantineDir)
    {
        Volatile.Write(ref s_local, new Local(UploadPolicy.Parse(policyJson), scanBytes));
        RaspDeepScan.SetQuarantineDir(quarantineDir);
    }

    /// <summary>The served directories the backdoor checks use (the signed config's, else the local ones).</summary>
    internal static IReadOnlyList<string> ServedDirs() =>
        RaspEngine.Remote?.Uploads?.ServedDirs ?? Volatile.Read(ref s_local).Policy?.ServedDirs ?? Array.Empty<string>();

    /// <summary>
    /// The policy for a route from the verified signed config (the first route that equals
    /// it, or a prefix ending in *, else the app's), else the local options.
    /// </summary>
    public static UploadOptions OptionsFor(string? route)
    {
        var local = Volatile.Read(ref s_local);
        var p = RaspEngine.Remote?.Uploads ?? local.Policy;
        var o = new UploadOptions();
        if (p is null)
        {
            return o;
        }

        o.Allow = p.Allow;
        o.MaxBytes = p.MaxBytes;
        o.Signatures = p.Signatures;
        o.DeepScanMode = p.DeepScanMode;
        o.DeepScan = p.DeepScan.Copy();
        o.Trusted = p.Trusted;
        o.ScanBytes = local.ScanBytes;
        var rt = route ?? string.Empty;
        foreach (var rp in p.Routes)
        {
            var match = rp.Route.EndsWith("*", StringComparison.Ordinal) ? rt.StartsWith(rp.Route.Substring(0, rp.Route.Length - 1), StringComparison.Ordinal) : rp.Route == rt;
            if (!match)
            {
                continue;
            }

            if (rp.Allow is not null)
            {
                o.Allow = rp.Allow;
            }

            if (rp.MaxBytes > 0)
            {
                o.MaxBytes = rp.MaxBytes;
            }

            o.Mode = rp.Mode;
            if (rp.DeepScan is not null)
            {
                o.DeepScanMode = rp.DeepScan;
            }

            if (rp.Scan is not null)
            {
                o.DeepScan.Async = rp.Scan == "async";
            }

            if (rp.TimeoutMs > 0)
            {
                o.DeepScan.TimeoutMs = rp.TimeoutMs;
            }

            if (rp.FailMode is not null)
            {
                o.DeepScan.FailClosed = rp.FailMode == "closed";
            }

            break;
        }

        return o;
    }
}
