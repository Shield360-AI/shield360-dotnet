using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Shield360.Internal;
using Shield360.Rasp;

namespace Shield360;

/// <summary>
/// SHIELD: runtime SCA — the NuGet packages this process has loaded, reported to
/// Shield360 so it can match them against vulnerability data server-side
/// (Security → Code, target type "runtime").
/// <para>
/// On by default whenever the SDK has a Shield360 URL and API key, whether or not
/// runtime protection is on; <see cref="Shield360Options.RuntimePackages"/> =
/// <c>false</c> or <c>SHIELD360_RUNTIME_PACKAGES=off</c> turns it off. The report
/// is the same <c>shield360.rasp.component</c> record runtime protection sends, on
/// the same route (<c>POST /api/guard/events</c>, the app's API key): the .NET
/// version and, for every loaded assembly that is not part of the runtime, the
/// NuGet package it came from as the app's <c>.deps.json</c> names it (package id
/// and version), or else its assembly name and version. Names and versions only,
/// never a path; at most <see cref="RaspReporter.MaxComponents"/>. Sent shortly
/// after start and then every day on the thread pool; a report that cannot be
/// delivered is dropped.
/// </para>
/// Must stay in step with sdk/typescript/src/runtime-packages.ts.
/// </summary>
internal static class RuntimePackages
{
    public static readonly TimeSpan StartDelay = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan Every = TimeSpan.FromHours(24);
    private const int Batch = 100;
    private const long MaxDepsBytes = 8 * 1024 * 1024;
    private static readonly Regex s_off = new("^(off|false|0|no)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex s_name = new("^[A-Za-z0-9@_][A-Za-z0-9@/._+~-]{0,213}\\z", RegexOptions.CultureInvariant);
    private static readonly Regex s_version = new("^v?[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}\\z", RegexOptions.CultureInvariant);
    private static readonly char[] s_separator = { ';' };
    private static readonly object s_lock = new();
    private static Timer? s_timer;

    /// <summary>Whether the report runs: <paramref name="option"/> = false, or SHIELD360_RUNTIME_PACKAGES=off|false|0|no, turns it off.</summary>
    public static bool Enabled(bool? option, Func<string, string?> env) =>
        option != false && !s_off.IsMatch((env("SHIELD360_RUNTIME_PACKAGES") ?? string.Empty).Trim());

    /// <summary>Whether the report is running (runtime protection then leaves its components report to it).</summary>
    public static bool Active
    {
        get
        {
            lock (s_lock)
            {
                return s_timer is not null;
            }
        }
    }

    /// <summary>Assembly file name (case-insensitive) → the NuGet package that ships it, from a <c>.deps.json</c>.</summary>
    public static Dictionary<string, (string Id, string Version)> PackagesByAssembly(string? depsJson)
    {
        var map = new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase);
        if (depsJson is null || depsJson.Length == 0)
        {
            return map;
        }

        try
        {
            using var doc = JsonDocument.Parse(depsJson);
            var root = doc.RootElement;
            var packages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (root.TryGetProperty("libraries", out var libraries) && libraries.ValueKind == JsonValueKind.Object)
            {
                foreach (var lib in libraries.EnumerateObject())
                {
                    if (lib.Value.ValueKind == JsonValueKind.Object && lib.Value.TryGetProperty("type", out var type) && type.ValueKind == JsonValueKind.String && type.GetString() == "package")
                    {
                        packages.Add(lib.Name);
                    }
                }
            }

            if (!root.TryGetProperty("targets", out var targets) || targets.ValueKind != JsonValueKind.Object)
            {
                return map;
            }

            foreach (var target in targets.EnumerateObject())
            {
                if (target.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (var lib in target.Value.EnumerateObject())
                {
                    var slash = lib.Name.IndexOf('/');
                    if (slash <= 0 || !packages.Contains(lib.Name) || lib.Value.ValueKind != JsonValueKind.Object || !lib.Value.TryGetProperty("runtime", out var runtime) || runtime.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var id = lib.Name.Substring(0, slash);
                    var version = lib.Name.Substring(slash + 1);
                    foreach (var file in runtime.EnumerateObject())
                    {
                        var name = Path.GetFileName(file.Name);
                        if (name.Length > 0 && !map.ContainsKey(name))
                        {
                            map[name] = (id, version);
                        }
                    }
                }
            }
        }
        catch (JsonException)
        {
            // an unreadable deps file maps nothing
        }

        return map;
    }

    /// <summary>The app's own <c>.deps.json</c> text, or null (single-file apps and hosts without one).</summary>
    private static string? ReadDepsFile()
    {
        try
        {
            var files = AppContext.GetData("APP_CONTEXT_DEPS_FILES") as string;
            var path = files?.Split(s_separator, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (string.IsNullOrEmpty(path))
            {
                var entry = Assembly.GetEntryAssembly()?.Location;
                path = string.IsNullOrEmpty(entry) ? null : Path.ChangeExtension(entry, ".deps.json");
            }

            if (path is null || !File.Exists(path) || new FileInfo(path).Length > MaxDepsBytes)
            {
                return null;
            }

            return File.ReadAllText(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// The runtime and the packages of the loaded assemblies: NuGet id and version from
    /// the deps file where it names the assembly's file, else the assembly's name and
    /// version (as runtime protection reports it). Names and versions only; at most 500.
    /// </summary>
    public static List<RaspComponent> Collect(IEnumerable<Assembly>? assemblies = null, string? depsJson = null)
    {
        var byFile = PackagesByAssembly(depsJson ?? ReadDepsFile());
        var list = assemblies?.ToList() ?? AppDomain.CurrentDomain.GetAssemblies().ToList();
        var fallback = RaspComponents.Collect(list);
        var output = new List<RaspComponent> { fallback[0] };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var mapped = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in list)
        {
            if (output.Count >= RaspReporter.MaxComponents)
            {
                break;
            }

            try
            {
                if (a.IsDynamic || string.IsNullOrEmpty(a.Location) || !byFile.TryGetValue(Path.GetFileName(a.Location), out var pkg))
                {
                    continue;
                }

                mapped.Add(a.GetName().Name ?? string.Empty);
                if (s_name.IsMatch(pkg.Id) && s_version.IsMatch(pkg.Version) && seen.Add(pkg.Id + "@" + pkg.Version))
                {
                    output.Add(new RaspComponent("nuget", pkg.Id, pkg.Version));
                }
            }
            catch (Exception e) when (e is NotSupportedException or FileNotFoundException or System.Security.SecurityException)
            {
                // an assembly we cannot read is left out
            }
        }

        foreach (var c in fallback.Skip(1))
        {
            if (output.Count >= RaspReporter.MaxComponents)
            {
                break;
            }

            if (!mapped.Contains(c.Name) && seen.Add(c.Name + "@" + c.Version))
            {
                output.Add(c);
            }
        }

        return output;
    }

    /// <summary>Sends one report now. Returns whether every batch was accepted; never throws.</summary>
    public static async Task<bool> ReportAsync(RaspStartContext ctx, Func<List<RaspComponent>>? collect = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(ctx.Url) || string.IsNullOrEmpty(ctx.ApiKey))
        {
            return false;
        }

        try
        {
            var components = (collect ?? (() => Collect()))().Take(RaspReporter.MaxComponents).ToList();
            var time = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            var events = components.Select(c => new GuardEvent(RaspReporter.ComponentName, time, new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["shield360.rasp.app"] = ctx.ApplicationName,
                ["shield360.rasp.component.ecosystem"] = c.Ecosystem,
                ["shield360.rasp.component.name"] = c.Name,
                ["shield360.rasp.component.version"] = c.Version,
            })).ToList();
            var resource = new Dictionary<string, string>(StringComparer.Ordinal) { ["service.name"] = ctx.ApplicationName };
            var host = SafeHost();
            if (host.Length > 0)
            {
                resource["host.name"] = host;
            }

            if (!string.IsNullOrEmpty(ctx.Environment))
            {
                resource["deployment.environment"] = ctx.Environment!;
            }

            if (!string.IsNullOrEmpty(ctx.SdkVersion))
            {
                resource["service.version"] = ctx.SdkVersion!;
            }

            using var http = ctx.Handler is null
                ? new HttpClient { Timeout = Timeout.InfiniteTimeSpan }
                : new HttpClient(ctx.Handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
            var endpoint = GuardEventsTransport.Endpoint(ctx.Url!);
            for (var i = 0; i < events.Count; i += Batch)
            {
                var batch = events.Skip(i).Take(Batch).ToList();
                var ok = await GuardEventsTransport.PostAsync(
                    http, endpoint, ctx.ApiKey!, GuardEventsTransport.Payload(resource, batch), batch.Count,
                    label: "runtime package report", cancellationToken: cancellationToken).ConfigureAwait(false);
                if (!ok)
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return false;
        }
    }

    /// <summary>
    /// Starts the report: once after <paramref name="delay"/> (default 15 s), then every
    /// <paramref name="every"/> (default a day). Returns whether it started; a second call
    /// while it runs, a missing URL or key, or a turned-off report start nothing.
    /// </summary>
    public static bool Start(RaspStartContext ctx, bool? option, TimeSpan? delay = null, TimeSpan? every = null, Func<List<RaspComponent>>? collect = null)
    {
        var env = ctx.Env ?? System.Environment.GetEnvironmentVariable;
        if (string.IsNullOrEmpty(ctx.Url) || string.IsNullOrEmpty(ctx.ApiKey) || !Enabled(option, env))
        {
            return false;
        }

        lock (s_lock)
        {
            if (s_timer is not null)
            {
                return false;
            }

            s_timer = new Timer(_ => _ = ReportAsync(ctx, collect), null, delay ?? StartDelay, every ?? Every);
        }

        return true;
    }

    /// <summary>Stops the report (shutdown, tests).</summary>
    public static void Stop()
    {
        Timer? timer;
        lock (s_lock)
        {
            timer = s_timer;
            s_timer = null;
        }

        timer?.Dispose();
    }

    private static string SafeHost()
    {
        try
        {
            return System.Environment.MachineName;
        }
        catch (InvalidOperationException)
        {
            return string.Empty;
        }
    }
}
