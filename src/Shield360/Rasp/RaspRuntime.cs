using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shield360.Internal;

namespace Shield360.Rasp;

/// <summary>What RASP needs from the SDK's settings to start.</summary>
internal sealed record RaspStartContext(
    string ApplicationName,
    string? Environment = null,
    string? Url = null,
    string? ApiKey = null,
    string? SdkVersion = null,
    string? OtlpEndpoint = null,
    Func<string, string?>? Env = null,
    HttpMessageHandler? Handler = null,
    string? HostEnvironment = null,
    bool? RuntimePackages = null)
{
    public static RaspStartContext From(ResolvedOptions o, Func<string, string?> env, string? hostEnvironment = null) =>
        new(o.ApplicationName, o.Environment, o.Shield360Url, o.ApiKey, Shield360Sdk.Version, o.OtlpEndpoint, env, HostEnvironment: hostEnvironment, RuntimePackages: o.RuntimePackages);

    /// <summary>
    /// The host's own environment name (<c>IHostEnvironment.EnvironmentName</c>) when the service
    /// collection holds the instance the host builder registered, else null. The host has already
    /// applied its own precedence between <c>DOTNET_ENVIRONMENT</c> and <c>ASPNETCORE_ENVIRONMENT</c>.
    /// </summary>
    public static string? HostEnvironmentOf(IServiceCollection services)
    {
        try
        {
            foreach (var d in services)
            {
                if (d.ServiceType == typeof(IHostEnvironment) && d.ImplementationInstance is IHostEnvironment h)
                {
                    return h.EnvironmentName;
                }
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // not known
        }

        return null;
    }
}

/// <summary>
/// Starts and stops RASP for the process: the engine's settings, the signed
/// config client, the reporter and the components report. Port of the
/// TypeScript <c>rasp/index.ts</c>, with the process-wide sink hooks (<see cref="RaspDiagnosticHooks"/>).
/// </summary>
internal static class RaspRuntime
{
    private static readonly TimeSpan s_componentsEvery = TimeSpan.FromHours(24);
    private static readonly Regex s_production = new("^prod(uction)?\\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly string[] s_environmentNames = { "ASPNETCORE_ENVIRONMENT", "DOTNET_ENVIRONMENT", "ENVIRONMENT", "NODE_ENV" };
    /// <summary>How long process or host shutdown waits for the last RASP events to be sent.</summary>
    internal static readonly TimeSpan ShutdownFlushWait = TimeSpan.FromSeconds(5);

    private static readonly object s_lock = new();
    private static RaspConfigClient? s_client;
    private static RaspReporter? s_reporter;
    private static Timer? s_componentsTimer;
    private static int s_warnedUnpinned;

    /// <summary>Where RASP's log lines go (tests replace it).</summary>
    internal static Action<string> Warn { get; set; } = message => Trace.TraceWarning(message);

    /// <summary>The config client, while one runs (tests).</summary>
    internal static RaspConfigClient? Client => Volatile.Read(ref s_client);

    /// <summary>The reporter, while one runs (tests).</summary>
    internal static RaspReporter? Reporter => Volatile.Read(ref s_reporter);

    /// <summary>The hosts of the Shield360 URL and the OTLP endpoint: always allowed outbound.</summary>
    public static List<string> AlwaysAllowedHosts(IEnumerable<string?> urls)
    {
        var hosts = new List<string>();
        foreach (var u in urls)
        {
            if (u is not null && Uri.TryCreate(u, UriKind.Absolute, out var uri) && uri.Host.Length > 0)
            {
                var host = JsText.Lower(uri.Host).Trim('[', ']');
                if (!hosts.Contains(host))
                {
                    hosts.Add(host);
                }
            }
        }

        return hosts;
    }

    /// <summary>
    /// Whether trust on first use is allowed: the explicit opt-in (option or
    /// <c>SHIELD360_CONFIG_TOFU=dev</c>), never when <c>ASPNETCORE_ENVIRONMENT</c>,
    /// <c>DOTNET_ENVIRONMENT</c>, <c>ENVIRONMENT</c> or <c>NODE_ENV</c> says production.
    /// </summary>
    public static bool TofuAllowed(bool option, Func<string, string?> env)
    {
        var asked = option || JsText.Lower(JsText.Trim(env("SHIELD360_CONFIG_TOFU") ?? string.Empty)) == "dev";
        if (!asked)
        {
            return false;
        }

        return !s_environmentNames.Any(name => s_production.IsMatch(JsText.Trim(env(name) ?? string.Empty)));
    }

    /// <summary>Settles whether RASP is on: options mean on unless <c>Enabled = false</c>; no options and <c>SHIELD360_RASP=monitor|block</c> mean on; <c>off</c> always wins.</summary>
    public static (RaspOptions Options, bool Enabled) Resolve(RaspOptions? option, Func<string, string?> env)
    {
        var e = RaspEngine.EnvSetting(env);
        var enabled = option is not null && option.Enabled != false;
        if (option is null && e is RaspMode.Monitor or RaspMode.Block)
        {
            enabled = true;
        }

        if (e == RaspMode.Off)
        {
            enabled = false;
        }

        return (option ?? new RaspOptions(), enabled);
    }

    /// <summary>The verified claims as the engine's remote config; malformed fields are left out.</summary>
    public static RemoteConfig ToRemote(RaspClaims c)
    {
        var j = c.Json;
        static bool Flag(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
        static IReadOnlyList<string>? List(JsonElement allow, string name) =>
            allow.ValueKind == JsonValueKind.Object && allow.TryGetProperty(name, out var a) && a.ValueKind == JsonValueKind.Array
                ? a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String && x.GetString()!.Length > 0).Select(x => x.GetString()!).Take(256).ToArray()
                : null;

        var attacks = new Dictionary<RaspAttackType, RaspMode>();
        if (j.TryGetProperty("attacks", out var at) && at.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in at.EnumerateObject())
            {
                if (RaspNames.TryAttack(p.Name, out var attack) && p.Value.ValueKind == JsonValueKind.String && RaspNames.Mode(p.Value.GetString()) is { } m)
                {
                    attacks[attack] = m;
                }
            }
        }

        var allow = j.TryGetProperty("allow", out var al) ? al : default;
        return new RemoteConfig
        {
            Version = c.Version,
            Exp = c.Exp,
            KillSwitch = Flag(j, "killSwitch"),
            Snippets = Flag(j, "snippets"),
            ReportTargets = Flag(j, "reportTargets"),
            Mode = j.TryGetProperty("mode", out var mode) && mode.ValueKind == JsonValueKind.String ? RaspNames.Mode(mode.GetString()) : null,
            Attacks = attacks,
            AllowCommands = List(allow, "commands"),
            AllowOutboundHosts = List(allow, "outboundHosts"),
            AllowFileRoots = List(allow, "fileRoots"),

            // .NET compiles its hooks in and ignores `sinks` (contract: "Sink rules").
            Rules = j.TryGetProperty("rules", out var rules) && rules.ValueKind == JsonValueKind.Array ? VirtualPatch.ListFromJson(rules) : null,
            CustomRulesJson = j.TryGetProperty("customRules", out var custom) && custom.ValueKind == JsonValueKind.Array ? custom.GetRawText() : null,
            Deception = RaspDeception.Parse(j.TryGetProperty("deception", out var deception) ? deception : null),
            EdgeKeys = EdgeContext.ParseKeys(j.TryGetProperty("edgeContext", out var edgeContext) ? edgeContext : null),
            Uploads = j.TryGetProperty("uploads", out var uploads) ? UploadPolicy.Parse(uploads) : null, // SHIELD: uploads
        };
    }

    /// <summary>Where passive IAST reports go: the reporter, unfolded (IAST dedupes and counts itself).</summary>
    internal static Func<RaspEvent, string, bool> IastSink(RaspReporter reporter) => (e, _) => reporter.AddUnfolded(e);

    /// <summary>One log line per process when the config key is not pinned (not a reported event).</summary>
    private static void WarnUnpinnedOnce()
    {
        if (Interlocked.Exchange(ref s_warnedUnpinned, 1) == 1)
        {
            return;
        }

        Warn("Shield360 RASP: the signed config key is not pinned, so the signed config is not used and RASP runs its built-in defaults in " +
             "monitor mode. Set RaspOptions.ConfigPublicKey (or SHIELD360_CONFIG_PUBLIC_KEY) to the environment's public key from the app's " +
             "Runtime protection settings in Shield360.");
    }

    /// <summary>Tests only: lets the once-per-process warning fire again.</summary>
    internal static void ResetWarnings() => Volatile.Write(ref s_warnedUnpinned, 0);

    /// <summary>
    /// Stops polling, reporting and the components timer. The reporter flushes what is
    /// queued in the background; only <paramref name="flushWait"/> (process or host
    /// shutdown) waits for it, and only that long. Start-up passes none, so a re-init
    /// never waits on the network.
    /// </summary>
    public static void Shutdown(TimeSpan? flushWait = null)
    {
        RaspConfigClient? client;
        RaspReporter? reporter;
        Timer? timer;
        lock (s_lock)
        {
            client = s_client;
            reporter = s_reporter;
            timer = s_componentsTimer;
            s_client = null;
            s_reporter = null;
            s_componentsTimer = null;
        }

        timer?.Dispose();
        client?.Dispose();
        RaspDiagnosticHooks.Uninstall();
        RaspEngine.SetEventSink(null);
        RaspIast.SetSink(null);
        if (reporter is not null)
        {
            // On the thread pool: even the synchronous part of a send (a handler, DNS) never runs on the caller.
            var stopping = Task.Run(async () =>
            {
                try
                {
                    await reporter.StopAsync().ConfigureAwait(false);
                }
                finally
                {
                    reporter.Dispose();
                }
            });
            if (flushWait is { } wait && wait > TimeSpan.Zero)
            {
                try
                {
                    stopping.Wait(wait);
                }
                catch (AggregateException)
                {
                    // the last batch is best effort
                }
            }
        }
    }

    /// <summary>Turns RASP on (or leaves it off) for this process. Returns whether it is on. Never throws.</summary>
    public static bool Start(RaspOptions? option, RaspStartContext ctx)
    {
        try
        {
            Shutdown();
            // SHIELD: runtime SCA — the package report runs with or without RASP; started
            // first, so RASP leaves its own components report to it.
            Shield360.RuntimePackages.Start(ctx, ctx.RuntimePackages);
            var env = ctx.Env ?? System.Environment.GetEnvironmentVariable;
            var (o, enabled) = Resolve(option, env);
            var hasRemote = !string.IsNullOrEmpty(ctx.Url) && !string.IsNullOrEmpty(ctx.ApiKey);
            var remoteWanted = enabled && o.Remote && hasRemote;
            var pinned = RaspJws.ParsePublicKeys(o.ConfigPublicKey ?? env("SHIELD360_CONFIG_PUBLIC_KEY"));
            var tofu = pinned.Count == 0 && TofuAllowed(o.AllowUnpinnedConfig, env);
            var unpinned = remoteWanted && pinned.Count == 0 && !tofu;
            RaspEngine.Configure(new EngineSettings(
                enabled,
                ctx.ApplicationName,
                o.Mode,
                o.Attacks,
                o.Allow,
                o.ModelOutput,

                // No pinned key while a remote config was expected: built-in defaults, monitor only.
                MonitorOnly: unpinned,
                Env: env));
            RaspEngine.AlwaysAllowedHosts = AlwaysAllowedHosts(new[] { ctx.Url, ctx.OtlpEndpoint });

            // SHIELD: uploads — the local policy, and the environment the reputation lookup uses.
            RaspUploads.SetLocal(o.Uploads, o.UploadScanBytes, o.QuarantineDir);
            RaspDeepScan.SetEnv(hasRemote ? ctx.Url : null, hasRemote ? ctx.ApiKey : null, ctx.Handler);
            RaspIast.Configure(new IastSettings(o.Iast, o.IastSampleRate, ctx.ApplicationName, ctx.Environment, env));
            if (!enabled)
            {
                return false;
            }

            if (o.Hooks)
            {
                RaspDiagnosticHooks.Install();
            }

            if (hasRemote)
            {
                var reporter = new RaspReporter(new RaspReporterOptions
                {
                    Url = ctx.Url!,
                    ApiKey = ctx.ApiKey!,
                    ApplicationName = ctx.ApplicationName,
                    Environment = ctx.Environment,
                    SdkVersion = ctx.SdkVersion,
                    Handler = ctx.Handler,
                });
                reporter.Start();
                RaspEngine.SetEventSink(reporter);
                RaspIast.SetSink(IastSink(reporter));
                Timer? timer = null;
                if (o.Components && !Shield360.RuntimePackages.Active)
                {
                    timer = new Timer(
                        _ =>
                        {
                            try
                            {
                                reporter.ReportComponents(RaspComponents.Collect());
                            }
                            catch (Exception e) when (e is not OutOfMemoryException)
                            {
                                // never
                            }
                        },
                        null,
                        TimeSpan.Zero,
                        s_componentsEvery);
                }

                lock (s_lock)
                {
                    s_reporter = reporter;
                    s_componentsTimer = timer;
                }
            }

            // Once per process, on the thread pool: monitor-only baseline events.
            RaspBaseline.Start(ctx.Environment, env, remoteWanted, pinned.Count > 0, ctx.HostEnvironment);

            if (unpinned)
            {
                WarnUnpinnedOnce();
            }
            else if (remoteWanted)
            {
                if (tofu)
                {
                    Warn("Shield360 RASP: trust on first use is on for the signed config (development only); set RaspOptions.ConfigPublicKey before production.");
                }

                var client = new RaspConfigClient(new RaspConfigClientOptions
                {
                    Url = ctx.Url!,
                    ApiKey = ctx.ApiKey!,
                    App = ctx.ApplicationName,
                    Pinned = pinned,
                    AllowUnpinned = tofu,
                    CacheDir = string.IsNullOrEmpty(o.CacheDir) ? Path.Combine(Path.GetTempPath(), "shield360-rasp") : o.CacheDir!,
                    OnConfig = claims =>
                    {
                        var remote = claims is null ? null : ToRemote(claims);
                        RaspEngine.SetRemoteConfig(remote);
                        RaspDeepScan.TestEngines(remote?.Uploads?.DeepScan); // SHIELD: uploads — a new deepScan.testId
                        RaspIast.SetRemote(claims is null ? null : RaspIast.RemoteOf(claims));
                    },

                    // Logged once per reason (the client dedupes); trust on first use was announced above.
                    OnWarning = reason =>
                    {
                        if (reason != "trust_on_first_use")
                        {
                            Warn($"Shield360 RASP: a signed config was refused ({reason}); the last verified config or the local options stay in force.");
                        }
                    },
                    Handler = ctx.Handler,
                });
                lock (s_lock)
                {
                    s_client = client;
                }

                client.Start();
            }

            return true;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Warn($"Shield360 RASP could not start: {e.GetType().Name}");
            return false;
        }
    }
}
