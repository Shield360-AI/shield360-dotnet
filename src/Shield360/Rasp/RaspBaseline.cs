using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Shield360.Rasp;

/// <summary>What the baseline rules read. Pure data, so each rule can be tested on its own.</summary>
internal sealed record BaselineInput
{
    public Func<string, string?> Env { get; init; } = _ => null;

    /// <summary>The SDK's deployment environment (<c>Shield360Options.Environment</c>).</summary>
    public string? Environment { get; init; }

    /// <summary>
    /// The host's own environment name (<c>IHostEnvironment.EnvironmentName</c>), when known.
    /// Without it the host variables are read, and a conflict between them is not judged.
    /// </summary>
    public string? HostEnvironment { get; init; }

    /// <summary>A signed config was expected (URL and API key set, remote on).</summary>
    public bool RemoteWanted { get; init; }

    /// <summary>A config public key is pinned.</summary>
    public bool Pinned { get; init; }

    /// <summary><see cref="RuntimeInformation.FrameworkDescription"/>, for example <c>.NET 8.0.11</c>.</summary>
    public string FrameworkDescription { get; init; } = string.Empty;

    /// <summary>Root on Unix or an elevated administrator on Windows; null where it cannot be told.</summary>
    public bool? Elevated { get; init; }

    /// <summary>A debugger is attached to the process.</summary>
    public bool DebuggerAttached { get; init; }

    /// <summary><c>ServicePointManager.ServerCertificateValidationCallback</c> accepts a certificate with every policy error.</summary>
    public bool TlsCallbackAcceptsAll { get; init; }

    public DateTimeOffset Now { get; init; }
}

/// <summary>
/// Security baseline (sdk/rasp/README.md, "Security baseline"): a one-time look, when
/// RASP starts, at how the running process is set up, reported as <c>baseline</c> events
/// at sink <c>startup</c> (monitor only, never blocks). Each rule reads a flag, a version
/// or an id, never a secret value, and reports only that a setting is risky. Port of the
/// TypeScript <c>baseline.ts</c>; adapted from the idea of OpenRASP's start-up security
/// policy checks.
/// </summary>
/// <remarks>
/// The rules .NET has: <c>baseline.tls_verify_off</c> (a
/// <c>ServicePointManager.ServerCertificateValidationCallback</c> that accepts every
/// certificate), <c>baseline.inspector_in_production</c> (a debugger attached in
/// production), <c>baseline.development_mode_in_production</c>
/// (the host's environment is Development while the SDK says production), <c>baseline.running_as_root</c>, <c>baseline.config_key_unpinned</c>
/// and <c>baseline.runtime_end_of_life</c>.
/// </remarks>
internal static class RaspBaseline
{
    /// <summary>The sink name of baseline events.</summary>
    public const string Sink = "startup";

    private static readonly Regex s_production = new("^prod(uction)?\\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex s_dotnet = new("^\\.NET (Core )?(\\d+)\\.", RegexOptions.CultureInvariant);
    private static readonly string[] s_environmentNames = { "ASPNETCORE_ENVIRONMENT", "DOTNET_ENVIRONMENT", "ENVIRONMENT", "NODE_ENV" };

    /// <summary>
    /// The last day each .NET release line gets security fixes. Lines older than the table
    /// (every .NET Core line) have ended; lines newer than it are not judged until a date
    /// is added. .NET Framework and Mono are not judged. .NET 11 (due November 2026)
    /// has no published end-of-support date yet, so it and later lines stay unjudged.
    /// </summary>
    internal static readonly IReadOnlyDictionary<int, string> DotnetEndOfLife = new Dictionary<int, string>
    {
        [5] = "2022-05-10",
        [6] = "2024-11-12",
        [7] = "2024-05-14",
        [8] = "2026-11-10",
        [9] = "2026-11-10",
        [10] = "2028-11-14",
    };

    private const int OldestListed = 5;

    private static int s_ran;

    private static bool IsProduction(string? v) => s_production.IsMatch(JsText.Trim(v ?? string.Empty));

    /// <summary>
    /// Production: <c>ASPNETCORE_ENVIRONMENT</c>, <c>DOTNET_ENVIRONMENT</c>,
    /// <c>ENVIRONMENT</c>, <c>NODE_ENV</c> (the variables trust on first use reads) or the
    /// SDK's environment is <c>prod</c> or <c>production</c>.
    /// </summary>
    public static bool ProductionEnv(string? environment, Func<string, string?> env)
    {
        foreach (var name in s_environmentNames)
        {
            if (IsProduction(env(name)))
            {
                return true;
            }
        }

        return IsProduction(environment);
    }

    /// <summary>
    /// The host's environment from the variables alone: <c>DOTNET_ENVIRONMENT</c> or
    /// <c>ASPNETCORE_ENVIRONMENT</c>, whichever is set. When both are set and differ, which one
    /// wins depends on the host (<c>WebApplication</c> and <c>HostApplicationBuilder</c> take
    /// <c>DOTNET_ENVIRONMENT</c>, <c>ConfigureWebHostDefaults</c> takes
    /// <c>ASPNETCORE_ENVIRONMENT</c>), so the answer is null: not judged.
    /// </summary>
    internal static string? HostEnvironmentFromVariables(Func<string, string?> env)
    {
        var a = JsText.Trim(env("ASPNETCORE_ENVIRONMENT") ?? string.Empty);
        var d = JsText.Trim(env("DOTNET_ENVIRONMENT") ?? string.Empty);
        if (a.Length > 0 && d.Length > 0 && !string.Equals(a, d, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return a.Length > 0 ? a : d;
    }

    /// <summary>The end-of-life date of the runtime's line, or null when it is not judged.</summary>
    internal static string? EndOfLife(string frameworkDescription)
    {
        var m = s_dotnet.Match(frameworkDescription ?? string.Empty);
        if (!m.Success)
        {
            return null;
        }

        // .NET Core 1.0 to 3.1 have all ended (and 2.x reports a 4.6 version here).
        if (m.Groups[1].Success)
        {
            return "1970-01-01";
        }

        if (!int.TryParse(m.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var major))
        {
            return null;
        }

        if (DotnetEndOfLife.TryGetValue(major, out var eol))
        {
            return eol;
        }

        return major < OldestListed ? "1970-01-01" : null;
    }

    /// <summary>The baseline rules that fire, in a fixed order. Pure.</summary>
    public static List<RaspFinding> Findings(BaselineInput i)
    {
        var env = i.Env;
        var production = ProductionEnv(i.Environment, env);
        var out_ = new List<RaspFinding>();
        void Hit(string rule) => out_.Add(new RaspFinding(RaspAttackType.Baseline, rule));

        // Certificate checks switched off for every HttpWebRequest / WebClient in the process.
        if (i.TlsCallbackAcceptsAll)
        {
            Hit("baseline.tls_verify_off");
        }

        // A debugger attached in production can read and change everything the process holds.
        if (production && i.DebuggerAttached)
        {
            Hit("baseline.inspector_in_production");
        }

        // The SDK says production while the host runs in Development (developer exception page, detailed errors).
        var sdkEnv = string.IsNullOrEmpty(i.Environment) || i.Environment == Internal.ResolvedOptions.DefaultName ? env("ENVIRONMENT") : i.Environment;
        var hostEnv = string.IsNullOrEmpty(i.HostEnvironment) ? HostEnvironmentFromVariables(env) : i.HostEnvironment;
        if (IsProduction(sdkEnv) && string.Equals(JsText.Trim(hostEnv ?? string.Empty), "Development", StringComparison.OrdinalIgnoreCase))
        {
            Hit("baseline.development_mode_in_production");
        }

        if (i.Elevated == true)
        {
            Hit("baseline.running_as_root");
        }

        // In production the signed config must be verified against a pinned key.
        if (production && i.RemoteWanted && !i.Pinned)
        {
            Hit("baseline.config_key_unpinned");
        }

        var eol = EndOfLife(i.FrameworkDescription);
        if (eol is not null && string.CompareOrdinal(i.Now.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), eol) > 0)
        {
            Hit("baseline.runtime_end_of_life");
        }

        return out_;
    }

    /// <summary>Whether the process runs elevated (root, or an elevated Windows administrator); null where unknown.</summary>
    internal static bool? Elevated()
    {
        try
        {
#if NET8_0_OR_GREATER
            return Environment.IsPrivilegedProcess;
#else
            // Without the Windows principal package there is no elevation check on .NET Standard 2.0.
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? null : NativeMethods.geteuid() == 0;
#endif
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether <c>ServicePointManager.ServerCertificateValidationCallback</c> accepts a
    /// certificate that has every policy error (no certificate, wrong name, broken chain).
    /// A callback that throws, or that inspects the certificate, counts as not accepting.
    /// </summary>
    internal static bool TlsCallbackAcceptsAll()
    {
        try
        {
#pragma warning disable SYSLIB0014 // ServicePointManager: the legacy process-wide setting is exactly what is read.
            var callback = ServicePointManager.ServerCertificateValidationCallback;
#pragma warning restore SYSLIB0014
            const SslPolicyErrors all = SslPolicyErrors.RemoteCertificateNotAvailable | SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors;
            return callback is not null && callback(new object(), null!, null!, all);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return false;
        }
    }

    /// <summary>Reports the baseline findings once per process. Never throws; a no-op while RASP is not active.</summary>
    public static void Run(BaselineInput i)
    {
        if (Interlocked.Exchange(ref s_ran, 1) == 0)
        {
            Report(i);
        }
    }

    private static void Report(BaselineInput i)
    {
        try
        {
            // Not a request: the events carry no route or method.
            RaspScope.Enter(null);
            foreach (var f in Findings(i))
            {
                RaspEngine.Check(Sink, () => f);
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>
    /// Runs the baseline once per process on the thread pool, off the caller's thread.
    /// Returns the work (tests wait on it), or a completed task when it already ran.
    /// </summary>
    public static Task Start(string? environment, Func<string, string?> env, bool remoteWanted, bool pinned, string? hostEnvironment = null)
    {
        if (Interlocked.Exchange(ref s_ran, 1) == 1)
        {
            return Task.CompletedTask;
        }

        try
        {
            return Task.Run(() =>
            {
                try
                {
                    Report(new BaselineInput
                    {
                        Env = env,
                        Environment = environment,
                        HostEnvironment = hostEnvironment,
                        RemoteWanted = remoteWanted,
                        Pinned = pinned,
                        FrameworkDescription = RuntimeInformation.FrameworkDescription,
                        Elevated = Elevated(),
                        DebuggerAttached = Debugger.IsAttached,
                        TlsCallbackAcceptsAll = TlsCallbackAcceptsAll(),
                        Now = DateTimeOffset.UtcNow,
                    });
                }
                catch (Exception e) when (e is not OutOfMemoryException)
                {
                    // fail open
                }
            });
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return Task.CompletedTask;
        }
    }

    /// <summary>Whether the baseline has run (or is running) in this process.</summary>
    internal static bool HasRun => Volatile.Read(ref s_ran) == 1;

    /// <summary>Tests only: lets the baseline run again.</summary>
    internal static void Reset() => Volatile.Write(ref s_ran, 0);

    /// <summary>Tests only: the baseline counts as already run, so starting RASP does not run it.</summary>
    internal static void MarkRan() => Volatile.Write(ref s_ran, 1);

#if !NET8_0_OR_GREATER
    private static class NativeMethods
    {
        [DllImport("libc", SetLastError = false)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern uint geteuid();
    }
#endif
}
