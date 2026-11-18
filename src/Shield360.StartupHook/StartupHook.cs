using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Threading;
using Shield360;
using Shield360.Rasp;

/// <summary>
/// The zero-code start for .NET: name this assembly in <c>DOTNET_STARTUP_HOOKS</c>
/// and Shield360 starts from SHIELD360_* / OTEL_* environment variables before
/// the app's <c>Main</c>, with no reference to Shield360 in the app.
/// <list type="bullet">
/// <item>Shield360 and its dependencies load from this assembly's directory when the app does not carry them.</item>
/// <item>Telemetry and RASP start as <c>Shield360Sdk.Init()</c> would start them.</item>
/// <item>In an ASP.NET Core app with RASP on, <c>Shield360.AspNetCore</c> is added to
/// <c>ASPNETCORE_HOSTINGSTARTUPASSEMBLIES</c>, so the RASP middleware is in the pipeline too
/// (<c>ASPNETCORE_HOSTINGSTARTUPEXCLUDEASSEMBLIES=Shield360.AspNetCore</c> leaves it out).</item>
/// </list>
/// Fail open: any failure prints one warning and the app starts without Shield360.
/// </summary>
/// <remarks>The runtime requires the type to be called <c>StartupHook</c> and to sit in no namespace.</remarks>
[SuppressMessage("Design", "CA1050:Declare types in namespaces", Justification = "DOTNET_STARTUP_HOOKS requires a StartupHook type in no namespace.")]
internal static class StartupHook
{
    private const string HostingStartupVariable = "ASPNETCORE_HOSTINGSTARTUPASSEMBLIES";
    private const string AspNetCoreAssembly = "Shield360.AspNetCore";

    private static int s_ran;

    /// <summary>Called by the runtime before <c>Main</c>.</summary>
    public static void Initialize()
    {
        if (Interlocked.Exchange(ref s_ran, 1) == 1)
        {
            return;
        }

        try
        {
            var dir = Path.GetDirectoryName(typeof(StartupHook).Assembly.Location);
            if (!string.IsNullOrEmpty(dir))
            {
                ResolveFrom(dir!);
            }

            Start(dir);
        }
#pragma warning disable CA1031 // Fail open: nothing may stop the app from starting.
        catch (Exception e)
#pragma warning restore CA1031
        {
            Console.Error.WriteLine($"Shield360: zero-code start-up failed ({e.GetType().Name}: {OneLine(e.Message)}); the app runs without Shield360.{Hint(e)}");
        }
    }

    /// <summary>On .NET 8 and 9 the newer framework assemblies Shield360 needs come from the host's additional deps.</summary>
    private static string Hint(Exception e) =>
        e is FileNotFoundException or FileLoadException
        && Environment.Version.Major < 10
        && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOTNET_ADDITIONAL_DEPS"))
            ? " On .NET 8 and 9, also set DOTNET_ADDITIONAL_DEPS to Shield360.AdditionalDeps.deps.json and DOTNET_SHARED_STORE to the store directory next to the hook."
            : string.Empty;

    private static string OneLine(string message) => message.Replace('\r', ' ').Replace('\n', ' ').Trim();

    /// <summary>Loads an assembly the app does not carry from the hook's directory (the app's own copy wins).</summary>
    private static void ResolveFrom(string dir)
    {
        AssemblyLoadContext.Default.Resolving += (context, name) =>
        {
            if (string.IsNullOrEmpty(name.Name))
            {
                return null;
            }

            var path = Path.Combine(dir, name.Name + ".dll");
            if (!File.Exists(path))
            {
                return null;
            }

            try
            {
                var found = AssemblyName.GetAssemblyName(path);
                if (name.Version is not null && found.Version is not null && found.Version < name.Version)
                {
                    return null;
                }

                return context.LoadFromAssemblyPath(path);
            }
#pragma warning disable CA1031 // Not found here: the runtime reports the missing assembly as it would have.
            catch (Exception)
#pragma warning restore CA1031
            {
                return null;
            }
        };
    }

    /// <summary>Kept out of <see cref="Initialize"/> so Shield360 loads only once the resolver is in place.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Start(string? dir)
    {
        Shield360Sdk.InitZeroCode(Environment.GetEnvironmentVariable);
        if (Shield360Rasp.IsActive && !string.IsNullOrEmpty(dir) && File.Exists(Path.Combine(dir, AspNetCoreAssembly + ".dll")) && AspNetCorePresent())
        {
            AddHostingStartup();
        }
    }

    /// <summary>Whether the app runs on the ASP.NET Core shared framework.</summary>
    private static bool AspNetCorePresent() =>
        AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") is string tpa
        && tpa.Split(Path.PathSeparator).Any(p => string.Equals(Path.GetFileName(p), "Microsoft.AspNetCore.Hosting.dll", StringComparison.OrdinalIgnoreCase));

    private static void AddHostingStartup()
    {
        var current = Environment.GetEnvironmentVariable(HostingStartupVariable) ?? string.Empty;
        var names = current.Split(';', StringSplitOptions.RemoveEmptyEntries).Select(n => n.Trim()).Where(n => n.Length > 0).ToList();
        if (names.Contains(AspNetCoreAssembly, StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        names.Add(AspNetCoreAssembly);
        Environment.SetEnvironmentVariable(HostingStartupVariable, string.Join(";", names));
    }
}
