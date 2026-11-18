using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Shield360.AspNetCore;
using Shield360.Internal;
using Shield360.Rasp;

[assembly: HostingStartup(typeof(Shield360HostingStartup))]

namespace Shield360.AspNetCore;

/// <summary>
/// Adds Shield360 runtime protection (RASP) to an ASP.NET Core app with no code
/// change: <c>ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=Shield360.AspNetCore</c>. The
/// Shield360 startup hook (<c>DOTNET_STARTUP_HOOKS</c>) sets that for you.
/// </summary>
/// <remarks>
/// RASP turns on from <c>SHIELD360_RASP=monitor|block</c> when nothing started it
/// yet; with RASP off the middleware passes every request through. The services
/// are the ones <c>AddShield360Rasp()</c> registers (the middleware first in the
/// pipeline, the block mapped to the 403 behind <c>UseExceptionHandler</c>, events
/// flushed at shutdown), added once even if the app calls <c>AddShield360Rasp()</c>
/// too.
/// </remarks>
public sealed class Shield360HostingStartup : IHostingStartup
{
    /// <inheritdoc />
    public void Configure(IWebHostBuilder builder)
    {
        if (builder is null)
        {
            throw new System.ArgumentNullException(nameof(builder));
        }

        builder.ConfigureServices(services =>
        {
            if (!RaspEngine.IsEnabled)
            {
                // Fail open: invalid settings leave RASP off with one warning; the host still builds.
                try
                {
                    var env = (System.Func<string, string?>)System.Environment.GetEnvironmentVariable;
                    var resolved = Shield360Runtime.Current?.Options ?? ResolvedOptions.Resolve(null, env);
                    RaspRuntime.Start(null, RaspStartContext.From(resolved, env, RaspStartContext.HostEnvironmentOf(services)));
                }
#pragma warning disable CA1031 // Nothing here may stop the app from starting.
                catch (System.Exception e)
#pragma warning restore CA1031
                {
                    System.Console.Error.WriteLine($"Shield360: runtime protection did not start ({e.GetType().Name}: {e.Message}); the app runs without it.");
                }
            }

            // SHIELD: each incoming request is a trace, health probes left out.
            try
            {
                var env = (System.Func<string, string?>)System.Environment.GetEnvironmentVariable;
                Shield360RequestTracing.Add(services, Shield360Runtime.Current?.Options ?? ResolvedOptions.Resolve(null, env));
            }
#pragma warning disable CA1031 // Nothing here may stop the app from starting.
            catch (System.Exception e)
#pragma warning restore CA1031
            {
                System.Console.Error.WriteLine($"Shield360: request tracing did not start ({e.GetType().Name}: {e.Message}); the app runs without it.");
            }

            // SHIELD: application logs: under the zero-code start, the host's ILogger
            // records go through the hook's logger factory when it captures logs.
            Shield360ServiceCollectionExtensions.AddForwardedLogs(services);

            services.TryAddEnumerable(ServiceDescriptor.Transient<IStartupFilter, Shield360RaspStartupFilter>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<MatcherPolicy, RaspDecoyMatcherPolicy>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IExceptionHandler, Shield360RaspExceptionHandler>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, Shield360RaspLifetime>());
        });
    }
}
