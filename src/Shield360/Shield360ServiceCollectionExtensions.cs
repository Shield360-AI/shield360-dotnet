using System;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using Shield360;
using Shield360.Internal;
using Shield360.Rasp;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registers Shield360 in a host's service collection.</summary>
public static class Shield360ServiceCollectionExtensions
{
    /// <summary>
    /// Adds OpenTelemetry tracing and metrics for Shield360 and the supported .NET
    /// AI libraries, exported over OTLP/HTTP. Returns the OpenTelemetry builder so
    /// you can add more instrumentation, such as ASP.NET Core.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddShield360(o =>
    /// {
    ///     o.ApplicationName = "orders-api";
    ///     o.Environment = builder.Environment.EnvironmentName;
    /// });
    /// </code>
    /// </example>
    /// <exception cref="Shield360Exception">The configuration is invalid.</exception>
    public static IOpenTelemetryBuilder AddShield360(this IServiceCollection services, Action<Shield360Options>? configure = null) =>
        services.AddShield360(configure, Environment.GetEnvironmentVariable);

    internal static IOpenTelemetryBuilder AddShield360(this IServiceCollection services, Action<Shield360Options>? configure, Func<string, string?> env)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        // SHIELD: the zero-code startup hook already started Shield360 for the process; add nothing twice.
        if (Shield360Sdk.StartedByZeroCode)
        {
            // The host's ILogger records go through the hook's logger factory when it captures logs.
            AddForwardedLogs(services);
            return services.AddOpenTelemetry();
        }

        var options = new Shield360Options();
        configure?.Invoke(options);
        var resolved = ResolvedOptions.Resolve(options, env);

        // Activated now, while the host is being built, so the AI libraries see
        // their telemetry switches before any client is created.
        var runtime = Shield360Runtime.Activate(resolved);
        services.TryAddSingleton(runtime);

        // RASP for the process (never throws), unless AddShield360Rasp() already
        // started it. The ASP.NET Core middleware comes from AddShield360Rasp() /
        // UseShield360Rasp() in Shield360.AspNetCore.
        if (options.Rasp is not null || !RaspEngine.IsEnabled)
        {
            RaspRuntime.Start(options.Rasp, RaspStartContext.From(resolved, env, RaspStartContext.HostEnvironmentOf(services)));
        }

        var otel = services.AddOpenTelemetry()
            .ConfigureResource(r => r.ConfigureShield360(resolved));

        if (!resolved.DisableTracing)
        {
            otel.WithTracing(t => t.AddShield360Sources(runtime).AddShield360Exporter(resolved));
        }

        if (!resolved.DisableMetrics)
        {
            otel.WithMetrics(m => m.AddShield360Meters(runtime).AddShield360Exporter(resolved));
        }

        // SHIELD: application logs, opt-in; they share this builder's resource.
        if (resolved.CaptureLogs)
        {
            services.AddLogging(b => b.AddShield360Logs(resolved, setResource: false));
        }

        return otel;
    }

    /// <summary>
    /// Sends the host's ILogger records to Shield360 through the logger factory
    /// <see cref="Shield360Sdk.Init(Shield360Options?)"/> built (the zero-code
    /// start), when it captures logs. Added once.
    /// </summary>
    internal static void AddForwardedLogs(IServiceCollection services)
    {
        if (Shield360Runtime.Current?.Options.CaptureLogs != true)
        {
            return;
        }

        services.AddLogging();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ILoggerProvider, Shield360ForwardingLoggerProvider>());
    }
}
