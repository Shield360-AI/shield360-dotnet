using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using OpenTelemetry;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Shield360.Internal;

namespace Shield360.AspNetCore;

/// <summary>
/// SHIELD: each incoming ASP.NET Core request is a trace, named by its route
/// (<c>GET /orders/{id}</c>), with the app's outgoing HTTP calls and SQL commands
/// inside it. Health probes (Kubernetes, load balancers, uptime checks,
/// /healthz-style paths) are not traced. Turn it off with <c>aspnetcore</c> in
/// <c>DisabledInstrumentors</c> (<c>SHIELD360_DISABLED_INSTRUMENTORS</c>).
/// </summary>
/// <remarks>
/// Under the zero-code start the SDK's tracer provider is built before ASP.NET
/// Core loads, so the requests get a provider of their own here, with the same
/// resource and exporter; the spans still nest, since the current activity is
/// shared. An app that builds OpenTelemetry through dependency injection gets the
/// instrumentation added to that provider instead.
/// </remarks>
internal static class Shield360RequestTracing
{
    private static readonly object s_gate = new();
    private static TracerProvider? s_zeroCodeProvider;

    /// <summary>Whether an incoming request is traced: not a health probe.</summary>
    internal static bool ShouldTrace(HttpContext context) =>
        !RequestNoise.IsHealthProbe(context.Request.Path.Value, context.Request.Headers.UserAgent.ToString());

    internal static void Add(IServiceCollection services, ResolvedOptions options)
    {
        if (!options.IsInstrumentationEnabled("aspnetcore"))
        {
            return;
        }

        if (Shield360Sdk.StartedByZeroCode)
        {
            StartZeroCodeProvider(options);
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, Shield360RequestTracingLifetime>());
            return;
        }

        services.ConfigureOpenTelemetryTracerProvider(b => b.AddAspNetCoreInstrumentation(o => o.Filter = ShouldTrace));
    }

    private static void StartZeroCodeProvider(ResolvedOptions options)
    {
        lock (s_gate)
        {
            if (s_zeroCodeProvider is not null)
            {
                return;
            }

            s_zeroCodeProvider = Sdk.CreateTracerProviderBuilder()
                .SetResourceBuilder(ResourceBuilder.CreateDefault().ConfigureShield360(options))
                .AddAspNetCoreInstrumentation(o => o.Filter = ShouldTrace)
                .AddShield360Exporter(options)
                .Build();
        }
    }

    internal static void Stop()
    {
        lock (s_gate)
        {
            s_zeroCodeProvider?.Dispose();
            s_zeroCodeProvider = null;
        }
    }

    /// <summary>Flushes the requests' provider when the host stops.</summary>
    internal sealed class Shield360RequestTracingLifetime : IHostedService
    {
        public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken)
        {
            Stop();
            return Task.CompletedTask;
        }
    }
}
