using System;
using Microsoft.Extensions.DependencyInjection;
using Shield360.Internal;

namespace Shield360.AspNetCore;

/// <summary>SHIELD: request tracing for apps that start Shield360 in code.</summary>
public static class Shield360RequestTracingExtensions
{
    /// <summary>
    /// Traces each incoming request, named by its route, with health probes left
    /// out. The zero-code start does this already; call it after <c>AddShield360</c>
    /// when the app starts Shield360 itself.
    /// <code>
    /// builder.Services.AddShield360(o => o.ApplicationName = "orders-api");
    /// builder.Services.AddShield360RequestTracing();
    /// </code>
    /// </summary>
    public static IServiceCollection AddShield360RequestTracing(this IServiceCollection services)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        Shield360RequestTracing.Add(services, Shield360Runtime.Current?.Options ?? ResolvedOptions.Resolve(null, Environment.GetEnvironmentVariable));
        return services;
    }
}
