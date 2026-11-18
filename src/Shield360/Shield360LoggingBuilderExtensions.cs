using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenTelemetry.Logs;
using OpenTelemetry.Resources;
using Shield360;
using Shield360.Internal;

namespace Microsoft.Extensions.Logging;

/// <summary>Sends a host's ILogger records to Shield360.</summary>
public static class Shield360LoggingBuilderExtensions
{
    /// <summary>
    /// Sends the application's ILogger records to Shield360, on the same endpoint,
    /// key and resource as traces, with the active trace and span ids. Calling it
    /// turns application logs on; <c>services.AddShield360(o =&gt; o.CaptureLogs = true)</c>
    /// (or <c>SHIELD360_CAPTURE_LOGS=true</c>) does the same for you.
    /// </summary>
    /// <remarks>
    /// Records at <see cref="Shield360Options.LogLevel"/> (or <c>SHIELD360_LOG_LEVEL</c>,
    /// <c>info</c> by default) and above are sent; the host's own logging filters
    /// still apply first. Credentials and long tokens are masked, the SDK's and
    /// OpenTelemetry's own categories are never sent, at most 500 records a second
    /// go out, in batches, and a failure to send never reaches the application.
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Logging.AddShield360Logs(o =&gt; o.LogLevel = "warn");
    /// </code>
    /// </example>
    public static ILoggingBuilder AddShield360Logs(this ILoggingBuilder builder, Action<Shield360Options>? configure = null) =>
        builder.AddShield360Logs(configure, System.Environment.GetEnvironmentVariable);

    internal static ILoggingBuilder AddShield360Logs(this ILoggingBuilder builder, Action<Shield360Options>? configure, Func<string, string?> env)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        var options = new Shield360Options();
        configure?.Invoke(options);
        return builder.AddShield360Logs(ResolvedOptions.Resolve(options, env), setResource: true);
    }

    /// <summary>Adds the Shield360 log pipeline once per service collection.</summary>
    internal static ILoggingBuilder AddShield360Logs(this ILoggingBuilder builder, ResolvedOptions resolved, bool setResource, Shield360LogProcessor? processor = null)
    {
        if (builder.Services is not null)
        {
            foreach (var d in builder.Services)
            {
                if (d.ServiceType == typeof(Shield360LogsMarker))
                {
                    return builder;
                }
            }

            builder.Services.TryAddSingleton<Shield360LogsMarker>();
        }

        processor ??= new Shield360LogProcessor(AppLogs.ExportProcessor(resolved), resolved.LogLevel);
        return builder.AddOpenTelemetry(o =>
        {
            o.IncludeFormattedMessage = true;
            if (setResource)
            {
                o.SetResourceBuilder(ResourceBuilder.CreateDefault().ConfigureShield360(resolved));
            }

            o.AddProcessor(processor);
        });
    }

    /// <summary>Marks a service collection that already has the Shield360 log pipeline.</summary>
    internal sealed class Shield360LogsMarker
    {
    }
}
