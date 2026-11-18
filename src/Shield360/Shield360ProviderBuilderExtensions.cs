using System;
using Shield360;
using Shield360.Internal;

namespace OpenTelemetry.Trace
{
    /// <summary>
    /// For apps that set up OpenTelemetry themselves: adds Shield360's sources and
    /// GenAI span processing to an existing tracing pipeline, without an exporter.
    /// </summary>
    public static class Shield360TracerProviderBuilderExtensions
    {
        /// <summary>
        /// Listens to Shield360 and the supported AI libraries and adds the GenAI span
        /// processor (cost, application and environment attributes, content removal).
        /// Call it before adding your exporter.
        /// </summary>
        public static TracerProviderBuilder AddShield360Instrumentation(this TracerProviderBuilder builder, Action<Shield360Options>? configure = null)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddShield360Sources(ProviderBuilderRuntime.For(configure));
        }
    }
}

namespace OpenTelemetry.Metrics
{
    /// <summary>
    /// For apps that set up OpenTelemetry themselves: adds the Shield360 and AI
    /// library meters to an existing metrics pipeline, without an exporter.
    /// </summary>
    public static class Shield360MeterProviderBuilderExtensions
    {
        /// <summary>Listens to the Shield360 and AI library meters.</summary>
        public static MeterProviderBuilder AddShield360Instrumentation(this MeterProviderBuilder builder, Action<Shield360Options>? configure = null)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddShield360Meters(ProviderBuilderRuntime.For(configure));
        }
    }
}

namespace Shield360.Internal
{
    internal static class ProviderBuilderRuntime
    {
        /// <summary>The active runtime, or a new one when settings are given or none is active.</summary>
        public static Shield360Runtime For(Action<Shield360Options>? configure)
        {
            if (configure is null && Shield360Runtime.Current is { } current)
            {
                return current;
            }

            var options = new Shield360Options();
            configure?.Invoke(options);
            return Shield360Runtime.Activate(ResolvedOptions.Resolve(options, Environment.GetEnvironmentVariable));
        }
    }
}
