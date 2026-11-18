using System;
using System.Collections.Generic;
using System.Net.Http;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Shield360.Internal;

/// <summary>Resource, source, processor and exporter wiring shared by every entry point.</summary>
internal static class OpenTelemetrySetup
{
    internal const string MySqlConnectorSource = "MySqlConnector";
    internal const string MongoDBSource = "MongoDB.Driver";

    public static ResourceBuilder ConfigureShield360(this ResourceBuilder builder, ResolvedOptions options)
    {
        builder.AddService(options.ApplicationName, serviceVersion: options.ServiceVersion);
        var attributes = new Dictionary<string, object>
        {
            [SemanticConventions.DeploymentEnvironment] = options.Environment,
            [SemanticConventions.DeploymentEnvironmentName] = options.Environment,
            [SemanticConventions.TelemetrySdkName] = SemanticConventions.Shield360SdkName,
            [SemanticConventions.Shield360SDKVersion] = Shield360Sdk.Version,
        };
        foreach (var kv in options.ResourceAttributes)
        {
            attributes[kv.Key] = kv.Value;
        }

        // Added after the default detectors, so these values win.
        return builder.AddAttributes(attributes);
    }

    public static TracerProviderBuilder AddShield360Sources(this TracerProviderBuilder builder, Shield360Runtime runtime)
    {
        foreach (var source in runtime.ActivitySources)
        {
            builder.AddSource(source);
        }

        builder.AddRequestTracing(runtime.Options);

        // Runs before the exporter so its changes are exported.
        return builder.AddProcessor(new GenAISpanProcessor(() => Shield360Runtime.Current ?? runtime));
    }

    /// <summary>
    /// SHIELD: outgoing HTTP calls, SQL Server, MySQL (MySqlConnector), MongoDB and gRPC client calls are traced, inside the
    /// incoming request's trace (Shield360.AspNetCore traces the request), with
    /// calls to Shield360 left out. SQL is recorded without parameters. Turn one
    /// off by name in DisabledInstrumentors: http, sqlclient, mysqlconnector, mongodb, grpc
    /// (aspnetcore for the request).
    /// </summary>
    public static TracerProviderBuilder AddRequestTracing(this TracerProviderBuilder builder, ResolvedOptions options)
    {
        var own = RequestNoise.Shield360Authority(options.Shield360Url);
        if (options.IsInstrumentationEnabled("http"))
        {
            builder.AddHttpClientInstrumentation(o =>
            {
                o.FilterHttpRequestMessage = req => !RequestNoise.IsOwnCall(req.RequestUri, own);
#if !NET8_0_OR_GREATER
                o.FilterHttpWebRequest = req => !RequestNoise.IsOwnCall(req.RequestUri, own);
#endif
            });
        }

        if (options.IsInstrumentationEnabled("sqlclient"))
        {
            builder.AddSqlClientInstrumentation();
        }

        // SHIELD: libraries that trace themselves through an ActivitySource, so
        // listening is enough and nothing is added to the app's dependencies.
        // MySqlConnector records the command text, never parameter values;
        // MongoDB.Driver 3.x records operation and collection, its query text
        // is off unless the app turns it on.
        if (options.IsInstrumentationEnabled("mysqlconnector"))
        {
            builder.AddSource(MySqlConnectorSource);
        }

        if (options.IsInstrumentationEnabled("mongodb"))
        {
            builder.AddSource(MongoDBSource);
        }

        if (options.IsInstrumentationEnabled("grpc"))
        {
            builder.AddSource(GrpcClientSpanProcessor.SourceName);
            builder.AddProcessor(new GrpcClientSpanProcessor());
        }

        return builder;
    }

    public static MeterProviderBuilder AddShield360Meters(this MeterProviderBuilder builder, Shield360Runtime runtime)
    {
        foreach (var meter in runtime.Meters)
        {
            builder.AddMeter(meter);
        }

        return builder;
    }

    public static TracerProviderBuilder AddShield360Exporter(this TracerProviderBuilder builder, ResolvedOptions options) =>
        builder.AddOtlpExporter(e =>
        {
            Configure(e, options, "traces");
            e.ExportProcessorType = options.DisableBatch ? ExportProcessorType.Simple : ExportProcessorType.Batch;
        });

    public static MeterProviderBuilder AddShield360Exporter(this MeterProviderBuilder builder, ResolvedOptions options) =>
        builder.AddOtlpExporter((e, reader) =>
        {
            Configure(e, options, "metrics");
            reader.PeriodicExportingMetricReaderOptions.ExportIntervalMilliseconds = (int)options.MetricExportInterval.TotalMilliseconds;
        });

    internal static void Configure(OtlpExporterOptions exporter, ResolvedOptions options, string signal)
    {
        exporter.Protocol = OtlpExportProtocol.HttpProtobuf;
        exporter.Endpoint = EndpointGuard.SignalEndpoint(options.OtlpEndpoint, signal);
        exporter.TimeoutMilliseconds = (int)options.ExportTimeout.TotalMilliseconds;

        // Headers are set on the HttpClient rather than through the exporter's
        // comma-separated Headers string, so a value containing '=' or ',' (an
        // API key, for one) reaches the server intact. The exporter also reads
        // OTEL_EXPORTER_OTLP_HEADERS on its own; clear that so headers are not sent twice.
        exporter.Headers = null;
        var headers = options.OtlpHeaders;
        var timeout = options.ExportTimeout;
        exporter.HttpClientFactory = () =>
        {
            var client = new HttpClient { Timeout = timeout };
            foreach (var kv in headers)
            {
                client.DefaultRequestHeaders.TryAddWithoutValidation(kv.Key, kv.Value);
            }

            return client;
        };
    }
}
