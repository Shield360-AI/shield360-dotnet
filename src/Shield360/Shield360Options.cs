using System;
using System.Collections.Generic;
using Shield360.Rasp;

namespace Shield360;

/// <summary>
/// Settings for <see cref="Shield360Sdk.Init(Shield360Options?)"/> and
/// <c>services.AddShield360(...)</c>. Every property is optional: an unset
/// property falls back to its environment variable, then to its default.
/// The names and environment variables match the Python, TypeScript and Go SDKs.
/// </summary>
public sealed class Shield360Options
{
    /// <summary>
    /// The OTLP/HTTP endpoint telemetry is sent to, for example
    /// <c>http://127.0.0.1:4318</c>. The signal path (<c>/v1/traces</c>,
    /// <c>/v1/metrics</c>) is added for you.
    /// Environment: <c>OTEL_EXPORTER_OTLP_ENDPOINT</c>. When neither is set and
    /// <see cref="Shield360Url"/> and <see cref="ApiKey"/> are, telemetry goes to
    /// the Shield360 ingest route with the API key as a bearer token.
    /// Default: <c>http://127.0.0.1:4318</c>.
    /// </summary>
    public string? OtlpEndpoint { get; set; }

    /// <summary>
    /// Extra headers sent with every OTLP export, such as an <c>Authorization</c> header.
    /// Environment: <c>OTEL_EXPORTER_OTLP_HEADERS</c> (comma-separated <c>name=value</c> pairs).
    /// </summary>
    public IDictionary<string, string>? OtlpHeaders { get; set; }

    /// <summary>
    /// The Shield360 API key. Used as the bearer token for the Shield360 ingest
    /// route when no OTLP endpoint is set, and by the rule engine client.
    /// Environment: <c>SHIELD360_API_KEY</c>. Never logged.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// The Shield360 dashboard URL, for example <c>https://app.shield360.ai</c>.
    /// Environment: <c>SHIELD360_URL</c>. Must be HTTPS unless it points at localhost.
    /// </summary>
    public string? Shield360Url { get; set; }

    /// <summary>
    /// The application name, recorded as <c>service.name</c>.
    /// Environment: <c>OTEL_SERVICE_NAME</c>. Default: <c>default</c>.
    /// </summary>
    public string? ApplicationName { get; set; }

    /// <summary>
    /// The deployment environment, recorded as <c>deployment.environment</c>.
    /// Environment: <c>OTEL_DEPLOYMENT_ENVIRONMENT</c>. Default: <c>default</c>.
    /// </summary>
    public string? Environment { get; set; }

    /// <summary>
    /// The application version, recorded as <c>service.version</c>.
    /// Environment: <c>SHIELD360_SERVICE_VERSION</c>, then <c>OTEL_SERVICE_VERSION</c>.
    /// </summary>
    public string? ServiceVersion { get; set; }

    /// <summary>
    /// Record prompt and response text (and tool call arguments and results) on spans.
    /// Off by default: nothing sensitive is sent unless you opt in, and a Shield360
    /// organisation stores content only when its Data retention setting allows it.
    /// Environment: <c>OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT</c>. Default: <c>false</c>.
    /// </summary>
    public bool? CaptureMessageContent { get; set; }

    /// <summary>
    /// Where the pricing data comes from: an <c>http(s)</c> URL, a file path, or a
    /// JSON string, in the same format as the Python and TypeScript SDKs
    /// (<c>chat</c>, <c>embeddings</c>, ... with prices per 1,000 tokens).
    /// Environment: <c>SHIELD360_PRICING_JSON</c>. Default: the pricing data shipped with the SDK.
    /// </summary>
    public string? PricingJson { get; set; }

    /// <summary>
    /// Per-model chat prices that win over the pricing data, keyed by model name.
    /// </summary>
    public IDictionary<string, ModelPricing>? PricingOverrides { get; set; }

    /// <summary>Turn off trace export. Default: <c>false</c>.</summary>
    public bool? DisableTracing { get; set; }

    /// <summary>
    /// Turn off metric export.
    /// Environment: <c>SHIELD360_DISABLE_METRICS</c>. Default: <c>false</c>.
    /// </summary>
    public bool? DisableMetrics { get; set; }

    /// <summary>
    /// Export each span as it ends instead of in batches (useful in tests and short scripts).
    /// Environment: <c>SHIELD360_DISABLE_BATCH</c>. Default: <c>false</c>.
    /// </summary>
    public bool? DisableBatch { get; set; }

    /// <summary>
    /// Instrumentations to leave off, by name: <c>microsoft-extensions-ai</c>,
    /// <c>openai</c>, <c>azure-ai-inference</c>, <c>semantic-kernel</c>.
    /// Environment: <c>SHIELD360_DISABLED_INSTRUMENTORS</c> (comma-separated).
    /// </summary>
    public ICollection<string>? DisabledInstrumentors { get; set; }

    /// <summary>
    /// Attributes added to every GenAI span (not to metrics).
    /// Environment: <c>SHIELD360_CUSTOM_SPAN_ATTRIBUTES</c> (a JSON object).
    /// </summary>
    public IDictionary<string, string>? CustomSpanAttributes { get; set; }

    /// <summary>Attributes added to the OpenTelemetry resource, such as <c>host.name</c>.</summary>
    public IDictionary<string, string>? ResourceAttributes { get; set; }

    /// <summary>Timeout for each OTLP export. Default: 10 seconds.</summary>
    public TimeSpan? ExportTimeout { get; set; }

    /// <summary>
    /// Runtime application self-protection (RASP): set it to turn RASP on (unless
    /// <see cref="RaspOptions.Enabled"/> is <c>false</c>). Unset, RASP is off unless
    /// <c>SHIELD360_RASP=monitor|block</c>; <c>SHIELD360_RASP=off</c> always wins.
    /// In ASP.NET Core, add the middleware with <c>services.AddShield360Rasp()</c>
    /// from the Shield360.AspNetCore package.
    /// </summary>
    public RaspOptions? Rasp { get; set; }

    /// <summary>
    /// SHIELD: runtime SCA — report the NuGet packages this process has loaded (package id
    /// and version, never paths) so Shield360 can match them against vulnerability data.
    /// On by default with a Shield360 URL and API key; <c>false</c> or
    /// <c>SHIELD360_RUNTIME_PACKAGES=off</c> turns it off.
    /// </summary>
    public bool? RuntimePackages { get; set; }

    /// <summary>
    /// How often metrics are exported.
    /// Environment: <c>OTEL_EXPORTER_OTLP_METRICS_EXPORT_INTERVAL</c> (milliseconds). Default: 30 seconds.
    /// </summary>
    public TimeSpan? MetricExportInterval { get; set; }

    /// <summary>
    /// Send the application's own ILogger records to Shield360, on the same
    /// endpoint and key as traces: through <see cref="Shield360Sdk.LoggerFactory"/>
    /// after <see cref="Shield360Sdk.Init(Shield360Options?)"/>, or the host's
    /// logging after <c>services.AddShield360()</c>. Messages and attributes are
    /// masked, at most 500 records a second are sent, in batches.
    /// Environment: <c>SHIELD360_CAPTURE_LOGS</c>. Default: <c>false</c>.
    /// </summary>
    public bool? CaptureLogs { get; set; }

    /// <summary>
    /// The lowest level sent when <see cref="CaptureLogs"/> is on: <c>trace</c>,
    /// <c>debug</c>, <c>info</c>, <c>warn</c>, <c>error</c> or <c>fatal</c>
    /// (<c>warning</c> and <c>critical</c> also work).
    /// Environment: <c>SHIELD360_LOG_LEVEL</c>. Default: <c>info</c>.
    /// </summary>
    public string? LogLevel { get; set; }
}

/// <summary>
/// Chat prices for one model, in USD per 1,000 tokens, the unit the pricing JSON uses.
/// </summary>
public sealed class ModelPricing
{
    /// <summary>Price per 1,000 input tokens.</summary>
    public double PromptPrice { get; set; }

    /// <summary>Price per 1,000 output tokens.</summary>
    public double CompletionPrice { get; set; }

    /// <summary>Price per 1,000 input tokens read from the prompt cache, if the model has one.</summary>
    public double? CacheReadPrice { get; set; }

    /// <summary>Price per 1,000 input tokens written to the prompt cache, if the model has one.</summary>
    public double? CacheCreationPrice { get; set; }
}
