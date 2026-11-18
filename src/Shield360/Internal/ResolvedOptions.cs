using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;

namespace Shield360.Internal;

/// <summary>
/// <see cref="Shield360Options"/> with every value settled. Precedence is
/// option, then environment variable, then default, matching the other SDKs.
/// </summary>
internal sealed class ResolvedOptions
{
    internal const string DefaultEndpoint = "http://127.0.0.1:4318";
    internal const string DefaultName = "default";
    internal const string IngestPath = "/api/ingest/otlp";

    public string OtlpEndpoint { get; private set; } = DefaultEndpoint;
    public IReadOnlyDictionary<string, string> OtlpHeaders { get; private set; } = new Dictionary<string, string>();
    public string? ApiKey { get; private set; }
    public string? Shield360Url { get; private set; }
    public string ApplicationName { get; private set; } = DefaultName;
    public string Environment { get; private set; } = DefaultName;
    public string? ServiceVersion { get; private set; }
    public bool CaptureMessageContent { get; private set; }
    public string? PricingJson { get; private set; }
    public IReadOnlyDictionary<string, ModelPricing> PricingOverrides { get; private set; } = new Dictionary<string, ModelPricing>();
    public bool DisableTracing { get; private set; }
    public bool DisableMetrics { get; private set; }
    public bool DisableBatch { get; private set; }
    public IReadOnlyCollection<string> DisabledInstrumentors { get; private set; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string> CustomSpanAttributes { get; private set; } = new Dictionary<string, string>();
    public IReadOnlyDictionary<string, string> ResourceAttributes { get; private set; } = new Dictionary<string, string>();
    public TimeSpan ExportTimeout { get; private set; } = TimeSpan.FromSeconds(10);
    public TimeSpan MetricExportInterval { get; private set; } = TimeSpan.FromSeconds(30);
    public bool CaptureLogs { get; private set; }
    /// <summary>SHIELD: runtime SCA — Shield360Options.RuntimePackages as given (null: on unless SHIELD360_RUNTIME_PACKAGES=off).</summary>
    public bool? RuntimePackages { get; private set; }
    public Microsoft.Extensions.Logging.LogLevel LogLevel { get; private set; } = AppLogs.DefaultLevel;

    public bool IsInstrumentationEnabled(string name) =>
        !DisabledInstrumentors.Contains(name, StringComparer.OrdinalIgnoreCase);

    public static ResolvedOptions Resolve(Shield360Options? options, Func<string, string?> env)
    {
        var o = options ?? new Shield360Options();
        var r = new ResolvedOptions
        {
            ApiKey = Trimmed(o.ApiKey) ?? Trimmed(env("SHIELD360_API_KEY")),
            Shield360Url = (Trimmed(o.Shield360Url) ?? Trimmed(env("SHIELD360_URL")))?.TrimEnd('/'),
            ApplicationName = Trimmed(o.ApplicationName) ?? Trimmed(env("OTEL_SERVICE_NAME")) ?? DefaultName,
            Environment = Trimmed(o.Environment) ?? Trimmed(env("OTEL_DEPLOYMENT_ENVIRONMENT")) ?? DefaultName,
            ServiceVersion = Trimmed(o.ServiceVersion) ?? Trimmed(env("SHIELD360_SERVICE_VERSION")) ?? Trimmed(env("OTEL_SERVICE_VERSION")),
            CaptureMessageContent = o.CaptureMessageContent ?? ParseBool(env("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT")) ?? false,
            PricingJson = Trimmed(o.PricingJson) ?? Trimmed(env("SHIELD360_PRICING_JSON")),
            DisableTracing = o.DisableTracing ?? false,
            DisableMetrics = o.DisableMetrics ?? ParseBool(env("SHIELD360_DISABLE_METRICS")) ?? false,
            DisableBatch = o.DisableBatch ?? ParseBool(env("SHIELD360_DISABLE_BATCH")) ?? false,
            ExportTimeout = Positive(o.ExportTimeout) ?? TimeSpan.FromSeconds(10),
            MetricExportInterval = Positive(o.MetricExportInterval)
                ?? Milliseconds(env("OTEL_EXPORTER_OTLP_METRICS_EXPORT_INTERVAL"))
                ?? TimeSpan.FromSeconds(30),
            CaptureLogs = o.CaptureLogs ?? ParseBool(env("SHIELD360_CAPTURE_LOGS")) ?? false,
            RuntimePackages = o.RuntimePackages,
            LogLevel = AppLogs.ResolveLevel(Trimmed(o.LogLevel) ?? Trimmed(env("SHIELD360_LOG_LEVEL"))),
        };

        r.DisabledInstrumentors = (o.DisabledInstrumentors ?? SplitCsv(env("SHIELD360_DISABLED_INSTRUMENTORS")))
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToArray();

        r.PricingOverrides = o.PricingOverrides is null
            ? new Dictionary<string, ModelPricing>()
            : new Dictionary<string, ModelPricing>(o.PricingOverrides, StringComparer.OrdinalIgnoreCase);

        r.CustomSpanAttributes = Clean(o.CustomSpanAttributes ?? ParseJsonObject(env("SHIELD360_CUSTOM_SPAN_ATTRIBUTES")));
        r.ResourceAttributes = Clean(o.ResourceAttributes);

        var headers = o.OtlpHeaders is null
            ? ParseOtlpHeaders(env("OTEL_EXPORTER_OTLP_HEADERS"))
            : new Dictionary<string, string>(o.OtlpHeaders, StringComparer.OrdinalIgnoreCase);

        var endpoint = Trimmed(o.OtlpEndpoint) ?? Trimmed(env("OTEL_EXPORTER_OTLP_ENDPOINT"));
        if (endpoint is null && r.Shield360Url is not null && r.ApiKey is not null)
        {
            // With no OTLP endpoint, the Shield360 URL and API key are the
            // destination: the platform's authenticated ingest route.
            EndpointGuard.RequireSecure(r.Shield360Url, "Shield360Url");
            endpoint = r.Shield360Url + IngestPath;
            if (!headers.Keys.Any(k => string.Equals(k, "Authorization", StringComparison.OrdinalIgnoreCase)))
            {
                headers["Authorization"] = "Bearer " + r.ApiKey;
            }
        }

        r.OtlpEndpoint = endpoint ?? DefaultEndpoint;
        r.OtlpHeaders = headers;
        return r;
    }

    /// <summary>
    /// Parses <c>OTEL_EXPORTER_OTLP_HEADERS</c>: comma-separated <c>name=value</c>
    /// pairs. Splits on the first <c>=</c> only, because a Shield360 API key can
    /// end in <c>=</c>.
    /// </summary>
    internal static Dictionary<string, string> ParseOtlpHeaders(string? raw)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return headers;
        }

        foreach (var pair in raw!.Split(','))
        {
            var at = pair.IndexOf('=');
            if (at <= 0)
            {
                continue;
            }

            var name = pair.Substring(0, at).Trim();
            var value = pair.Substring(at + 1).Trim();
            if (name.Length > 0 && value.Length > 0)
            {
                headers[name] = value;
            }
        }

        return headers;
    }

    internal static bool? ParseBool(string? raw)
    {
        switch (raw?.Trim().ToLowerInvariant())
        {
            case "true":
            case "1":
            case "yes":
            case "on":
                return true;
            case "false":
            case "0":
            case "no":
            case "off":
                return false;
            default:
                return null;
        }
    }

    private static string? Trimmed(string? value)
    {
        var t = value?.Trim();
        return string.IsNullOrEmpty(t) ? null : t;
    }

    private static TimeSpan? Positive(TimeSpan? value) => value > TimeSpan.Zero ? value : null;

    private static TimeSpan? Milliseconds(string? raw) =>
        int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ms) && ms > 0
            ? TimeSpan.FromMilliseconds(ms)
            : null;

    private static string[] SplitCsv(string? raw) =>
        string.IsNullOrWhiteSpace(raw) ? Array.Empty<string>() : raw!.Split(',');

    private static Dictionary<string, string>? ParseJsonObject(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(raw!);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var result = new Dictionary<string, string>();
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                result[p.Name] = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? string.Empty : p.Value.GetRawText();
            }

            return result;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static Dictionary<string, string> Clean(IDictionary<string, string>? source)
    {
        var result = new Dictionary<string, string>();
        if (source is null)
        {
            return result;
        }

        foreach (var kv in source)
        {
            if (!string.IsNullOrWhiteSpace(kv.Key) && !string.IsNullOrEmpty(kv.Value))
            {
                result[kv.Key.Trim()] = kv.Value;
            }
        }

        return result;
    }
}
