using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using Shield360.Rasp;

namespace Shield360.Internal;

/// <summary>
/// Application logs to Shield360, when asked for: the same rules as the Python
/// SDK (the reference) and every other Shield360 SDK.
/// </summary>
/// <remarks>
/// Records go through OpenTelemetry's ILogger provider to an OTLP/HTTP log
/// exporter on the same endpoint, headers and resource as the traces, so they
/// carry the active Activity's trace and span ids. Off by default
/// (<c>CaptureLogs</c> or <c>SHIELD360_CAPTURE_LOGS</c>).
/// </remarks>
internal static class AppLogs
{
    /// <summary>The lowest level sent when nothing says otherwise.</summary>
    public const LogLevel DefaultLevel = LogLevel.Information;

    /// <summary>Records a second each bridge sends at most; the rest are dropped.</summary>
    public const int DefaultMaxPerSecond = 500;

    internal const int MaxBodyLength = 16384;
    internal const int MaxStackTraceLength = 16384;
    internal const int MaxAttributeLength = 4096;

    internal const string OriginalFormat = "{OriginalFormat}";
    private static readonly string[] s_ownCategories = { "Shield360", "OpenTelemetry" };

    /// <summary>A level from a name (<c>info</c>, <c>WARN</c>, <c>critical</c>); Information when empty or unknown.</summary>
    public static LogLevel ResolveLevel(string? name)
    {
        switch (name?.Trim().ToLowerInvariant())
        {
            case "trace":
                return LogLevel.Trace;
            case "debug":
                return LogLevel.Debug;
            case "warn":
            case "warning":
                return LogLevel.Warning;
            case "error":
                return LogLevel.Error;
            case "fatal":
            case "critical":
                return LogLevel.Critical;
            default:
                return DefaultLevel;
        }
    }

    /// <summary>The SDK's own categories (and OpenTelemetry's), which are never exported.</summary>
    public static bool IsOwnCategory(string? category)
    {
        if (string.IsNullOrEmpty(category))
        {
            return false;
        }

        foreach (var own in s_ownCategories)
        {
            if (string.Equals(category, own, StringComparison.OrdinalIgnoreCase)
                || category!.StartsWith(own + ".", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The OpenTelemetry short severity name for a level. The number (1, 5, 9,
    /// 13, 17, 21) comes from the level in OpenTelemetry's ILogger provider.
    /// </summary>
    public static string SeverityText(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRACE",
        LogLevel.Debug => "DEBUG",
        LogLevel.Information => "INFO",
        LogLevel.Warning => "WARN",
        LogLevel.Error => "ERROR",
        _ => "FATAL",
    };

    /// <summary>Masked by the shared contract (sdk/rasp/README.md, Masking), then cut to <paramref name="max"/> characters.</summary>
    public static string Mask(string value, int max) => Masking.MaskText(value, max);

    /// <summary>Whether an attribute is masked: everything but <c>code.*</c> and <c>exception.type</c>.</summary>
    public static bool IsMasked(string key) =>
        !key.StartsWith("code.", StringComparison.Ordinal) && !string.Equals(key, "exception.type", StringComparison.Ordinal);

    /// <summary>
    /// An attribute value as exported: <c>code.*</c> and <c>exception.type</c>
    /// as they are; anything under a credential name <c>***</c>; strings
    /// masked and cut; lists item by item (an array); maps entry by entry (as
    /// JSON text); other primitives as they are, anything else as masked text.
    /// </summary>
    public static object? CleanValue(string key, object? value)
    {
        if (value is null)
        {
            return null;
        }

        if (!IsMasked(key))
        {
            return value is string || IsPrimitive(value) ? value : Convert.ToString(value, CultureInfo.InvariantCulture);
        }

        var limit = key == "exception.stacktrace" ? MaxStackTraceLength : MaxAttributeLength;
        if (value is not string && !IsPrimitive(value) && value is not System.Collections.IEnumerable)
        {
            value = Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
        }

        var masked = Masking.MaskValue(key, value, limit);
        switch (masked)
        {
            case IDictionary<string, object?> map:
                return Mask(System.Text.Json.JsonSerializer.Serialize(map), limit);
            case List<object?> list:
                var items = new object?[list.Count];
                for (var i = 0; i < list.Count; i++)
                {
                    items[i] = list[i] switch
                    {
                        null => null,
                        string s => s,
                        var p when IsPrimitive(p) => p,
                        var other => Convert.ToString(other is IDictionary<string, object?> m ? System.Text.Json.JsonSerializer.Serialize(m) : other, CultureInfo.InvariantCulture),
                    };
                }

                return items;
            default:
                return masked;
        }
    }

    private static bool IsPrimitive(object value) =>
        value is bool or byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal;

    /// <summary>The OTLP log exporter wired like the trace exporter, with batching unless DisableBatch.</summary>
    public static BaseProcessor<LogRecord> ExportProcessor(ResolvedOptions options)
    {
        var exporterOptions = new OtlpExporterOptions();
        OpenTelemetrySetup.Configure(exporterOptions, options, "logs");
        var exporter = new OtlpLogExporter(exporterOptions);
        return options.DisableBatch
            ? new SimpleLogRecordExportProcessor(exporter)
            : new BatchLogRecordExportProcessor(exporter);
    }
}

/// <summary>
/// Sits in front of Shield360's log exporter: drops what must never be sent
/// (below the level, the SDK's own categories, records written while one is
/// exported, the excess over the rate limit), masks the rest, and passes it on.
/// Never throws into the application.
/// </summary>
internal sealed class Shield360LogProcessor : CompositeProcessor<LogRecord>
{
    [ThreadStatic]
    private static bool t_emitting;

    private readonly LogLevel _minimum;
    private readonly RateLimiter _limiter;

    public Shield360LogProcessor(BaseProcessor<LogRecord> exporter, LogLevel minimum, int maxPerSecond = AppLogs.DefaultMaxPerSecond, Func<long>? clock = null)
        : base(new[] { exporter })
    {
        _minimum = minimum;
        _limiter = new RateLimiter(maxPerSecond, clock);
    }

    /// <summary>The lowest level sent.</summary>
    public LogLevel MinimumLevel => _minimum;

    /// <summary>Records dropped by the rate limit so far.</summary>
    public long Dropped => _limiter.Dropped;

    /// <inheritdoc />
    public override void OnEnd(LogRecord data)
    {
        if (data is null || t_emitting || Sdk.SuppressInstrumentation)
        {
            return;
        }

        t_emitting = true;
        try
        {
            if (data.LogLevel == LogLevel.None || data.LogLevel < _minimum || AppLogs.IsOwnCategory(data.CategoryName) || !_limiter.TryAcquire())
            {
                return;
            }

            Shape(data);
            base.OnEnd(data);
        }
#pragma warning disable CA1031 // Logging never throws into the application.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
        finally
        {
            t_emitting = false;
        }
    }

    /// <summary>Body, severity and attributes as every Shield360 SDK sends them.</summary>
    internal static void Shape(LogRecord data)
    {
        SetSeverityText(data, AppLogs.SeverityText(data.LogLevel));

        string? template = null;
        var attributes = new List<KeyValuePair<string, object?>>();
        if (data.Attributes is not null)
        {
            foreach (var kv in data.Attributes)
            {
                if (kv.Key == AppLogs.OriginalFormat)
                {
                    template = kv.Value as string;
                    continue;
                }

                attributes.Add(new KeyValuePair<string, object?>(kv.Key, AppLogs.CleanValue(kv.Key, kv.Value)));
            }
        }

        // Masked before it is cut (the contract's look-ahead), so a credential crossing the cut stays hidden.
        var message = data.FormattedMessage ?? data.Body ?? template ?? string.Empty;
        var body = AppLogs.Mask(message, AppLogs.MaxBodyLength);
        data.FormattedMessage = body;
        data.Body = body;

        // The exception goes out as masked attributes, not as the object the
        // exporter would write unmasked.
        var exception = data.Exception;
        if (exception is not null)
        {
            attributes.Add(new KeyValuePair<string, object?>("exception.type", exception.GetType().FullName ?? exception.GetType().Name));
            attributes.Add(new KeyValuePair<string, object?>("exception.message", AppLogs.Mask(exception.Message, AppLogs.MaxAttributeLength)));
            attributes.Add(new KeyValuePair<string, object?>("exception.stacktrace", AppLogs.Mask(exception.ToString(), AppLogs.MaxStackTraceLength)));
            data.Exception = null;
        }

        data.Attributes = attributes;
    }

    // LogRecord.SeverityText is public only in OpenTelemetry's prerelease
    // builds; the stable one writes the ILogger level name ("Information").
    // Set through reflection when it is there, so the text matches the other
    // SDKs (INFO, WARN, FATAL); the severity number is right either way.
    private static readonly System.Reflection.PropertyInfo? s_severityText =
        typeof(LogRecord).GetProperty("SeverityText", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic);

    internal static void SetSeverityText(LogRecord data, string text)
    {
        try
        {
            if (s_severityText?.CanWrite == true && s_severityText.PropertyType == typeof(string))
            {
                s_severityText.SetValue(data, text);
            }
        }
#pragma warning disable CA1031 // Only the text is lost.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
    }

    /// <summary>A fixed one-second window: at most <c>max</c> records in each.</summary>
    private sealed class RateLimiter
    {
        private readonly int _max;
        private readonly Func<long> _clock;
        private readonly object _lock = new();
        private long _windowStart = long.MinValue;
        private int _count;
        private long _dropped;

        public RateLimiter(int max, Func<long>? clock)
        {
            _max = max > 0 ? max : AppLogs.DefaultMaxPerSecond;
            _clock = clock ?? (() => Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency);
        }

        public long Dropped => Interlocked.Read(ref _dropped);

        public bool TryAcquire()
        {
            var now = _clock();
            lock (_lock)
            {
                if (_windowStart == long.MinValue || now - _windowStart >= 1000)
                {
                    _windowStart = now;
                    _count = 0;
                }

                if (_count < _max)
                {
                    _count++;
                    return true;
                }
            }

            Interlocked.Increment(ref _dropped);
            return false;
        }
    }
}

/// <summary>
/// An ILoggerProvider that writes through the logger factory
/// <see cref="Shield360Sdk.Init(Shield360Options?)"/> built, so a host started
/// by the zero-code hook sends its ILogger records to Shield360 too.
/// </summary>
internal sealed class Shield360ForwardingLoggerProvider : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new Forwarding(categoryName);

    public void Dispose()
    {
    }

    private sealed class Forwarding : ILogger
    {
        private readonly string _category;

        public Forwarding(string category) => _category = category;

        private ILogger Target => Shield360Sdk.LoggerFactory.CreateLogger(_category);

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => Target.IsEnabled(logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            try
            {
                Target.Log(logLevel, eventId, state, exception, formatter);
            }
#pragma warning disable CA1031 // Logging never throws into the application.
            catch (Exception)
#pragma warning restore CA1031
            {
            }
        }
    }
}
