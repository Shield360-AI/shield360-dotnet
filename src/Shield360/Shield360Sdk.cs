using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Shield360.Flags;
using Shield360.Internal;
using Shield360.Rasp;
using Shield360.RuleEngine;

namespace Shield360;

/// <summary>
/// Entry point for console apps and other code without a host: call
/// <see cref="Init(Shield360Options?)"/> once at start-up and dispose the
/// handle (or call <see cref="Shutdown"/>) before the process exits.
/// For ASP.NET Core and other hosted apps, use <c>services.AddShield360()</c>.
/// </summary>
/// <example>
/// <code>
/// using var shield360 = Shield360Sdk.Init(new Shield360Options
/// {
///     ApplicationName = "my-app",
///     Environment = "production",
/// });
/// </code>
/// </example>
public static partial class Shield360Sdk
{
    /// <summary>
    /// The SDK version. Read from the assembly, so <c>&lt;Version&gt;</c> in
    /// Shield360.csproj is the only place it is set (the release bumps it there).
    /// </summary>
    public static string Version { get; } = ReadVersion();

    /// <summary>The name of the ActivitySource Shield360's own spans come from.</summary>
    public const string ActivitySourceName = "Shield360";

    /// <summary>The name of the Meter Shield360's own metrics come from.</summary>
    public const string MeterName = "Shield360";

    private static readonly object s_lock = new();
    private static readonly Lazy<FlagsClient> s_flags = new(() => new FlagsClient(), LazyThreadSafetyMode.ExecutionAndPublication);
    private static Shield360Handle? s_handle;

    /// <summary>
    /// The SDK's own feature-flags client. It reads <see cref="Init(Shield360Options?)"/>'s
    /// Shield360 URL, API key and application name (or <c>SHIELD360_URL</c>,
    /// <c>SHIELD360_API_KEY</c> and <c>OTEL_SERVICE_NAME</c>) when it fetches,
    /// and starts polling on first use.
    /// </summary>
    public static FlagsClient Flags => s_flags.Value;

    /// <summary>
    /// The logger factory whose records go to Shield360 when application logs are
    /// on (<see cref="Shield360Options.CaptureLogs"/> or <c>SHIELD360_CAPTURE_LOGS=true</c>),
    /// and a no-op factory otherwise, so a library can take loggers from it
    /// without deciding for the application. Hosted apps use the host's logging
    /// with <c>services.AddShield360()</c> or <c>builder.Logging.AddShield360Logs()</c>.
    /// </summary>
    public static ILoggerFactory LoggerFactory
    {
        get
        {
            lock (s_lock)
            {
                return s_handle?.LoggerFactory ?? NullLoggerFactory.Instance;
            }
        }
    }

    /// <summary>A logger for <paramref name="categoryName"/> from <see cref="LoggerFactory"/>.</summary>
    public static ILogger CreateLogger(string categoryName) => LoggerFactory.CreateLogger(categoryName);

    /// <summary>Whether <see cref="Init(Shield360Options?)"/> has run and not been shut down.</summary>
    public static bool IsInitialized
    {
        get
        {
            lock (s_lock)
            {
                return s_handle is not null;
            }
        }
    }

    /// <summary>
    /// Starts exporting traces and metrics from Shield360 and the supported .NET
    /// AI libraries over OTLP/HTTP. Call it before creating any AI client: the
    /// libraries read their telemetry switches once.
    /// </summary>
    /// <exception cref="InvalidOperationException">Shield360 is already initialised.</exception>
    /// <exception cref="Shield360Exception">The configuration is invalid.</exception>
    public static Shield360Handle Init(Shield360Options? options = null) =>
        Init(options, System.Environment.GetEnvironmentVariable);

    internal static Shield360Handle Init(Shield360Options? options, Func<string, string?> env)
    {
        lock (s_lock)
        {
            if (s_handle is not null)
            {
                // SHIELD: started by the zero-code startup hook: the app's own Init() is a no-op.
                if (ReferenceEquals(s_handle, s_zeroCodeHandle))
                {
                    NoteSkippedInit();
                    return s_handle;
                }

                throw new InvalidOperationException("Shield360 is already initialized. Call Shield360Sdk.Shutdown() first.");
            }

            var resolved = ResolvedOptions.Resolve(options, env);
            var runtime = Shield360Runtime.Activate(resolved);

            TracerProvider? tracerProvider = null;
            MeterProvider? meterProvider = null;
            ILoggerFactory? loggerFactory = null;
            Shield360LogProcessor? logProcessor = null;
            try
            {
                // SHIELD: application logs, opt-in (data minimisation).
                if (resolved.CaptureLogs)
                {
                    var processor = new Shield360LogProcessor(AppLogs.ExportProcessor(resolved), resolved.LogLevel);
                    logProcessor = processor;
                    loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(b => b
                        .SetMinimumLevel(resolved.LogLevel)
                        .AddShield360Logs(resolved, setResource: true, processor));
                }

                if (!resolved.DisableTracing)
                {
                    tracerProvider = Sdk.CreateTracerProviderBuilder()
                        .SetResourceBuilder(ResourceBuilder.CreateDefault().ConfigureShield360(resolved))
                        .AddShield360Sources(runtime)
                        .AddShield360Exporter(resolved)
                        .Build();
                }

                if (!resolved.DisableMetrics)
                {
                    meterProvider = Sdk.CreateMeterProviderBuilder()
                        .SetResourceBuilder(ResourceBuilder.CreateDefault().ConfigureShield360(resolved))
                        .AddShield360Meters(runtime)
                        .AddShield360Exporter(resolved)
                        .Build();
                }
            }
            catch
            {
                tracerProvider?.Dispose();
                meterProvider?.Dispose();
                loggerFactory?.Dispose();
                runtime.Deactivate();
                throw;
            }

            // Never throws; RASP stays off when it cannot start.
            RaspRuntime.Start(options?.Rasp, RaspStartContext.From(resolved, env));
            s_handle = new Shield360Handle(runtime, tracerProvider, meterProvider, loggerFactory, logProcessor);
            return s_handle;
        }
    }

    /// <summary>Flushes and stops exporting. Safe to call when not initialised.</summary>
    public static void Shutdown()
    {
        Shield360Handle? handle;
        lock (s_lock)
        {
            handle = s_handle;
            s_handle = null;
        }

        handle?.Stop();
    }

    /// <summary>
    /// Evaluates trace attributes against the Shield360 rule engine and returns
    /// the matching rules and entities. Does not need <see cref="Init(Shield360Options?)"/>.
    /// </summary>
    public static async Task<EvaluateRuleResult> EvaluateRuleAsync(EvaluateRuleOptions options, CancellationToken cancellationToken = default)
    {
        using var client = new RuleEngineClient();
        return await client.EvaluateRuleAsync(options, cancellationToken).ConfigureAwait(false);
    }

    private static string ReadVersion()
    {
        var informational = typeof(Shield360Sdk).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrEmpty(informational))
        {
            return typeof(Shield360Sdk).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        }

        // Source Link appends "+<commit>"; the version is what comes before it.
        var plus = informational!.IndexOf('+');
        return plus < 0 ? informational : informational.Substring(0, plus);
    }

    internal static void Release(Shield360Handle handle)
    {
        lock (s_lock)
        {
            if (ReferenceEquals(s_handle, handle))
            {
                s_handle = null;
            }
        }

        handle.Stop();
    }
}

/// <summary>
/// Returned by <see cref="Shield360Sdk.Init(Shield360Options?)"/>. Disposing it
/// flushes pending telemetry and shuts Shield360 down.
/// </summary>
public sealed class Shield360Handle : IDisposable
{
    private readonly Shield360Runtime _runtime;
    private int _stopped;

    private readonly Shield360LogProcessor? _logProcessor;

    internal Shield360Handle(Shield360Runtime runtime, TracerProvider? tracerProvider, MeterProvider? meterProvider, ILoggerFactory? loggerFactory = null, Shield360LogProcessor? logProcessor = null)
    {
        _runtime = runtime;
        LoggerFactory = loggerFactory;
        _logProcessor = logProcessor;
        TracerProvider = tracerProvider;
        MeterProvider = meterProvider;
    }

    /// <summary>The tracer provider, or null when tracing is off.</summary>
    public TracerProvider? TracerProvider { get; }

    /// <summary>The meter provider, or null when metrics are off.</summary>
    public MeterProvider? MeterProvider { get; }

    /// <summary>The logger factory for application logs, or null when they are off.</summary>
    public ILoggerFactory? LoggerFactory { get; }

    /// <summary>Exports anything buffered now.</summary>
    public bool ForceFlush(int timeoutMilliseconds = 10000)
    {
        var traces = TracerProvider?.ForceFlush(timeoutMilliseconds) ?? true;
        var metrics = MeterProvider?.ForceFlush(timeoutMilliseconds) ?? true;
        var logs = _logProcessor?.ForceFlush(timeoutMilliseconds) ?? true;
        return traces && metrics && logs;
    }

    /// <summary>Flushes and shuts Shield360 down.</summary>
    public void Dispose() => Shield360Sdk.Release(this);

    internal void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) == 1)
        {
            return;
        }

        RaspRuntime.Shutdown(RaspRuntime.ShutdownFlushWait);
        RuntimePackages.Stop(); // SHIELD: runtime SCA
        RaspEngine.Configure(new EngineSettings(Enabled: false, ApplicationName: _runtime.Options.ApplicationName));
        TracerProvider?.Dispose();
        MeterProvider?.Dispose();
        // Disposing the factory disposes the OpenTelemetry logger provider, which flushes the batch.
        LoggerFactory?.Dispose();
        _runtime.Deactivate();
    }
}
