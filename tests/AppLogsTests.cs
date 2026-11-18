using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Logs;
using Shield360.Internal;
using Xunit;

namespace Shield360.Tests;

/// <summary>
/// Application logs: the same rules as the Python SDK (the reference) and every
/// other Shield360 SDK — level, masking, the SDK's own categories, re-entry,
/// the rate limit, trace correlation, and failing open.
/// </summary>
public class AppLogsTests
{
    /// <summary>What an exported record carried, copied out (LogRecords are pooled).</summary>
    internal sealed record Captured(
        string? Category,
        LogLevel Level,
        string? Body,
        string? FormattedMessage,
        string? SeverityText,
        ActivityTraceId TraceId,
        ActivitySpanId SpanId,
        bool HasException,
        Dictionary<string, object?> Attributes);

    internal sealed class CapturingExporter : BaseExporter<LogRecord>
    {
        public ConcurrentQueue<Captured> Records { get; } = new();

        public Action? OnExport { get; set; }

        public override ExportResult Export(in Batch<LogRecord> batch)
        {
            OnExport?.Invoke();
            foreach (var r in batch)
            {
                var attrs = new Dictionary<string, object?>();
                foreach (var kv in r.Attributes ?? Array.Empty<KeyValuePair<string, object?>>())
                {
                    attrs[kv.Key] = kv.Value;
                }

                var text = typeof(LogRecord).GetProperty("SeverityText", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)?.GetValue(r) as string;
                Records.Enqueue(new Captured(r.CategoryName, r.LogLevel, r.Body, r.FormattedMessage, text, r.TraceId, r.SpanId, r.Exception is not null, attrs));
            }

            return ExportResult.Success;
        }
    }

    private sealed class ThrowingExporter : BaseExporter<LogRecord>
    {
        public override ExportResult Export(in Batch<LogRecord> batch) => throw new InvalidOperationException("collector down");
    }

    private static ILoggerFactory Factory(BaseExporter<LogRecord> exporter, LogLevel level = LogLevel.Information, int maxPerSecond = AppLogs.DefaultMaxPerSecond, Func<long>? clock = null)
    {
        var resolved = ResolvedOptions.Resolve(new Shield360Options { ApplicationName = "logs-test", CaptureLogs = true }, Env.Empty);
        var processor = new Shield360LogProcessor(new SimpleLogRecordExportProcessor(exporter), level, maxPerSecond, clock);
        return LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddShield360Logs(resolved, setResource: true, processor));
    }

    [Fact]
    public void Sends_records_at_the_level_and_above_with_OpenTelemetry_short_severity_names()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter, LogLevel.Warning))
        {
            var log = factory.CreateLogger("tests.app");
            log.LogTrace("t");
            log.LogDebug("d");
            log.LogInformation("i");
            log.LogWarning("w {Arg}", "arg");
            log.LogError("e");
            log.LogCritical("c");
        }

        var records = exporter.Records.ToList();
        Assert.Equal(new[] { "w arg", "e", "c" }, records.Select(r => r.Body));
        Assert.Equal(new[] { "w arg", "e", "c" }, records.Select(r => r.FormattedMessage));
        Assert.Equal(new[] { LogLevel.Warning, LogLevel.Error, LogLevel.Critical }, records.Select(r => r.Level));
        Assert.Equal(new[] { "WARN", "ERROR", "FATAL" }, records.Select(r => r.SeverityText));
        Assert.All(records, r => Assert.Equal("tests.app", r.Category));
    }

    [Fact]
    public void Defaults_to_info()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            var log = factory.CreateLogger("tests.app");
            log.LogDebug("d");
            log.LogInformation("i");
        }

        Assert.Equal(new[] { "i" }, exporter.Records.Select(r => r.Body));
        Assert.Equal("INFO", exporter.Records.Single().SeverityText);
    }

    [Fact]
    public void Keeps_structured_values_as_attributes_without_the_template()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            factory.CreateLogger("tests.app").LogInformation("order {OrderId} placed, {Count} items", "o-1", 3);
        }

        var record = exporter.Records.Single();
        Assert.Equal("order o-1 placed, 3 items", record.Body);
        Assert.Equal("o-1", record.Attributes["OrderId"]);
        Assert.Equal(3, record.Attributes["Count"]);
        Assert.False(record.Attributes.ContainsKey("{OriginalFormat}"));
    }

    [Fact]
    public void Links_a_record_to_the_active_activity()
    {
        using var source = new ActivitySource("tests.app-logs");
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == "tests.app-logs",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);

        var exporter = new CapturingExporter();
        ActivityTraceId traceId;
        ActivitySpanId spanId;
        using (var factory = Factory(exporter))
        {
            var log = factory.CreateLogger("tests.app");
            using (var activity = source.StartActivity("work")!)
            {
                traceId = activity.TraceId;
                spanId = activity.SpanId;
                log.LogInformation("inside");
            }

            log.LogInformation("outside");
        }

        var records = exporter.Records.ToList();
        Assert.Equal(traceId, records[0].TraceId);
        Assert.Equal(spanId, records[0].SpanId);
        Assert.Equal(default, records[1].TraceId);
    }

    [Fact]
    public void Masks_credentials_and_long_tokens_in_the_body_attributes_and_exception()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            var log = factory.CreateLogger("tests.app");
            log.LogInformation("login password=hunter2 with k3j4h5g6f7d8s9a0q1w2e3r4");
            log.LogInformation("header {Header} count {Count}", "Bearer: k3j4h5g6f7d8s9a0q1w2e3r4", 7);
            log.LogError(new InvalidOperationException("token=s3cr3t failed"), "boom");
        }

        var records = exporter.Records.ToList();
        Assert.Equal("login password=*** with ***", records[0].Body);
        Assert.Equal("Bearer: ***", records[1].Attributes["Header"]);
        Assert.Equal(7, records[1].Attributes["Count"]);

        var error = records[2];
        Assert.False(error.HasException);
        Assert.Equal("System.InvalidOperationException", error.Attributes["exception.type"]);
        Assert.Equal("token=*** failed", error.Attributes["exception.message"]);
        var stack = Assert.IsType<string>(error.Attributes["exception.stacktrace"]);
        Assert.Contains("token=***", stack, StringComparison.Ordinal);
        Assert.DoesNotContain("s3cr3t", stack, StringComparison.Ordinal);
    }

    [Fact]
    public void Masks_values_under_credential_names_whatever_they_hold()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            // The names are the point: lower-case ones, as apps write them.
#pragma warning disable CA1727
            factory.CreateLogger("tests.app").LogInformation(
                "sign-in {password} {XApiKey} {sessionId} {Pin} {User}", "pw1", "short", "s-1", 1234, "ann");
#pragma warning restore CA1727
            factory.CreateLogger("tests.app").LogInformation("tags {Tags} otp {Otp}", new[] { "token=abc", "ok" }, 123456);
        }

        var records = exporter.Records.ToList();
        Assert.Equal("***", records[0].Attributes["password"]);
        Assert.Equal("***", records[0].Attributes["XApiKey"]);
        Assert.Equal("***", records[0].Attributes["sessionId"]);
        Assert.Equal(1234, records[0].Attributes["Pin"]);
        Assert.Equal("ann", records[0].Attributes["User"]);
        Assert.Equal(new object?[] { "token=***", "ok" }, Assert.IsType<object?[]>(records[1].Attributes["Tags"]));
        Assert.Equal("***", records[1].Attributes["Otp"]);
    }

    [Fact]
    public void Masks_quoted_credentials_and_authorization_schemes_in_the_message()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            var log = factory.CreateLogger("tests.app");
            log.LogInformation("Authorization: Bearer abc");
            log.LogInformation("sent Bearer abc");
            log.LogInformation("body {Json}", "{\"password\":\"x\",\"user\":\"ann\"}");
        }

        var records = exporter.Records.ToList();
        Assert.Equal("Authorization: ***", records[0].Body);
        Assert.Equal("sent Bearer ***", records[1].Body);
        Assert.Equal("body {\"password\":\"***\",\"user\":\"ann\"}", records[2].Body);
        Assert.Equal("{\"password\":\"***\",\"user\":\"ann\"}", records[2].Attributes["Json"]);
    }

    [Fact]
    public void Masks_a_token_that_crosses_the_cut_rather_than_leaving_its_start()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            var message = new string('a', AppLogs.MaxBodyLength - 10).Replace("a", "a ").Substring(0, AppLogs.MaxBodyLength - 10)
                + "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
            factory.CreateLogger("tests.app").LogInformation(message);
        }

        var body = exporter.Records.Single().Body!;
        Assert.DoesNotContain("9f86d0", body, StringComparison.Ordinal);
        Assert.EndsWith("***", body, StringComparison.Ordinal);
        Assert.True(body.Length <= AppLogs.MaxBodyLength);
    }

    [Fact]
    public void Keeps_class_names_and_file_paths_readable_in_the_body_and_stack_trace()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            InvalidOperationException thrown;
            try
            {
                throw new InvalidOperationException("index out of range");
            }
            catch (InvalidOperationException e)
            {
                thrown = e;
            }

            factory.CreateLogger("tests.app").LogError(thrown, "System.InvalidOperationException in /srv/app/src/Orders/OrderService.cs");
        }

        var record = exporter.Records.Single();
        Assert.Equal("System.InvalidOperationException in /srv/app/src/Orders/OrderService.cs", record.Body);
        var stack = Assert.IsType<string>(record.Attributes["exception.stacktrace"]);
        Assert.StartsWith("System.InvalidOperationException: index out of range", stack, StringComparison.Ordinal);
        Assert.Contains(nameof(Keeps_class_names_and_file_paths_readable_in_the_body_and_stack_trace), stack, StringComparison.Ordinal);
    }

    [Fact]
    public void Truncates_the_body_and_attributes()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            factory.CreateLogger("tests.app").LogInformation("{Value} " + new string('a', 20000).Replace("a", "a "), new string('b', 10).Replace("b", "b ") + new string('c', 5000).Replace("c", "c "));
        }

        var record = exporter.Records.Single();
        Assert.Equal(AppLogs.MaxBodyLength, record.Body!.Length);
        Assert.Equal(AppLogs.MaxAttributeLength, ((string)record.Attributes["Value"]!).Length);
    }

    [Theory]
    [InlineData("Shield360")]
    [InlineData("shield360")]
    [InlineData("Shield360.Flags.FlagsClient")]
    [InlineData("OpenTelemetry")]
    [InlineData("OpenTelemetry.Exporter.OtlpLogExporter")]
    public void Never_exports_its_own_categories(string category)
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            factory.CreateLogger(category).LogError("sdk");
            factory.CreateLogger("Shield360App").LogError("not ours");
        }

        Assert.Equal(new[] { "not ours" }, exporter.Records.Select(r => r.Body));
    }

    [Fact]
    public void Drops_records_written_while_instrumentation_is_suppressed()
    {
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter))
        {
            var log = factory.CreateLogger("tests.app");
            using (SuppressInstrumentationScope.Begin())
            {
                log.LogWarning("from the exporter's HTTP client");
            }

            log.LogWarning("after");
        }

        Assert.Equal(new[] { "after" }, exporter.Records.Select(r => r.Body));
    }

    [Fact]
    public void A_record_logged_during_export_does_not_loop()
    {
        var exporter = new CapturingExporter();
        ILogger? log = null;
        exporter.OnExport = () => log!.LogWarning("logged by the exporter");
        using (var factory = Factory(exporter))
        {
            log = factory.CreateLogger("tests.app");
            log.LogError("once");
        }

        Assert.Equal(new[] { "once" }, exporter.Records.Select(r => r.Body));
    }

    [Fact]
    public void Sends_at_most_the_rate_limit_each_second()
    {
        long now = 10_000;
        var exporter = new CapturingExporter();
        using (var factory = Factory(exporter, maxPerSecond: 500, clock: () => now))
        {
            var log = factory.CreateLogger("tests.app");
            for (var i = 0; i < 600; i++)
            {
                log.LogInformation("storm");
            }

            Assert.Equal(500, exporter.Records.Count);
            now += 999;
            log.LogInformation("same second");
            Assert.Equal(500, exporter.Records.Count);
            now += 1;
            log.LogInformation("next second");
        }

        Assert.Equal(501, exporter.Records.Count);
        Assert.Equal("next second", exporter.Records.Last().Body);
    }

    [Fact]
    public void A_failing_exporter_never_reaches_the_application()
    {
        using var factory = Factory(new ThrowingExporter());
        var log = factory.CreateLogger("tests.app");
        log.LogError(new InvalidOperationException("x"), "still fine");
        log.LogInformation("and again");
    }

    [Theory]
    [InlineData(null, LogLevel.Information)]
    [InlineData("", LogLevel.Information)]
    [InlineData("trace", LogLevel.Trace)]
    [InlineData("debug", LogLevel.Debug)]
    [InlineData("INFO", LogLevel.Information)]
    [InlineData("WARN", LogLevel.Warning)]
    [InlineData("warning", LogLevel.Warning)]
    [InlineData("error", LogLevel.Error)]
    [InlineData("fatal", LogLevel.Critical)]
    [InlineData("critical", LogLevel.Critical)]
    [InlineData("loud", LogLevel.Information)]
    public void Resolves_level_names(string? name, LogLevel expected) =>
        Assert.Equal(expected, AppLogs.ResolveLevel(name));

    [Fact]
    public void Application_logs_are_off_by_default()
    {
        var r = ResolvedOptions.Resolve(null, Env.Empty);
        Assert.False(r.CaptureLogs);
        Assert.Equal(LogLevel.Information, r.LogLevel);
    }

    [Fact]
    public void The_environment_turns_them_on_and_an_explicit_option_wins()
    {
        var env = Env.Of(("SHIELD360_CAPTURE_LOGS", "true"), ("SHIELD360_LOG_LEVEL", "ERROR"));
        var fromEnv = ResolvedOptions.Resolve(null, env);
        Assert.True(fromEnv.CaptureLogs);
        Assert.Equal(LogLevel.Error, fromEnv.LogLevel);

        var explicitOff = ResolvedOptions.Resolve(new Shield360Options { CaptureLogs = false, LogLevel = "debug" }, env);
        Assert.False(explicitOff.CaptureLogs);
        Assert.Equal(LogLevel.Debug, explicitOff.LogLevel);
    }
}
