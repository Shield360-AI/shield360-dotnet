using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Shield360.Internal;
using Xunit;

namespace Shield360.Tests;

public class InitTests
{
    [Fact]
    public async Task Init_exports_spans_and_metrics_over_OTLP_with_the_configured_headers()
    {
        using var collector = new FakeCollector();
        var handle = Shield360Sdk.Init(new Shield360Options
        {
            OtlpEndpoint = collector.Url,
            OtlpHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer s360_key==" },
            ApplicationName = "init-test",
            DisableBatch = true,
        }, Env.Empty);

        try
        {
            Assert.True(Shield360Sdk.IsInitialized);
            Assert.NotNull(Shield360Runtime.Current);

            var resource = handle.TracerProvider!.GetResource();
            var attributes = resource.Attributes.ToDictionary(a => a.Key, a => a.Value);
            Assert.Equal("shield360", attributes["telemetry.sdk.name"]);
            Assert.Equal("init-test", attributes["service.name"]);
            Assert.Equal("default", attributes["deployment.environment"]);
            Assert.Equal(Shield360Sdk.Version, attributes["shield360.sdk.version"]);

            await new FakeChatClient().AsBuilder().UseShield360().Build().GetResponseAsync("hi");
        }
        finally
        {
            handle.Dispose();
        }

        Assert.False(Shield360Sdk.IsInitialized);
        Assert.Null(Shield360Runtime.Current);

        var traces = collector.Requests.Where(r => r.Path == "/v1/traces").ToList();
        var metrics = collector.Requests.Where(r => r.Path == "/v1/metrics").ToList();
        Assert.NotEmpty(traces);
        Assert.NotEmpty(metrics);
        Assert.All(traces.Concat(metrics), r =>
        {
            Assert.Equal("POST", r.Method);
            Assert.Equal("Bearer s360_key==", r.Authorization);
            Assert.Equal("application/x-protobuf", r.ContentType);
        });
    }

    [Fact]
    public void The_version_comes_from_the_project_file_without_build_metadata()
    {
        Assert.Matches(@"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$", Shield360Sdk.Version);
        Assert.StartsWith(Shield360Sdk.Version, typeof(Shield360Sdk).Assembly.GetName().Version!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Init_twice_is_an_error_and_shutdown_is_idempotent()
    {
        var options = new Shield360Options { DisableMetrics = true, DisableTracing = true };
        using var first = Shield360Sdk.Init(options, Env.Empty);
        Assert.Throws<InvalidOperationException>(() => Shield360Sdk.Init(options, Env.Empty));

        Shield360Sdk.Shutdown();
        Shield360Sdk.Shutdown();
        Assert.False(Shield360Sdk.IsInitialized);

        using var second = Shield360Sdk.Init(options, Env.Empty);
        first.Dispose(); // a stale handle does not shut down the newer one
        Assert.True(Shield360Sdk.IsInitialized);
        second.Dispose();
        Assert.False(Shield360Sdk.IsInitialized);
    }

    [Fact]
    public void Invalid_configuration_does_not_leave_Shield360_half_initialised()
    {
        Assert.Throws<Shield360Exception>(() => Shield360Sdk.Init(new Shield360Options { OtlpEndpoint = "not a url" }, Env.Empty));
        Assert.False(Shield360Sdk.IsInitialized);
        Assert.Null(Shield360Runtime.Current);
    }

    [Fact]
    public void AddShield360_registers_tracing_and_metrics_in_the_host()
    {
        var services = new ServiceCollection();
        services.AddShield360(o =>
        {
            o.ApplicationName = "hosted";
            o.Environment = "staging";
            o.ResourceAttributes = new Dictionary<string, string> { ["host.name"] = "web-1" };
        }, Env.Empty);

        using var provider = services.BuildServiceProvider();
        try
        {
            var tracer = provider.GetRequiredService<TracerProvider>();
            Assert.NotNull(provider.GetRequiredService<MeterProvider>());
            Assert.Same(Shield360Runtime.Current, provider.GetRequiredService<Shield360Runtime>());

            var attributes = tracer.GetResource().Attributes.ToDictionary(a => a.Key, a => a.Value);
            Assert.Equal("shield360", attributes["telemetry.sdk.name"]);
            Assert.Equal("hosted", attributes["service.name"]);
            Assert.Equal("staging", attributes["deployment.environment"]);
            Assert.Equal("web-1", attributes["host.name"]);
        }
        finally
        {
            Shield360Runtime.Current?.Deactivate();
        }
    }

    [Fact]
    public void AddShield360_leaves_out_disabled_signals()
    {
        var services = new ServiceCollection();
        services.AddShield360(o => o.DisableMetrics = true, Env.Empty);

        using var provider = services.BuildServiceProvider();
        try
        {
            Assert.NotNull(provider.GetService<TracerProvider>());
            Assert.Null(provider.GetService<MeterProvider>());
        }
        finally
        {
            Shield360Runtime.Current?.Deactivate();
        }
    }

    [Fact]
    public void Init_leaves_application_logs_off_by_default()
    {
        using var handle = Shield360Sdk.Init(new Shield360Options { DisableMetrics = true, DisableTracing = true }, Env.Empty);
        Assert.Null(handle.LoggerFactory);
        Assert.Same(NullLoggerFactory.Instance, Shield360Sdk.LoggerFactory);
        Shield360Sdk.CreateLogger("app").LogError("goes nowhere");
    }

    [Fact]
    public void Init_sends_application_logs_to_the_logs_route_with_the_key_when_the_environment_asks()
    {
        using var collector = new FakeCollector();
        var env = Env.Of(("SHIELD360_CAPTURE_LOGS", "true"), ("SHIELD360_LOG_LEVEL", "warn"));
        var handle = Shield360Sdk.Init(new Shield360Options
        {
            OtlpEndpoint = collector.Url + "/api/ingest/otlp",
            OtlpHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer s360_key==" },
            ApplicationName = "logs-init-test",
            DisableMetrics = true,
            DisableTracing = true,
        }, env);
        try
        {
            Assert.NotNull(handle.LoggerFactory);
            Assert.Same(handle.LoggerFactory, Shield360Sdk.LoggerFactory);
            var log = Shield360Sdk.CreateLogger("orders");
            log.LogInformation("below the level");
            log.LogWarning("payment retried");
            Assert.True(handle.ForceFlush());
        }
        finally
        {
            handle.Dispose();
        }

        var logs = collector.Requests.Where(r => r.Path == "/api/ingest/otlp/v1/logs").ToList();
        Assert.NotEmpty(logs);
        Assert.All(logs, r =>
        {
            Assert.Equal("POST", r.Method);
            Assert.Equal("Bearer s360_key==", r.Authorization);
            Assert.Equal("application/x-protobuf", r.ContentType);
        });
        Assert.Same(NullLoggerFactory.Instance, Shield360Sdk.LoggerFactory);
    }

    [Fact]
    public void AddShield360_sends_the_host_logs_when_capture_is_on()
    {
        using var collector = new FakeCollector();
        var services = new ServiceCollection();
        services.AddShield360(o =>
        {
            o.OtlpEndpoint = collector.Url;
            o.CaptureLogs = true;
            o.DisableBatch = true;
            o.DisableMetrics = true;
        }, Env.Empty);
        services.AddShield360(o => o.CaptureLogs = true, Env.Empty);

        try
        {
            using (var provider = services.BuildServiceProvider())
            {
                provider.GetRequiredService<ILoggerFactory>().CreateLogger("orders").LogWarning("hosted record");
            }

            Assert.Single(collector.Requests, r => r.Path == "/v1/logs");
        }
        finally
        {
            Shield360Runtime.Current?.Deactivate();
        }
    }

    [Fact]
    public void AddShield360_leaves_host_logs_alone_by_default()
    {
        var services = new ServiceCollection();
        services.AddShield360(o => o.DisableMetrics = true, Env.Empty);
        try
        {
            Assert.DoesNotContain(services, d => d.ImplementationType?.Name == "OpenTelemetryLoggerProvider" || d.ServiceType.Name == "Shield360LogsMarker");
        }
        finally
        {
            Shield360Runtime.Current?.Deactivate();
        }
    }

    /// <summary>A minimal OTLP/HTTP receiver that records each request.</summary>
    private sealed class FakeCollector : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly CancellationTokenSource _stop = new();

        public FakeCollector()
        {
            var port = FreePort();
            Url = $"http://127.0.0.1:{port}";
            _listener.Prefixes.Add(Url + "/");
            _listener.Start();
            _ = Task.Run(Serve);
        }

        public string Url { get; }

        public ConcurrentBag<Received> Requests { get; } = new();

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Close();
        }

        private async Task Serve()
        {
            while (!_stop.IsCancellationRequested)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync();
                }
                catch (Exception) when (_stop.IsCancellationRequested || !_listener.IsListening)
                {
                    return;
                }

                Requests.Add(new Received(
                    context.Request.HttpMethod,
                    context.Request.Url!.AbsolutePath,
                    context.Request.Headers["Authorization"],
                    context.Request.ContentType));
                context.Response.StatusCode = 200;
                context.Response.Close();
            }
        }

        private static int FreePort()
        {
            using var socket = new TcpListener(IPAddress.Loopback, 0);
            socket.Start();
            return ((IPEndPoint)socket.LocalEndpoint).Port;
        }

        public sealed record Received(string Method, string Path, string? Authorization, string? ContentType);
    }
}
