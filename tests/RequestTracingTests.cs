using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Trace;
using Shield360.AspNetCore;
using Shield360.Internal;
using Xunit;

namespace Shield360.Tests;

/// <summary>
/// SHIELD: requests are traces, health probes and calls to Shield360 left out
/// (mirrors sdk/typescript/src/instrumentation/__tests__/http-noise.test.ts).
/// </summary>
public class RequestTracingTests
{
    [Theory]
    [InlineData("/healthz", null, true)]
    [InlineData("/health/", null, true)]
    [InlineData("/api/health", null, true)]
    [InlineData("/readyz?deep=1", null, true)]
    [InlineData("/anything", "kube-probe/1.31", true)]
    [InlineData("/", "ELB-HealthChecker/2.0", true)]
    [InlineData("/api/orders", "Mozilla/5.0", false)]
    [InlineData("/healthy-recipes", null, false)]
    [InlineData(null, null, false)]
    public void Recognizes_health_probes(string? path, string? agent, bool probe) =>
        Assert.Equal(probe, RequestNoise.IsHealthProbe(path, agent));

    [Fact]
    public void Recognizes_calls_to_Shield360()
    {
        var own = RequestNoise.Shield360Authority("https://app.shield360.ai/");
        Assert.True(RequestNoise.IsOwnCall(new Uri("https://APP.shield360.ai/api/guard/events"), own));
        Assert.False(RequestNoise.IsOwnCall(new Uri("https://api.openai.com/v1/chat"), own));
        Assert.False(RequestNoise.IsOwnCall(new Uri("https://app.shield360.ai/x"), null));
        Assert.Null(RequestNoise.Shield360Authority("not a url"));
    }

    [Fact]
    public async Task Traces_each_request_by_route_and_skips_health_probes()
    {
        var spans = new List<Activity>();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddShield360(o => { o.ApplicationName = "orders-api"; o.DisableMetrics = true; }, Env.Empty);
        builder.Services.ConfigureOpenTelemetryTracerProvider(t => t.AddInMemoryExporter(spans));
        builder.Services.AddShield360RequestTracing();
        await using var app = builder.Build();
        app.MapGet("/orders/{id}", (string id) => Results.Ok(id));
        app.MapGet("/healthz", () => Results.Ok());
        try
        {
            await app.StartAsync();
            var client = app.GetTestClient();
            (await client.GetAsync(new Uri("/orders/42", UriKind.Relative))).EnsureSuccessStatusCode();
            (await client.GetAsync(new Uri("/healthz", UriKind.Relative))).EnsureSuccessStatusCode();
            // The server span ends after the response reaches the test client: wait for it.
            List<string> requests;
            var deadline = DateTime.UtcNow.AddSeconds(10);
            do
            {
                app.Services.GetRequiredService<TracerProvider>().ForceFlush();
                lock (spans)
                {
                    requests = spans.Where(s => s.Kind == ActivityKind.Server).Select(s => s.DisplayName).ToList();
                }

                if (requests.Count >= 1 || DateTime.UtcNow > deadline)
                {
                    break;
                }

                await Task.Delay(50);
            }
            while (true);

            // Give a traced /healthz span the same time to arrive, so its absence means something.
            await Task.Delay(200);
            app.Services.GetRequiredService<TracerProvider>().ForceFlush();
            lock (spans)
            {
                requests = spans.Where(s => s.Kind == ActivityKind.Server).Select(s => s.DisplayName).ToList();
            }

            Assert.Contains("GET /orders/{id}", requests);
            Assert.DoesNotContain(requests, n => n.Contains("healthz", StringComparison.Ordinal));
        }
        finally
        {
            await app.StopAsync();
            Shield360Runtime.Current?.Deactivate();
        }
    }
}
