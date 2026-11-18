using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// RASP reporter: batched events through the guard events transport, folding of
/// repeats, the per-minute cap, the components report. Port of reporter.test.ts.
/// </summary>
public class RaspReporterTests
{
    private static RaspEvent Event(string rule = "sqli.userinput") => new(
        "shield360.rasp.event",
        "1970-01-01T00:00:00.000Z",
        new Dictionary<string, string> { ["shield360.rasp.attack"] = "sql_injection", ["shield360.rasp.rule"] = rule });

    private sealed class Harness
    {
        public long Now { get; set; } = 1_000_000;

        public FakeHandler Handler { get; } = new(HttpStatusCode.OK, "{}");

        public RaspReporter Create() => new(new RaspReporterOptions
        {
            Url = "https://shield.example.com/",
            ApiKey = "test-api-key",
            ApplicationName = "orders-api",
            Environment = "prod",
            SdkVersion = "1.2.0",
            Handler = Handler,
            NowMs = () => Now,
            RetryDelay = TimeSpan.FromMilliseconds(1),
        });

        public List<JsonObject> Sent() =>
            Handler.Requests.SelectMany(r => ((JsonArray)JsonNode.Parse(r.Body!)!["events"]!).Select(e => (JsonObject)e!)).ToList();
    }

    [Fact]
    public async Task Posts_batches_to_guard_events_with_the_resource_and_the_api_key()
    {
        var h = new Harness();
        using var r = h.Create();
        r.Add(Event(), "k1");
        await r.FlushAsync();
        var (request, body) = Assert.Single(h.Handler.Requests);
        Assert.Equal("https://shield.example.com/api/guard/events", request.RequestUri!.ToString());
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("Bearer test-api-key", request.Headers.Authorization!.ToString());
        var json = JsonNode.Parse(body!)!;
        Assert.Equal("orders-api", (string?)json["resource"]!["service.name"]);
        Assert.Equal("prod", (string?)json["resource"]!["deployment.environment"]);
        Assert.Equal("1.2.0", (string?)json["resource"]!["service.version"]);
        Assert.Equal("shield360.rasp.event", (string?)json["events"]![0]!["name"]);
    }

    [Fact]
    public async Task Folds_repeats_within_10_s_into_one_more_event_with_a_count()
    {
        var h = new Harness();
        using var r = h.Create();
        Assert.True(r.Add(Event(), "same"));
        Assert.False(r.Add(Event(), "same"));
        Assert.False(r.Add(Event(), "same"));
        Assert.True(r.Add(Event("sqli.stacked"), "other"));
        h.Now += RaspReporter.FoldMs;
        await r.FlushAsync();
        var sent = h.Sent();
        Assert.Equal(3, sent.Count);
        Assert.Equal("2", (string?)sent[2]["attrs"]!["shield360.rasp.count"]);
        Assert.Equal("sqli.userinput", (string?)sent[2]["attrs"]!["shield360.rasp.rule"]);
    }

    [Fact]
    public async Task Caps_events_at_100_a_minute_per_process()
    {
        var h = new Harness();
        using var r = h.Create();
        for (var i = 0; i < RaspReporter.PerMinute + 20; i++)
        {
            r.Add(Event(), "k" + i);
        }

        Assert.Equal(RaspReporter.PerMinute, r.Pending().Count);
        h.Now += 60_000;
        Assert.True(r.Add(Event(), "later"));
        await r.FlushAsync();
        Assert.Equal(RaspReporter.PerMinute + 1, h.Sent().Count);
        Assert.Equal(2, h.Handler.Requests.Count);
    }

    [Fact]
    public async Task Stop_closes_open_folds_and_sends_them()
    {
        var h = new Harness();
        using var r = h.Create();
        r.Add(Event(), "k");
        r.Add(Event(), "k");
        await r.StopAsync();
        Assert.Equal(new string?[] { null, "1" }, h.Sent().Select(e => (string?)e["attrs"]!["shield360.rasp.count"]));
    }

    [Fact]
    public async Task Components_are_names_and_versions_only()
    {
        var h = new Harness();
        using var r = h.Create();
        r.ReportComponents(new[] { new RaspComponent("nuget", "Newtonsoft.Json", "13.0.3") });
        await r.FlushAsync();
        var e = Assert.Single(h.Sent());
        Assert.Equal("shield360.rasp.component", (string?)e["name"]);
        var attrs = (JsonObject)e["attrs"]!;
        Assert.Equal(4, attrs.Count);
        Assert.Equal("orders-api", (string?)attrs["shield360.rasp.app"]);
        Assert.Equal("nuget", (string?)attrs["shield360.rasp.component.ecosystem"]);
        Assert.Equal("Newtonsoft.Json", (string?)attrs["shield360.rasp.component.name"]);
        Assert.Equal("13.0.3", (string?)attrs["shield360.rasp.component.version"]);
    }

    [Fact]
    public async Task Never_throws_when_the_transport_fails_and_gives_up_on_a_refusal()
    {
        var offline = new FakeHandler(_ => throw new HttpRequestException("offline"));
        using var r = new RaspReporter(new RaspReporterOptions { Url = "https://shield.example.com", ApiKey = "k", Handler = offline, RetryDelay = TimeSpan.FromMilliseconds(1) });
        r.Add(Event(), "k");
        await r.FlushAsync();
        Assert.Equal(3, offline.Requests.Count);

        var refused = new FakeHandler(HttpStatusCode.Unauthorized, "{}");
        using var r2 = new RaspReporter(new RaspReporterOptions { Url = "https://shield.example.com", ApiKey = "k", Handler = refused, RetryDelay = TimeSpan.FromMilliseconds(1) });
        r2.Add(Event(), "k");
        await r2.FlushAsync();
        Assert.Single(refused.Requests);
    }

    [Fact]
    public void Collect_lists_the_runtime_then_app_assemblies_but_not_the_runtimes_own()
    {
        var got = RaspComponents.Collect(new[] { typeof(Shield360Sdk).Assembly, typeof(object).Assembly, typeof(Shield360Sdk).Assembly });
        Assert.Equal(new RaspComponent("runtime", "dotnet", Environment.Version.ToString()), got[0]);
        var app = Assert.Single(got.Skip(1));
        Assert.Equal(new RaspComponent("nuget", "Shield360", Shield360Sdk.Version), app);
        Assert.True(RaspComponents.Collect().Count <= RaspReporter.MaxComponents);
    }
}
