using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests;

/// <summary>Runtime package report. Port of sdk/typescript/src/__tests__/runtime-packages.test.ts.</summary>
public class RuntimePackagesTests
{
    private static RaspStartContext Ctx(FakeHandler handler, string? url = "https://shield.example.com/") =>
        new("orders-api", "prod", url, "test-api-key", "1.2.0", Env: _ => null, Handler: handler);

    private static List<RaspComponent> One() => new() { new RaspComponent("nuget", "Newtonsoft.Json", "13.0.3") };

    [Fact]
    public void Is_on_by_default_and_off_by_option_or_env()
    {
        Assert.True(RuntimePackages.Enabled(null, _ => null));
        Assert.True(RuntimePackages.Enabled(true, _ => null));
        Assert.False(RuntimePackages.Enabled(false, _ => null));
        foreach (var v in new[] { "off", "false", "0", "NO" })
        {
            Assert.False(RuntimePackages.Enabled(null, _ => v));
        }

        Assert.True(RuntimePackages.Enabled(null, _ => "on"));
    }

    [Fact]
    public async Task Sends_names_and_versions_to_guard_events_with_the_api_key()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{}");
        Assert.True(await RuntimePackages.ReportAsync(Ctx(handler), One));
        var (request, body) = Assert.Single(handler.Requests);
        Assert.Equal("https://shield.example.com/api/guard/events", request.RequestUri!.ToString());
        Assert.Equal("Bearer test-api-key", request.Headers.Authorization!.ToString());
        var json = JsonNode.Parse(body!)!;
        Assert.Equal("orders-api", (string?)json["resource"]!["service.name"]);
        Assert.Equal("prod", (string?)json["resource"]!["deployment.environment"]);
        var e = json["events"]![0]!;
        Assert.Equal("shield360.rasp.component", (string?)e["name"]);
        var attrs = ((JsonObject)e["attrs"]!).ToDictionary(kv => kv.Key, kv => (string?)kv.Value);
        Assert.Equal(
            new Dictionary<string, string?>
            {
                ["shield360.rasp.app"] = "orders-api",
                ["shield360.rasp.component.ecosystem"] = "nuget",
                ["shield360.rasp.component.name"] = "Newtonsoft.Json",
                ["shield360.rasp.component.version"] = "13.0.3",
            },
            attrs);
    }

    [Fact]
    public async Task Batches_by_100_and_caps_at_500()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{}");
        var many = Enumerable.Range(0, 700).Select(i => new RaspComponent("nuget", "P" + i, "1.0.0")).ToList();
        await RuntimePackages.ReportAsync(Ctx(handler), () => many);
        Assert.Equal(new[] { 100, 100, 100, 100, 100 }, handler.Requests.Select(r => ((JsonArray)JsonNode.Parse(r.Body!)!["events"]!).Count).ToArray());
    }

    [Fact]
    public async Task Stops_at_a_refusal_and_never_throws()
    {
        var handler = new FakeHandler(HttpStatusCode.Unauthorized, "{}");
        var many = Enumerable.Range(0, 250).Select(i => new RaspComponent("nuget", "P" + i, "1.0.0")).ToList();
        Assert.False(await RuntimePackages.ReportAsync(Ctx(handler), () => many));
        Assert.Single(handler.Requests);
        Assert.False(await RuntimePackages.ReportAsync(Ctx(handler), () => throw new InvalidOperationException("boom")));
        Assert.False(await RuntimePackages.ReportAsync(Ctx(handler, url: null), One));
    }

    [Fact]
    public async Task Starts_once_reports_after_the_delay_and_stops()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{}");
        // An earlier test's Init may have left the report running.
        RuntimePackages.Stop();
        try
        {
            Assert.True(RuntimePackages.Start(Ctx(handler), null, TimeSpan.FromMilliseconds(10), TimeSpan.FromHours(1), One));
            Assert.False(RuntimePackages.Start(Ctx(handler), null, TimeSpan.FromMilliseconds(10), TimeSpan.FromHours(1), One));
            Assert.True(RuntimePackages.Active);
            for (var i = 0; i < 500 && handler.Requests.Count == 0; i++)
            {
                await Task.Delay(10);
            }

            Assert.Single(handler.Requests);
        }
        finally
        {
            RuntimePackages.Stop();
        }

        Assert.False(RuntimePackages.Active);
        Assert.False(RuntimePackages.Start(Ctx(handler), false));
        Assert.False(RuntimePackages.Start(Ctx(handler) with { Env = _ => "off" }, null));
        Assert.False(RuntimePackages.Start(Ctx(handler, url: null), null));
        Assert.False(RuntimePackages.Active);
    }

    [Fact]
    public void Maps_loaded_assemblies_to_their_nuget_packages_from_deps_json()
    {
        const string deps = """
            {
              "targets": {
                ".NETCoreApp,Version=v8.0": {
                  "App/1.0.0": { "runtime": { "App.dll": {} } },
                  "Newtonsoft.Json/13.0.3": { "runtime": { "lib/net6.0/Newtonsoft.Json.dll": {} } }
                }
              },
              "libraries": {
                "App/1.0.0": { "type": "project" },
                "Newtonsoft.Json/13.0.3": { "type": "package" }
              }
            }
            """;
        var map = RuntimePackages.PackagesByAssembly(deps);
        Assert.Equal(("Newtonsoft.Json", "13.0.3"), map["newtonsoft.json.dll"]);
        Assert.False(map.ContainsKey("App.dll"));
        Assert.Empty(RuntimePackages.PackagesByAssembly("{not json"));
        Assert.Empty(RuntimePackages.PackagesByAssembly(null));
    }

    [Fact]
    public void Collect_reports_the_runtime_first_and_no_paths()
    {
        var got = RuntimePackages.Collect(new[] { typeof(Xunit.FactAttribute).Assembly, typeof(RuntimePackages).Assembly }, depsJson: "{}");
        Assert.Equal("runtime", got[0].Ecosystem);
        Assert.Contains(got, c => c.Ecosystem == "nuget" && c.Name == "xunit.core");
        Assert.All(got, c => Assert.DoesNotContain("/", c.Name));
    }
}
