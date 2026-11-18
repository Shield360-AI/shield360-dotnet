using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Event route (sdk/rasp/README.md "Event route"): the shared conformance cases
/// (sdk/rasp/testdata/routes.json), and attack events built from a path when the
/// framework gives no route template. Port of route.test.ts.
/// </summary>
public class RaspRouteTests : RaspStateTest
{
    private static readonly RaspFinding s_finding = new(RaspAttackType.SqlInjection, "sqli.userinput", new RaspInput("v", "query.id"));

    public static IEnumerable<object[]> Cases() =>
        ((JsonArray)RaspCorpus.Load("testdata/routes.json")["cases"]!)
            .Select(c => new object[] { RaspCorpus.Str(c!["path"]), RaspCorpus.Str(c!["route"]) });

    [Theory]
    [MemberData(nameof(Cases))]
    public void Event_route_conformance(string path, string route)
    {
        Assert.Equal(route, RaspScope.EventRouteOf(path));
        Assert.Equal(route, RaspIast.RouteOf(path));
    }

    private static string RouteOfEvent(RaspContext ctx, FindingExtra? extra = null)
    {
        var sink = Configure(new EngineSettings(true, "a"));
        RaspScope.Run(ctx, () => RaspEngine.HandleFinding(s_finding, "db", extra));
        return sink.Events[0].Attrs["shield360.rasp.route"];
    }

    [Fact]
    public void Attack_event_never_carries_a_secret_looking_path_segment()
    {
        var ctx = new RaspContext(inRequest: true) { Method = "get", Path = "/reset/Zx9TqLm2Rk7WpA4s/confirm" };
        Assert.Equal("/reset/:id/confirm", RouteOfEvent(ctx));
    }

    [Fact]
    public void Attack_event_keeps_the_framework_route_template()
    {
        var ctx = new RaspContext(inRequest: true) { Method = "get", Path = "/reset/Zx9TqLm2Rk7WpA4s/confirm", RouteSource = () => "/reset/{Token}/confirm" };
        Assert.Equal("/reset/{Token}/confirm", RouteOfEvent(ctx));
    }

    [Fact]
    public void Attack_event_keeps_a_route_passed_by_the_hook()
    {
        var ctx = new RaspContext(inRequest: true) { Method = "get" };
        Assert.Equal("/Files/{fileName}", RouteOfEvent(ctx, new FindingExtra(Route: "/Files/{fileName}", Path: "/Files/Secret")));
    }
}
