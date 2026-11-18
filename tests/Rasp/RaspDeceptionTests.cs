using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Deception (sdk/rasp/README.md, "Deception"): the shared corpus (testdata/deception.json),
/// the suspicious-address table, and the ASP.NET Core middleware answering decoys.
/// </summary>
public class RaspDeceptionTests : RaspStateTest
{
    private static readonly JsonObject s_corpus = RaspCorpus.Load("testdata/deception.json");
    private ListSink _sink = new();
    private DateTimeOffset _now = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);

    public RaspDeceptionTests()
    {
        RaspDeception.Table = new RaspSuspiciousTable(now: () => _now);
    }

    protected override void Dispose(bool disposing)
    {
        RaspDeception.Table = new RaspSuspiciousTable();
        base.Dispose(disposing);
    }

    private static DeceptionConfig? Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return RaspDeception.Parse(doc.RootElement.Clone());
    }

    private static JsonObject? Normalized(DeceptionConfig? c) => c is null ? null : new JsonObject
    {
        ["paths"] = new JsonArray(c.Paths.Select(p => (JsonNode)JsonValue.Create(p)!).ToArray()),
        ["action"] = c.Block ? "block" : "monitor",
        ["ttlSeconds"] = c.TtlSeconds,
    };

    public static IEnumerable<object[]> ConfigCases() =>
        ((JsonArray)s_corpus["config"]!).Select(c => new object[] { RaspCorpus.Str(c!["name"]) });

    public static IEnumerable<object[]> MatchCases() =>
        ((JsonArray)s_corpus["match"]!).Select((c, i) => new object[] { i, RaspCorpus.Str(c!["target"]) });

    [Theory]
    [MemberData(nameof(ConfigCases))]
    public void Config_conformance(string name)
    {
        var c = (JsonObject)((JsonArray)s_corpus["config"]!).Single(x => RaspCorpus.Str(x!["name"]) == name)!;
        var got = c.ContainsKey("deception") ? Parse(c["deception"]?.ToJsonString() ?? "null") : RaspDeception.Parse(null);
        var expect = c["expect"];
        Assert.Equal(expect?.ToJsonString() ?? "null", Normalized(got)?.ToJsonString() ?? "null");
    }

    [Fact]
    public void Config_conformance_goes_through_the_signed_config_claims()
    {
        // The claims parser carries the block to the engine; absent and malformed mean off.
        static RemoteConfig From(string deception) => RaspRuntime.ToRemote(new RaspClaims("v1", 0, TestJson.Parse("{" + deception + "}")));
        Assert.Null(From(string.Empty).Deception);
        Assert.Null(From("\"deception\":null").Deception);
        var d = From("\"deception\":{\"paths\":[\"/wp-admin/\"],\"action\":\"block\",\"ttlSeconds\":60}").Deception!;
        Assert.Equal(new[] { "/wp-admin" }, d.Paths);
        Assert.True(d.Block);
        Assert.Equal(60, d.TtlSeconds);
    }

    [Theory]
    [MemberData(nameof(MatchCases))]
    public void Match_conformance(int index, string target)
    {
        var c = (JsonObject)((JsonArray)s_corpus["match"]!)[index]!;
        var decoys = (c["decoys"] ?? s_corpus["decoys"])!.ToJsonString();
        var config = Parse("{\"paths\":" + decoys + "}")!;
        var expect = c["expect"] is null ? null : RaspCorpus.Str(c["expect"]);
        Assert.Equal(expect, RaspDeception.Match(config, RaspDeception.RawPathBytes(target)));
    }

    [Fact]
    public void A_ttl_too_large_for_a_double_is_capped()
    {
        Assert.Equal(86400, Parse("{\"paths\":[\"/x\"],\"ttlSeconds\":1e400}")!.TtlSeconds);
        Assert.Equal(900, Parse("{\"paths\":[\"/x\"],\"ttlSeconds\":-1e400}")!.TtlSeconds);
    }

    [Fact]
    public void The_table_holds_its_cap_and_re_marking_refreshes_a_mark()
    {
        var table = new RaspSuspiciousTable(3, () => _now);
        var ttl = TimeSpan.FromMinutes(15);
        foreach (var a in new[] { "a", "b", "c" })
        {
            table.Mark(a, ttl);
        }

        table.Mark("a", ttl); // a expires last now: b is the soonest
        Assert.Equal(new[] { "b", "c", "a" }, table.Addresses());
        table.Mark("d", ttl);
        table.Mark("e", ttl);
        Assert.Equal(3, table.Count);
        Assert.Equal(new[] { "a", "d", "e" }, table.Addresses());
        Assert.False(table.IsSuspicious("b"));
        Assert.True(table.IsSuspicious("a"));
    }

    [Fact]
    public void A_full_table_drops_expired_marks_before_any_live_one()
    {
        var table = new RaspSuspiciousTable(3, () => _now);
        table.Mark("short", TimeSpan.FromSeconds(1));
        table.Mark("live1", TimeSpan.FromMinutes(15));
        table.Mark("live2", TimeSpan.FromMinutes(15));
        _now = _now.AddSeconds(5);
        table.Mark("new", TimeSpan.FromMinutes(15));
        Assert.Equal(new[] { "live1", "live2", "new" }, table.Addresses());
    }

    [Fact]
    public void A_full_table_drops_an_expired_mark_behind_live_ones_before_any_live_mark()
    {
        // After a TTL change a newer mark can expire first; it goes before an older live one.
        var table = new RaspSuspiciousTable(3, () => _now);
        table.Mark("a", TimeSpan.FromSeconds(3600));
        table.Mark("b", TimeSpan.FromSeconds(3600));
        table.Mark("c", TimeSpan.FromSeconds(1));
        _now = _now.AddSeconds(2);
        table.Mark("d", TimeSpan.FromSeconds(3600));
        Assert.Equal(3, table.Count);
        Assert.True(table.IsSuspicious("a"));
        Assert.True(table.IsSuspicious("b"));
        Assert.True(table.IsSuspicious("d"));
        Assert.False(table.IsSuspicious("c"));
    }

    [Fact]
    public void A_full_table_without_expired_marks_drops_the_one_closest_to_expiring()
    {
        var table = new RaspSuspiciousTable(2, () => _now);
        table.Mark("a", TimeSpan.FromSeconds(3600));
        table.Mark("b", TimeSpan.FromSeconds(10));
        table.Mark("c", TimeSpan.FromSeconds(3600));
        Assert.Equal(2, table.Count);
        Assert.False(table.IsSuspicious("b"));
        Assert.True(table.IsSuspicious("a"));
        Assert.True(table.IsSuspicious("c"));
    }

    [Fact]
    public void Equal_expiries_keep_the_order_they_were_marked_in()
    {
        var table = new RaspSuspiciousTable(10, () => _now);
        table.Mark("late", TimeSpan.FromSeconds(100));
        table.Mark("x", TimeSpan.FromSeconds(50));
        table.Mark("y", TimeSpan.FromSeconds(50));
        table.Mark("early", TimeSpan.FromSeconds(10));
        Assert.Equal(new[] { "early", "x", "y", "late" }, table.Addresses());
    }

    [Fact]
    public void A_mark_expires_and_a_lookup_never_extends_it()
    {
        var table = new RaspSuspiciousTable(10, () => _now);
        table.Mark("1.2.3.4", TimeSpan.FromSeconds(60));
        _now = _now.AddSeconds(59);
        Assert.True(table.IsSuspicious("1.2.3.4"));
        _now = _now.AddSeconds(1);
        Assert.False(table.IsSuspicious("1.2.3.4"));
        Assert.Equal(0, table.Count);
    }

    // The middleware in a TestServer app.

    private sealed class App
    {
        public WebApplication Web = null!;
        public List<string> Called { get; } = new();
    }

    private static async Task<App> Serve(bool statusCodePages = false, Action<IServiceCollection>? services = null, bool forwardedHeaders = false)
    {
        var app = new App();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        services?.Invoke(builder.Services);
        var web = builder.Build();
        if (statusCodePages)
        {
            web.UseStatusCodePages();
        }

        web.UseShield360Rasp();
        if (forwardedHeaders)
        {
            web.UseForwardedHeaders();
        }

        foreach (var p in new[] { "/ok", "/wp-admin", "/wp-admin/{**rest}" })
        {
            web.MapGet(p, (HttpContext c) =>
            {
                lock (app.Called)
                {
                    app.Called.Add(c.Request.Path.Value!);
                }

                return "ok";
            });
        }

        await web.StartAsync();
        app.Web = web;
        return app;
    }

    private void Arm(string action = "block", RaspMode? attackMode = null, Dictionary<RaspAttackType, RaspMode>? local = null, int ttl = 900)
    {
        _sink = Configure(new EngineSettings(true, "orders-api", Attacks: local));
        var attacks = new Dictionary<RaspAttackType, RaspMode>();
        if (attackMode is { } m)
        {
            attacks[RaspAttackType.Deception] = m;
        }

        RaspEngine.SetRemoteConfig(new RemoteConfig
        {
            Version = "v7",
            Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
            Mode = RaspMode.Monitor,
            Attacks = attacks,
            Deception = Parse("{\"paths\":[\"/wp-admin\",\"/.env\",\"/.git/config\"],\"action\":\"" + action + "\",\"ttlSeconds\":" + ttl + "}"),
        });
    }

    private static async Task<HttpContext> Send(App app, string target, string? ip = "203.0.113.9", Dictionary<string, string>? headers = null, bool rawTarget = true)
    {
        return await app.Web.GetTestServer().SendAsync(c =>
        {
            c.Request.Method = "GET";
            var q = target.IndexOf('?');
            var path = q >= 0 ? target.Substring(0, q) : target;
            c.Request.Path = PathString.FromUriComponent(path);
            if (q >= 0)
            {
                c.Request.QueryString = new QueryString(target.Substring(q));
            }

            var feature = c.Features.Get<IHttpRequestFeature>()!;
            feature.RawTarget = rawTarget ? target : string.Empty;
            if (ip is not null)
            {
                c.Connection.RemoteIpAddress = IPAddress.Parse(ip);
            }

            foreach (var kv in headers ?? new())
            {
                c.Request.Headers[kv.Key] = kv.Value;
            }
        });
    }

    private static string Body(HttpContext c)
    {
        if (c.Response.Body.CanSeek)
        {
            c.Response.Body.Position = 0;
        }

        return new System.IO.StreamReader(c.Response.Body).ReadToEnd();
    }

    private List<RaspEvent> Events(string rule) => _sink.Events.Where(e => e.Attrs["shield360.rasp.rule"] == rule).ToList();

    [Fact]
    public async Task A_decoy_never_reaches_the_handler_and_gets_the_same_404_as_an_unknown_path()
    {
        Arm();
        var app = await Serve();
        await using var _ = app.Web;
        var unknown = await Send(app, "/no-such-page", ip: "198.51.100.1");
        var decoy = await Send(app, "/wp-admin/install.php?x=1");
        Assert.Empty(app.Called);
        Assert.Equal(404, unknown.Response.StatusCode);
        Assert.Equal(unknown.Response.StatusCode, decoy.Response.StatusCode);
        Assert.Equal(string.Empty, Body(unknown));
        Assert.Equal(string.Empty, Body(decoy));
        Assert.Equal(unknown.Response.ContentType, decoy.Response.ContentType);
        Assert.Equal(unknown.Response.Headers.Keys.OrderBy(k => k), decoy.Response.Headers.Keys.OrderBy(k => k));

        var e = Assert.Single(Events(RaspDeception.HitRule));
        Assert.Equal("deception", e.Attrs["shield360.rasp.attack"]);
        Assert.Equal("http.deception", e.Attrs["shield360.rasp.sink"]);
        Assert.Equal("aspnetcore", e.Attrs["shield360.rasp.framework"]);
        Assert.Equal("GET", e.Attrs["shield360.rasp.method"]);
        Assert.Equal("/wp-admin", e.Attrs["shield360.rasp.route"]);
        Assert.Equal("blocked", e.Attrs["shield360.rasp.decision"]);
        Assert.Equal("block", e.Attrs["shield360.rasp.mode"]);
        Assert.Equal("v7", e.Attrs["shield360.rasp.config_version"]);
        Assert.False(e.Attrs.ContainsKey("shield360.rasp.input_key"));
        Assert.False(e.Attrs.ContainsKey("shield360.rasp.snippet"));
    }

    [Fact]
    public async Task With_status_code_pages_a_decoy_is_rendered_like_an_unknown_path()
    {
        Arm();
        var app = await Serve(statusCodePages: true);
        await using var _ = app.Web;
        var unknown = await Send(app, "/no-such-page", ip: "198.51.100.1");
        var decoy = await Send(app, "/.env");
        Assert.Empty(app.Called);
        Assert.Equal(404, decoy.Response.StatusCode);
        var page = Body(unknown);
        Assert.StartsWith("Status Code: 404", page, StringComparison.Ordinal);
        Assert.Equal(page, Body(decoy));
        Assert.Equal(unknown.Response.ContentType, decoy.Response.ContentType);
    }

    [Fact]
    public async Task Encoded_decoys_hit_from_the_raw_target_and_the_fallback_path_is_not_decoded_twice()
    {
        Arm();
        var app = await Serve();
        await using var _ = app.Web;
        Assert.Equal(404, (await Send(app, "/.git%2Fconfig")).Response.StatusCode);
        Assert.Equal(404, (await Send(app, "/%2Eenv")).Response.StatusCode);

        // No raw target: Path as the server decoded it. %2F stays encoded there, so it is not a slash.
        Assert.Equal(404, (await Send(app, "/%2Eenv", rawTarget: false)).Response.StatusCode);
        Assert.Equal(200, (await Send(app, "/ok", ip: "198.51.100.7", rawTarget: false)).Response.StatusCode);
        var fallback = await Send(app, "/.git%2Fconfig", ip: "198.51.100.7", rawTarget: false);
        Assert.Equal(404, fallback.Response.StatusCode); // unknown to routing, not a decoy
        Assert.Equal(3, Events(RaspDeception.HitRule).Count);
    }

    [Fact]
    public async Task A_hit_marks_the_client_and_its_next_request_is_blocked_in_block_mode()
    {
        Arm("block");
        var app = await Serve();
        await using var _ = app.Web;
        Assert.Equal(200, (await Send(app, "/ok")).Response.StatusCode);
        Assert.Equal(404, (await Send(app, "/wp-admin")).Response.StatusCode);
        app.Called.Clear();

        var next = await Send(app, "/ok?id=5");
        Assert.Equal(403, next.Response.StatusCode);
        Assert.Empty(app.Called);
        using var body = JsonDocument.Parse(Body(next));
        Assert.Equal("deception", body.RootElement.GetProperty("attack").GetString());
        Assert.Equal("deception.suspicious", body.RootElement.GetProperty("rule").GetString());
        var e = Assert.Single(Events(RaspDeception.SuspiciousRule));
        Assert.Equal("blocked", e.Attrs["shield360.rasp.decision"]);
        Assert.Equal("/ok", e.Attrs["shield360.rasp.route"]);
        Assert.Equal(body.RootElement.GetProperty("event").GetString(), e.Attrs["shield360.rasp.event_id"]);

        // Another client is untouched.
        Assert.Equal(200, (await Send(app, "/ok", ip: "198.51.100.1")).Response.StatusCode);
    }

    [Fact]
    public async Task Monitor_reports_the_suspicious_client_and_lets_it_through()
    {
        Arm("monitor");
        var app = await Serve();
        await using var _ = app.Web;
        Assert.Equal(404, (await Send(app, "/wp-admin")).Response.StatusCode);
        Assert.Empty(app.Called);
        Assert.Equal(200, (await Send(app, "/ok")).Response.StatusCode);
        Assert.Equal(new[] { "/ok" }, app.Called);
        Assert.Equal("monitored", Assert.Single(Events(RaspDeception.HitRule)).Attrs["shield360.rasp.decision"]);
        var e = Assert.Single(Events(RaspDeception.SuspiciousRule));
        Assert.Equal("monitored", e.Attrs["shield360.rasp.decision"]);
        Assert.Equal("monitor", e.Attrs["shield360.rasp.mode"]);
    }

    [Fact]
    public async Task A_mark_expires_after_its_ttl()
    {
        Arm("block", ttl: 60);
        var app = await Serve();
        await using var _ = app.Web;
        await Send(app, "/wp-admin");
        _now = _now.AddSeconds(59);
        Assert.Equal(403, (await Send(app, "/ok")).Response.StatusCode);
        _now = _now.AddSeconds(1);
        Assert.Equal(200, (await Send(app, "/ok")).Response.StatusCode);
    }

    [Fact]
    public async Task Attacks_deception_off_lets_decoys_reach_the_app_and_reports_nothing()
    {
        foreach (var off in new[] { true, false })
        {
            _sink.Events.Clear();
            if (off)
            {
                Arm("block", attackMode: RaspMode.Off);
            }
            else
            {
                Arm("block", local: new() { [RaspAttackType.Deception] = RaspMode.Off });
            }

            var app = await Serve();
            await using var _ = app.Web;
            Assert.Equal(200, (await Send(app, "/wp-admin")).Response.StatusCode);
            Assert.Equal(200, (await Send(app, "/ok")).Response.StatusCode);
            Assert.Equal(new[] { "/wp-admin", "/ok" }, app.Called);
            Assert.Empty(_sink.Events);
            Assert.Equal(0, RaspDeception.Table.Count);
        }
    }

    [Fact]
    public async Task Attacks_deception_monitor_caps_a_block_action_and_the_default_mode_never_applies()
    {
        Arm("block", attackMode: RaspMode.Monitor);
        var app = await Serve();
        await using var _ = app.Web;
        await Send(app, "/wp-admin");
        Assert.Equal(200, (await Send(app, "/ok")).Response.StatusCode);
        Assert.Equal("monitor", Assert.Single(Events(RaspDeception.SuspiciousRule)).Attrs["shield360.rasp.mode"]);

        // Unset: the action decides, not the config's default mode (monitor here).
        Arm("block");
        Assert.Equal(RaspMode.Block, RaspEngine.ModeFor(RaspAttackType.Deception));
    }

    [Fact]
    public async Task Monitor_only_without_a_pinned_key_lowers_block_to_monitor()
    {
        Arm("block");
        RaspEngine.SetMonitorOnly(true);
        var app = await Serve();
        await using var _ = app.Web;
        Assert.Equal(404, (await Send(app, "/wp-admin")).Response.StatusCode);
        Assert.Equal(200, (await Send(app, "/ok")).Response.StatusCode);
        Assert.Equal("monitored", Assert.Single(Events(RaspDeception.HitRule)).Attrs["shield360.rasp.decision"]);
        Assert.Equal("monitored", Assert.Single(Events(RaspDeception.SuspiciousRule)).Attrs["shield360.rasp.decision"]);
    }

    [Fact]
    public async Task The_kill_switch_and_a_dropped_config_leave_requests_untouched()
    {
        Arm("block");
        var app = await Serve();
        await using var _ = app.Web;
        Shield360Rasp.Disable();
        Assert.Equal(200, (await Send(app, "/wp-admin")).Response.StatusCode);
        Shield360Rasp.Enable();
        RaspEngine.SetRemoteConfig(null);
        Assert.Equal(200, (await Send(app, "/wp-admin")).Response.StatusCode);
        Assert.Equal(new[] { "/wp-admin", "/wp-admin" }, app.Called);
        Assert.Empty(_sink.Events);
        Assert.Equal(0, RaspDeception.Table.Count);
    }

    [Fact]
    public async Task A_config_change_keeps_existing_marks()
    {
        Arm("block", ttl: 60);
        var app = await Serve();
        await using var _ = app.Web;
        await Send(app, "/wp-admin");
        Arm("block", ttl: 3600);
        _now = _now.AddSeconds(30);
        Assert.Equal(403, (await Send(app, "/ok")).Response.StatusCode);
        _now = _now.AddSeconds(30);
        Assert.Equal(200, (await Send(app, "/ok")).Response.StatusCode); // the old mark's TTL, not recomputed
    }

    [Fact]
    public async Task Without_a_client_address_the_decoy_still_gets_the_404_and_nothing_is_marked()
    {
        Arm("block");
        var app = await Serve();
        await using var _ = app.Web;
        Assert.Equal(404, (await Send(app, "/wp-admin", ip: null)).Response.StatusCode);
        Assert.Empty(app.Called);
        Assert.Equal(0, RaspDeception.Table.Count);
        Assert.Equal(200, (await Send(app, "/ok", ip: null)).Response.StatusCode);
    }

    [Fact]
    public async Task Failures_in_deception_stay_open()
    {
        Arm("block");
        RaspDeception.Table = new RaspSuspiciousTable(now: () => throw new InvalidOperationException("clock"));
        var app = await Serve();
        await using var _ = app.Web;
        Assert.Equal(200, (await Send(app, "/wp-admin")).Response.StatusCode);
        Assert.Equal(200, (await Send(app, "/ok")).Response.StatusCode);
        Assert.Equal(new[] { "/wp-admin", "/ok" }, app.Called);

        // A throwing event sink never breaks the request either: the decoy still gets its 404.
        RaspDeception.Table = new RaspSuspiciousTable(now: () => _now);
        RaspEngine.SetEventSink(new ThrowingSink());
        Assert.Equal(404, (await Send(app, "/wp-admin")).Response.StatusCode);
        Assert.Equal(403, (await Send(app, "/ok")).Response.StatusCode);
    }

    private sealed class ThrowingSink : IRaspEventSink
    {
        public void Add(RaspEvent e, string foldKey) => throw new InvalidOperationException("sink");
    }

    [Fact]
    public async Task Behind_a_proxy_trusted_by_forwarded_headers_the_client_is_marked_not_the_proxy()
    {
        Arm("block");
        var app = await Serve(
            services: s => s.Configure<ForwardedHeadersOptions>(o =>
            {
                o.ForwardedHeaders = ForwardedHeaders.XForwardedFor;
                o.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(IPAddress.Parse("10.0.0.0"), 8));
            }),
            forwardedHeaders: true);
        await using var _ = app.Web;
        var xff = new Dictionary<string, string> { ["X-Forwarded-For"] = "203.0.113.9" };
        Assert.Equal(404, (await Send(app, "/wp-admin", ip: "10.0.0.2", headers: xff)).Response.StatusCode);
        Assert.Equal(new[] { "203.0.113.9" }, RaspDeception.Table.Addresses());
        Assert.Equal(403, (await Send(app, "/ok", ip: "10.0.0.2", headers: xff)).Response.StatusCode);
        Assert.Equal(200, (await Send(app, "/ok", ip: "10.0.0.2", headers: new() { ["X-Forwarded-For"] = "198.51.100.1" })).Response.StatusCode);
    }

    [Fact]
    public async Task Without_forwarded_headers_X_Forwarded_For_is_never_read()
    {
        Arm("block");
        var app = await Serve();
        await using var _ = app.Web;
        await Send(app, "/wp-admin", ip: "10.0.0.2", headers: new() { ["X-Forwarded-For"] = "203.0.113.9" });
        Assert.Equal(new[] { "10.0.0.2" }, RaspDeception.Table.Addresses());
    }

    [Fact]
    public async Task The_middleware_added_by_AddShield360Rasp_answers_decoys_too()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddShield360Rasp(r => r.Enabled = true);
        await using var web = builder.Build();
        var called = false;
        web.MapGet("/wp-admin", () =>
        {
            called = true;
            return "ok";
        });
        await web.StartAsync();

        // AddShield360Rasp restarted RASP: the signed config arrives after start.
        RaspEngine.SetEventSink(_sink);
        RaspEngine.SetRemoteConfig(new RemoteConfig
        {
            Version = "v1",
            Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
            Deception = Parse("{\"paths\":[\"/wp-admin\"]}"),
        });
        var ctx = await web.GetTestServer().SendAsync(c =>
        {
            c.Request.Method = "GET";
            c.Request.Path = "/wp-admin";
        });
        Assert.Equal(404, ctx.Response.StatusCode);
        Assert.False(called);
        Assert.Single(Events(RaspDeception.HitRule));
    }

    /// <summary>
    /// The default registration puts RASP ahead of the app's own middleware; a decoy must still
    /// get exactly what an unknown path gets from it (status code pages, re-execute).
    /// </summary>
    [Theory]
    [InlineData("none", false)]
    [InlineData("pages", false)]
    [InlineData("reexecute", false)]
    [InlineData("reexecute", true)]
    [InlineData("redirects", false)]
    public async Task With_the_default_registration_a_decoy_gets_the_apps_own_not_found(string pages, bool alsoUse)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddShield360Rasp(r => r.Enabled = true);
        var app = new App { Web = builder.Build() };
        await using var _ = app.Web;
        switch (pages)
        {
            case "pages":
                app.Web.UseStatusCodePages();
                break;
            case "reexecute":
                app.Web.UseStatusCodePagesWithReExecute("/error/{0}");
                break;
            case "redirects":
                app.Web.UseStatusCodePagesWithRedirects("/error/{0}");
                break;
        }

        if (alsoUse)
        {
            app.Web.UseShield360Rasp();
        }

        foreach (var p in new[] { "/ok", "/wp-admin", "/wp-admin/{**rest}" })
        {
            app.Web.MapGet(p, (HttpContext c) =>
            {
                lock (app.Called)
                {
                    app.Called.Add(c.Request.Path.Value!);
                }

                return "ok";
            });
        }

        app.Web.MapGet("/error/{code}", (string code) => "custom error " + code);
        await app.Web.StartAsync();

        // AddShield360Rasp restarted RASP: the signed config arrives after start.
        RaspEngine.SetEventSink(_sink);
        RaspEngine.SetRemoteConfig(new RemoteConfig
        {
            Version = "v1",
            Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
            Attacks = new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.Deception] = RaspMode.Block },
            Deception = Parse("{\"paths\":[\"/wp-admin\"],\"action\":\"monitor\"}"),
        });

        var unknown = await Send(app, "/no-such-page", ip: "198.51.100.1");
        var decoy = await Send(app, "/wp-admin/install.php");
        Assert.Empty(app.Called);
        Assert.Equal(unknown.Response.StatusCode, decoy.Response.StatusCode);
        Assert.Equal(unknown.Response.ContentType, decoy.Response.ContentType);
        Assert.Equal(unknown.Response.Headers.Location.ToString(), decoy.Response.Headers.Location.ToString());
        var page = Body(unknown);
        Assert.Equal(page, Body(decoy));
        if (pages == "reexecute")
        {
            Assert.Equal("custom error 404", page);
        }
        else if (pages == "pages")
        {
            Assert.StartsWith("Status Code: 404", page, StringComparison.Ordinal);
        }

        // Marked and reported once; the marked client's next request goes on (monitor).
        Assert.Single(Events(RaspDeception.HitRule));
        Assert.Equal(new[] { "203.0.113.9" }, RaspDeception.Table.Addresses());
        Assert.Equal(200, (await Send(app, "/ok")).Response.StatusCode);
        Assert.Equal(new[] { "/ok" }, app.Called);
        Assert.Single(Events(RaspDeception.SuspiciousRule));
        Assert.Single(Events(RaspDeception.HitRule));
    }

    [Fact]
    public async Task With_the_default_registration_a_blocked_suspicious_client_still_gets_the_403()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddShield360Rasp(r => r.Enabled = true);
        var app = new App { Web = builder.Build() };
        await using var _ = app.Web;
        app.Web.UseStatusCodePages();
        app.Web.MapGet("/ok", () => "ok");
        await app.Web.StartAsync();
        RaspEngine.SetEventSink(_sink);
        RaspEngine.SetRemoteConfig(new RemoteConfig
        {
            Version = "v1",
            Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
            Deception = Parse("{\"paths\":[\"/wp-admin\"],\"action\":\"block\"}"),
        });
        Assert.Equal(404, (await Send(app, "/wp-admin")).Response.StatusCode);
        Assert.Equal(403, (await Send(app, "/ok")).Response.StatusCode);
    }
}
