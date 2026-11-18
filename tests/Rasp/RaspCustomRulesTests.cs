using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Custom rules in the SDK (contract "Custom rules"): rules arrive inside the signed config,
/// invalid ones are skipped with one warning and never break the config, request rules run
/// with the request's capture, finding rules when a built-in check fires, the custom_rule
/// mode caps every action, and evaluation fails open. Port of custom-rules.test.ts.
/// </summary>
public class RaspCustomRulesTests : RaspStateTest
{
    private ListSink _sink;
    private readonly List<SkippedRule> _warnings = new();

    public RaspCustomRulesTests()
    {
        _sink = Configure(new EngineSettings(true, "orders-api"));
    }

    private static JsonObject Rule(string id = "r1", string expression = "request.path.startsWith(\"/admin\")", string action = "monitor", JsonNode? extra = null)
    {
        var r = new JsonObject { ["id"] = id, ["name"] = "Rule one", ["expression"] = expression, ["action"] = action, ["enabled"] = true };
        if (extra is JsonObject o)
        {
            foreach (var kv in o.ToList())
            {
                o.Remove(kv.Key);
                r[kv.Key] = kv.Value;
            }
        }

        return r;
    }

    private static JsonElement Json(JsonNode node) => TestJson.Parse(node.ToJsonString());

    private static JsonElement List(params JsonNode?[] rules) => Json(new JsonArray(rules));

    private static RemoteConfig Remote(JsonElement? customRules, Dictionary<RaspAttackType, RaspMode>? attacks = null) => new()
    {
        Version = "v1",
        Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
        Mode = RaspMode.Monitor,
        Attacks = attacks ?? new Dictionary<RaspAttackType, RaspMode>(),
        CustomRulesJson = customRules?.GetRawText(),
    };

    private static RaspContext Request(string url, string method = "GET", Dictionary<string, string>? headers = null) =>
        RaspCapture.CaptureRequest(new RequestShape
        {
            Framework = "test",
            Method = method,
            Url = url,
            Headers = headers ?? new Dictionary<string, string>(StringComparer.Ordinal) { ["user-agent"] = "curl/8.4", ["host"] = "a" },
            Ip = "::ffff:10.1.2.3",
        });

    private IReadOnlyList<CustomRule> Parse(JsonElement raw, string app = "orders-api") => RaspCustomRules.Parse(raw, app, _warnings.Add);

    private List<string> Rules() => _sink.Events.Select(e => e.Attrs["shield360.rasp.rule"]).ToList();

    private static readonly RaspFinding s_sqli = new(RaspAttackType.SqlInjection, "sqli.userinput", new RaspInput("1 OR 1=1", "query.q"));

    [Fact]
    public void Keeps_valid_enabled_rules_for_this_app_in_order()
    {
        var rules = Parse(List(
            Rule(),
            Rule("r2", extra: new JsonObject { ["apps"] = new JsonArray("orders-api", "billing") }),
            Rule("r3", extra: new JsonObject { ["apps"] = new JsonArray("billing") }),
            Rule("r4", extra: new JsonObject { ["enabled"] = false })));
        Assert.Equal(new[] { "r1", "r2" }, rules.Select(r => r.Id));
        Assert.Empty(_warnings);
    }

    [Fact]
    public void Skips_each_invalid_rule_with_one_warning_and_never_warns_twice_for_it()
    {
        var raw = List(
            Rule("Bad Id"),
            Rule("ok-1"),
            Rule("ok-1"),
            Rule("x2", action: "allow"),
            Rule("x3", extra: new JsonObject { ["enabled"] = "yes" }),
            Rule("x4", "request.method = \"GET\""),
            Rule("x5", extra: new JsonObject { ["apps"] = "orders-api" }),
            Rule("x6", extra: new JsonObject { ["name"] = 7 }),
            null,
            JsonValue.Create("rule"));
        Assert.Equal(new[] { "ok-1" }, Parse(raw).Select(r => r.Id));
        Assert.Equal(9, _warnings.Count);
        Assert.Contains(_warnings, w => w.Id == "x4" && w.Reason == "expression: syntax");
        Parse(raw);
        Assert.Equal(9, _warnings.Count);
    }

    [Fact]
    public void Keeps_at_most_64()
    {
        Assert.Equal(64, Parse(List(Enumerable.Range(0, 70).Select(i => (JsonNode?)Rule("r" + i)).ToArray()), "a").Count);
    }

    [Fact]
    public void Is_empty_for_anything_but_a_list()
    {
        Assert.Empty(RaspCustomRules.Parse(null, "a"));
        Assert.Empty(RaspCustomRules.Parse(Json(new JsonObject()), "a"));
        Assert.Empty(RaspCustomRules.Parse(Json(JsonValue.Create("x")), "a"));
    }

    [Fact]
    public void The_request_subject_reads_the_request_as_the_language_sees_it()
    {
        var ctx = Request("/api/orders/42?id=42&id=43&q=%252e%252e", "post", new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["user-agent"] = "curl/8.4",
            ["x-multi"] = "a, b",
        });
        RaspCapture.CaptureBody(ctx, new BodyShape("{\"user\":{\"role\":\"admin\"}}", "application/json"));
        var s = RaspCustomRules.Subject(ctx, "orders-api");
        var r = s.Request!;
        Assert.Equal(("POST", "/api/orders/42", "/api/orders/:id", "::ffff:10.1.2.3"), (r.Method, r.Path, r.Route, r.Ip));
        Assert.Equal("42", r.Query!["id"]);
        Assert.Equal("%2e%2e", r.Query["q"]);
        Assert.Equal("admin", r.Body!["user.role"]);
        Assert.Equal("curl/8.4", r.Headers!["user-agent"]);
        Assert.Equal("a, b", r.Headers["x-multi"]);
        Assert.Contains(s.Inputs!, i => i.Key == "query.q" && i.Value == "..");
        Assert.Null(RaspCustomRules.Subject(new RaspContext(), "a").Request);
    }

    [Fact]
    public void Request_rules_report_a_match_as_a_custom_rule_event_and_let_the_request_through_in_monitor()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule(action: "alert"))));
        RaspCapture.RunVirtualPatches(Request("/admin/users"));
        var e = Assert.Single(_sink.Events);
        Assert.Equal("custom_rule", e.Attrs["shield360.rasp.attack"]);
        Assert.Equal("custom.r1", e.Attrs["shield360.rasp.rule"]);
        Assert.Equal("monitored", e.Attrs["shield360.rasp.decision"]);
        Assert.Equal("server.request", e.Attrs["shield360.rasp.sink"]);
        Assert.Equal("/admin/users", e.Attrs["shield360.rasp.route"]);
        Assert.Equal("v1", e.Attrs["shield360.rasp.config_version"]);
    }

    [Fact]
    public void Request_rules_block_only_when_the_rule_says_block_and_the_custom_rule_mode_is_block()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule(action: "block"))));
        RaspCapture.RunVirtualPatches(Request("/admin"));
        Assert.Equal("monitored", _sink.Events[0].Attrs["shield360.rasp.decision"]);

        RaspEngine.SetRemoteConfig(Remote(List(Rule(action: "monitor")), new() { [RaspAttackType.CustomRule] = RaspMode.Block }));
        RaspCapture.RunVirtualPatches(Request("/admin"));

        RaspEngine.SetRemoteConfig(Remote(List(Rule(action: "block")), new() { [RaspAttackType.CustomRule] = RaspMode.Block }));
        var ex = Assert.Throws<Shield360RaspBlockedException>(() => RaspCapture.RunVirtualPatches(Request("/admin")));
        Assert.Equal(("custom_rule", "custom.r1"), (ex.Attack, ex.Rule));

        RaspEngine.SetRemoteConfig(Remote(List(Rule(action: "block")), new() { [RaspAttackType.CustomRule] = RaspMode.Off }));
        _sink.Events.Clear();
        RaspCapture.RunVirtualPatches(Request("/admin"));
        Assert.Empty(_sink.Events);
    }

    [Fact]
    public void Request_rules_match_once_per_request_and_input_rules_run_again_when_the_body_arrives()
    {
        RaspEngine.SetRemoteConfig(Remote(List(
            Rule("path", "request.path == \"/upload\""),
            Rule("traversal", "input.value.contains(\"../\")"),
            Rule("role", "request.body[\"role\"] == \"admin\""),
            Rule("ip", "request.ip.inCidr(\"10.0.0.0/8\") && request.headers[\"user-agent\"].startsWith(\"curl/\")"))));
        var ctx = Request("/upload", "POST");
        RaspCapture.RunVirtualPatches(ctx);
        Assert.Equal(new[] { "custom.path", "custom.ip" }, Rules());
        RaspCapture.CaptureBody(ctx, new BodyShape("{\"role\":\"admin\",\"file\":\"../../etc/passwd\"}", "application/json"));
        RaspCapture.RunVirtualPatches(ctx);
        Assert.Equal(new[] { "custom.path", "custom.ip", "custom.traversal", "custom.role" }, Rules());
        Assert.Equal("body.file", _sink.Events[2].Attrs["shield360.rasp.input_key"]);
    }

    [Fact]
    public void Request_rules_stop_at_the_first_rule_that_blocks()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule("a", action: "block"), Rule("b")), new() { [RaspAttackType.CustomRule] = RaspMode.Block }));
        Assert.Throws<Shield360RaspBlockedException>(() => RaspCapture.RunVirtualPatches(Request("/admin")));
        Assert.Equal(new[] { "custom.a" }, Rules());
    }

    [Fact]
    public void Request_rules_fail_open_when_the_work_budget_runs_out()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule(expression: "input.value.matches(\"a{100}x\")", action: "block")), new() { [RaspAttackType.CustomRule] = RaspMode.Block }));
        var query = string.Join("&", Enumerable.Range(0, 200).Select(i => $"k{i}={new string('a', 4096)}"));
        RaspCapture.RunVirtualPatches(Request("/x?" + query));
        Assert.Empty(_sink.Events);
    }

    [Fact]
    public void Request_rules_do_nothing_while_RASP_is_off()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule(action: "block")), new() { [RaspAttackType.CustomRule] = RaspMode.Block }));
        RaspEngine.Configure(new EngineSettings(false, "orders-api", Env: Env.Empty));
        RaspCapture.RunVirtualPatches(Request("/admin"));
        Assert.Empty(_sink.Events);
    }

    [Fact]
    public async Task Request_rules_block_through_the_middleware_with_the_contract_403()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule(expression: "request.headers[\"x-debug\"] == \"1\"", action: "block")), new() { [RaspAttackType.CustomRule] = RaspMode.Block }));
        var ran = false;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.UseShield360Rasp();
        app.MapGet("/a", () =>
        {
            ran = true;
            return "ok";
        });
        await app.StartAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/a");
        request.Headers.TryAddWithoutValidation("X-Debug", "1");
        var res = await app.GetTestClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        Assert.False(ran);
        var body = JsonNode.Parse(await res.Content.ReadAsStringAsync())!;
        Assert.Equal(("custom_rule", "custom.r1"), (RaspCorpus.Str(body["attack"]), RaspCorpus.Str(body["rule"])));
    }

    private static string BigJsonBody() =>
        "{" + string.Join(",", Enumerable.Range(0, 200).Select(i => $"\"k{i}\":\"{new string('a', 4000)}\"")) + "}";

    private static RemoteConfig Blocking(params JsonNode?[] rules) =>
        Remote(List(rules), new() { [RaspAttackType.CustomRule] = RaspMode.Block });

    [Fact]
    public void Head_rules_see_only_the_inputs_known_before_the_body_even_when_the_body_was_captured_first()
    {
        // The body is buffered before the head is judged: its fields still join only at body.
        RaspEngine.SetRemoteConfig(Remote(List(
            Rule("body-key", "input.key.startsWith(\"body.\")"),
            Rule("path", "request.path == \"/orders\""))));
        var ctx = Request("/orders", "POST");
        RaspCapture.CaptureBody(ctx, new BodyShape("{\"role\":\"admin\"}", "application/json"));
        RaspCapture.RunVirtualPatches(ctx);
        Assert.Equal(new[] { "custom.path", "custom.body-key" }, Rules());
    }

    [Fact]
    public void Body_fields_cannot_spend_the_budget_at_head_before_a_later_path_rule_blocks()
    {
        RaspEngine.SetRemoteConfig(Blocking(
            Rule("heavy", "input.value.matches(\"a{100}x\")"),
            Rule("admin", "request.path == \"/admin\"", "block")));
        var ctx = Request("/admin", "POST");
        RaspCapture.CaptureBody(ctx, new BodyShape(BigJsonBody(), "application/json"));
        var ex = Assert.Throws<Shield360RaspBlockedException>(() => RaspCapture.RunVirtualPatches(ctx));
        Assert.Equal("custom.admin", ex.Rule);
    }

    private static async Task<WebApplication> Serve(Action<WebApplication>? before = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        before?.Invoke(app);
        app.UseShield360Rasp();
        app.MapGet("/admin", () => "ok");
        app.MapPost("/admin", () => "ok");
        await app.StartAsync();
        return app;
    }

    private static async Task<int> Send(WebApplication app, HttpMethod method, string? body = null, string contentType = "application/json")
    {
        var request = new HttpRequestMessage(method, "/admin");
        if (body is not null)
        {
            request.Content = new StringContent(body);
            request.Content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(contentType);
        }

        return (int)(await app.GetTestClient().SendAsync(request)).StatusCode;
    }

    [Fact]
    public async Task The_middleware_judges_head_rules_before_it_reads_the_body()
    {
        RaspEngine.SetRemoteConfig(Blocking(
            Rule("heavy", "input.value.matches(\"a{100}x\")"),
            Rule("admin", "request.path == \"/admin\"", "block")));
        await using var app = await Serve();
        Assert.Equal(403, await Send(app, HttpMethod.Post, BigJsonBody()));
        Assert.Equal(new[] { "custom.admin" }, Rules());
    }

    [Fact]
    public async Task An_empty_or_absent_body_is_a_known_body_so_body_rules_run_on_it()
    {
        RaspEngine.SetRemoteConfig(Blocking(Rule("marker", "request.body[\"marker\"] == null", "block")));
        await using var app = await Serve();
        Assert.Equal(403, await Send(app, HttpMethod.Post, string.Empty));                                      // an empty JSON POST
        Assert.Equal(403, await Send(app, HttpMethod.Post, string.Empty, "application/x-www-form-urlencoded")); // an empty form POST
        Assert.Equal(403, await Send(app, HttpMethod.Post));                                                    // a POST with no body
        Assert.Equal(403, await Send(app, HttpMethod.Get));                                                     // a GET
        Assert.Equal(200, await Send(app, HttpMethod.Post, "{\"marker\":\"m1\"}"));
    }

    [Fact]
    public async Task A_body_an_earlier_middleware_consumed_stays_unknown()
    {
        RaspEngine.SetRemoteConfig(Blocking(Rule("marker", "request.body[\"marker\"] == null", "block")));
        await using var app = await Serve(a => a.Use(async (context, next) =>
        {
            await context.Request.Body.CopyToAsync(System.IO.Stream.Null);
            await next(context);
        }));
        Assert.Equal(200, await Send(app, HttpMethod.Post, "{\"name\":\"x\"}"));
    }

    [Fact]
    public async Task A_chunked_body_an_earlier_middleware_consumed_stays_unknown()
    {
        RaspEngine.SetRemoteConfig(Blocking(Rule("marker", "request.body[\"marker\"] == null", "block")));
        await using var app = await Serve(a => a.Use(async (context, next) =>
        {
            await context.Request.Body.CopyToAsync(System.IO.Stream.Null);
            await next(context);
        }));

        // No Content-Length: the body is framed by chunks, so reading nothing does not mean there was none.
        var request = new HttpRequestMessage(HttpMethod.Post, "/admin")
        {
            Content = new StreamContent(new UnseekableStream(System.Text.Encoding.UTF8.GetBytes("{\"marker\":\"m1\"}"))),
        };
        request.Content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
        request.Headers.TransferEncodingChunked = true;
        Assert.Null(request.Content.Headers.ContentLength);
        Assert.Equal(200, (int)(await app.GetTestClient().SendAsync(request)).StatusCode);
    }

    private sealed class UnseekableStream(byte[] data) : System.IO.MemoryStream(data)
    {
        public override bool CanSeek => false;
    }

    [Fact]
    public void Finding_rules_on_an_upload_check_see_the_request_and_its_inputs_before_its_context_is_entered()
    {
        RaspEngine.SetRemoteConfig(Remote(
            List(Rule(
                "upload-from-office",
                "attack.type == \"file_write\" && sink.name == \"request.upload\" && request.path == \"/upload\" && request.method == \"POST\" && request.ip.inCidr(\"10.0.0.0/8\") && input.key == \"body.f.filename\"",
                "block")),
            new() { [RaspAttackType.CustomRule] = RaspMode.Block, [RaspAttackType.FileWrite] = RaspMode.Monitor }));
        Assert.Null(RaspScope.Current);
        var ctx = Request("/upload", "POST");
        var ex = Assert.Throws<Shield360RaspBlockedException>(() =>
            RaspCapture.CaptureBody(ctx, new BodyShape(null, "multipart/form-data; boundary=b", new[] { new RaspUpload("f", "page.php") })));
        Assert.Equal("custom.upload-from-office", ex.Rule);
        Assert.Equal(new[] { "file_write.upload", "custom.upload-from-office" }, Rules());
    }

    private static async Task<WebApplication> ServeBehindProxy(Action<IServiceCollection>? services, bool inlineForwardedHeaders, string expression)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddShield360Rasp(o => o.Mode = RaspMode.Monitor, Env.Empty);
        services?.Invoke(builder.Services);
        var app = builder.Build();
        if (inlineForwardedHeaders)
        {
            var options = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor };
            options.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(IPAddress.Parse("10.0.0.0"), 8));
            app.UseForwardedHeaders(options);
        }
        else if (services is not null)
        {
            app.UseForwardedHeaders();
        }

        app.MapGet("/admin", () => "ok");
        await app.StartAsync();

        // AddShield360Rasp restarted RASP: the signed config arrives after start.
        RaspEngine.SetRemoteConfig(Remote(List(Rule("ip", expression, "block")), new() { [RaspAttackType.CustomRule] = RaspMode.Block }));
        return app;
    }

    private static async Task<int> Status(WebApplication app, string socket, string? forwardedFor)
    {
        var ctx = await app.GetTestServer().SendAsync(c =>
        {
            c.Request.Method = "GET";
            c.Request.Path = "/admin";
            c.Connection.RemoteIpAddress = IPAddress.Parse(socket);
            if (forwardedFor is not null)
            {
                c.Request.Headers["X-Forwarded-For"] = forwardedFor;
            }
        });
        return ctx.Response.StatusCode;
    }

    [Fact]
    public async Task Request_ip_is_the_forwarded_client_once_UseForwardedHeaders_runs_after_the_start_up_filter()
    {
        await using var app = await ServeBehindProxy(null, inlineForwardedHeaders: true, "!request.ip.inCidr(\"10.0.0.0/8\")");
        Assert.Equal(403, await Status(app, "10.0.0.2", "203.0.113.9")); // an outside client through the trusted proxy
        Assert.Equal(200, await Status(app, "10.0.0.2", "10.1.1.1"));    // an inside client through it
        Assert.Equal(403, await Status(app, "203.0.113.9", "10.1.1.1")); // an untrusted sender cannot claim to be inside
    }

    [Fact]
    public async Task A_rule_matching_the_proxy_address_waits_for_forwarded_headers_configured_in_services()
    {
        await using var app = await ServeBehindProxy(
            s => s.Configure<ForwardedHeadersOptions>(o =>
            {
                o.ForwardedHeaders = ForwardedHeaders.XForwardedFor;
                o.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(IPAddress.Parse("10.0.0.0"), 8));
            }),
            inlineForwardedHeaders: false,
            "request.ip.inCidr(\"10.0.0.0/8\")");
        Assert.Equal(200, await Status(app, "10.0.0.2", "203.0.113.9")); // judged as the client, not the proxy
        Assert.Equal(403, await Status(app, "10.0.0.2", "10.1.1.1"));
        Assert.Equal(403, await Status(app, "10.0.0.2", null));
    }

    [Fact]
    public async Task Without_forwarded_headers_a_spoofed_X_Forwarded_For_changes_nothing()
    {
        await using var app = await ServeBehindProxy(null, inlineForwardedHeaders: false, "request.ip.inCidr(\"10.0.0.0/8\")");
        Assert.Equal(403, await Status(app, "10.0.0.2", "203.0.113.9"));
        Assert.Equal(200, await Status(app, "203.0.113.9", "10.1.1.1"));
    }

    private static readonly VirtualPatch s_headPatch = VirtualPatch.ListFromJson(TestJson.Parse(
        "[{\"id\":\"vp.test-head\",\"match\":[{\"target\":\"method\",\"op\":\"equals\",\"values\":[\"GET\"]}]}]"))[0];

    private static RemoteConfig WithPatch(JsonElement rules) => new()
    {
        Version = "v1",
        Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
        Mode = RaspMode.Monitor,
        Attacks = new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.CustomRule] = RaspMode.Block },
        Rules = new[] { s_headPatch },
        CustomRulesJson = rules.GetRawText(),
    };

    [Fact]
    public void Finding_rules_on_a_capture_time_finding_see_the_request_before_its_context_is_entered()
    {
        RaspEngine.SetRemoteConfig(WithPatch(List(Rule("vp-on-x", "attack.type == \"virtual_patch\" && request.path == \"/x\"", "block"))));
        Assert.Null(RaspScope.Current);
        var ex = Assert.Throws<Shield360RaspBlockedException>(() => RaspCapture.RunVirtualPatches(Request("/x")));
        Assert.Equal("custom.vp-on-x", ex.Rule);
    }

    [Fact]
    public void Finding_rules_on_a_capture_time_finding_share_the_requests_budget()
    {
        RaspEngine.SetRemoteConfig(WithPatch(List(Rule("vp-any", "attack.type == \"virtual_patch\"", "monitor"))));
        var ctx = Request("/x");
        RaspCustomRules.StateOf(ctx).Budget.Steps = -1; // this request's work budget is spent
        RaspCapture.RunVirtualPatches(ctx);
        Assert.Equal(new[] { "vp.test-head" }, Rules());
    }

    [Fact]
    public void Finding_rules_see_the_built_in_finding_its_sink_and_the_request()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule(
            "admin-sqli",
            "attack.type == \"sql_injection\" && sink.name == \"pg.query\" && request.path.startsWith(\"/admin\")",
            "alert"))));
        RaspScope.Run(Request("/admin/search?q=1%20OR%201%3D1"), () => RaspEngine.HandleFinding(s_sqli, "pg.query"));
        Assert.Equal(
            new[] { ("sql_injection", "sqli.userinput", "pg.query"), ("custom_rule", "custom.admin-sqli", "pg.query") },
            _sink.Events.Select(e => (e.Attrs["shield360.rasp.attack"], e.Attrs["shield360.rasp.rule"], e.Attrs["shield360.rasp.sink"])));
        Assert.Equal("query.q", _sink.Events[1].Attrs["shield360.rasp.input_key"]);
    }

    [Fact]
    public void Finding_rules_never_run_in_the_request_phase_and_request_rules_never_run_on_findings()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule("f", "attack.type != null"), Rule("q", "request.path == \"/a\""))));
        var ctx = Request("/a");
        RaspCapture.RunVirtualPatches(ctx);
        Assert.Equal(new[] { "custom.q" }, Rules());
        _sink.Events.Clear();
        RaspScope.Run(ctx, () => RaspEngine.HandleFinding(s_sqli, "pg.query"));
        Assert.Equal(new[] { "sqli.userinput", "custom.f" }, Rules());
    }

    [Fact]
    public void Finding_rules_can_block_a_finding_the_attack_type_only_monitors_and_the_built_in_block_wins_when_both_block()
    {
        var rules = List(Rule("stop", "attack.type == \"sql_injection\"", "block"));
        RaspEngine.SetRemoteConfig(Remote(rules, new() { [RaspAttackType.CustomRule] = RaspMode.Block }));
        var ex = Assert.Throws<Shield360RaspBlockedException>(() => RaspScope.Run(Request("/a"), () => RaspEngine.HandleFinding(s_sqli, "pg.query")));
        Assert.Equal(RaspAttackType.CustomRule, ex.AttackType);
        RaspEngine.SetRemoteConfig(Remote(rules, new() { [RaspAttackType.CustomRule] = RaspMode.Block, [RaspAttackType.SqlInjection] = RaspMode.Block }));
        ex = Assert.Throws<Shield360RaspBlockedException>(() => RaspScope.Run(Request("/a"), () => RaspEngine.HandleFinding(s_sqli, "pg.query")));
        Assert.Equal(RaspAttackType.SqlInjection, ex.AttackType);
    }

    [Fact]
    public void Custom_rule_off_evaluates_no_rule_and_spends_no_budget()
    {
        RaspEngine.SetRemoteConfig(Remote(
            List(Rule("req", "input.value.matches(\"x.*y\")"), Rule("fnd", "attack.type == \"sql_injection\" && input.value.matches(\"x.*y\")")),
            new() { [RaspAttackType.CustomRule] = RaspMode.Off }));
        var ctx = Request("/a?q=" + new string('a', 200));
        var before = RaspCustomRules.StateOf(ctx).Budget.Steps;
        RaspCapture.RunVirtualPatches(ctx);
        RaspScope.Run(ctx, () => RaspEngine.HandleFinding(s_sqli, "pg.query"));
        Assert.Equal(before, RaspCustomRules.StateOf(ctx).Budget.Steps);
        Assert.Equal(new[] { "sqli.userinput" }, Rules());
    }

    [Fact]
    public void Finding_rules_skip_attack_types_that_are_off()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule(expression: "attack.type == \"sql_injection\"")), new() { [RaspAttackType.SqlInjection] = RaspMode.Off }));
        Assert.Equal(RaspMode.Off, RaspEngine.ModeFor(RaspAttackType.SqlInjection));
        RaspScope.Run(Request("/a"), () => RaspEngine.HandleFinding(s_sqli, "pg.query"));
        Assert.Empty(_sink.Events);
    }

    [Fact]
    public void Finding_rules_run_outside_a_request_with_the_request_fields_null()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule(expression: "request.path == null && app.name == \"orders-api\" && attack.type == \"sql_injection\""))));
        RaspEngine.HandleFinding(s_sqli, "pg.query");
        Assert.Equal(new[] { "sqli.userinput", "custom.r1" }, Rules());
    }

    [Fact]
    public void Finding_rules_run_on_a_real_check_through_the_engine()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule("sql-from-search", "attack.type == \"sql_injection\" && input.key == \"query.q\""))));
        var ctx = Request("/search?q=" + Uri.EscapeDataString("1 OR 1=1"));
        RaspScope.Run(ctx, () => RaspEngine.Check("pg.query", () => RaspDetect.Sql("SELECT * FROM t WHERE id = 1 OR 1=1", RaspScope.InputsOf(ctx))));
        Assert.Equal(new[] { "sqli.userinput", "custom.sql-from-search" }, Rules());
    }

    [Fact]
    public void The_signed_claims_carry_the_rules_and_an_invalid_rule_is_skipped_while_the_rest_of_the_config_holds()
    {
        var warnings = new List<string>();
        var previous = RaspRuntime.Warn;
        RaspRuntime.Warn = warnings.Add;
        try
        {
            var claims = new JsonObject
            {
                ["v"] = 1,
                ["app"] = "orders-api",
                ["version"] = "cfg-1",
                ["exp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 600,
                ["mode"] = "monitor",
                ["attacks"] = new JsonObject { ["ssrf"] = "block", ["custom_rule"] = "block" },
                ["customRules"] = new JsonArray(Rule(action: "block"), Rule("broken", "request.path.matches(\"(a+)+\")")),
            };
            RaspEngine.SetRemoteConfig(RaspRuntime.ToRemote(new RaspClaims("cfg-1", 0, Json(claims))));
            Assert.Equal(new[] { "r1" }, RaspEngine.CustomRules.Select(r => r.Id));
            Assert.Equal(RaspMode.Block, RaspEngine.ModeFor(RaspAttackType.Ssrf));
            var warning = Assert.Single(warnings, w => w.Contains("custom rule", StringComparison.Ordinal));
            Assert.Contains("\"broken\"", warning, StringComparison.Ordinal);
            Assert.Contains("expression: regex", warning, StringComparison.Ordinal);
            Assert.Throws<Shield360RaspBlockedException>(() => RaspCapture.RunVirtualPatches(Request("/admin")));
        }
        finally
        {
            RaspRuntime.Warn = previous;
        }
    }

    [Fact]
    public void Dropping_the_signed_config_drops_its_rules()
    {
        RaspEngine.SetRemoteConfig(Remote(List(Rule())));
        Assert.Single(RaspEngine.CustomRules);
        RaspEngine.SetRemoteConfig(null);
        Assert.Empty(RaspEngine.CustomRules);
    }
}
