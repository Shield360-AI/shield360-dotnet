using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Shield360.AI;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// The ASP.NET Core middleware in a real pipeline (TestServer): inputs recorded in
/// the request's context (query, route values, body, cookies, the input headers),
/// virtual patches run before the endpoint, the block exception mapped to the
/// contract's 403. Port of middleware.test.ts for ASP.NET Core.
/// </summary>
public class RaspMiddlewareTests : RaspStateTest
{
    private static readonly VirtualPatch s_example = RaspVirtualPatches.BuiltIn.Single(r => r.Example);
    private static readonly VpRequest s_exampleShape = RaspCorpus.RequestFor(s_example);

    /// <summary>A body rule for .NET (the built-in body rules are Node-only), served as the signed config's rules.</summary>
    private static readonly VirtualPatch s_bodyRule = VirtualPatch.ListFromJson(TestJson.Parse("""
        [{"id":"vp.test-body","match":[{"target":"method","op":"equals","values":["POST"]},
          {"target":"body","op":"contains_any","values":["resolved_model"]}]}]
        """))[0];

    private ListSink _sink = new();

    private void SetMode(RaspMode vp, Dictionary<RaspAttackType, RaspMode>? extra = null)
    {
        var attacks = new Dictionary<RaspAttackType, RaspMode>(extra ?? new()) { [RaspAttackType.VirtualPatch] = vp };
        _sink = Configure(new EngineSettings(true, "orders-api", Attacks: attacks));
    }

    private static Dictionary<string, string> Keys()
    {
        var ctx = RaspScope.Current;
        return ctx is null
            ? new Dictionary<string, string>()
            : RaspScope.InputsOf(ctx).GroupBy(i => i.Key).ToDictionary(g => g.Key, g => g.First().Value);
    }

    private static async Task<WebApplication> Serve(Action<WebApplication> map, Action<IServiceCollection>? services = null, bool use = true, Action<WebApplication>? before = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        services?.Invoke(builder.Services);
        var app = builder.Build();
        before?.Invoke(app);
        if (use)
        {
            app.UseShield360Rasp();
        }

        map(app);
        await app.StartAsync();
        return app;
    }

    private static HttpRequestMessage Request(HttpMethod method, string url, Dictionary<string, string>? headers = null, string? body = null, string contentType = "application/json")
    {
        var r = new HttpRequestMessage(method, url);
        foreach (var kv in headers ?? new())
        {
            r.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        }

        if (body is not null)
        {
            r.Content = new StringContent(body, Encoding.UTF8);
            r.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
        }

        return r;
    }

    [Fact]
    public async Task Records_query_cookies_and_the_input_headers_in_the_request_context_only()
    {
        SetMode(RaspMode.Monitor);
        await using var app = await Serve(a => a.MapGet("/items/{id}", () => Results.Json(Keys())));
        var res = await app.GetTestClient().SendAsync(Request(HttpMethod.Get, "/items/42?q=" + Uri.EscapeDataString("hello world"), new()
        {
            ["Cookie"] = "sid=abc123; theme=dark",
            ["User-Agent"] = "test-agent/1",
            ["X-Other"] = "skip",
        }));
        var got = JsonSerializer.Deserialize<Dictionary<string, string>>(await res.Content.ReadAsStringAsync())!;
        Assert.Equal("hello world", got["query.q"]);
        Assert.Equal("abc123", got["cookie.sid"]);
        Assert.Equal("test-agent/1", got["header.user-agent"]);
        Assert.Equal("42", got["params.id"]);
        Assert.False(got.ContainsKey("header.x-other"));
        Assert.Null(RaspScope.Current);
    }

    [Fact]
    public async Task A_virtual_patch_in_block_mode_answers_403_with_the_contract_body_and_monitor_lets_it_through()
    {
        SetMode(RaspMode.Block);
        var ran = 0;
        await using var app = await Serve(a => a.MapGet("/", () =>
        {
            ran++;
            return "ok";
        }));
        var client = app.GetTestClient();
        var blocked = await client.SendAsync(Request(HttpMethod.Get, "/", s_exampleShape.Headers));
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Equal("application/json", blocked.Content.Headers.ContentType!.MediaType);
        Assert.Equal("no-store", blocked.Headers.CacheControl!.ToString());
        var body = JsonNode.Parse(await blocked.Content.ReadAsStringAsync())!;
        Assert.Equal(Shield360RaspBlockedException.BlockMessage, (string?)body["error"]);
        Assert.Equal("virtual_patch", (string?)body["attack"]);
        Assert.Equal(s_example.Id, (string?)body["rule"]);
        Assert.Equal(_sink.Events[0].Attrs["shield360.rasp.event_id"], (string?)body["event"]);
        Assert.Equal("blocked", _sink.Events[0].Attrs["shield360.rasp.decision"]);
        Assert.Equal("aspnetcore", _sink.Events[0].Attrs["shield360.rasp.framework"]);
        Assert.Equal("server.request", _sink.Events[0].Attrs["shield360.rasp.sink"]);
        Assert.Equal(0, ran);

        SetMode(RaspMode.Monitor);
        var passed = await client.SendAsync(Request(HttpMethod.Get, "/", s_exampleShape.Headers));
        Assert.Equal(HttpStatusCode.OK, passed.StatusCode);
        Assert.Equal("monitored", _sink.Events[0].Attrs["shield360.rasp.decision"]);
        Assert.Equal(1, ran);
    }

    [Fact]
    public async Task Records_json_and_form_body_leaves_and_the_endpoint_still_reads_the_body()
    {
        SetMode(RaspMode.Monitor);
        await using var app = await Serve(a => a.MapPost("/orders", async (HttpRequest req) =>
        {
            var keys = Keys();
            using var reader = new System.IO.StreamReader(req.Body);
            keys["raw"] = await reader.ReadToEndAsync();
            return Results.Json(keys);
        }));
        var client = app.GetTestClient();
        var json = """{"user":{"name":"O'Brien"},"tags":["a1","b2"]}""";
        var got = JsonSerializer.Deserialize<Dictionary<string, string>>(await (await client.SendAsync(Request(HttpMethod.Post, "/orders?sort=name", body: json))).Content.ReadAsStringAsync())!;
        Assert.Equal("name", got["query.sort"]);
        Assert.Equal("O'Brien", got["body.user.name"]);
        Assert.Equal("a1", got["body.tags.0"]);
        Assert.Equal(json, got["raw"]);

        var form = await client.SendAsync(Request(HttpMethod.Post, "/orders", body: "name=Ana&city=Lisbon+Centro", contentType: "application/x-www-form-urlencoded"));
        var formKeys = JsonSerializer.Deserialize<Dictionary<string, string>>(await form.Content.ReadAsStringAsync())!;
        Assert.Equal("Lisbon Centro", formKeys["body.city"]);
        Assert.Equal("name=Ana&city=Lisbon+Centro", formKeys["raw"]);
    }

    [Fact]
    public async Task Placed_after_middleware_that_consumed_part_of_the_body_it_leaves_the_stream_where_it_found_it()
    {
        SetMode(RaspMode.Monitor);
        await using var app = await Serve(
            a => a.MapPost("/upload", async (HttpRequest req) =>
            {
                var keys = Keys();
                using var reader = new System.IO.StreamReader(req.Body);
                keys["raw"] = await reader.ReadToEndAsync();
                return Results.Json(keys);
            }),
            before: a => a.Use(async (context, next) =>
            {
                // An earlier middleware buffers the body and reads a five-byte prefix of its own.
                context.Request.EnableBuffering();
                var prefix = new byte[5];
                var read = 0;
                while (read < prefix.Length)
                {
                    var n = await context.Request.Body.ReadAsync(prefix.AsMemory(read));
                    if (n == 0)
                    {
                        break;
                    }

                    read += n;
                }

                await next(context);
            }));
        var res = await app.GetTestClient().SendAsync(Request(HttpMethod.Post, "/upload", body: "HEAD:the rest of the body", contentType: "text/plain"));
        var got = JsonSerializer.Deserialize<Dictionary<string, string>>(await res.Content.ReadAsStringAsync())!;
        Assert.Equal("the rest of the body", got["raw"]);
        Assert.Equal("the rest of the body", got["body"]);
    }

    [Fact]
    public async Task A_body_rule_blocks_before_the_endpoint()
    {
        SetMode(RaspMode.Block);
        RaspEngine.SetRemoteConfig(new RemoteConfig
        {
            Version = "v1",
            Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 600,
            Attacks = new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.VirtualPatch] = RaspMode.Block },
            Rules = new[] { s_bodyRule },
        });
        var ran = false;
        await using var app = await Serve(a => a.MapPost("/action", () =>
        {
            ran = true;
            return "ok";
        }));
        var client = app.GetTestClient();
        var res = await client.SendAsync(Request(HttpMethod.Post, "/action", body: "{\"then\":\"resolved_model\"}"));
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        Assert.Equal("vp.test-body", (string?)JsonNode.Parse(await res.Content.ReadAsStringAsync())!["rule"]);
        Assert.Equal("v1", _sink.Events[0].Attrs["shield360.rasp.config_version"]);
        Assert.False(ran);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Post, "/action", body: "{\"a\":1}"))).StatusCode);
    }

    [Fact]
    public async Task Maps_a_block_from_the_endpoint_to_403_and_lets_other_errors_through()
    {
        SetMode(RaspMode.Block, new() { [RaspAttackType.SqlInjection] = RaspMode.Block });
        await using var app = await Serve(a =>
        {
            a.MapGet("/orders/{id}", (string id) =>
            {
                RaspEngine.Check("db.query", () => RaspDetect.Sql($"SELECT * FROM t WHERE id = {id}", RaspScope.InputsOf(RaspScope.Current!)));
                return "ok";
            });
            a.MapGet("/broken", string () => throw new InvalidOperationException("app error"));
        });
        var client = app.GetTestClient();
        var res = await client.GetAsync("/orders/" + Uri.EscapeDataString("1 OR 1=1"));
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        var body = JsonNode.Parse(await res.Content.ReadAsStringAsync())!;
        Assert.Equal("sql_injection", (string?)body["attack"]);
        Assert.Equal("sqli.userinput", (string?)body["rule"]);
        var a = _sink.Events.Single().Attrs;
        Assert.Equal("/orders/{id}", a["shield360.rasp.route"]);
        Assert.Equal("params.id", a["shield360.rasp.input_key"]);
        Assert.Equal("GET", a["shield360.rasp.method"]);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/orders/42")).StatusCode);
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAsync("/broken"));
    }

    [Fact]
    public async Task Add_shield360_rasp_inserts_the_middleware_and_maps_blocks_behind_use_exception_handler()
    {
        await using var app = await Serve(
            a => a.MapGet("/", string () => throw RaspBlock()),
            services => services.AddShield360Rasp(o => o.Mode = RaspMode.Block, Env.Empty),
            use: false,
            before: a => a.UseExceptionHandler("/error"));
        Assert.True(Shield360Rasp.IsActive);
        var client = app.GetTestClient();

        // The start-up filter put the middleware first: a virtual patch blocks before anything else.
        var blocked = await client.SendAsync(Request(HttpMethod.Get, "/", s_exampleShape.Headers));
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

        // A block from the endpoint reaches UseExceptionHandler first; the registered handler answers 403.
        var fromEndpoint = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.Forbidden, fromEndpoint.StatusCode);
        Assert.Equal("code.eval", (string?)JsonNode.Parse(await fromEndpoint.Content.ReadAsStringAsync())!["rule"]);
    }

    private static Shield360RaspBlockedException RaspBlock()
    {
        Configure(new EngineSettings(true, "a", RaspMode.Block));
        try
        {
            RaspEngine.HandleFinding(new RaspFinding(RaspAttackType.CodeInjection, "code.eval"), "eval");
        }
        catch (Shield360RaspBlockedException e)
        {
            return e;
        }

        throw new InvalidOperationException("expected a block");
    }

    [Fact]
    public async Task Inactive_the_endpoint_runs_with_no_context()
    {
        Configure(new EngineSettings(false, "a"));
        await using var app = await Serve(a => a.MapGet("/", () => Results.Json(new { ctx = RaspScope.Current is null })));
        var res = await app.GetTestClient().SendAsync(Request(HttpMethod.Get, "/?q=x", s_exampleShape.Headers));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.True((bool)JsonNode.Parse(await res.Content.ReadAsStringAsync())!["ctx"]!);
    }

    // ---- model output as input (the IChatClient middleware) ---------------------

    private static IChatClient Chat(ChatResponse response) =>
        new FakeChatClient { Respond = (_, _) => response }.AsBuilder().UseShield360().Build();

    private static ChatResponse WithToolCall() => new(new ChatMessage(ChatRole.Assistant, new List<AIContent>
    {
        new TextContent("first line\nsecond line"),
        new FunctionCallContent("call-1", "run_query", new Dictionary<string, object?> { ["sql"] = "select 1" }),
    }));

    [Fact]
    public async Task Records_completion_fragments_and_tool_call_argument_leaves_inside_a_request()
    {
        Configure(new EngineSettings(true, "a"));
        var ctx = RaspCapture.CaptureRequest(new RequestShape { Framework = "aspnetcore", Method = "POST", Url = "/chat" });
        var got = await RaspScope.Run(ctx, async () =>
        {
            await Chat(WithToolCall()).GetResponseAsync("hi");
            return RaspScope.InputsOf(RaspScope.Current!);
        });
        Assert.Equal(
            new[] { ("model.completion", "first line"), ("model.completion", "second line"), ("model.tool.run_query.sql", "select 1") },
            got.Where(i => i.Source == RaspInputSource.ModelOutput).Select(i => (i.Key, i.Value)));
    }

    [Fact]
    public async Task Outside_a_request_the_answer_is_input_for_the_rest_of_the_callers_flow()
    {
        Configure(new EngineSettings(true, "a"));
        Assert.Null(RaspScope.Current);
        await Chat(new ChatResponse(new ChatMessage(ChatRole.Assistant, "git status; git log"))).GetResponseAsync("hi");
        var inputs = RaspScope.InputsOf(RaspScope.Current!);
        Assert.Equal("git status; git log", Assert.Single(inputs).Value);
        Assert.Equal("cmdi.model_output", RaspDetect.Command("git status; git log", inputs)?.Rule);
    }

    [Fact]
    public async Task Streaming_responses_are_recorded_when_the_stream_ends()
    {
        Configure(new EngineSettings(true, "a"));
        var client = new FakeChatClient
        {
            Updates = new[] { new ChatResponseUpdate(ChatRole.Assistant, "SELECT a "), new ChatResponseUpdate(null, "FROM t") },
        }.AsBuilder().UseShield360().Build();
        var keys = await Shield360Rasp.RunInScope(async () =>
        {
            await foreach (var _ in client.GetStreamingResponseAsync("hi"))
            {
            }

            return RaspScope.InputsOf(RaspScope.Current!).Select(i => i.Value).ToList();
        });
        Assert.Equal(new[] { "SELECT a FROM t" }, keys);
    }

    [Fact]
    public async Task Records_nothing_when_rasp_is_off_or_model_output_is_false()
    {
        Configure(new EngineSettings(true, "a", ModelOutput: false));
        Assert.Empty(await Shield360Rasp.RunInScope(async () =>
        {
            await Chat(WithToolCall()).GetResponseAsync("hi");
            return RaspScope.Current!.InputsSnapshot();
        }));
        Configure(new EngineSettings(false, "a"));
        Assert.Empty(await Shield360Rasp.RunInScope(async () =>
        {
            await Chat(WithToolCall()).GetResponseAsync("hi");
            return RaspScope.Current!.InputsSnapshot();
        }));
    }

    [Fact]
    public void Public_record_helpers_take_json_strings_and_sanitize_tool_names()
    {
        Configure(new EngineSettings(true, "a"));
        var keys = Shield360Rasp.RunInScope(() =>
        {
            Shield360Rasp.RecordToolArguments("{\"url\":\"https://example.com\",\"n\":2}", "fetch page!");
            Shield360Rasp.RecordToolArguments("not json", "t");
            Shield360Rasp.RecordModelOutput("```\nline\n```");
            return RaspScope.Current!.InputsSnapshot().Select(i => i.Key + "=" + i.Value).ToList();
        });
        Assert.Equal(new[] { "model.tool.fetch_page_.url=https://example.com", "model.tool.t=not json", "model.completion=line" }, keys);
    }
}
