using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Shield360.Flags;
using Xunit;

namespace Shield360.Tests;

public class FlagsClientTests
{
    private const string Key = "s360_live_DO_NOT_LEAK_flags==";
    private const string Url = "https://app.shield360.ai";

    private const string Feed = """
        {"version":"v1","flags":[
          {"key":"new-checkout","type":"boolean","salt":"s1","on":true,"offVariation":"off",
           "variations":[{"key":"on","value":true},{"key":"off","value":false}],
           "rules":[{"id":"beta","conditions":[{"attribute":"segment","operator":"in_segment","values":["beta-users"]}],"serve":{"variation":"on"}}],
           "fallthrough":{"variation":"off"}},
          {"key":"model-choice","type":"string","salt":"s1","on":true,"offVariation":"mini",
           "variations":[{"key":"mini","value":"openai/gpt-4o-mini"},{"key":"big","value":"anthropic/claude-sonnet"}],
           "rules":[{"id":"pro","conditions":[{"attribute":"plan","operator":"equals","values":["pro"]}],"serve":{"variation":"big"}}],
           "fallthrough":{"variation":"mini"}},
          {"key":"max-tokens","type":"number","salt":"s1","on":true,"offVariation":"low",
           "variations":[{"key":"low","value":256},{"key":"high","value":4096}],"rules":[],"fallthrough":{"variation":"high"}},
          {"key":"settings","type":"json","salt":"s1","on":true,"offVariation":"a",
           "variations":[{"key":"a","value":{"temperature":0.2}},{"key":"b","value":[1,2]}],"rules":[],"fallthrough":{"variation":"a"}},
          {"key":"chat-enabled","type":"boolean","salt":"s1","on":true,"offVariation":"off",
           "variations":[{"key":"on","value":true},{"key":"off","value":false}],
           "rules":[{"id":"stop","conditions":[{"attribute":"region","operator":"equals","values":["eu"]}],"serve":{"variation":"off"}}],
           "fallthrough":{"variation":"on"}},
          {"key":"billing-only","type":"boolean","salt":"s1","on":true,"offVariation":"off","appName":"billing-api",
           "variations":[{"key":"on","value":true},{"key":"off","value":false}],"rules":[],"fallthrough":{"variation":"on"}},
          {"key":"support-prompt","type":"json","salt":"s1","on":true,"offVariation":"v1",
           "variations":[{"key":"v1","value":{"name":"support","version":"2"}},{"key":"v2","value":"support-short@3"}],
           "rules":[{"id":"short","conditions":[{"attribute":"plan","operator":"equals","values":["free"]}],"serve":{"variation":"v2"}}],
           "fallthrough":{"variation":"v1"}},
          {"key":"empty-prompt","type":"string","salt":"s1","on":true,"offVariation":"a",
           "variations":[{"key":"a","value":""},{"key":"b","value":"x"}],"rules":[],"fallthrough":{"variation":"a"}},
          {"key":"broken","type":"boolean","salt":"s1","on":true,"offVariation":"nope",
           "variations":[{"key":"on","value":true},{"key":"off","value":false}],"rules":[],"fallthrough":{"variation":"on"}}
        ],
        "segments":[
          {"key":"beta-users","conditions":[{"attribute":"groups","operator":"in","values":["beta"]}]},
          {"key":"bad","conditions":[]}
        ]}
        """;

    private static HttpResponseMessage Json(string body, string? etag = "\"v1\"")
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (etag is not null)
        {
            response.Headers.TryAddWithoutValidation("ETag", etag);
        }

        return response;
    }

    private static FlagsClient Client(FakeHandler handler, string? app = "checkout-api", bool record = true) =>
        new(new FlagsOptions
        {
            Url = Url + "/",
            ApiKey = Key,
            ApplicationName = app,
            HttpHandler = handler,
            PollInterval = TimeSpan.FromMinutes(10),
            RecordOnActivity = record,
        }, Env.Empty);

    private static async Task<FlagsClient> Ready(FakeHandler handler, string? app = "checkout-api")
    {
        var client = Client(handler, app);
        Assert.True(await client.WaitUntilReadyAsync(TimeSpan.FromSeconds(10)));
        return client;
    }

    private static Dictionary<string, object?> Ctx(params (string Key, object? Value)[] pairs) =>
        pairs.ToDictionary(p => p.Key, p => p.Value);

    [Fact]
    public async Task Fetches_the_rules_with_the_key_and_then_revalidates_with_the_etag()
    {
        var calls = 0;
        var handler = new FakeHandler(_ => ++calls == 1 ? Json(Feed) : new HttpResponseMessage(HttpStatusCode.NotModified));
        using var client = await Ready(handler);

        Assert.True(await client.RefreshAsync());
        Assert.True(client.IsEnabled("new-checkout", Ctx(("groups", new[] { "beta" }))));

        Assert.Equal(2, handler.Requests.Count);
        var (first, _) = handler.Requests[0];
        Assert.Equal(HttpMethod.Get, first.Method);
        Assert.Equal(new Uri(Url + "/api/flags/rules"), first.RequestUri);
        Assert.Equal("Bearer", first.Headers.Authorization!.Scheme);
        Assert.Equal(Key, first.Headers.Authorization.Parameter);
        Assert.Contains("application/json", first.Headers.Accept.Select(a => a.MediaType));
        Assert.False(first.Headers.Contains("If-None-Match"));
        Assert.Equal("\"v1\"", handler.Requests[1].Request.Headers.GetValues("If-None-Match").Single());
    }

    [Fact]
    public async Task Serves_defaults_until_rules_arrive()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var client = Client(handler);

        var detail = client.GetFlagDetail("new-checkout", null, JsonValue.Create(true));
        Assert.Equal(FlagReasonKinds.NotReady, detail.Reason.Kind);
        Assert.Null(detail.Variation);
        Assert.True(detail.Value!.GetValue<bool>());
        Assert.False(await client.WaitUntilReadyAsync(TimeSpan.FromMilliseconds(200)));
        Assert.False(client.IsEnabled("new-checkout"));
        Assert.Equal("fallback", client.Model("model-choice", null, "fallback"));
        Assert.False(client.KillSwitch("chat-enabled"));
    }

    [Fact]
    public async Task Without_a_destination_every_flag_serves_its_default()
    {
        using var client = new FlagsClient(new FlagsOptions { HttpHandler = new FakeHandler(_ => Json(Feed)) }, Env.Empty);
        Assert.False(await client.RefreshAsync());
        Assert.Equal(FlagReasonKinds.NotReady, client.GetFlagDetail("new-checkout").Reason.Kind);
    }

    [Fact]
    public async Task Refuses_to_send_the_key_over_plain_http_to_another_host()
    {
        var handler = new FakeHandler(_ => Json(Feed));
        using var client = new FlagsClient(new FlagsOptions { Url = "http://flags.example.com", ApiKey = Key, HttpHandler = handler }, Env.Empty);
        Assert.False(await client.RefreshAsync());
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Reads_the_destination_from_the_environment()
    {
        var handler = new FakeHandler(_ => Json(Feed));
        using var client = new FlagsClient(
            new FlagsOptions { HttpHandler = handler },
            Env.Of(("SHIELD360_URL", "http://localhost:3000/"), ("SHIELD360_API_KEY", Key)));
        Assert.True(await client.RefreshAsync());
        Assert.Equal(new Uri("http://localhost:3000/api/flags/rules"), handler.Requests.Single().Request.RequestUri);
    }

    [Fact]
    public async Task Reads_the_destination_from_the_initialised_sdk()
    {
        var handler = new FakeHandler(_ => Json(Feed));
        using var runtime = new ActiveRuntime(new Shield360Options { Shield360Url = "https://sdk.example.com", ApiKey = Key, ApplicationName = "billing-api" });
        using var client = new FlagsClient(new FlagsOptions { HttpHandler = handler }, Env.Empty);
        Assert.True(await client.RefreshAsync());
        Assert.Equal(new Uri("https://sdk.example.com/api/flags/rules"), handler.Requests.Single().Request.RequestUri);
        Assert.True(client.IsEnabled("billing-only"));
    }

    [Fact]
    public async Task Evaluates_each_kind_of_flag()
    {
        using var client = await Ready(new FakeHandler(_ => Json(Feed)));

        Assert.Equal("anthropic/claude-sonnet", client.GetString("model-choice", Ctx(("plan", "pro")), "x"));
        Assert.Equal(4096d, client.GetNumber("max-tokens", null, 1));
        Assert.Equal(0.2, client.GetJson("settings", null, new JsonObject())!["temperature"]!.GetValue<double>());

        var detail = client.GetFlagDetail("model-choice", Ctx(("plan", "pro")), "x");
        Assert.Equal("big", detail.Variation);
        Assert.Equal(FlagReasonKinds.RuleMatch, detail.Reason.Kind);
        Assert.Equal(0, detail.Reason.RuleIndex);
        Assert.Equal("pro", detail.Reason.RuleId);
    }

    [Fact]
    public async Task Uses_the_segments_in_the_feed_and_drops_invalid_ones()
    {
        using var client = await Ready(new FakeHandler(_ => Json(Feed)));
        Assert.True(client.IsEnabled("new-checkout", Ctx(("groups", new[] { "staff", "beta" }))));
        Assert.False(client.IsEnabled("new-checkout", Ctx(("groups", "staff"))));
        Assert.False(client.IsEnabled("new-checkout"));
    }

    [Fact]
    public async Task Unknown_malformed_and_other_apps_flags_serve_the_default()
    {
        using var client = await Ready(new FakeHandler(_ => Json(Feed)));

        Assert.Equal(FlagReasonKinds.FlagNotFound, client.GetFlagDetail("nope", null, true).Reason.Kind);
        // A flag that fails validation is dropped from the feed.
        Assert.Equal(FlagReasonKinds.FlagNotFound, client.GetFlagDetail("broken", null, false).Reason.Kind);
        Assert.Equal(FlagReasonKinds.FlagNotFound, client.GetFlagDetail("billing-only", null, false).Reason.Kind);
        Assert.False(client.IsEnabled("billing-only"));

        using var billing = await Ready(new FakeHandler(_ => Json(Feed)), app: "billing-api");
        Assert.True(billing.IsEnabled("billing-only"));
    }

    [Fact]
    public async Task A_value_of_another_kind_than_the_default_is_WRONG_TYPE()
    {
        using var client = await Ready(new FakeHandler(_ => Json(Feed)));

        var detail = client.GetFlagDetail("model-choice", null, JsonValue.Create(5));
        Assert.Equal(FlagReasonKinds.WrongType, detail.Reason.Kind);
        Assert.Null(detail.Variation);
        Assert.Equal(5, detail.Value!.GetValue<int>());
        Assert.Equal(7d, client.GetNumber("model-choice", null, 7));
        Assert.True(client.GetBool("model-choice", null, true));
        Assert.Equal("d", client.GetString("max-tokens", null, "d"));
        Assert.Equal(FlagReasonKinds.WrongType, client.GetFlagDetail("settings", null, "x").Reason.Kind);
        // An object default takes an array value, as in JavaScript.
        Assert.NotNull(client.GetJson("settings", null, new JsonArray()));
        // A null default takes anything.
        Assert.Equal("openai/gpt-4o-mini", client.GetFlagDetail("model-choice").Value!.GetValue<string>());
    }

    [Fact]
    public async Task Stamps_the_served_variation_on_the_current_activity()
    {
        using var client = await Ready(new FakeHandler(_ => Json(Feed)));
        using var capture = new TelemetryCapture("Shield360.Tests.Flags");
        using var source = new ActivitySource("Shield360.Tests.Flags");

        using (var activity = source.StartActivity("request"))
        {
            Assert.NotNull(activity);
            client.GetString("model-choice", Ctx(("plan", "pro")), "x");
            client.GetFlagDetail("nope", null, true);
            client.GetFlagDetail("model-choice", null, 1);
        }

        var span = capture.Single();
        Assert.Equal("big", span.GetTagItem("shield360.flag.model-choice"));
        Assert.Null(span.GetTagItem("shield360.flag.nope"));
    }

    [Fact]
    public async Task Does_not_stamp_when_told_not_to()
    {
        var handler = new FakeHandler(_ => Json(Feed));
        using var client = Client(handler, record: false);
        Assert.True(await client.WaitUntilReadyAsync(TimeSpan.FromSeconds(10)));
        using var capture = new TelemetryCapture("Shield360.Tests.Flags");
        using var source = new ActivitySource("Shield360.Tests.Flags");
        using (source.StartActivity("request"))
        {
            client.GetString("model-choice", null, "x");
        }

        Assert.Null(capture.Single().GetTagItem("shield360.flag.model-choice"));
    }

    [Fact]
    public async Task Model_and_kill_switch_helpers()
    {
        using var client = await Ready(new FakeHandler(_ => Json(Feed)));

        Assert.Equal("openai/gpt-4o-mini", client.Model("model-choice", null, "fallback"));
        Assert.Equal("fallback", client.Model("empty-prompt", null, "fallback"));
        Assert.Equal("fallback", client.Model("unknown", null, "fallback"));
        Assert.False(client.KillSwitch("chat-enabled", Ctx(("region", "us"))));
        Assert.True(client.KillSwitch("chat-enabled", Ctx(("region", "eu"))));
        Assert.False(client.KillSwitch("unknown"));
    }

    [Theory]
    [InlineData("\"support\"", "support", null)]
    [InlineData("\"support@3\"", "support", "3")]
    [InlineData("{\"name\":\"support\",\"version\":\"1.2\"}", "support", "1.2")]
    [InlineData("{\"name\":\"support\",\"version\":2}", "support", "2")]
    [InlineData("{\"name\":\"support\"}", "support", null)]
    public void Reads_prompt_references(string json, string name, string? version)
    {
        Assert.True(PromptRef.TryParse(JsonNode.Parse(json), out var reference));
        Assert.Equal(name, reference!.Name);
        Assert.Equal(version, reference.Version);
    }

    [Theory]
    [InlineData("\"\"")]
    [InlineData("\"@3\"")]
    [InlineData("{\"version\":\"1\"}")]
    [InlineData("{\"name\":5}")]
    [InlineData("{\"name\":\"x\",\"version\":{}}")]
    [InlineData("true")]
    [InlineData("[\"x\"]")]
    public void Rejects_unusable_prompt_references(string json) =>
        Assert.False(PromptRef.TryParse(JsonNode.Parse(json), out _));

    [Fact]
    public async Task Fetches_the_prompt_the_flag_picks()
    {
        var handler = new FakeHandler(r => r.Method == HttpMethod.Get
            ? Json(Feed)
            : Json("""{"err":null,"res":{"name":"support-short","version":"3","prompt":"Be brief, {{name}}."}}""", null));
        using var client = await Ready(handler);

        var result = await client.PromptAsync(
            "support-prompt",
            Ctx(("plan", "free")),
            new PromptRef("default-prompt"),
            new PromptOptions { Variables = new Dictionary<string, object?> { ["name"] = "Ada" } });

        Assert.Null(result.Error);
        Assert.Equal("support-short", result.Name);
        Assert.Equal("3", result.Version);
        Assert.Equal("v2", result.Variation);
        Assert.Equal("Be brief, {{name}}.", result.Prompt!["prompt"]!.GetValue<string>());

        var (request, body) = handler.Requests.Last();
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(new Uri(Url + "/api/prompt/get-compiled"), request.RequestUri);
        Assert.Equal(Key, request.Headers.Authorization!.Parameter);
        var payload = JsonNode.Parse(body!)!;
        Assert.Equal("support-short", payload["name"]!.GetValue<string>());
        Assert.Equal("3", payload["version"]!.GetValue<string>());
        Assert.True(payload["shouldCompile"]!.GetValue<bool>());
        Assert.Equal("Ada", payload["variables"]!["name"]!.GetValue<string>());
        Assert.Equal("dotnet-sdk", payload["source"]!.GetValue<string>());
        Assert.Equal("checkout-api", payload["metaProperties"]!["applicationName"]!.GetValue<string>());
    }

    [Fact]
    public async Task Uses_the_default_prompt_when_the_flag_gives_nothing_usable()
    {
        var handler = new FakeHandler(r => r.Method == HttpMethod.Get ? Json(Feed) : Json("""{"err":null,"res":{"prompt":"hi"}}""", null));
        using var client = await Ready(handler);

        var result = await client.PromptAsync("empty-prompt", null, new PromptRef("default-prompt", "1"));
        Assert.Null(result.Error);
        Assert.Equal("default-prompt", result.Name);
        Assert.Equal("1", result.Version);
        Assert.Null(result.Variation);
        var payload = JsonNode.Parse(handler.Requests.Last().Body!)!;
        Assert.Equal("default-prompt", payload["name"]!.GetValue<string>());
        Assert.False(payload["shouldCompile"]!.GetValue<bool>());

        var structured = await client.PromptAsync("support-prompt", null, new PromptRef("default-prompt"));
        Assert.Equal("support", structured.Name);
        Assert.Equal("2", structured.Version);
        Assert.Equal("v1", structured.Variation);
    }

    [Theory]
    [InlineData(HttpStatusCode.OK, """{"err":"Prompt not found","res":null}""", "Prompt not found")]
    [InlineData(HttpStatusCode.Forbidden, """{"err":"no"}""", "The Prompt Hub returned status 403.")]
    [InlineData(HttpStatusCode.OK, "not json", "The prompt request failed (")]
    [InlineData(HttpStatusCode.OK, "[1]", "The Prompt Hub response could not be read.")]
    [InlineData(HttpStatusCode.OK, """{"err":null}""", "The Prompt Hub returned no prompt.")]
    public async Task Prompt_failures_are_reported_not_thrown(HttpStatusCode status, string body, string error)
    {
        var handler = new FakeHandler(r => r.Method == HttpMethod.Get
            ? Json(Feed)
            : new HttpResponseMessage(status) { Content = new StringContent(body) });
        using var client = await Ready(handler);

        var result = await client.PromptAsync("support-prompt", null, new PromptRef("default-prompt"));
        Assert.Null(result.Prompt);
        Assert.StartsWith(error, result.Error, StringComparison.Ordinal);
        Assert.DoesNotContain(Key, result.Error!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_failing_transport_never_throws()
    {
        var handler = new FakeHandler(_ => throw new HttpRequestException("boom " + Key));
        using var client = Client(handler);
        Assert.False(await client.RefreshAsync());
        Assert.False(client.IsEnabled("new-checkout"));
        var result = await client.PromptAsync("support-prompt", null, new PromptRef("p"));
        Assert.Equal("The prompt request failed (HttpRequestException).", result.Error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{\"flags\":{}}")]
    [InlineData("{\"flags\":[1,null,\"x\",{\"key\":\"a\"}],\"segments\":\"nope\"}")]
    [InlineData("{\"flags\":[],\"segments\":[1,{}]}")]
    public async Task Garbage_bodies_never_throw(string body)
    {
        using var client = Client(new FakeHandler(_ => Json(body)));
        await client.RefreshAsync();
        var detail = client.GetFlagDetail("new-checkout", null, true);
        Assert.True(detail.Value!.GetValue<bool>());
        Assert.Null(detail.Variation);
        Assert.Null(await Record.ExceptionAsync(() => client.PromptAsync("x", null, new PromptRef("p"))));
    }

    [Fact]
    public async Task A_bad_refresh_keeps_the_rules_already_fetched()
    {
        var calls = 0;
        using var client = await Ready(new FakeHandler(_ => ++calls == 1 ? Json(Feed) : Json("garbage")));
        Assert.False(await client.RefreshAsync());
        Assert.Equal("openai/gpt-4o-mini", client.GetString("model-choice", null, "x"));
    }

    [Fact]
    public async Task Close_and_dispose_stop_polling_but_keep_serving()
    {
        var handler = new FakeHandler(_ => Json(Feed));
        var client = await Ready(handler);
        client.Close();
        Assert.Equal("openai/gpt-4o-mini", client.GetString("model-choice", null, "x"));
        client.Dispose();
        client.Dispose();
        Assert.Equal("openai/gpt-4o-mini", client.GetString("model-choice", null, "x"));
        Assert.False(await client.RefreshAsync());
    }

    [Fact]
    public void The_sdk_has_a_default_client()
    {
        Assert.Same(Shield360Sdk.Flags, Shield360Sdk.Flags);
    }
}
