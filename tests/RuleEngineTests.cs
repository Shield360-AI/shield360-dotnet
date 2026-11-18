using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Shield360.RuleEngine;
using Xunit;

namespace Shield360.Tests;

public class RuleEngineTests
{
    private const string Key = "s360_live_DO_NOT_LEAK_abc123==";

    private const string Matched = """
        {"matchingRuleIds":["r1","r2"],
         "entities":[{"rule_id":"r1","entity_type":"context","entity_id":"c1"}],
         "entity_data":{"context:c1":{"content":"Be nice"}}}
        """;

    private static RuleEngineClient Client(FakeHandler handler, Func<string, string?>? env = null) =>
        new(new HttpClient(handler), ownsHttpClient: true, env ?? Env.Empty);

    private static EvaluateRuleOptions Options(string? url = "https://app.shield360.ai", string? key = Key) => new()
    {
        Url = url,
        ApiKey = key,
        EntityType = RuleEntityType.Prompt,
        Fields = new Dictionary<string, object?>
        {
            ["gen_ai.system"] = "openai",
            ["gen_ai.request.model"] = "gpt-4o",
            ["gen_ai.request.temperature"] = 0.5,
            ["gen_ai.request.is_stream"] = true,
            ["gen_ai.request.max_tokens"] = 100,
        },
        IncludeEntityData = true,
        EntityInputs = new Dictionary<string, object?> { ["name"] = "Ada" },
    };

    [Fact]
    public async Task Sends_the_same_request_as_the_Go_SDK_and_reads_the_result()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, Matched);
        using var client = Client(handler);

        var result = await client.EvaluateRuleAsync(Options("https://app.shield360.ai/"));

        var (request, body) = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(new Uri("https://app.shield360.ai/api/rule-engine/evaluate"), request.RequestUri);
        Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        Assert.Equal(Key, request.Headers.Authorization.Parameter);
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);

        using var json = JsonDocument.Parse(body!);
        var root = json.RootElement;
        Assert.Equal("prompt", root.GetProperty("entity_type").GetString());
        Assert.Equal("dotnet-sdk", root.GetProperty("source").GetString());
        Assert.True(root.GetProperty("include_entity_data").GetBoolean());
        Assert.Equal("openai", root.GetProperty("fields").GetProperty("gen_ai.system").GetString());
        Assert.Equal(0.5, root.GetProperty("fields").GetProperty("gen_ai.request.temperature").GetDouble());
        Assert.True(root.GetProperty("fields").GetProperty("gen_ai.request.is_stream").GetBoolean());
        Assert.Equal(100, root.GetProperty("fields").GetProperty("gen_ai.request.max_tokens").GetInt32());
        Assert.Equal("Ada", root.GetProperty("entity_inputs").GetProperty("name").GetString());

        Assert.Equal(new[] { "r1", "r2" }, result.MatchingRuleIds);
        var entity = Assert.Single(result.Entities);
        Assert.Equal("r1", entity.RuleId);
        Assert.Equal("context", entity.EntityType);
        Assert.Equal("c1", entity.EntityId);
        Assert.Equal("Be nice", result.EntityData!.Value.GetProperty("context:c1").GetProperty("content").GetString());
    }

    [Fact]
    public async Task Falls_back_to_environment_variables()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, """{"matchingRuleIds":[],"entities":[]}""");
        using var client = Client(handler, Env.Of(("SHIELD360_URL", "http://localhost:3000"), ("SHIELD360_API_KEY", Key)));

        var result = await client.EvaluateRuleAsync(Options(url: null, key: null));

        Assert.Empty(result.MatchingRuleIds);
        var (request, _) = Assert.Single(handler.Requests);
        Assert.Equal(new Uri("http://localhost:3000/api/rule-engine/evaluate"), request.RequestUri);
        Assert.Equal(Key, request.Headers.Authorization!.Parameter);
    }

    [Fact]
    public async Task Defaults_to_the_local_dashboard()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, """{"matchingRuleIds":[],"entities":[]}""");
        using var client = Client(handler);

        await client.EvaluateRuleAsync(Options(url: null));

        Assert.Equal(new Uri("http://127.0.0.1:3000/api/rule-engine/evaluate"), handler.Requests[0].Request.RequestUri);
    }

    [Fact]
    public async Task A_missing_api_key_is_reported_without_sending_anything()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, Matched);
        using var client = Client(handler);

        var e = await Assert.ThrowsAsync<Shield360Exception>(() => client.EvaluateRuleAsync(Options(key: null)));

        Assert.Contains("SHIELD360_API_KEY", e.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Refuses_plain_http_to_another_host()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, Matched);
        using var client = Client(handler);

        var e = await Assert.ThrowsAsync<Shield360Exception>(() => client.EvaluateRuleAsync(Options("http://app.shield360.ai")));

        Assert.Contains("https", e.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Key, e.ToString(), StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Empty_fields_are_rejected()
    {
        using var client = Client(new FakeHandler(HttpStatusCode.OK, Matched));
        var options = Options();
        options.Fields = new Dictionary<string, object?>();

        await Assert.ThrowsAsync<Shield360Exception>(() => client.EvaluateRuleAsync(options));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task Error_statuses_are_reported_without_the_key(HttpStatusCode status)
    {
        // A server that echoes the Authorization header back must not get it into the error.
        var handler = new FakeHandler(req => new HttpResponseMessage(status)
        {
            Content = new StringContent($$"""{"err":"bad key {{req.Headers.Authorization}}"}"""),
        });
        using var client = Client(handler);

        var e = await Assert.ThrowsAsync<Shield360Exception>(() => client.EvaluateRuleAsync(Options()));

        Assert.Equal((int)status, e.StatusCode);
        Assert.Contains(((int)status).ToString(System.Globalization.CultureInfo.InvariantCulture), e.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Key, e.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Transport_failures_and_bad_json_are_reported_without_the_key()
    {
        var failing = new FakeHandler(_ => throw new HttpRequestException("connection refused"));
        using (var client = Client(failing))
        {
            var e = await Assert.ThrowsAsync<Shield360Exception>(() => client.EvaluateRuleAsync(Options()));
            Assert.IsType<HttpRequestException>(e.InnerException);
            Assert.DoesNotContain(Key, e.ToString(), StringComparison.Ordinal);
        }

        using (var client = Client(new FakeHandler(HttpStatusCode.OK, "<html>not json</html>")))
        {
            var e = await Assert.ThrowsAsync<Shield360Exception>(() => client.EvaluateRuleAsync(Options()));
            Assert.DoesNotContain(Key, e.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Times_out()
    {
        var slow = new SlowHandler();
        using var client = new RuleEngineClient(new HttpClient(slow), ownsHttpClient: true, Env.Empty);
        var options = Options();
        options.Timeout = TimeSpan.FromMilliseconds(50);

        var e = await Assert.ThrowsAsync<Shield360Exception>(() => client.EvaluateRuleAsync(options));
        Assert.Contains("timed out", e.Message, StringComparison.Ordinal);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.EvaluateRuleAsync(Options(), cts.Token));
    }

    [Fact]
    public async Task Nothing_the_client_writes_to_trace_output_contains_the_key()
    {
        using var writer = new StringWriter();
        using var listener = new TextWriterTraceListener(writer);
        Trace.Listeners.Add(listener);
        try
        {
            using var client = Client(new FakeHandler(HttpStatusCode.Unauthorized, "{}"));
            await Assert.ThrowsAsync<Shield360Exception>(() => client.EvaluateRuleAsync(Options()));
            using var ok = Client(new FakeHandler(HttpStatusCode.OK, Matched));
            await ok.EvaluateRuleAsync(Options());
        }
        finally
        {
            Trace.Listeners.Remove(listener);
        }

        listener.Flush();
        Assert.DoesNotContain(Key, writer.ToString(), StringComparison.Ordinal);
    }

    private sealed class SlowHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}
