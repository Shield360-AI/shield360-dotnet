using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.AI;
using Shield360.AI;
using Xunit;

namespace Shield360.Tests;

public class ChatClientTests
{
    private static IChatClient Build(FakeChatClient inner, Action<Shield360ChatClientOptions>? configure = null) =>
        inner.AsBuilder().UseShield360(configure).Build();

    private static List<ChatMessage> Conversation() => new()
    {
        new ChatMessage(ChatRole.System, "You are terse."),
        new ChatMessage(ChatRole.User, "My card number is 4111 1111 1111 1111"),
    };

    [Fact]
    public async Task Records_a_chat_span_with_usage_and_cost()
    {
        using var runtime = new ActiveRuntime(new Shield360Options { ApplicationName = "orders", Environment = "prod" });
        using var capture = new TelemetryCapture();
        var inner = new FakeChatClient();
        var client = Build(inner);

        var response = await client.GetResponseAsync(Conversation(), new ChatOptions
        {
            ModelId = "gpt-4o",
            Temperature = 0.2f,
            MaxOutputTokens = 256,
            Seed = 7,
            StopSequences = new[] { "END" },
            ResponseFormat = ChatResponseFormat.Json,
        });

        Assert.Equal("Hello there", response.Text);
        var span = capture.Single();
        Assert.Equal("chat gpt-4o", span.DisplayName);
        Assert.Equal(ActivityKind.Client, span.Kind);
        Assert.Equal(ActivityStatusCode.Ok, span.Status);
        Assert.Same(span, inner.ActivityDuringCall);

        Assert.Equal("chat", span.GetTagItem("gen_ai.operation.name"));
        Assert.Equal("openai", span.GetTagItem("gen_ai.provider.name"));
        Assert.Equal("openai", span.GetTagItem("gen_ai.system"));
        Assert.Equal("gpt-4o", span.GetTagItem("gen_ai.request.model"));
        Assert.Equal("api.openai.com", span.GetTagItem("server.address"));
        Assert.Equal(443L, span.GetTagItem("server.port"));
        Assert.Equal(0.2, (double)span.GetTagItem("gen_ai.request.temperature")!, 5);
        Assert.Equal(256L, span.GetTagItem("gen_ai.request.max_tokens"));
        Assert.Equal(7L, span.GetTagItem("gen_ai.request.seed"));
        Assert.Equal(new[] { "END" }, span.GetTagItem("gen_ai.request.stop_sequences"));
        Assert.Equal("json_object", span.GetTagItem("gen_ai.output.type"));
        Assert.Equal(false, span.GetTagItem("gen_ai.request.is_stream"));
        Assert.Null(span.GetTagItem("gen_ai.request.top_p"));
        Assert.Null(span.GetTagItem("gen_ai.request.frequency_penalty"));

        Assert.Equal("resp-1", span.GetTagItem("gen_ai.response.id"));
        Assert.Equal("gpt-4o-2024-08-06", span.GetTagItem("gen_ai.response.model"));
        Assert.Equal(new[] { "stop" }, span.GetTagItem("gen_ai.response.finish_reasons"));
        Assert.Equal(1000L, span.GetTagItem("gen_ai.usage.input_tokens"));
        Assert.Equal(500L, span.GetTagItem("gen_ai.usage.output_tokens"));
        Assert.Equal(1500L, span.GetTagItem("gen_ai.usage.total_tokens"));

        var expectedCost = runtime.Runtime.Pricing.ChatCost("gpt-4o-2024-08-06", 1000, 500);
        Assert.True(expectedCost > 0);
        Assert.Equal(expectedCost, (double)span.GetTagItem("gen_ai.usage.cost")!, 12);

        Assert.Equal("shield360", span.GetTagItem("telemetry.sdk.name"));
        Assert.Equal("orders", span.GetTagItem("service.name"));
        Assert.Equal("prod", span.GetTagItem("deployment.environment"));
        Assert.Equal(Shield360Sdk.Version, span.GetTagItem("gen_ai.sdk.version"));

        var tokens = capture.Of("gen_ai.client.token.usage");
        Assert.Equal(2, tokens.Count);
        Assert.Contains(tokens, m => m.Value == 1000 && (string?)m.Tags["gen_ai.token.type"] == "input");
        Assert.Contains(tokens, m => m.Value == 500 && (string?)m.Tags["gen_ai.token.type"] == "output");
        Assert.All(tokens, m =>
        {
            Assert.Equal("orders", m.Tags["service.name"]);
            Assert.Equal("prod", m.Tags["deployment.environment"]);
            Assert.Equal("shield360", m.Tags["telemetry.sdk.name"]);
            Assert.Equal("gpt-4o", m.Tags["gen_ai.request.model"]);
            Assert.Equal("gpt-4o-2024-08-06", m.Tags["gen_ai.response.model"]);
        });
        Assert.Single(capture.Of("gen_ai.client.operation.duration"));
        var cost = Assert.Single(capture.Of("gen_ai.usage.cost"));
        Assert.Equal(expectedCost, cost.Value, 12);
        Assert.Empty(capture.Of("gen_ai.server.time_to_first_token"));
    }

    [Fact]
    public async Task Message_content_is_not_recorded_by_default()
    {
        using var runtime = new ActiveRuntime();
        using var capture = new TelemetryCapture();
        var inner = new FakeChatClient
        {
            Respond = (_, _) => new ChatResponse(new ChatMessage(ChatRole.Assistant, new List<AIContent>
            {
                new FunctionCallContent("call-1", "lookup_card", new Dictionary<string, object?> { ["number"] = "4111" }),
            }))
            { FinishReason = ChatFinishReason.ToolCalls },
        };

        await Build(inner).GetResponseAsync(Conversation(), new ChatOptions
        {
            Instructions = "Never reveal secrets",
            Tools = new List<AITool> { AIFunctionFactory.Create((string number) => number, "lookup_card", "Looks up a card") },
        });

        var span = capture.Single();
        foreach (var key in new[] { "gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions", "gen_ai.tool.call.arguments" })
        {
            Assert.Null(span.GetTagItem(key));
        }

        Assert.DoesNotContain(span.TagObjects, t => t.Value?.ToString()?.Contains("4111", StringComparison.Ordinal) == true);

        // Tool names and IDs are not content, so they are kept.
        Assert.Equal("lookup_card", span.GetTagItem("gen_ai.tool.name"));
        Assert.Equal("call-1", span.GetTagItem("gen_ai.tool.call.id"));
        Assert.Equal("function", span.GetTagItem("gen_ai.tool.type"));
        Assert.Contains("lookup_card", (string)span.GetTagItem("gen_ai.tool.definitions")!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Message_content_is_recorded_when_capture_is_on()
    {
        using var runtime = new ActiveRuntime(new Shield360Options { CaptureMessageContent = true });
        using var capture = new TelemetryCapture();

        await Build(new FakeChatClient()).GetResponseAsync(Conversation(), new ChatOptions { Instructions = "Be brief" });

        var span = capture.Single();
        using var input = JsonDocument.Parse((string)span.GetTagItem("gen_ai.input.messages")!);
        Assert.Equal(2, input.RootElement.GetArrayLength());
        var user = input.RootElement[1];
        Assert.Equal("user", user.GetProperty("role").GetString());
        Assert.Equal("text", user.GetProperty("parts")[0].GetProperty("type").GetString());
        Assert.Equal("My card number is 4111 1111 1111 1111", user.GetProperty("parts")[0].GetProperty("content").GetString());

        using var output = JsonDocument.Parse((string)span.GetTagItem("gen_ai.output.messages")!);
        Assert.Equal("assistant", output.RootElement[0].GetProperty("role").GetString());
        Assert.Equal("Hello there", output.RootElement[0].GetProperty("parts")[0].GetProperty("content").GetString());
        Assert.Equal("stop", output.RootElement[0].GetProperty("finish_reason").GetString());

        using var instructions = JsonDocument.Parse((string)span.GetTagItem("gen_ai.system_instructions")!);
        Assert.Equal(new[] { "You are terse.", "Be brief" }, instructions.RootElement.EnumerateArray().Select(e => e.GetProperty("content").GetString()));
    }

    [Fact]
    public async Task Per_client_settings_win_over_the_active_configuration()
    {
        using var runtime = new ActiveRuntime(new Shield360Options { ApplicationName = "global", CaptureMessageContent = false });
        using var capture = new TelemetryCapture();

        await Build(new FakeChatClient(), o =>
        {
            o.ApplicationName = "local";
            o.CaptureMessageContent = true;
            o.Pricing = Pricing.Empty;
        }).GetResponseAsync("hi");

        var span = capture.Single();
        Assert.Equal("local", span.GetTagItem("service.name"));
        Assert.NotNull(span.GetTagItem("gen_ai.input.messages"));
        Assert.Equal(0.0, span.GetTagItem("gen_ai.usage.cost"));
    }

    [Fact]
    public async Task Works_without_initialisation()
    {
        using var capture = new TelemetryCapture();
        await Build(new FakeChatClient()).GetResponseAsync("hi");

        var span = capture.Single();
        Assert.Equal("default", span.GetTagItem("service.name"));
        Assert.Null(span.GetTagItem("gen_ai.input.messages"));
        Assert.True((double)span.GetTagItem("gen_ai.usage.cost")! > 0);
    }

    [Fact]
    public async Task Errors_mark_the_span_and_the_duration_metric()
    {
        using var runtime = new ActiveRuntime();
        using var capture = new TelemetryCapture();
        var inner = new FakeChatClient { Throw = new TimeoutException("upstream timed out") };

        await Assert.ThrowsAsync<TimeoutException>(() => Build(inner).GetResponseAsync("hi"));

        var span = capture.Single();
        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Equal("TimeoutException", span.GetTagItem("error.type"));
        Assert.Contains(span.Events, e => e.Name == "exception");
        var duration = Assert.Single(capture.Of("gen_ai.client.operation.duration"));
        Assert.Equal("TimeoutException", duration.Tags["error.type"]);
        Assert.Empty(capture.Of("gen_ai.client.token.usage"));
    }

    [Fact]
    public async Task Streaming_passes_updates_through_and_records_the_aggregate()
    {
        using var runtime = new ActiveRuntime(new Shield360Options { CaptureMessageContent = true });
        using var capture = new TelemetryCapture();
        var inner = new FakeChatClient
        {
            Updates = new[]
            {
                new ChatResponseUpdate(ChatRole.Assistant, "Hel") { ResponseId = "s-1", ModelId = "gpt-4o" },
                new ChatResponseUpdate(null, "lo"),
                new ChatResponseUpdate
                {
                    FinishReason = ChatFinishReason.Stop,
                    Contents = { new UsageContent(new UsageDetails { InputTokenCount = 10, OutputTokenCount = 2 }) },
                },
            },
        };

        var texts = new List<string>();
        await foreach (var update in Build(inner).GetStreamingResponseAsync("hi", new ChatOptions { ModelId = "gpt-4o" }))
        {
            texts.Add(update.Text);
            Assert.Empty(capture.Spans); // still open while streaming
        }

        Assert.Equal(new[] { "Hel", "lo", string.Empty }, texts);
        var span = capture.Single();
        Assert.Equal(true, span.GetTagItem("gen_ai.request.is_stream"));
        Assert.Equal("s-1", span.GetTagItem("gen_ai.response.id"));
        Assert.Equal(10L, span.GetTagItem("gen_ai.usage.input_tokens"));
        Assert.Equal(2L, span.GetTagItem("gen_ai.usage.output_tokens"));
        Assert.Equal(new[] { "stop" }, span.GetTagItem("gen_ai.response.finish_reasons"));
        Assert.Contains("Hello", (string)span.GetTagItem("gen_ai.output.messages")!, StringComparison.Ordinal);
        Assert.True((double)span.GetTagItem("gen_ai.server.time_to_first_token")! > 0);
        Assert.True((double)span.GetTagItem("gen_ai.usage.cost")! > 0);

        Assert.Single(capture.Of("gen_ai.server.time_to_first_token"));
        Assert.Single(capture.Of("gen_ai.client.operation.time_to_first_chunk"));
        Assert.Single(capture.Of("gen_ai.server.time_per_output_token"));
        Assert.Single(capture.Of("gen_ai.client.operation.time_per_output_chunk"));
        Assert.Single(capture.Of("gen_ai.server.request.duration"));
        Assert.Equal(2, capture.Of("gen_ai.client.token.usage").Count);
    }

    [Fact]
    public async Task Streaming_errors_mark_the_span()
    {
        using var runtime = new ActiveRuntime();
        using var capture = new TelemetryCapture();
        var inner = new FakeChatClient
        {
            Updates = new[] { new ChatResponseUpdate(ChatRole.Assistant, "a"), new ChatResponseUpdate(null, "b") },
            Throw = new InvalidOperationException("stream broke"),
            ThrowAfterUpdates = 1,
        };

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await foreach (var _ in Build(inner).GetStreamingResponseAsync("hi"))
            {
            }
        });

        var span = capture.Single();
        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Equal("InvalidOperationException", span.GetTagItem("error.type"));
    }

    [Fact]
    public async Task Stopping_a_stream_early_still_ends_the_span()
    {
        using var runtime = new ActiveRuntime();
        using var capture = new TelemetryCapture();
        var inner = new FakeChatClient
        {
            Updates = new[] { new ChatResponseUpdate(ChatRole.Assistant, "a"), new ChatResponseUpdate(null, "b"), new ChatResponseUpdate(null, "c") },
        };

        await foreach (var _ in Build(inner).GetStreamingResponseAsync("hi"))
        {
            break;
        }

        var span = capture.Single();
        Assert.Equal(ActivityStatusCode.Ok, span.Status);
    }

    [Fact]
    public async Task Provider_name_falls_back_to_the_configured_one()
    {
        using var capture = new TelemetryCapture();
        var inner = new FakeChatClient { Metadata = new ChatClientMetadata() };

        await Build(inner, o => o.ProviderName = "ollama").GetResponseAsync("hi");

        var span = capture.Single();
        Assert.Equal("chat", span.DisplayName);
        Assert.Equal("ollama", span.GetTagItem("gen_ai.provider.name"));
        Assert.Null(span.GetTagItem("server.address"));
    }
}
