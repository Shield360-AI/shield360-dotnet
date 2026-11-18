using System;
using System.ClientModel;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Azure.AI.Inference;
using Microsoft.Extensions.AI;
using Microsoft.SemanticKernel;
using OpenAI;
using OpenTelemetry;
using OpenTelemetry.Trace;
using Shield360.Internal;
using Xunit;

namespace Shield360.Tests;

/// <summary>
/// Runs the real AI libraries against a fake server and checks that the
/// sources Shield360 registers are the ones they emit on, and that the span
/// processor fills in cost and the Shield360 attributes.
/// </summary>
public class InstrumentationTests
{
    [Fact]
    public void Every_library_is_registered_by_default()
    {
        using var active = new ActiveRuntime();
        var sources = active.Runtime.ActivitySources.ToList();

        Assert.Contains("Shield360", sources);
        Assert.Contains("Experimental.Microsoft.Extensions.AI*", sources);
        Assert.Contains("OpenAI.*", sources);
        Assert.Contains("Azure.AI.Inference.*", sources);
        Assert.Contains("Microsoft.SemanticKernel*", sources);
        Assert.Equal(sources, active.Runtime.Meters.ToList());
    }

    [Fact]
    public void Disabled_instrumentors_are_not_registered()
    {
        using var active = new ActiveRuntime(new Shield360Options { DisabledInstrumentors = new[] { "openai", "semantic-kernel" } });

        Assert.DoesNotContain("OpenAI.*", active.Runtime.ActivitySources);
        Assert.DoesNotContain("Microsoft.SemanticKernel*", active.Runtime.Meters);
        Assert.Contains("Shield360", active.Runtime.ActivitySources);
    }

    [Fact]
    public void Library_switches_follow_the_configuration()
    {
        using (new ActiveRuntime(new Shield360Options { CaptureMessageContent = true }))
        {
            Assert.True(AppContext.TryGetSwitch(Shield360Instrumentations.OpenAIEnableTelemetrySwitch, out var openai) && openai);
            Assert.True(AppContext.TryGetSwitch(Shield360Instrumentations.AzureEnableActivitySourceSwitch, out var azure) && azure);
            Assert.True(AppContext.TryGetSwitch(Shield360Instrumentations.SemanticKernelDiagnosticsSwitch, out var sk) && sk);
            Assert.True(AppContext.TryGetSwitch(Shield360Instrumentations.SemanticKernelSensitiveSwitch, out var sensitive) && sensitive);
            Assert.True(AppContext.TryGetSwitch(Shield360Instrumentations.AzureTraceContentSwitch, out var content) && content);
        }

        using (new ActiveRuntime())
        {
            Assert.True(AppContext.TryGetSwitch(Shield360Instrumentations.SemanticKernelSensitiveSwitch, out var sensitive) && !sensitive);
            Assert.True(AppContext.TryGetSwitch(Shield360Instrumentations.AzureTraceContentSwitch, out var content) && !content);
        }
    }

    [Fact]
    public async Task OpenAI_sdk_spans_are_collected_and_priced()
    {
        var (spans, provider) = Pipeline(new Shield360Options { ApplicationName = "svc", Environment = "test" });
        using (provider)
        {
            var client = OpenAIClient(out _);
            await client.GetChatClient("gpt-4o-mini").CompleteChatAsync(new OpenAI.Chat.UserChatMessage("hello"));
        }

        var span = Assert.Single(spans, s => s.Source.Name == "OpenAI.ChatClient");
        Assert.Equal("chat", span.GetTagItem("gen_ai.operation.name"));
        Assert.Equal("openai", span.GetTagItem("gen_ai.system"));
        Assert.Equal("openai", span.GetTagItem("gen_ai.provider.name"));
        Assert.Equal("svc", span.GetTagItem("service.name"));
        Assert.Equal("test", span.GetTagItem("deployment.environment"));
        Assert.Equal("shield360", span.GetTagItem("telemetry.sdk.name"));
        var expected = Shield360Runtime.BundledPricing.ChatCost("gpt-4o-mini-2024-07-18", 2000, 1000);
        Assert.True(expected > 0);
        Assert.Equal(expected, (double)span.GetTagItem("gen_ai.usage.cost")!, 12);
    }

    [Fact]
    public async Task Nested_GenAI_spans_are_priced_once()
    {
        var (spans, provider) = Pipeline(new Shield360Options());
        using (provider)
        {
            var client = OpenAIClient(out _);
            IChatClient chat = client.GetChatClient("gpt-4o-mini").AsIChatClient()
                .AsBuilder()
                .UseOpenTelemetry()
                .Build();
            await chat.GetResponseAsync("hello");
        }

        var outer = Assert.Single(spans, s => s.Source.Name == "Experimental.Microsoft.Extensions.AI");
        var inner = Assert.Single(spans, s => s.Source.Name == "OpenAI.ChatClient");
        Assert.Same(outer, inner.Parent);
        Assert.NotNull(outer.GetTagItem("gen_ai.usage.cost"));
        Assert.Null(inner.GetTagItem("gen_ai.usage.cost"));
    }

    [Fact]
    public async Task Shield360_middleware_over_the_OpenAI_sdk_is_priced_once()
    {
        var (spans, provider) = Pipeline(new Shield360Options());
        using (provider)
        {
            var client = OpenAIClient(out _);
            IChatClient chat = client.GetChatClient("gpt-4o-mini").AsIChatClient().AsBuilder().UseShield360().Build();
            await chat.GetResponseAsync("hello");
        }

        var outer = Assert.Single(spans, s => s.Source.Name == "Shield360");
        var inner = Assert.Single(spans, s => s.Source.Name == "OpenAI.ChatClient");
        Assert.Same(outer, inner.Parent);
        Assert.Equal("openai", outer.GetTagItem("gen_ai.provider.name"));
        Assert.True((double)outer.GetTagItem("gen_ai.usage.cost")! > 0);
        Assert.Null(inner.GetTagItem("gen_ai.usage.cost"));
    }

    [Fact]
    public async Task Content_from_other_libraries_is_removed_unless_capture_is_on()
    {
        var (spans, provider) = Pipeline(new Shield360Options());
        using (provider)
        {
            IChatClient chat = new FakeChatClient().AsBuilder()
                .UseOpenTelemetry(configure: c => c.EnableSensitiveData = true)
                .Build();
            await chat.GetResponseAsync("my secret prompt");
        }

        var span = Assert.Single(spans, s => s.Source.Name == "Experimental.Microsoft.Extensions.AI");
        Assert.Null(span.GetTagItem("gen_ai.input.messages"));
        Assert.Null(span.GetTagItem("gen_ai.output.messages"));
        Assert.DoesNotContain(span.TagObjects, t => t.Value?.ToString()?.Contains("my secret prompt", StringComparison.Ordinal) == true);

        var (kept, provider2) = Pipeline(new Shield360Options { CaptureMessageContent = true });
        using (provider2)
        {
            IChatClient chat = new FakeChatClient().AsBuilder()
                .UseOpenTelemetry(configure: c => c.EnableSensitiveData = true)
                .Build();
            await chat.GetResponseAsync("my secret prompt");
        }

        var keptSpan = Assert.Single(kept, s => s.Source.Name == "Experimental.Microsoft.Extensions.AI");
        Assert.Contains("my secret prompt", (string)keptSpan.GetTagItem("gen_ai.input.messages")!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Azure_AI_Inference_spans_are_collected()
    {
        var (spans, provider) = Pipeline(new Shield360Options());
        using (provider)
        {
            using var http = new HttpClient(new FakeHandler(HttpStatusCode.OK, OpenAIResponses.AzureInferenceCompletion));
            var client = new ChatCompletionsClient(
                new Uri("https://models.example.test"),
                new Azure.AzureKeyCredential("azure-key"),
                new AzureAIInferenceClientOptions { Transport = new Azure.Core.Pipeline.HttpClientTransport(http) });
            await client.CompleteAsync(new ChatCompletionsOptions { Model = "gpt-4o-mini", Messages = { new ChatRequestUserMessage("hello") } });
        }

        var span = Assert.Single(spans, s => s.Source.Name == "Azure.AI.Inference.ChatCompletionsClient");
        Assert.Equal("chat", span.GetTagItem("gen_ai.operation.name"));
        Assert.Equal(2000L, GenAISpanProcessor.Long(span.GetTagItem("gen_ai.usage.input_tokens")));
        Assert.True((double)span.GetTagItem("gen_ai.usage.cost")! > 0);
        Assert.Equal("shield360", span.GetTagItem("telemetry.sdk.name"));
    }

    [Fact]
    public async Task Semantic_Kernel_spans_are_collected_and_priced_once()
    {
        var (spans, provider) = Pipeline(new Shield360Options());
        using (provider)
        {
            using var http = new HttpClient(new FakeHandler(HttpStatusCode.OK, OpenAIResponses.ChatCompletion));
            var builder = Kernel.CreateBuilder();
            builder.AddOpenAIChatCompletion("gpt-4o-mini", "sk-test", httpClient: http);
            await builder.Build().InvokePromptAsync("hello");
        }

        var chat = Assert.Single(spans, s => s.Source.Name == "Microsoft.SemanticKernel.Diagnostics");
        Assert.Equal("chat", chat.GetTagItem("gen_ai.operation.name"));
        Assert.True((double)chat.GetTagItem("gen_ai.usage.cost")! > 0);
        Assert.Contains(spans, s => s.Source.Name == "Microsoft.SemanticKernel");

        // The OpenAI SDK call underneath is traced too, but not priced again.
        var openai = spans.Where(s => s.Source.Name == "OpenAI.ChatClient").ToList();
        Assert.All(openai, s => Assert.Null(s.GetTagItem("gen_ai.usage.cost")));
    }

    private static (List<Activity> Spans, TracerProvider Provider) Pipeline(Shield360Options options)
    {
        var spans = new List<Activity>();
        var provider = Sdk.CreateTracerProviderBuilder()
            .AddShield360Instrumentation(o =>
            {
                o.ApplicationName = options.ApplicationName;
                o.Environment = options.Environment;
                o.CaptureMessageContent = options.CaptureMessageContent;
            })
            .AddInMemoryExporter(spans)
            .Build()!;
        return (spans, new DeactivatingProvider(provider));
    }

    private static OpenAIClient OpenAIClient(out FakeHandler handler)
    {
        handler = new FakeHandler(HttpStatusCode.OK, OpenAIResponses.ChatCompletion);
        return new OpenAIClient(new ApiKeyCredential("sk-test"), new OpenAIClientOptions
        {
            Endpoint = new Uri("https://openai.example.test/v1"),
            Transport = new HttpClientPipelineTransport(new HttpClient(handler)),
        });
    }

    /// <summary>Disposes the provider and clears the runtime the test activated.</summary>
    private sealed class DeactivatingProvider : TracerProvider
    {
        private readonly TracerProvider _inner;

        public DeactivatingProvider(TracerProvider inner)
        {
            _inner = inner;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
                Shield360Runtime.Current?.Deactivate();
            }

            base.Dispose(disposing);
        }
    }
}
