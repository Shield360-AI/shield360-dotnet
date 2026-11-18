using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.AI;
using Shield360.Internal;
using Xunit;

// Shield360 keeps one active configuration per process, and the AI libraries
// read their switches once, so tests run one at a time.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Shield360.Tests;

internal static class Env
{
    public static Func<string, string?> Of(params (string Name, string Value)[] vars)
    {
        var map = vars.ToDictionary(v => v.Name, v => (string?)v.Value);
        return name => map.TryGetValue(name, out var v) ? v : null;
    }

    public static readonly Func<string, string?> Empty = _ => null;
}

/// <summary>Activates a runtime for one test and clears it afterwards.</summary>
internal sealed class ActiveRuntime : IDisposable
{
    public ActiveRuntime(Shield360Options? options = null, Func<string, string?>? env = null)
    {
        Runtime = Shield360Runtime.Activate(ResolvedOptions.Resolve(options, env ?? Env.Empty));
    }

    public Shield360Runtime Runtime { get; }

    public void Dispose() => Runtime.Deactivate();
}

/// <summary>Records Activities and measurements from the given sources.</summary>
internal sealed class TelemetryCapture : IDisposable
{
    private readonly ActivityListener _activities;
    private readonly MeterListener _meters;

    public TelemetryCapture(string source = Shield360Sdk.ActivitySourceName)
    {
        _activities = new ActivityListener
        {
            ShouldListenTo = s => s.Name == source,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a => Spans.Add(a),
        };
        ActivitySource.AddActivityListener(_activities);

        _meters = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == source)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            },
        };
        _meters.SetMeasurementEventCallback<long>((i, v, tags, _) => Record(i, v, tags));
        _meters.SetMeasurementEventCallback<double>((i, v, tags, _) => Record(i, v, tags));
        _meters.Start();
    }

    public ConcurrentBag<Activity> Spans { get; } = new();

    public ConcurrentQueue<Measurement> Measurements { get; } = new();

    public Activity Single() => Assert.Single(Spans);

    public IReadOnlyList<Measurement> Of(string metric) => Measurements.Where(m => m.Name == metric).ToList();

    public void Dispose()
    {
        _activities.Dispose();
        _meters.Dispose();
    }

    private void Record(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags) =>
        Measurements.Enqueue(new Measurement(instrument.Name, value, tags.ToArray().ToDictionary(t => t.Key, t => t.Value)));

    public sealed record Measurement(string Name, double Value, IReadOnlyDictionary<string, object?> Tags);
}

/// <summary>An IChatClient that returns canned responses.</summary>
internal sealed class FakeChatClient : IChatClient
{
    public Func<IEnumerable<ChatMessage>, ChatOptions?, ChatResponse> Respond { get; set; } =
        (_, _) => new ChatResponse(new ChatMessage(ChatRole.Assistant, "Hello there"))
        {
            ResponseId = "resp-1",
            ModelId = "gpt-4o-2024-08-06",
            FinishReason = ChatFinishReason.Stop,
            Usage = new UsageDetails { InputTokenCount = 1000, OutputTokenCount = 500, TotalTokenCount = 1500 },
        };

    public IReadOnlyList<ChatResponseUpdate>? Updates { get; set; }

    public Exception? Throw { get; set; }

    public int ThrowAfterUpdates { get; set; } = -1;

    public Activity? ActivityDuringCall { get; private set; }

    public ChatClientMetadata Metadata { get; set; } = new("openai", new Uri("https://api.openai.com:443/v1"), "gpt-4o");

    public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        ActivityDuringCall = Activity.Current;
        if (Throw is not null)
        {
            throw Throw;
        }

        return Task.FromResult(Respond(messages, options));
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ActivityDuringCall = Activity.Current;
        if (Throw is not null && ThrowAfterUpdates < 0)
        {
            throw Throw;
        }

        var updates = Updates ?? Array.Empty<ChatResponseUpdate>();
        for (var i = 0; i < updates.Count; i++)
        {
            if (i == ThrowAfterUpdates && Throw is not null)
            {
                throw Throw;
            }

            await Task.Delay(5, cancellationToken);
            yield return updates[i];
        }
    }

    public object? GetService(Type serviceType, object? serviceKey = null) =>
        serviceType == typeof(ChatClientMetadata) ? Metadata : null;

    public void Dispose()
    {
    }
}

/// <summary>An HttpMessageHandler that records requests and returns a canned response.</summary>
internal sealed class FakeHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

    public FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        _respond = respond;
    }

    public FakeHandler(HttpStatusCode status, string body, string mediaType = "application/json")
        : this(_ => new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, mediaType) })
    {
    }

    public List<(HttpRequestMessage Request, string? Body)> Requests { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request, body));
        return _respond(request);
    }
}

internal static class OpenAIResponses
{
    public const string ChatCompletion = """
        {"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"gpt-4o-mini-2024-07-18",
         "choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}],
         "usage":{"prompt_tokens":2000,"completion_tokens":1000,"total_tokens":3000}}
        """;

    public const string AzureInferenceCompletion = """
        {"id":"cmpl-1","created":1,"model":"gpt-4o-mini",
         "choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}],
         "usage":{"prompt_tokens":2000,"completion_tokens":1000,"total_tokens":3000}}
        """;
}
