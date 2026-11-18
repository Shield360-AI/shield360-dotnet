using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Extensions.AI;
using Shield360.Internal;

namespace Shield360.AI;

internal sealed record ChatCallSettings(
    string ApplicationName,
    string Environment,
    bool CaptureMessageContent,
    Pricing Pricing,
    IReadOnlyDictionary<string, string>? CustomSpanAttributes,
    string? ProviderName,
    Uri? ServerUri,
    string? RequestModel);

/// <summary>The span and measurements for one chat call.</summary>
internal sealed class ChatCall : IDisposable
{
    private readonly ChatCallSettings _settings;
    private readonly bool _streaming;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly Activity? _activity;
    private TimeSpan? _firstChunk;
    private TimeSpan _lastChunk;
    private int _chunks;

    private ChatCall(ChatCallSettings settings, bool streaming, Activity? activity)
    {
        _settings = settings;
        _streaming = streaming;
        _activity = activity;
    }

    public bool Ended { get; private set; }

    private string? ServerAddress => _settings.ServerUri?.Host;

    private long? ServerPort => _settings.ServerUri is { } u && u.Port > 0 ? u.Port : null;

    public static ChatCall Start(ChatCallSettings settings, IList<ChatMessage> messages, ChatOptions? options, bool streaming)
    {
        var operation = SemanticConventions.GenAIOperationTypeChat;
        var name = settings.RequestModel is null ? operation : operation + " " + settings.RequestModel;

        // These five are set at start so samplers can see them.
        var tags = new List<KeyValuePair<string, object?>>
        {
            new(SemanticConventions.GenAIOperationName, operation),
        };
        if (settings.ProviderName is not null)
        {
            tags.Add(new(SemanticConventions.GenAIProviderName, settings.ProviderName));
            tags.Add(new(SemanticConventions.GenAISystem, settings.ProviderName));
        }

        if (settings.RequestModel is not null)
        {
            tags.Add(new(SemanticConventions.GenAIRequestModel, settings.RequestModel));
        }

        if (settings.ServerUri is { } uri)
        {
            tags.Add(new(SemanticConventions.ServerAddress, uri.Host));
            if (uri.Port > 0)
            {
                tags.Add(new(SemanticConventions.ServerPort, (long)uri.Port));
            }
        }

        var activity = Shield360Telemetry.Source.StartActivity(ActivityKind.Client, tags: tags, name: name);
        var call = new ChatCall(settings, streaming, activity);
        if (activity is { IsAllDataRequested: true })
        {
            SpanStamp.Common(activity, settings.ApplicationName, settings.Environment, settings.CustomSpanAttributes);
            Safely(() => SetRequest(activity, messages, options, streaming, settings.CaptureMessageContent));
        }

        return call;
    }

    public void Chunk()
    {
        var now = _clock.Elapsed;
        if (_firstChunk is null)
        {
            _firstChunk = now;
        }

        _lastChunk = now;
        _chunks++;
    }

    public void Complete(ChatResponse response)
    {
        if (Ended)
        {
            return;
        }

        Ended = true;
        var elapsed = _clock.Elapsed;
        var usage = response.Usage;
        var input = usage?.InputTokenCount;
        var output = usage?.OutputTokenCount;
        var cacheRead = usage?.CachedInputTokenCount ?? 0;
        var model = response.ModelId ?? _settings.RequestModel;
        var cost = input is null && output is null
            ? (double?)null
            : _settings.Pricing.ChatCost(model, input ?? 0, output ?? 0, cacheRead);

        if (_activity is { IsAllDataRequested: true })
        {
            var activity = _activity;
            Safely(() => SetResponse(activity, response, cost));
            _activity.SetStatus(ActivityStatusCode.Ok);
        }

        var tags = Tags(response.ModelId, errorType: null);
        Shield360Telemetry.OperationDuration.Record(elapsed.TotalSeconds, tags);
        if (input is long i)
        {
            var t = tags;
            t.Add(SemanticConventions.GenAITokenType, "input");
            Shield360Telemetry.TokenUsage.Record(i, t);
        }

        if (output is long o)
        {
            var t = tags;
            t.Add(SemanticConventions.GenAITokenType, "output");
            Shield360Telemetry.TokenUsage.Record(o, t);
        }

        if (cost is double c)
        {
            Shield360Telemetry.Cost.Record(c, tags);
        }

        if (_streaming && _firstChunk is TimeSpan first && first > TimeSpan.Zero)
        {
            Shield360Telemetry.TimeToFirstToken.Record(first.TotalSeconds, tags);
            Shield360Telemetry.TimeToFirstChunk.Record(first.TotalSeconds, tags);
            if (_chunks > 1)
            {
                var perChunk = (_lastChunk - first).TotalSeconds / (_chunks - 1);
                if (perChunk > 0)
                {
                    Shield360Telemetry.TimePerOutputToken.Record(perChunk, tags);
                    Shield360Telemetry.TimePerOutputChunk.Record(perChunk, tags);
                }
            }

            Shield360Telemetry.ServerRequestDuration.Record(elapsed.TotalSeconds, tags);
        }

        _activity?.Stop();
    }

    public void Fail(Exception error)
    {
        if (Ended)
        {
            return;
        }

        Ended = true;
        var errorType = error.GetType().Name;
        if (_activity is not null)
        {
            _activity.SetTag(SemanticConventions.ErrorType, errorType);
            _activity.SetStatus(ActivityStatusCode.Error, errorType);
            _activity.AddException(error);
        }

        Shield360Telemetry.OperationDuration.Record(_clock.Elapsed.TotalSeconds, Tags(responseModel: null, errorType));
        _activity?.Stop();
    }

    public void Dispose()
    {
        _activity?.Dispose();
    }

    private TagList Tags(string? responseModel, string? errorType) =>
        MetricTags.For(
            _settings.ApplicationName,
            _settings.Environment,
            _settings.ProviderName,
            SemanticConventions.GenAIOperationTypeChat,
            _settings.RequestModel,
            responseModel,
            ServerAddress,
            ServerPort,
            errorType);

    private static void SetRequest(Activity a, IList<ChatMessage> messages, ChatOptions? options, bool streaming, bool capture)
    {
        a.SetTag(SemanticConventions.GenAIRequestIsStream, streaming);
        if (options is not null)
        {
            SetIf(a, SemanticConventions.GenAIRequestTemperature, options.Temperature);
            SetIf(a, SemanticConventions.GenAIRequestTopP, options.TopP);
            SetIf(a, SemanticConventions.GenAIRequestTopK, options.TopK);
            SetIf(a, SemanticConventions.GenAIRequestMaxTokens, options.MaxOutputTokens);
            if (options.FrequencyPenalty is float fp && fp != 0)
            {
                a.SetTag(SemanticConventions.GenAIRequestFrequencyPenalty, (double)fp);
            }

            if (options.PresencePenalty is float pp && pp != 0)
            {
                a.SetTag(SemanticConventions.GenAIRequestPresencePenalty, (double)pp);
            }

            if (options.Seed is long seed)
            {
                a.SetTag(SemanticConventions.GenAIRequestSeed, seed);
            }

            if (options.StopSequences is { Count: > 0 } stops)
            {
                a.SetTag(SemanticConventions.GenAIRequestStopSequences, stops.ToArray());
            }

            switch (options.ResponseFormat)
            {
                case ChatResponseFormatJson:
                    a.SetTag(SemanticConventions.GenAIOutputType, SemanticConventions.GenAIOutputTypeJSON);
                    break;
                case ChatResponseFormatText:
                    a.SetTag(SemanticConventions.GenAIOutputType, SemanticConventions.GenAIOutputTypeText);
                    break;
            }

            if (!string.IsNullOrEmpty(options.ConversationId))
            {
                a.SetTag(SemanticConventions.GenAIConversationID, options.ConversationId);
            }

            if (MessageJson.ToolDefinitions(options) is { } tools)
            {
                a.SetTag(SemanticConventions.GenAIToolDefinitions, tools);
            }
        }

        if (!capture)
        {
            return;
        }

        a.SetTag(SemanticConventions.GenAIInputMessages, MessageJson.Input(messages));
        if (MessageJson.SystemInstructions(messages, options) is { } instructions)
        {
            a.SetTag(SemanticConventions.GenAISystemInstructions, instructions);
        }
    }

    private void SetResponse(Activity a, ChatResponse response, double? cost)
    {
        if (!string.IsNullOrEmpty(response.ResponseId))
        {
            a.SetTag(SemanticConventions.GenAIResponseID, response.ResponseId);
        }

        if (!string.IsNullOrEmpty(response.ModelId))
        {
            a.SetTag(SemanticConventions.GenAIResponseModel, response.ModelId);
        }

        if (response.FinishReason is { } finish)
        {
            a.SetTag(SemanticConventions.GenAIResponseFinishReasons, new[] { finish.Value });
        }

        if (!string.IsNullOrEmpty(response.ConversationId))
        {
            a.SetTag(SemanticConventions.GenAIConversationID, response.ConversationId);
        }

        if (response.Usage is { } usage)
        {
            SetIf(a, SemanticConventions.GenAIUsageInputTokens, usage.InputTokenCount);
            SetIf(a, SemanticConventions.GenAIUsageOutputTokens, usage.OutputTokenCount);
            var total = usage.TotalTokenCount ?? (usage.InputTokenCount is null && usage.OutputTokenCount is null
                ? null
                : (usage.InputTokenCount ?? 0) + (usage.OutputTokenCount ?? 0));
            SetIf(a, SemanticConventions.GenAIUsageTotalTokens, total);
            if (usage.CachedInputTokenCount is long cached && cached > 0)
            {
                a.SetTag(SemanticConventions.GenAIUsageCacheReadInputTokens, cached);
            }

            if (usage.ReasoningTokenCount is long reasoning && reasoning > 0)
            {
                a.SetTag(SemanticConventions.GenAIUsageReasoningTokens, reasoning);
            }
        }

        if (cost is double c)
        {
            a.SetTag(SemanticConventions.GenAIUsageCost, c);
        }

        var calls = response.Messages.SelectMany(m => m.Contents).OfType<FunctionCallContent>().ToList();
        if (calls.Count > 0)
        {
            a.SetTag(SemanticConventions.GenAIToolName, string.Join(", ", calls.Select(c => c.Name)));
            a.SetTag(SemanticConventions.GenAIToolCallID, string.Join(", ", calls.Select(c => c.CallId)));
            a.SetTag(SemanticConventions.GenAIToolType, "function");
            if (_settings.CaptureMessageContent)
            {
                a.SetTag(SemanticConventions.GenAIToolCallArguments, calls.Select(c => MessageJson.Serialize(c.Arguments)).ToArray());
            }
        }

        if (_settings.CaptureMessageContent)
        {
            a.SetTag(SemanticConventions.GenAIOutputMessages, MessageJson.Output(response));
        }

        if (_streaming && _firstChunk is TimeSpan first)
        {
            // Same span attributes as the Python SDK's streaming spans.
            a.SetTag(SemanticConventions.GenAIServerTimeToFirstToken, first.TotalSeconds);
            if (_chunks > 1)
            {
                a.SetTag(SemanticConventions.GenAIServerTimePerOutputToken, (_lastChunk - first).TotalSeconds / (_chunks - 1));
            }
        }
    }

    /// <summary>Telemetry must never break the call it observes.</summary>
    private static void Safely(Action action)
    {
        try
        {
            action();
        }
        catch (Exception e) when (e is NotSupportedException or InvalidOperationException or ArgumentException or System.Text.Json.JsonException or FormatException)
        {
            Trace.TraceWarning("Shield360: could not record a span attribute ({0}).", e.GetType().Name);
        }
    }

    private static void SetIf(Activity a, string key, float? value)
    {
        if (value is float f)
        {
            a.SetTag(key, (double)f);
        }
    }

    private static void SetIf(Activity a, string key, int? value)
    {
        if (value is int i)
        {
            a.SetTag(key, (long)i);
        }
    }

    private static void SetIf(Activity a, string key, long? value)
    {
        if (value is long l)
        {
            a.SetTag(key, l);
        }
    }
}
