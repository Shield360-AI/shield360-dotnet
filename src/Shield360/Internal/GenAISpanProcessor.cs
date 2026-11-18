using System;
using System.Diagnostics;
using System.Globalization;
using OpenTelemetry;

namespace Shield360.Internal;

/// <summary>
/// Brings GenAI spans from other libraries (Microsoft.Extensions.AI, OpenAI,
/// Azure AI Inference, Semantic Kernel) in line with Shield360 spans before they
/// are exported: adds the application, environment and SDK attributes, fills in
/// <c>gen_ai.usage.cost</c> from the pricing data, stamps both provider attribute
/// names, and removes message content unless content capture is on.
/// Must be added before the exporter.
/// </summary>
internal sealed class GenAISpanProcessor : BaseProcessor<Activity>
{
    /// <summary>Span attributes that can carry prompt, response or tool data.</summary>
    internal static readonly string[] ContentAttributes =
    {
        SemanticConventions.GenAIInputMessages,
        SemanticConventions.GenAIOutputMessages,
        SemanticConventions.GenAISystemInstructions,
        SemanticConventions.GenAIPrompt,
        SemanticConventions.GenAICompletion,
        SemanticConventions.GenAIToolCallArguments,
        SemanticConventions.GenAIToolCallResult,
    };

    private readonly Func<Shield360Runtime?> _runtime;

    public GenAISpanProcessor(Func<Shield360Runtime?> runtime)
    {
        _runtime = runtime;
    }

    public override void OnEnd(Activity data)
    {
        if (data.Source.Name == Shield360Sdk.ActivitySourceName)
        {
            return;
        }

        if (data.GetTagItem(SemanticConventions.GenAIOperationName) is not string operation)
        {
            return;
        }

        var runtime = _runtime();
        if (runtime is null)
        {
            return;
        }

        var options = runtime.Options;
        SpanStamp.Common(data, options.ApplicationName, options.Environment, options.CustomSpanAttributes);

        var provider = data.GetTagItem(SemanticConventions.GenAIProviderName) as string;
        var system = data.GetTagItem(SemanticConventions.GenAISystem) as string;
        if (provider is null && system is not null)
        {
            data.SetTag(SemanticConventions.GenAIProviderName, system);
        }
        else if (system is null && provider is not null)
        {
            data.SetTag(SemanticConventions.GenAISystem, provider);
        }

        if (!options.CaptureMessageContent)
        {
            foreach (var key in ContentAttributes)
            {
                if (data.GetTagItem(key) is not null)
                {
                    data.SetTag(key, null);
                }
            }
        }

        AddCost(data, operation, runtime);
    }

    private static void AddCost(Activity data, string operation, Shield360Runtime runtime)
    {
        if (data.GetTagItem(SemanticConventions.GenAIUsageCost) is not null)
        {
            return;
        }

        // When GenAI spans nest (Semantic Kernel over OpenAI, or a
        // Microsoft.Extensions.AI pipeline over a client that also traces), only
        // the outermost carries the cost, so the dashboards do not count it twice.
        for (var parent = data.Parent; parent is not null; parent = parent.Parent)
        {
            if (parent.GetTagItem(SemanticConventions.GenAIOperationName) is string parentOperation &&
                string.Equals(parentOperation, operation, StringComparison.Ordinal))
            {
                return;
            }
        }

        var input = Long(data.GetTagItem(SemanticConventions.GenAIUsageInputTokens));
        var output = Long(data.GetTagItem(SemanticConventions.GenAIUsageOutputTokens));
        if (input is null && output is null)
        {
            return;
        }

        var model = data.GetTagItem(SemanticConventions.GenAIResponseModel) as string
            ?? data.GetTagItem(SemanticConventions.GenAIRequestModel) as string;

        double cost;
        if (operation.StartsWith("embedding", StringComparison.Ordinal))
        {
            cost = runtime.Pricing.EmbeddingCost(model, input ?? 0);
        }
        else if (operation is "chat" or "text_completion" or "completion" or "generate_content")
        {
            var cacheRead = Long(data.GetTagItem(SemanticConventions.GenAIUsageCacheReadInputTokens))
                ?? Long(data.GetTagItem("gen_ai.usage.cache_read.input_tokens"))
                ?? 0;
            cost = runtime.Pricing.ChatCost(model, input ?? 0, output ?? 0, cacheRead);
        }
        else
        {
            return;
        }

        data.SetTag(SemanticConventions.GenAIUsageCost, cost);

        var tags = MetricTags.For(
            runtime.Options.ApplicationName,
            runtime.Options.Environment,
            data.GetTagItem(SemanticConventions.GenAIProviderName) as string,
            operation,
            data.GetTagItem(SemanticConventions.GenAIRequestModel) as string,
            data.GetTagItem(SemanticConventions.GenAIResponseModel) as string,
            data.GetTagItem(SemanticConventions.ServerAddress) as string,
            Long(data.GetTagItem(SemanticConventions.ServerPort)));
        Shield360Telemetry.Cost.Record(cost, tags);
    }

    internal static long? Long(object? value) => value switch
    {
        null => null,
        long l => l,
        int i => i,
        short s => s,
        uint u => u,
        ulong ul when ul <= long.MaxValue => (long)ul,
        double d when !double.IsNaN(d) => (long)d,
        string str when long.TryParse(str, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) => parsed,
        _ => null,
    };
}
