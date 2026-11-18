using System.Collections.Generic;
using System.Diagnostics;

namespace Shield360.Internal;

/// <summary>Attributes every Shield360 GenAI span and metric carries.</summary>
internal static class SpanStamp
{
    public static void Common(Activity activity, string applicationName, string environment, IReadOnlyDictionary<string, string>? custom)
    {
        activity.SetTag(SemanticConventions.TelemetrySdkName, SemanticConventions.Shield360SdkName);
        activity.SetTag(SemanticConventions.ServiceName, applicationName);
        activity.SetTag(SemanticConventions.DeploymentEnvironment, environment);
        activity.SetTag(SemanticConventions.GenAISdkVersion, Shield360Sdk.Version);
        if (custom is null)
        {
            return;
        }

        foreach (var kv in custom)
        {
            activity.SetTag(kv.Key, kv.Value);
        }
    }
}

/// <summary>Builds the attribute set GenAI metrics are recorded with.</summary>
internal static class MetricTags
{
    public static TagList For(
        string applicationName,
        string environment,
        string? provider,
        string? operation,
        string? requestModel,
        string? responseModel,
        string? serverAddress,
        long? serverPort,
        string? errorType = null)
    {
        var tags = new TagList
        {
            { SemanticConventions.TelemetrySdkName, SemanticConventions.Shield360SdkName },
            { SemanticConventions.ServiceName, applicationName },
            { SemanticConventions.DeploymentEnvironment, environment },
        };
        if (provider is not null)
        {
            tags.Add(SemanticConventions.GenAIProviderName, provider);
            tags.Add(SemanticConventions.GenAISystem, provider);
        }

        AddIf(ref tags, SemanticConventions.GenAIOperationName, operation);
        AddIf(ref tags, SemanticConventions.GenAIRequestModel, requestModel);
        AddIf(ref tags, SemanticConventions.GenAIResponseModel, responseModel);
        AddIf(ref tags, SemanticConventions.ServerAddress, serverAddress);
        if (serverPort is long port)
        {
            tags.Add(SemanticConventions.ServerPort, port);
        }

        AddIf(ref tags, SemanticConventions.ErrorType, errorType);
        return tags;
    }

    private static void AddIf(ref TagList tags, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            tags.Add(key, value);
        }
    }
}
