using System;
using Microsoft.Extensions.AI;
using Shield360.AI;

namespace Microsoft.Extensions.AI;

/// <summary>Adds Shield360 to a Microsoft.Extensions.AI chat pipeline.</summary>
public static class Shield360ChatClientBuilderExtensions
{
    /// <summary>
    /// Records every call through this pipeline as a Shield360 GenAI span with
    /// token usage, cost and GenAI metrics. Settings come from
    /// <c>Shield360Sdk.Init</c> or <c>AddShield360</c> unless <paramref name="configure"/> sets them.
    /// </summary>
    /// <param name="builder">The chat client builder.</param>
    /// <param name="configure">Optional per-client settings.</param>
    public static ChatClientBuilder UseShield360(this ChatClientBuilder builder, Action<Shield360ChatClientOptions>? configure = null)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        Shield360ChatClientOptions? options = null;
        if (configure is not null)
        {
            options = new Shield360ChatClientOptions();
            configure(options);
        }

        return builder.Use(inner => new Shield360ChatClient(inner, options));
    }
}
