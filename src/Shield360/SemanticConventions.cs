namespace Shield360;

/// <summary>
/// Attribute, metric and event names for GenAI telemetry. The names match the
/// Go SDK's <c>semconv</c> package and the Python and TypeScript SDKs, so the
/// Shield360 dashboards read .NET telemetry the same way.
/// </summary>
public static class SemanticConventions
{
    // Operation types

    /// <summary>The name of the operation being performed.</summary>
    public const string GenAIOperationName = "gen_ai.operation.name";
    /// <summary>A chat completion operation.</summary>
    public const string GenAIOperationTypeChat = "chat";
    /// <summary>A text completion operation.</summary>
    public const string GenAIOperationTypeCompletion = "completion";
    /// <summary>An embedding operation.</summary>
    public const string GenAIOperationTypeEmbedding = "embedding";
    /// <summary>An image generation operation.</summary>
    public const string GenAIOperationTypeImage = "image";
    /// <summary>An audio generation operation.</summary>
    public const string GenAIOperationTypeAudio = "audio";

    // System and provider identifiers

    /// <summary>Legacy provider attribute. Stamped alongside <see cref="GenAIProviderName"/> until consumers move over.</summary>
    public const string GenAISystem = "gen_ai.system";
    /// <summary>The AI provider (OpenTelemetry GenAI semantic conventions 1.36 and later).</summary>
    public const string GenAIProviderName = "gen_ai.provider.name";
    /// <summary>The OpenAI provider.</summary>
    public const string GenAISystemOpenAI = "openai";
    /// <summary>The Anthropic provider.</summary>
    public const string GenAISystemAnthropic = "anthropic";
    /// <summary>The vLLM provider.</summary>
    public const string GenAISystemVLLM = "vllm";

    // Request attributes

    /// <summary>The model requested.</summary>
    public const string GenAIRequestModel = "gen_ai.request.model";
    /// <summary>The temperature requested.</summary>
    public const string GenAIRequestTemperature = "gen_ai.request.temperature";
    /// <summary>The top_p requested.</summary>
    public const string GenAIRequestTopP = "gen_ai.request.top_p";
    /// <summary>The top_k requested.</summary>
    public const string GenAIRequestTopK = "gen_ai.request.top_k";
    /// <summary>The maximum number of output tokens requested.</summary>
    public const string GenAIRequestMaxTokens = "gen_ai.request.max_tokens";
    /// <summary>The frequency penalty requested.</summary>
    public const string GenAIRequestFrequencyPenalty = "gen_ai.request.frequency_penalty";
    /// <summary>The presence penalty requested.</summary>
    public const string GenAIRequestPresencePenalty = "gen_ai.request.presence_penalty";
    /// <summary>The stop sequences requested.</summary>
    public const string GenAIRequestStopSequences = "gen_ai.request.stop_sequences";
    /// <summary>The seed requested.</summary>
    public const string GenAIRequestSeed = "gen_ai.request.seed";
    /// <summary>The number of choices requested.</summary>
    public const string GenAIRequestChoiceCount = "gen_ai.request.choice_count";
    /// <summary>Whether the request streams its response.</summary>
    public const string GenAIRequestIsStream = "gen_ai.request.is_stream";
    /// <summary>The end-user identifier sent with the request.</summary>
    public const string GenAIRequestUser = "gen_ai.request.user";

    // Response attributes

    /// <summary>The model that produced the response.</summary>
    public const string GenAIResponseModel = "gen_ai.response.model";
    /// <summary>The provider's identifier for the response.</summary>
    public const string GenAIResponseID = "gen_ai.response.id";
    /// <summary>Why generation stopped, one entry per choice.</summary>
    public const string GenAIResponseFinishReasons = "gen_ai.response.finish_reasons";
    /// <summary>The number of choices in the response.</summary>
    public const string GenAIResponseChoiceCount = "gen_ai.response.choice_count";

    // Usage attributes

    /// <summary>Input (prompt) tokens.</summary>
    public const string GenAIUsageInputTokens = "gen_ai.usage.input_tokens";
    /// <summary>Output (completion) tokens.</summary>
    public const string GenAIUsageOutputTokens = "gen_ai.usage.output_tokens";
    /// <summary>Input plus output tokens.</summary>
    public const string GenAIUsageTotalTokens = "gen_ai.usage.total_tokens";
    /// <summary>Estimated cost of the operation in USD, from the pricing data. Also the name of the cost metric.</summary>
    public const string GenAIUsageCost = "gen_ai.usage.cost";
    /// <summary>Distinguishes input from output on the token usage metric.</summary>
    public const string GenAITokenType = "gen_ai.token.type";

    // Token details (legacy OpenAI-shaped names)

    /// <summary>Audio output tokens (legacy).</summary>
    public const string GenAIUsageCompletionTokensDetailsAudio = "gen_ai.usage.completion_tokens_details.audio";
    /// <summary>Reasoning tokens (legacy; prefer <see cref="GenAIUsageReasoningTokens"/>).</summary>
    public const string GenAIUsageCompletionTokensDetailsReasoning = "gen_ai.usage.completion_tokens_details.reasoning";
    /// <summary>Cached input tokens read (legacy; prefer <see cref="GenAIUsageCacheReadInputTokens"/>).</summary>
    public const string GenAIUsagePromptTokensDetailsCacheRead = "gen_ai.usage.prompt_tokens_details.cache_read";
    /// <summary>Cached input tokens written (legacy; prefer <see cref="GenAIUsageCacheCreationInputTokens"/>).</summary>
    public const string GenAIUsagePromptTokensDetailsCacheWrite = "gen_ai.usage.prompt_tokens_details.cache_write";

    // Token details (OpenTelemetry 1.36 and later)

    /// <summary>Input tokens served from the provider's prompt cache.</summary>
    public const string GenAIUsageCacheReadInputTokens = "gen_ai.usage.cache.read_input_tokens";
    /// <summary>Input tokens written to a new prompt cache entry.</summary>
    public const string GenAIUsageCacheCreationInputTokens = "gen_ai.usage.cache.creation_input_tokens";
    /// <summary>Reasoning or thinking tokens spent on the response.</summary>
    public const string GenAIUsageReasoningTokens = "gen_ai.usage.reasoning_tokens";

    // Message attributes (recorded only when content capture is on)

    /// <summary>Legacy prompt attribute.</summary>
    public const string GenAIPrompt = "gen_ai.prompt";
    /// <summary>Legacy completion attribute.</summary>
    public const string GenAICompletion = "gen_ai.completion";
    /// <summary>Structured input messages, as JSON.</summary>
    public const string GenAIInputMessages = "gen_ai.input.messages";
    /// <summary>Structured output messages, as JSON.</summary>
    public const string GenAIOutputMessages = "gen_ai.output.messages";
    /// <summary>System instructions, as JSON.</summary>
    public const string GenAISystemInstructions = "gen_ai.system_instructions";

    // Tool attributes

    /// <summary>The tool definitions offered to the model, as JSON.</summary>
    public const string GenAIToolDefinitions = "gen_ai.tool.definitions";
    /// <summary>The tool calls the model made, as JSON.</summary>
    public const string GenAIToolCalls = "gen_ai.tool.calls";
    /// <summary>The tool type, for example <c>function</c>.</summary>
    public const string GenAIToolType = "gen_ai.tool.type";
    /// <summary>Comma-joined names of the tools the model called.</summary>
    public const string GenAIToolName = "gen_ai.tool.name";
    /// <summary>Comma-joined tool call identifiers from the response.</summary>
    public const string GenAIToolCallID = "gen_ai.tool.call.id";
    /// <summary>The JSON arguments of each tool call (recorded only when content capture is on).</summary>
    public const string GenAIToolCallArguments = "gen_ai.tool.call.arguments";
    /// <summary>The result of a tool call (recorded only when content capture is on).</summary>
    public const string GenAIToolCallResult = "gen_ai.tool.call.result";

    // Conversation

    /// <summary>Identifies a conversation or session.</summary>
    public const string GenAIConversationID = "gen_ai.conversation.id";

    // OpenAI-specific attributes

    /// <summary>The OpenAI assistant identifier.</summary>
    public const string GenAIOpenAIAssistantID = "gen_ai.openai.assistant.id";
    /// <summary>The OpenAI thread identifier.</summary>
    public const string GenAIOpenAIThreadID = "gen_ai.openai.thread.id";
    /// <summary>The OpenAI run identifier.</summary>
    public const string GenAIOpenAIRunID = "gen_ai.openai.run.id";
    /// <summary>The service tier requested.</summary>
    public const string GenAIOpenAIRequestServiceTier = "gen_ai.openai.request.service_tier";
    /// <summary>The service tier used.</summary>
    public const string GenAIOpenAIResponseServiceTier = "gen_ai.openai.response.service_tier";
    /// <summary>The system fingerprint returned.</summary>
    public const string GenAIOpenAIResponseSystemFingerprint = "gen_ai.openai.response.system_fingerprint";

    // Output type

    /// <summary>The requested output content type.</summary>
    public const string GenAIOutputType = "gen_ai.output.type";
    /// <summary>Text output.</summary>
    public const string GenAIOutputTypeText = "text";
    /// <summary>JSON output.</summary>
    public const string GenAIOutputTypeJSON = "json_object";

    // Server and error attributes

    /// <summary>The server host name.</summary>
    public const string ServerAddress = "server.address";
    /// <summary>The server port.</summary>
    public const string ServerPort = "server.port";
    /// <summary>A low-cardinality description of the error.</summary>
    public const string ErrorType = "error.type";

    // Event names

    /// <summary>The inference operation details event.</summary>
    public const string GenAIClientInferenceOperationDetails = "gen_ai.client.inference.operation.details";
    /// <summary>A user message event.</summary>
    public const string GenAIUserMessage = "gen_ai.user.message";
    /// <summary>A system message event.</summary>
    public const string GenAISystemMessage = "gen_ai.system.message";
    /// <summary>An assistant message event.</summary>
    public const string GenAIAssistantMessage = "gen_ai.assistant.message";
    /// <summary>A tool message event.</summary>
    public const string GenAIToolMessage = "gen_ai.tools.message";
    /// <summary>A choice event.</summary>
    public const string GenAIChoice = "gen_ai.choice";

    // Metric names

    /// <summary>Token usage histogram.</summary>
    public const string GenAIClientTokenUsage = "gen_ai.client.token.usage";
    /// <summary>Operation duration histogram.</summary>
    public const string GenAIClientOperationDuration = "gen_ai.client.operation.duration";
    /// <summary>Server request duration histogram (streaming).</summary>
    public const string GenAIServerRequestDuration = "gen_ai.server.request.duration";
    /// <summary>Time per output token histogram (streaming).</summary>
    public const string GenAIServerTimePerOutputToken = "gen_ai.server.time_per_output_token";
    /// <summary>Time to first token histogram (streaming).</summary>
    public const string GenAIServerTimeToFirstToken = "gen_ai.server.time_to_first_token";
    /// <summary>Client-side time to first chunk histogram (streaming).</summary>
    public const string GenAIClientOperationTimeToFirstChunk = "gen_ai.client.operation.time_to_first_chunk";
    /// <summary>Client-side time per output chunk histogram (streaming).</summary>
    public const string GenAIClientOperationTimePerOutputChunk = "gen_ai.client.operation.time_per_output_chunk";

    // Shield360 attributes

    /// <summary>The deployment environment (Go SDK name).</summary>
    public const string Shield360Environment = "shield360.environment";
    /// <summary>The application name (Go SDK name).</summary>
    public const string Shield360ApplicationName = "shield360.application.name";
    /// <summary>The Shield360 SDK version, set on the resource.</summary>
    public const string Shield360SDKVersion = "shield360.sdk.version";
    /// <summary>The SDK version, set on GenAI spans (Python and TypeScript SDK name).</summary>
    public const string GenAISdkVersion = "gen_ai.sdk.version";
    /// <summary>The telemetry SDK name; Shield360 sets it to <c>shield360</c>.</summary>
    public const string TelemetrySdkName = "telemetry.sdk.name";
    /// <summary>The service name, set from the application name.</summary>
    public const string ServiceName = "service.name";
    /// <summary>The service version.</summary>
    public const string ServiceVersion = "service.version";
    /// <summary>The deployment environment.</summary>
    public const string DeploymentEnvironment = "deployment.environment";
    /// <summary>The deployment environment (OpenTelemetry 1.27 and later name).</summary>
    public const string DeploymentEnvironmentName = "deployment.environment.name";

    /// <summary>The value Shield360 sets for <see cref="TelemetrySdkName"/>.</summary>
    public const string Shield360SdkName = "shield360";
}
