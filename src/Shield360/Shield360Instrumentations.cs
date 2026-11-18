using System;
using System.Collections.Generic;

namespace Shield360;

/// <summary>
/// The .NET AI libraries Shield360 collects telemetry from, with the
/// ActivitySource and Meter names they emit and the AppContext switches that
/// turn their telemetry on. Names were checked against the packages listed in
/// the README by running each library against a fake server and recording
/// which sources and meters fired.
/// </summary>
public static class Shield360Instrumentations
{
    /// <summary>Microsoft.Extensions.AI, when a pipeline uses <c>UseOpenTelemetry()</c>.</summary>
    public const string MicrosoftExtensionsAI = "microsoft-extensions-ai";

    /// <summary>The OpenAI .NET SDK (and Azure.AI.OpenAI, which is built on it).</summary>
    public const string OpenAI = "openai";

    /// <summary>Azure.AI.Inference.</summary>
    public const string AzureAIInference = "azure-ai-inference";

    /// <summary>Semantic Kernel.</summary>
    public const string SemanticKernel = "semantic-kernel";

    /// <summary>AppContext switch that turns on the OpenAI .NET SDK's experimental OpenTelemetry support.</summary>
    public const string OpenAIEnableTelemetrySwitch = "OpenAI.Experimental.EnableOpenTelemetry";

    /// <summary>AppContext switch that makes Azure SDK clients, Azure.AI.Inference among them, emit through ActivitySource.</summary>
    public const string AzureEnableActivitySourceSwitch = "Azure.Experimental.EnableActivitySource";

    /// <summary>AppContext switch that makes Azure.AI.Inference record message content. Set to the content capture setting.</summary>
    public const string AzureTraceContentSwitch = "Azure.Experimental.TraceGenAIMessageContent";

    /// <summary>AppContext switch that turns on Semantic Kernel's GenAI diagnostics.</summary>
    public const string SemanticKernelDiagnosticsSwitch = "Microsoft.SemanticKernel.Experimental.GenAI.EnableOTelDiagnostics";

    /// <summary>AppContext switch that makes Semantic Kernel record message content. Set to the content capture setting.</summary>
    public const string SemanticKernelSensitiveSwitch = "Microsoft.SemanticKernel.Experimental.GenAI.EnableOTelDiagnosticsSensitive";

    /// <summary>One instrumented library.</summary>
    /// <param name="Name">The name used in <c>DisabledInstrumentors</c>.</param>
    /// <param name="ActivitySources">ActivitySource names (wildcards allowed).</param>
    /// <param name="Meters">Meter names (wildcards allowed).</param>
    /// <param name="EnableSwitches">AppContext switches set to <c>true</c>.</param>
    /// <param name="ContentSwitches">AppContext switches set to the content capture setting.</param>
    public sealed record Library(
        string Name,
        IReadOnlyList<string> ActivitySources,
        IReadOnlyList<string> Meters,
        IReadOnlyList<string> EnableSwitches,
        IReadOnlyList<string> ContentSwitches);

    /// <summary>Every library Shield360 knows about.</summary>
    public static IReadOnlyList<Library> All { get; } = new[]
    {
        new Library(
            MicrosoftExtensionsAI,
            new[] { "Experimental.Microsoft.Extensions.AI*" },
            new[] { "Experimental.Microsoft.Extensions.AI*" },
            Array.Empty<string>(),
            Array.Empty<string>()),
        new Library(
            OpenAI,
            new[] { "OpenAI.*" },
            new[] { "OpenAI.*" },
            new[] { OpenAIEnableTelemetrySwitch },
            Array.Empty<string>()),
        new Library(
            AzureAIInference,
            new[] { "Azure.AI.Inference.*" },
            new[] { "Azure.AI.Inference.*" },
            new[] { AzureEnableActivitySourceSwitch },
            new[] { AzureTraceContentSwitch }),
        new Library(
            SemanticKernel,
            new[] { "Microsoft.SemanticKernel*" },
            new[] { "Microsoft.SemanticKernel*" },
            new[] { SemanticKernelDiagnosticsSwitch },
            new[] { SemanticKernelSensitiveSwitch }),
    };
}
