using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.AI;
using Shield360.Internal;
using Shield360.Rasp;

namespace Shield360.AI;

/// <summary>
/// An <see cref="IChatClient"/> middleware that records each call as a Shield360
/// GenAI span (<c>chat {model}</c>) with token usage, cost, and the GenAI
/// metrics. Prompt and response text is recorded only when content capture is on.
/// Add it with <c>chatClientBuilder.UseShield360()</c>.
/// </summary>
/// <remarks>
/// This middleware does the job of <c>UseOpenTelemetry()</c> for Shield360; use
/// one or the other in a pipeline, not both, or each call is traced twice.
/// </remarks>
public sealed class Shield360ChatClient : DelegatingChatClient
{
    private readonly Shield360ChatClientOptions? _options;

    /// <summary>Wraps <paramref name="innerClient"/>.</summary>
    public Shield360ChatClient(IChatClient innerClient, Shield360ChatClientOptions? options = null)
        : base(innerClient)
    {
        _options = options;
    }

    /// <inheritdoc />
    public override Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        // Synchronous on purpose: a RASP context made here reaches the caller, so
        // the model's answer counts as untrusted input after the call returns.
        RaspModelOutput.PrepareScope();
        return GetResponseCoreAsync(messages, options, cancellationToken);
    }

    /// <inheritdoc />
    public override IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        RaspModelOutput.PrepareScope();
        return GetStreamingResponseCoreAsync(messages, options, cancellationToken);
    }

    private async Task<ChatResponse> GetResponseCoreAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options,
        CancellationToken cancellationToken)
    {
        var list = messages as IList<ChatMessage> ?? messages.ToList();
        using var call = Begin(list, options, streaming: false);
        ChatResponse response;
        try
        {
            response = await base.GetResponseAsync(list, options, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            call.Fail(e);
            throw;
        }

        call.Complete(response);
        RaspModelOutput.RecordChatResponse(response);
        return response;
    }

    private async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseCoreAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var list = messages as IList<ChatMessage> ?? messages.ToList();
        using var call = Begin(list, options, streaming: true);

        IAsyncEnumerator<ChatResponseUpdate> enumerator;
        try
        {
            enumerator = base.GetStreamingResponseAsync(list, options, cancellationToken).GetAsyncEnumerator(cancellationToken);
        }
        catch (Exception e)
        {
            call.Fail(e);
            throw;
        }

        var updates = new List<ChatResponseUpdate>();
        try
        {
            while (true)
            {
                try
                {
                    if (!await enumerator.MoveNextAsync().ConfigureAwait(false))
                    {
                        break;
                    }
                }
                catch (Exception e)
                {
                    call.Fail(e);
                    throw;
                }

                call.Chunk();
                updates.Add(enumerator.Current);
                yield return enumerator.Current;
            }
        }
        finally
        {
            await enumerator.DisposeAsync().ConfigureAwait(false);

            // Also reached when the caller stops reading early: the span then
            // records what was received.
            if (!call.Ended)
            {
                var response = updates.ToChatResponse();
                call.Complete(response);
                RaspModelOutput.RecordChatResponse(response);
            }
        }
    }

    private ChatCall Begin(IList<ChatMessage> messages, ChatOptions? options, bool streaming)
    {
        var runtime = Shield360Runtime.Current;
        var metadata = InnerClient.GetService<ChatClientMetadata>();
        var settings = new ChatCallSettings(
            ApplicationName: _options?.ApplicationName ?? runtime?.Options.ApplicationName ?? ResolvedOptions.DefaultName,
            Environment: _options?.Environment ?? runtime?.Options.Environment ?? ResolvedOptions.DefaultName,
            CaptureMessageContent: _options?.CaptureMessageContent ?? runtime?.Options.CaptureMessageContent ?? false,
            Pricing: _options?.Pricing ?? runtime?.Pricing ?? Shield360Runtime.BundledPricing,
            CustomSpanAttributes: runtime?.Options.CustomSpanAttributes,
            ProviderName: metadata?.ProviderName ?? _options?.ProviderName,
            ServerUri: metadata?.ProviderUri,
            RequestModel: options?.ModelId ?? metadata?.DefaultModelId);
        return ChatCall.Start(settings, messages, options, streaming);
    }
}
