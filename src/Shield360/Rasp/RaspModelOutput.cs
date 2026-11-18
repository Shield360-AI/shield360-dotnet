using System;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.Extensions.AI;

namespace Shield360.Rasp;

/// <summary>
/// The hook point the SDK's LLM instrumentation (<c>UseShield360()</c>) calls
/// with what a model returned (sdk/rasp/README.md, <c>source: "model_output"</c>).
/// No patching: the instrumentation already holds the response and hands the
/// text over. A no-op unless RASP is on with <see cref="RaspOptions.ModelOutput"/>.
/// </summary>
/// <remarks>
/// Inside a request (or <see cref="Shield360Rasp.RunInScope{T}(Func{T})"/>) the
/// fragments join that context's inputs. Outside one, the chat client enters a
/// new context into its caller's flow before the call (<see cref="PrepareScope"/>),
/// so the rest of the caller's async method sees the model's answer as input;
/// a worker gets reliable scoping by wrapping each job in <c>RunInScope</c>.
/// </remarks>
internal static class RaspModelOutput
{
    private static int s_enabled;

    public static bool Recording => Volatile.Read(ref s_enabled) == 1;

    /// <summary>Set by the engine: whether model output is recorded at all.</summary>
    public static void SetRecording(bool on) => Volatile.Write(ref s_enabled, on ? 1 : 0);

    /// <summary>
    /// Called synchronously by the instrumentation before an async call, so that a
    /// context created here reaches the caller's flow. Never throws.
    /// </summary>
    public static void PrepareScope()
    {
        if (!Recording)
        {
            return;
        }

        try
        {
            RaspScope.Ensure();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>Registers completion text a model returned as untrusted input. Never throws.</summary>
    public static void Record(string? text, string key = "model.completion")
    {
        if (!Recording || string.IsNullOrEmpty(text))
        {
            return;
        }

        try
        {
            RaspScope.Ensure().Mutate((inputs, _) => RaspNormalize.AddModelOutput(inputs, text!, key));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>Registers tool-call arguments (a JSON string, a dictionary or a JSON tree) as untrusted input. Never throws.</summary>
    public static void RecordToolArguments(object? args, string? toolName = null)
    {
        if (!Recording || args is null || (args is string s && s.Length == 0))
        {
            return;
        }

        try
        {
            var name = SafeToolName(toolName);
            RaspScope.Ensure().Mutate((inputs, _) =>
                RaspNormalize.AddToolArguments(inputs, args, name.Length > 0 ? "model.tool." + name : "model.tool"));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>
    /// Records a Microsoft.Extensions.AI response: text becomes completion fragments,
    /// function-call arguments become <c>model.tool.&lt;name&gt;</c> inputs. Never throws.
    /// </summary>
    public static void RecordChatResponse(ChatResponse? response)
    {
        if (!Recording || response is null)
        {
            return;
        }

        try
        {
            foreach (var message in response.Messages.Take(8))
            {
                // Text first, then tool calls, as the other SDKs order them.
                var text = new StringBuilder();
                var calls = new System.Collections.Generic.List<FunctionCallContent>();
                foreach (var content in message.Contents.Take(64))
                {
                    switch (content)
                    {
                        case TextContent t when !string.IsNullOrEmpty(t.Text):
                            text.Append(t.Text);
                            break;
                        case FunctionCallContent call when calls.Count < 32:
                            calls.Add(call);
                            break;
                    }
                }

                if (text.Length > 0)
                {
                    Record(text.ToString());
                }

                foreach (var call in calls)
                {
                    RecordToolArguments(call.Arguments, call.Name);
                }
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    private static string SafeToolName(string? toolName)
    {
        if (string.IsNullOrEmpty(toolName))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(Math.Min(toolName!.Length, 64));
        foreach (var c in toolName)
        {
            if (sb.Length >= 64)
            {
                break;
            }

            sb.Append((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' ? c : '_');
        }

        return sb.ToString();
    }
}
