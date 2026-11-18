using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.AI;

namespace Shield360.AI;

/// <summary>
/// Writes messages in the OpenTelemetry GenAI message schema used by every
/// Shield360 SDK: <c>[{"role": "user", "parts": [{"type": "text", "content": "..."}]}]</c>.
/// </summary>
internal static class MessageJson
{
    public static string Input(IEnumerable<ChatMessage> messages) =>
        Write(w =>
        {
            w.WriteStartArray();
            foreach (var m in messages)
            {
                WriteMessage(w, m, finishReason: null);
            }

            w.WriteEndArray();
        });

    public static string Output(ChatResponse response) =>
        Write(w =>
        {
            w.WriteStartArray();
            foreach (var m in response.Messages)
            {
                WriteMessage(w, m, response.FinishReason?.Value);
            }

            w.WriteEndArray();
        });

    /// <summary>System instructions: system messages' text, then <c>ChatOptions.Instructions</c>.</summary>
    public static string? SystemInstructions(IEnumerable<ChatMessage> messages, ChatOptions? options)
    {
        var texts = messages
            .Where(m => m.Role == ChatRole.System)
            .SelectMany(m => m.Contents.OfType<TextContent>())
            .Select(t => t.Text)
            .ToList();
        if (!string.IsNullOrEmpty(options?.Instructions))
        {
            texts.Add(options!.Instructions!);
        }

        if (texts.Count == 0)
        {
            return null;
        }

        return Write(w =>
        {
            w.WriteStartArray();
            foreach (var t in texts)
            {
                w.WriteStartObject();
                w.WriteString("type", "text");
                w.WriteString("content", t);
                w.WriteEndObject();
            }

            w.WriteEndArray();
        });
    }

    /// <summary>Tool definitions offered to the model: type, name, description and parameter schema.</summary>
    public static string? ToolDefinitions(ChatOptions? options)
    {
        var tools = options?.Tools;
        if (tools is null || tools.Count == 0)
        {
            return null;
        }

        return Write(w =>
        {
            w.WriteStartArray();
            foreach (var tool in tools)
            {
                w.WriteStartObject();
                w.WriteString("type", tool is AIFunctionDeclaration ? "function" : tool.GetType().Name);
                w.WriteString("name", tool.Name);
                if (!string.IsNullOrEmpty(tool.Description))
                {
                    w.WriteString("description", tool.Description);
                }

                if (tool is AIFunctionDeclaration f)
                {
                    w.WritePropertyName("parameters");
                    f.JsonSchema.WriteTo(w);
                }

                w.WriteEndObject();
            }

            w.WriteEndArray();
        });
    }

    public static string Serialize(object? value)
    {
        if (value is null)
        {
            return "null";
        }

        if (value is string s)
        {
            return s;
        }

        if (value is JsonElement e)
        {
            return e.GetRawText();
        }

        return JsonSerializer.Serialize(value, AIJsonUtilities.DefaultOptions.GetTypeInfo(value.GetType()));
    }

    private static void WriteMessage(Utf8JsonWriter w, ChatMessage m, string? finishReason)
    {
        w.WriteStartObject();
        w.WriteString("role", m.Role.Value);
        w.WritePropertyName("parts");
        w.WriteStartArray();
        foreach (var content in m.Contents)
        {
            switch (content)
            {
                case TextContent t:
                    w.WriteStartObject();
                    w.WriteString("type", "text");
                    w.WriteString("content", t.Text);
                    w.WriteEndObject();
                    break;
                case TextReasoningContent r:
                    w.WriteStartObject();
                    w.WriteString("type", "reasoning");
                    w.WriteString("content", r.Text);
                    w.WriteEndObject();
                    break;
                case FunctionCallContent call:
                    w.WriteStartObject();
                    w.WriteString("type", "tool_call");
                    w.WriteString("id", call.CallId);
                    w.WriteString("name", call.Name);
                    w.WritePropertyName("arguments");
                    w.WriteRawValue(call.Arguments is null ? "{}" : Serialize(call.Arguments));
                    w.WriteEndObject();
                    break;
                case FunctionResultContent result:
                    w.WriteStartObject();
                    w.WriteString("type", "tool_call_response");
                    w.WriteString("id", result.CallId);
                    w.WriteString("result", result.Result is string rs ? rs : Serialize(result.Result));
                    w.WriteEndObject();
                    break;
                case UriContent uri:
                    w.WriteStartObject();
                    w.WriteString("type", "uri");
                    w.WriteString("uri", uri.Uri.ToString());
                    w.WriteString("mime_type", uri.MediaType);
                    w.WriteEndObject();
                    break;
                case DataContent data:
                    // The bytes are not copied onto the span; the type is enough to show what was sent.
                    w.WriteStartObject();
                    w.WriteString("type", "blob");
                    w.WriteString("mime_type", data.MediaType);
                    w.WriteEndObject();
                    break;
            }
        }

        w.WriteEndArray();
        if (finishReason is not null)
        {
            w.WriteString("finish_reason", finishReason);
        }

        w.WriteEndObject();
    }

    private static string Write(System.Action<Utf8JsonWriter> body)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            body(writer);
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }
}
