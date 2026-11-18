using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Shield360.Rasp;

/// <summary>
/// Input normalization: percent-decoded forms, JSON flattening and model-output
/// fragments (sdk/rasp/README.md, "Sources of untrusted input" and
/// "Implementation notes"). Port of the TypeScript <c>normalize.ts</c>.
/// </summary>
internal static class RaspNormalize
{
    public const int MaxInputs = 256;
    public const int MaxValue = 4096;
    public const int MaxFragments = 32;
    public const int MaxRawBody = 8 * 1024;
    private const int MaxDepth = 16;

    private static readonly UTF8Encoding s_utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

    /// <summary>Lenient percent decoding: <c>%XX</c> to bytes, other <c>%</c> kept, <c>+</c> kept, UTF-8 with U+FFFD.</summary>
    public static string PercentDecode(string s)
    {
        if (!JsText.Has(s, '%'))
        {
            return s;
        }

        var enc = s_utf8.GetBytes(s);
        var bytes = new List<byte>(enc.Length);
        for (var i = 0; i < enc.Length; i++)
        {
            if (enc[i] == 0x25 && i + 2 < enc.Length && IsHex(enc[i + 1]) && IsHex(enc[i + 2]))
            {
                bytes.Add((byte)((Hex(enc[i + 1]) << 4) | Hex(enc[i + 2])));
                i += 2;
                continue;
            }

            bytes.Add(enc[i]);
        }

        return s_utf8.GetString(bytes.ToArray());
    }

    /// <summary>Adds an input and, for request input holding <c>%</c>, its decoded and double-decoded forms. Caps count and length.</summary>
    public static void AddInput(List<RaspInput> list, string? value, string key, RaspInputSource source = RaspInputSource.Request)
    {
        if (string.IsNullOrEmpty(value) || list.Count >= MaxInputs)
        {
            return;
        }

        var v = value!.Length > MaxValue ? value.Substring(0, MaxValue) : value;
        list.Add(new RaspInput(v, key, source));
        if (source != RaspInputSource.Request || !JsText.Has(v, '%'))
        {
            return;
        }

        var once = PercentDecode(v);
        if (once != v && list.Count < MaxInputs)
        {
            list.Add(new RaspInput(once, key, source));
            var twice = PercentDecode(once);
            if (twice != once && list.Count < MaxInputs)
            {
                list.Add(new RaspInput(twice, key, source));
            }
        }
    }

    /// <summary>
    /// Flattens the string leaves of a parsed value (<c>body.a.b</c>, arrays by index).
    /// Takes <see cref="JsonNode"/>, <see cref="JsonElement"/>, dictionaries and lists.
    /// </summary>
    public static void Flatten(List<RaspInput> list, object? value, string key, int depth = 0)
    {
        if (list.Count >= MaxInputs || depth > MaxDepth || value is null)
        {
            return;
        }

        switch (value)
        {
            case string s:
                AddInput(list, s, key);
                return;
            case JsonElement e:
                FlattenElement(list, e, key, depth);
                return;
            case JsonValue v:
                if (v.TryGetValue<string>(out var text))
                {
                    AddInput(list, text, key);
                }
                else if (v.TryGetValue<JsonElement>(out var el))
                {
                    FlattenElement(list, el, key, depth);
                }

                return;
            case JsonObject o:
                foreach (var kv in o)
                {
                    Flatten(list, kv.Value, key + "." + kv.Key, depth + 1);
                }

                return;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    Flatten(list, a[i], key + "." + i.ToString(CultureInfo.InvariantCulture), depth + 1);
                }

                return;
            case byte[]:
                return;
            case IDictionary<string, object?> d:
                foreach (var kv in d)
                {
                    Flatten(list, kv.Value, key + "." + kv.Key, depth + 1);
                }

                return;
            case IDictionary nd:
                foreach (DictionaryEntry kv in nd)
                {
                    Flatten(list, kv.Value, key + "." + Convert.ToString(kv.Key, CultureInfo.InvariantCulture), depth + 1);
                }

                return;
            case IEnumerable items:
                var index = 0;
                foreach (var item in items)
                {
                    Flatten(list, item, key + "." + index.ToString(CultureInfo.InvariantCulture), depth + 1);
                    index++;
                }

                return;
            default:
                return;
        }
    }

    private static void FlattenElement(List<RaspInput> list, JsonElement e, string key, int depth)
    {
        if (list.Count >= MaxInputs || depth > MaxDepth)
        {
            return;
        }

        switch (e.ValueKind)
        {
            case JsonValueKind.String:
                AddInput(list, e.GetString(), key);
                return;
            case JsonValueKind.Object:
                foreach (var p in e.EnumerateObject())
                {
                    FlattenElement(list, p.Value, key + "." + p.Name, depth + 1);
                }

                return;
            case JsonValueKind.Array:
                var i = 0;
                foreach (var item in e.EnumerateArray())
                {
                    FlattenElement(list, item, key + "." + i.ToString(CultureInfo.InvariantCulture), depth + 1);
                    i++;
                }

                return;
        }
    }

    /// <summary>Splits model text into fragments: the content of each fenced code block, then each line; trimmed, deduplicated, capped.</summary>
    public static List<string> ModelFragments(string text)
    {
        var output = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Push(string f)
        {
            var t = JsText.Trim(f);
            if (t.Length == 0 || seen.Contains(t) || output.Count >= MaxFragments)
            {
                return;
            }

            seen.Add(t);
            output.Add(t.Length > MaxValue ? t.Substring(0, MaxValue) : t);
        }

        var lines = text.Split('\n');
        List<string>? block = null;
        foreach (var line in lines)
        {
            if (JsText.Starts(JsText.Trim(line), "```"))
            {
                if (block is not null)
                {
                    Push(string.Join("\n", block));
                    block = null;
                }
                else
                {
                    block = new List<string>();
                }

                continue;
            }

            block?.Add(line);
        }

        if (block is not null)
        {
            Push(string.Join("\n", block));
        }

        foreach (var line in lines)
        {
            if (!JsText.Starts(JsText.Trim(line), "```"))
            {
                Push(line);
            }
        }

        return output;
    }

    /// <summary>Adds model text as <c>model_output</c> fragments.</summary>
    public static void AddModelOutput(List<RaspInput> list, string text, string key = "model.completion")
    {
        foreach (var f in ModelFragments(text))
        {
            if (list.Count >= MaxInputs)
            {
                return;
            }

            list.Add(new RaspInput(f, key, RaspInputSource.ModelOutput));
        }
    }

    /// <summary>Adds tool-call argument string leaves as <c>model_output</c> (<c>model.tool.&lt;path&gt;</c>). A string is parsed as JSON first.</summary>
    public static void AddToolArguments(List<RaspInput> list, object? args, string path = "model.tool")
    {
        if (args is string s)
        {
            try
            {
                args = JsonNode.Parse(s);
                if (args is null)
                {
                    return;
                }
            }
            catch (JsonException)
            {
                AddModelOutput(list, s, path);
                return;
            }
        }

        var tmp = new List<RaspInput>();
        Flatten(tmp, args, path);
        foreach (var i in tmp)
        {
            if (list.Count < MaxInputs)
            {
                list.Add(new RaspInput(i.Value, i.Key, RaspInputSource.ModelOutput));
            }
        }
    }

    /// <summary>Parses a Cookie header into name/value pairs.</summary>
    public static List<KeyValuePair<string, string>> ParseCookies(string? header)
    {
        var output = new List<KeyValuePair<string, string>>();
        if (string.IsNullOrEmpty(header))
        {
            return output;
        }

        foreach (var part in header!.Split(';'))
        {
            var i = part.IndexOf('=');
            if (i <= 0)
            {
                continue;
            }

            output.Add(new KeyValuePair<string, string>(JsText.Trim(part.Substring(0, i)), JsText.Trim(part.Substring(i + 1))));
        }

        return output;
    }

    /// <summary>
    /// <c>application/x-www-form-urlencoded</c> parsing as WHATWG <c>URLSearchParams</c>
    /// does it: <c>&amp;</c>-separated, split at the first <c>=</c>, <c>+</c> is a space,
    /// percent-decoded as UTF-8.
    /// </summary>
    public static List<KeyValuePair<string, string>> ParseUrlEncoded(string s)
    {
        var output = new List<KeyValuePair<string, string>>();
        if (s.Length > 0 && s[0] == '?')
        {
            s = s.Substring(1);
        }

        foreach (var part in s.Split('&'))
        {
            if (part.Length == 0)
            {
                continue;
            }

            var eq = part.IndexOf('=');
            var name = eq < 0 ? part : part.Substring(0, eq);
            var value = eq < 0 ? string.Empty : part.Substring(eq + 1);
            output.Add(new KeyValuePair<string, string>(FormDecode(name), FormDecode(value)));
        }

        return output;
    }

    private static string FormDecode(string s) => PercentDecode(s.Replace('+', ' '));

    private static bool IsHex(byte b) => (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F');

    private static int Hex(byte b) => b <= '9' ? b - '0' : (b | 0x20) - 'a' + 10;
}
