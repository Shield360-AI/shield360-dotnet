using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Shield360.Internal;

namespace Shield360;

/// <summary>
/// Model prices used to compute <c>gen_ai.usage.cost</c>. The format is the
/// Shield360 pricing JSON shared by every SDK: <c>chat</c> entries carry
/// <c>promptPrice</c>, <c>completionPrice</c> and optional <c>cacheReadPrice</c>
/// and <c>cacheCreationPrice</c>; <c>embeddings</c> entries are a single price.
/// All prices are USD per 1,000 tokens.
/// </summary>
public sealed class Pricing
{
    private const double TokenFactor = 1000;
    private const string BundledResource = "Shield360.pricing.json";

    private readonly Dictionary<string, ModelPricing> _chat;
    private readonly Dictionary<string, double> _embeddings;

    private Pricing(Dictionary<string, ModelPricing> chat, Dictionary<string, double> embeddings)
    {
        _chat = chat;
        _embeddings = embeddings;
    }

    /// <summary>A table with no prices; every cost is zero.</summary>
    public static Pricing Empty { get; } = new(
        new Dictionary<string, ModelPricing>(StringComparer.OrdinalIgnoreCase),
        new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase));

    /// <summary>The number of chat models priced.</summary>
    public int ChatModelCount => _chat.Count;

    /// <summary>The pricing data shipped with the SDK.</summary>
    public static Pricing Bundled()
    {
        using var stream = typeof(Pricing).Assembly.GetManifestResourceStream(BundledResource)
            ?? throw new Shield360Exception("The bundled pricing data is missing from the Shield360 assembly.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    }

    /// <summary>Parses pricing JSON.</summary>
    /// <exception cref="Shield360Exception">The JSON is malformed.</exception>
    public static Pricing Parse(string json)
    {
        var chat = new Dictionary<string, ModelPricing>(StringComparer.OrdinalIgnoreCase);
        var embeddings = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new Shield360Exception("Pricing JSON must be an object.");
            }

            if (root.TryGetProperty("chat", out var chatElement) && chatElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var model in chatElement.EnumerateObject())
                {
                    if (model.Value.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    chat[model.Name] = new ModelPricing
                    {
                        PromptPrice = Number(model.Value, "promptPrice") ?? 0,
                        CompletionPrice = Number(model.Value, "completionPrice") ?? 0,
                        CacheReadPrice = Number(model.Value, "cacheReadPrice"),
                        CacheCreationPrice = Number(model.Value, "cacheCreationPrice"),
                    };
                }
            }

            if (root.TryGetProperty("embeddings", out var embedElement) && embedElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var model in embedElement.EnumerateObject())
                {
                    if (model.Value.ValueKind == JsonValueKind.Number)
                    {
                        embeddings[model.Name] = model.Value.GetDouble();
                    }
                }
            }
        }
        catch (JsonException e)
        {
            throw new Shield360Exception("Pricing JSON is malformed.", e);
        }

        return new Pricing(chat, embeddings);
    }

    /// <summary>
    /// Loads pricing from a URL, a file path or a JSON string. With no source,
    /// returns the bundled pricing data.
    /// </summary>
    public static async Task<Pricing> LoadAsync(string? source, HttpClient? httpClient = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return Bundled();
        }

        var s = source!.Trim();
        if (s.StartsWith("{", StringComparison.Ordinal))
        {
            return Parse(s);
        }

        if (Uri.TryCreate(s, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
        {
            var owned = httpClient is null;
            var client = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            try
            {
                using var response = await client.GetAsync(uri, cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    throw new Shield360Exception($"Fetching pricing data failed with status {(int)response.StatusCode}.") { StatusCode = (int)response.StatusCode };
                }

                return Parse(await Http.ReadBodyAsync(response.Content, cancellationToken).ConfigureAwait(false));
            }
            finally
            {
                if (owned)
                {
                    client.Dispose();
                }
            }
        }

        if (!File.Exists(s))
        {
            throw new Shield360Exception("The pricing file was not found.");
        }

        return Parse(File.ReadAllText(s));
    }

    /// <summary>Returns a copy with <paramref name="overrides"/> replacing or adding chat prices.</summary>
    public Pricing WithOverrides(IEnumerable<KeyValuePair<string, ModelPricing>>? overrides)
    {
        var chat = new Dictionary<string, ModelPricing>(_chat, StringComparer.OrdinalIgnoreCase);
        if (overrides is not null)
        {
            foreach (var kv in overrides)
            {
                if (!string.IsNullOrWhiteSpace(kv.Key) && kv.Value is not null)
                {
                    chat[kv.Key.Trim()] = kv.Value;
                }
            }
        }

        return new Pricing(chat, new Dictionary<string, double>(_embeddings, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>Finds the chat prices for a model: an exact match, then the part after a <c>provider/</c> prefix.</summary>
    public bool TryGetChatPricing(string? model, out ModelPricing pricing) => TryFind(_chat, model, out pricing!);

    /// <summary>
    /// The cost of a chat call in USD, the same calculation as the Python and
    /// TypeScript SDKs. When the model has a cache price, cache tokens are billed
    /// at it; with <paramref name="inputIncludesCache"/> (OpenAI-style usage, where
    /// input tokens include cached ones) they are taken out of the input count so
    /// they are not billed twice. Unknown models cost zero.
    /// </summary>
    public double ChatCost(
        string? model,
        long inputTokens,
        long outputTokens,
        long cacheReadTokens = 0,
        long cacheCreationTokens = 0,
        bool inputIncludesCache = true)
    {
        if (!TryGetChatPricing(model, out var p))
        {
            return 0;
        }

        double billableInput = inputTokens;
        double cacheCost = 0;
        if (p.CacheReadPrice is double readPrice)
        {
            cacheCost += cacheReadTokens / TokenFactor * readPrice;
            if (inputIncludesCache)
            {
                billableInput -= cacheReadTokens;
            }
        }

        if (p.CacheCreationPrice is double createPrice)
        {
            cacheCost += cacheCreationTokens / TokenFactor * createPrice;
            if (inputIncludesCache)
            {
                billableInput -= cacheCreationTokens;
            }
        }

        if (billableInput < 0)
        {
            billableInput = 0;
        }

        var cost = billableInput / TokenFactor * p.PromptPrice + outputTokens / TokenFactor * p.CompletionPrice + cacheCost;
        return double.IsNaN(cost) || double.IsInfinity(cost) ? 0 : cost;
    }

    /// <summary>The cost of an embeddings call in USD. Unknown models cost zero.</summary>
    public double EmbeddingCost(string? model, long inputTokens) =>
        TryFind(_embeddings, model, out var unit) ? inputTokens / TokenFactor * unit : 0;

    private static bool TryFind<T>(Dictionary<string, T> table, string? model, out T value)
    {
        value = default!;
        if (string.IsNullOrWhiteSpace(model))
        {
            return false;
        }

        var m = model!.Trim();
        if (table.TryGetValue(m, out value!))
        {
            return true;
        }

        var slash = m.IndexOf('/');
        return slash >= 0 && table.TryGetValue(m.Substring(slash + 1), out value!);
    }

    private static double? Number(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : null;
}
