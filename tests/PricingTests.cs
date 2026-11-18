using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Shield360.Internal;
using Xunit;

namespace Shield360.Tests;

public class PricingTests
{
    private const string Json = """
        {
          "chat": {
            "gpt-4o": {"promptPrice": 0.0025, "completionPrice": 0.01, "cacheReadPrice": 0.00125},
            "claude-x": {"promptPrice": 0.003, "completionPrice": 0.015, "cacheReadPrice": 0.0003, "cacheCreationPrice": 0.00375}
          },
          "embeddings": {"text-embedding-3-small": 0.00002},
          "images": {}, "audio": {}
        }
        """;

    [Fact]
    public void Bundled_pricing_loads()
    {
        var pricing = Pricing.Bundled();
        Assert.True(pricing.ChatModelCount > 100);
        Assert.True(pricing.TryGetChatPricing("gpt-4o", out var p));
        Assert.True(p.PromptPrice > 0);
    }

    [Fact]
    public void Chat_cost_uses_prices_per_thousand_tokens()
    {
        var pricing = Pricing.Parse(Json);
        Assert.Equal(0.0025 + 0.005, pricing.ChatCost("gpt-4o", 1000, 500), 10);
    }

    [Fact]
    public void Cached_input_is_billed_at_the_cache_price_and_not_twice()
    {
        var pricing = Pricing.Parse(Json);

        // OpenAI-style usage: the 1000 input tokens include 400 cached ones.
        var inclusive = pricing.ChatCost("gpt-4o", 1000, 0, cacheReadTokens: 400, inputIncludesCache: true);
        Assert.Equal(0.6 * 0.0025 + 0.4 * 0.00125, inclusive, 10);

        // Anthropic-style usage: cache tokens are on top of the input count.
        var exclusive = pricing.ChatCost("claude-x", 1000, 0, cacheReadTokens: 1000, cacheCreationTokens: 1000, inputIncludesCache: false);
        Assert.Equal(0.003 + 0.0003 + 0.00375, exclusive, 10);
    }

    [Fact]
    public void Unknown_models_cost_nothing_and_provider_prefixes_are_ignored()
    {
        var pricing = Pricing.Parse(Json);
        Assert.Equal(0, pricing.ChatCost("no-such-model", 1000, 1000));
        Assert.Equal(0, pricing.ChatCost(null, 1000, 1000));
        Assert.Equal(pricing.ChatCost("gpt-4o", 1000, 1000), pricing.ChatCost("openai/gpt-4o", 1000, 1000));
        Assert.Equal(pricing.ChatCost("gpt-4o", 1000, 1000), pricing.ChatCost("GPT-4o", 1000, 1000));
    }

    [Fact]
    public void Embedding_cost()
    {
        var pricing = Pricing.Parse(Json);
        Assert.Equal(0.00002, pricing.EmbeddingCost("text-embedding-3-small", 1000), 12);
        Assert.Equal(0, pricing.EmbeddingCost("unknown", 1000));
    }

    [Fact]
    public void Overrides_replace_and_add_models()
    {
        var pricing = Pricing.Parse(Json).WithOverrides(new Dictionary<string, ModelPricing>
        {
            ["gpt-4o"] = new() { PromptPrice = 1, CompletionPrice = 2 },
            ["my-model"] = new() { PromptPrice = 0.5, CompletionPrice = 0.5 },
        });

        Assert.Equal(1 + 2, pricing.ChatCost("gpt-4o", 1000, 1000), 10);
        Assert.Equal(1, pricing.ChatCost("my-model", 1000, 1000), 10);
    }

    [Fact]
    public void Malformed_json_is_rejected()
    {
        Assert.Throws<Shield360Exception>(() => Pricing.Parse("{not json"));
        Assert.Throws<Shield360Exception>(() => Pricing.Parse("[]"));
    }

    [Fact]
    public async Task Loads_from_a_json_string_a_file_and_a_url()
    {
        var inline = await Pricing.LoadAsync(Json);
        Assert.Equal(2, inline.ChatModelCount);

        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, Json);
            var fromFile = await Pricing.LoadAsync(path);
            Assert.Equal(2, fromFile.ChatModelCount);
        }
        finally
        {
            File.Delete(path);
        }

        var handler = new FakeHandler(HttpStatusCode.OK, Json);
        using var http = new HttpClient(handler);
        var fromUrl = await Pricing.LoadAsync("https://pricing.example.com/pricing.json", http);
        Assert.Equal(2, fromUrl.ChatModelCount);

        using var failing = new HttpClient(new FakeHandler(HttpStatusCode.NotFound, "{}"));
        var e = await Assert.ThrowsAsync<Shield360Exception>(() => Pricing.LoadAsync("https://pricing.example.com/pricing.json", failing));
        Assert.Equal(404, e.StatusCode);

        await Assert.ThrowsAsync<Shield360Exception>(() => Pricing.LoadAsync("/no/such/pricing.json"));
    }

    [Fact]
    public void A_bad_pricing_source_falls_back_to_the_bundled_prices()
    {
        var runtime = Shield360Runtime.Create(ResolvedOptions.Resolve(
            new Shield360Options { PricingJson = "/no/such/pricing.json" }, Env.Empty));
        Assert.True(runtime.Pricing.ChatModelCount > 100);
    }

    [Fact]
    public async Task A_pricing_file_and_overrides_are_applied_by_the_runtime()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, Json);
            var runtime = Shield360Runtime.Create(ResolvedOptions.Resolve(new Shield360Options
            {
                PricingJson = path,
                PricingOverrides = new Dictionary<string, ModelPricing> { ["mine"] = new() { PromptPrice = 1, CompletionPrice = 1 } },
            }, Env.Empty));

            await runtime.PricingLoaded;
            Assert.Equal(3, runtime.Pricing.ChatModelCount);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
