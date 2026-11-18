using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Shield360.Internal;

namespace Shield360.RuleEngine;

/// <summary>The kind of entity a rule returns.</summary>
public enum RuleEntityType
{
    /// <summary>Context entities.</summary>
    Context,

    /// <summary>Prompt entities.</summary>
    Prompt,

    /// <summary>Evaluation entities.</summary>
    Evaluation,
}

/// <summary>Parameters for <see cref="RuleEngineClient.EvaluateRuleAsync"/>.</summary>
public sealed class EvaluateRuleOptions
{
    /// <summary>
    /// The Shield360 dashboard URL. Falls back to <c>SHIELD360_URL</c>, then
    /// <c>http://127.0.0.1:3000</c>. Must be HTTPS unless it points at localhost.
    /// </summary>
    public string? Url { get; set; }

    /// <summary>The API key, sent as a bearer token. Falls back to <c>SHIELD360_API_KEY</c>. Never logged.</summary>
    public string? ApiKey { get; set; }

    /// <summary>Which kind of entities to match.</summary>
    public RuleEntityType EntityType { get; set; } = RuleEntityType.Context;

    /// <summary>
    /// The trace attributes to evaluate, for example <c>gen_ai.request.model</c>.
    /// Values must be strings, numbers or booleans.
    /// </summary>
    public IDictionary<string, object?> Fields { get; set; } = new Dictionary<string, object?>();

    /// <summary>Return the full entity data as well as the matches.</summary>
    public bool IncludeEntityData { get; set; }

    /// <summary>Inputs for entity resolution, such as prompt variables.</summary>
    public IDictionary<string, object?>? EntityInputs { get; set; }

    /// <summary>Request timeout. Default: 30 seconds.</summary>
    public TimeSpan? Timeout { get; set; }
}

/// <summary>One matched rule and entity.</summary>
public sealed class RuleEntity
{
    /// <summary>The rule that matched.</summary>
    [JsonPropertyName("rule_id")]
    public string RuleId { get; set; } = string.Empty;

    /// <summary>The entity type.</summary>
    [JsonPropertyName("entity_type")]
    public string EntityType { get; set; } = string.Empty;

    /// <summary>The entity identifier.</summary>
    [JsonPropertyName("entity_id")]
    public string EntityId { get; set; } = string.Empty;
}

/// <summary>The rule engine's answer.</summary>
public sealed class EvaluateRuleResult
{
    /// <summary>The identifiers of the rules that matched.</summary>
    [JsonPropertyName("matchingRuleIds")]
    public IList<string> MatchingRuleIds { get; set; } = new List<string>();

    /// <summary>The entities attached to the matching rules.</summary>
    [JsonPropertyName("entities")]
    public IList<RuleEntity> Entities { get; set; } = new List<RuleEntity>();

    /// <summary>Full entity data, when it was asked for.</summary>
    [JsonPropertyName("entity_data")]
    public JsonElement? EntityData { get; set; }
}

/// <summary>
/// Client for the Shield360 rule engine (<c>POST /api/rule-engine/evaluate</c>),
/// the same call as the Go SDK's <c>EvaluateRule</c>. It does not need
/// <c>Shield360Sdk.Init</c>.
/// </summary>
public sealed class RuleEngineClient : IDisposable
{
    internal const string DefaultUrl = "http://127.0.0.1:3000";
    internal const string EvaluatePath = "/api/rule-engine/evaluate";

    private static readonly JsonSerializerOptions s_json = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly Func<string, string?> _env;

    /// <summary>Creates a client with its own <see cref="HttpClient"/>.</summary>
    public RuleEngineClient()
        : this(new HttpClient { Timeout = System.Threading.Timeout.InfiniteTimeSpan }, ownsHttpClient: true, Environment.GetEnvironmentVariable)
    {
    }

    /// <summary>Creates a client that sends through <paramref name="httpClient"/>, for example one from <c>IHttpClientFactory</c>.</summary>
    public RuleEngineClient(HttpClient httpClient)
        : this(httpClient ?? throw new ArgumentNullException(nameof(httpClient)), ownsHttpClient: false, Environment.GetEnvironmentVariable)
    {
    }

    internal RuleEngineClient(HttpClient httpClient, bool ownsHttpClient, Func<string, string?> env)
    {
        _http = httpClient;
        _ownsHttp = ownsHttpClient;
        _env = env;
    }

    /// <summary>
    /// Sends <paramref name="options"/>' fields to the rule engine and returns the
    /// matching rule IDs, entities and (optionally) entity data.
    /// </summary>
    /// <exception cref="Shield360Exception">
    /// The API key is missing, the URL is not allowed, the request failed, or the
    /// response was not understood. The message never contains the API key.
    /// </exception>
    public async Task<EvaluateRuleResult> EvaluateRuleAsync(EvaluateRuleOptions options, CancellationToken cancellationToken = default)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        var baseUrl = (Trimmed(options.Url) ?? Trimmed(_env("SHIELD360_URL")) ?? DefaultUrl).TrimEnd('/');
        var apiKey = Trimmed(options.ApiKey) ?? Trimmed(_env("SHIELD360_API_KEY"))
            ?? throw new Shield360Exception("Missing API key: set EvaluateRuleOptions.ApiKey or SHIELD360_API_KEY.");
        var endpoint = EndpointGuard.RequireSecure(baseUrl + EvaluatePath, "The Shield360 URL");

        if (options.Fields is null || options.Fields.Count == 0)
        {
            throw new Shield360Exception("Fields must contain at least one attribute.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(Payload(options), Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Timeout is { } t && t > TimeSpan.Zero ? t : TimeSpan.FromSeconds(30));

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new Shield360Exception("The rule engine request timed out.");
        }
        catch (HttpRequestException e)
        {
            // The inner exception is kept for its type and stack only; the
            // request (and its Authorization header) is not part of it.
            throw new Shield360Exception("The rule engine request failed.", e);
        }

        using (response)
        {
            var status = (int)response.StatusCode;
            var body = await Http.ReadBodyAsync(response.Content, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new Shield360Exception($"The rule engine returned status {status}.") { StatusCode = status };
            }

            try
            {
                return JsonSerializer.Deserialize<EvaluateRuleResult>(body, s_json)
                    ?? throw new Shield360Exception("The rule engine returned an empty response.") { StatusCode = status };
            }
            catch (JsonException e)
            {
                throw new Shield360Exception("The rule engine response could not be read.", e) { StatusCode = status };
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    internal static string Payload(EvaluateRuleOptions options)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteString("entity_type", options.EntityType.ToString().ToLowerInvariant());
            w.WritePropertyName("fields");
            WriteObject(w, options.Fields);
            w.WriteBoolean("include_entity_data", options.IncludeEntityData);
            if (options.EntityInputs is not null)
            {
                w.WritePropertyName("entity_inputs");
                WriteObject(w, options.EntityInputs);
            }

            w.WriteString("source", "dotnet-sdk");
            w.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteObject(Utf8JsonWriter w, IDictionary<string, object?> values)
    {
        w.WriteStartObject();
        foreach (var kv in values)
        {
            w.WritePropertyName(kv.Key);
            switch (kv.Value)
            {
                case null:
                    w.WriteNullValue();
                    break;
                case string s:
                    w.WriteStringValue(s);
                    break;
                case bool b:
                    w.WriteBooleanValue(b);
                    break;
                case int or long or short or byte or uint or ulong or ushort or sbyte:
                    w.WriteNumberValue(Convert.ToInt64(kv.Value, System.Globalization.CultureInfo.InvariantCulture));
                    break;
                case float or double or decimal:
                    w.WriteNumberValue(Convert.ToDouble(kv.Value, System.Globalization.CultureInfo.InvariantCulture));
                    break;
                case JsonElement e:
                    e.WriteTo(w);
                    break;
                default:
                    w.WriteStringValue(Convert.ToString(kv.Value, System.Globalization.CultureInfo.InvariantCulture));
                    break;
            }
        }

        w.WriteEndObject();
    }

    private static string? Trimmed(string? value)
    {
        var t = value?.Trim();
        return string.IsNullOrEmpty(t) ? null : t;
    }
}
