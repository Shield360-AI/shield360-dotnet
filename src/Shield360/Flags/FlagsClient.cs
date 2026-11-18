using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Shield360.Internal;

namespace Shield360.Flags;

/// <summary>Settings for a <see cref="FlagsClient"/>. Every property is optional.</summary>
public sealed class FlagsOptions
{
    /// <summary>
    /// The Shield360 URL. Falls back to the initialised SDK's <see cref="Shield360Options.Shield360Url"/>,
    /// then <c>SHIELD360_URL</c>. Must be HTTPS unless it points at localhost.
    /// </summary>
    public string? Url { get; set; }

    /// <summary>
    /// The environment's API key, sent as a bearer token. Falls back to the initialised SDK's
    /// <see cref="Shield360Options.ApiKey"/>, then <c>SHIELD360_API_KEY</c>. Never logged.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// The application's <c>service.name</c>, for flags scoped to one application. Falls back to
    /// the initialised SDK's <see cref="Shield360Options.ApplicationName"/>, then <c>OTEL_SERVICE_NAME</c>.
    /// </summary>
    public string? ApplicationName { get; set; }

    /// <summary>How often to fetch the rules (at least 5 seconds, with ±10% jitter). Default: 30 seconds.</summary>
    public TimeSpan? PollInterval { get; set; }

    /// <summary>Timeout for each request. Default: 10 seconds.</summary>
    public TimeSpan? Timeout { get; set; }

    /// <summary>Set <c>shield360.flag.&lt;key&gt;</c> = the served variation on <see cref="Activity.Current"/>. Default: true.</summary>
    public bool RecordOnActivity { get; set; } = true;

    /// <summary>The <see cref="System.Net.Http.HttpClient"/> to send with, for example one from <c>IHttpClientFactory</c>. Not disposed by the client.</summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>A handler to send through when <see cref="HttpClient"/> is not set (for tests and proxies). Not disposed by the client.</summary>
    public HttpMessageHandler? HttpHandler { get; set; }
}

/// <summary>A flag's value for one context, the variation served and why.</summary>
public sealed class FlagDetail
{
    internal FlagDetail(JsonNode? value, string? variation, FlagReason reason)
    {
        Value = value;
        Variation = variation;
        Reason = reason;
    }

    /// <summary>The served value, or the caller's default.</summary>
    public JsonNode? Value { get; }

    /// <summary>The served variation's key; null when the caller's default was returned.</summary>
    public string? Variation { get; }

    /// <summary>Why: an engine reason, or NOT_READY, FLAG_NOT_FOUND, WRONG_TYPE or ERROR.</summary>
    public FlagReason Reason { get; }
}

/// <summary>A Prompt Hub prompt, by name and optionally version.</summary>
public sealed class PromptRef
{
    /// <summary>Creates a reference.</summary>
    public PromptRef(string name, string? version = null)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        Version = string.IsNullOrEmpty(version) ? null : version;
    }

    /// <summary>The prompt's name.</summary>
    public string Name { get; }

    /// <summary>The version; null for the latest.</summary>
    public string? Version { get; }

    /// <summary>
    /// Reads a flag value: <c>{"name": "...", "version": "..."}</c>, <c>"name"</c> or
    /// <c>"name@version"</c>. False for anything else.
    /// </summary>
    public static bool TryParse(JsonNode? value, out PromptRef? reference)
    {
        reference = null;
        if (FlagEngine.TryString(value, out var text))
        {
            text = text.Trim();
            var at = text.LastIndexOf('@');
            if (at == 0)
            {
                return false; // "@version" names no prompt
            }

            var name = at > 0 ? text.Substring(0, at).Trim() : text;
            var version = at > 0 ? text.Substring(at + 1).Trim() : null;
            if (name.Length == 0)
            {
                return false;
            }

            reference = new PromptRef(name, version);
            return true;
        }

        if (value is JsonObject o)
        {
            if (!FlagEngine.TryString(o["name"], out var name) || name.Trim().Length == 0)
            {
                return false;
            }

            string? version = null;
            if (o.TryGetPropertyValue("version", out var v) && v is not null)
            {
                if (FlagEngine.TryString(v, out var s))
                {
                    version = s.Trim();
                }
                else if (FlagEngine.TryNumber(v, out var n))
                {
                    version = FlagEngine.JsNumber(n);
                }
                else
                {
                    return false;
                }
            }

            reference = new PromptRef(name.Trim(), version);
            return true;
        }

        return false;
    }

    /// <inheritdoc />
    public override string ToString() => Version is null ? Name : Name + "@" + Version;
}

/// <summary>Options for <see cref="FlagsClient.PromptAsync"/>.</summary>
public sealed class PromptOptions
{
    /// <summary>Variables to compile the prompt with.</summary>
    public IDictionary<string, object?>? Variables { get; set; }

    /// <summary>Compile the prompt with <see cref="Variables"/>. Default: true when variables are given.</summary>
    public bool? ShouldCompile { get; set; }

    /// <summary>Request timeout. Default: the client's timeout.</summary>
    public TimeSpan? Timeout { get; set; }
}

/// <summary>The prompt a flag chose, fetched from the Prompt Hub.</summary>
public sealed class PromptResult
{
    /// <summary>The prompt's name (from the flag, or the default reference).</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>The version asked for; null for the latest.</summary>
    public string? Version { get; init; }

    /// <summary>The flag variation that chose the prompt; null when the default reference was used.</summary>
    public string? Variation { get; init; }

    /// <summary>The Prompt Hub's answer (the compiled prompt and its metadata); null when the fetch failed.</summary>
    public JsonNode? Prompt { get; init; }

    /// <summary>Why <see cref="Prompt"/> is null; null on success. Never contains the API key.</summary>
    public string? Error { get; init; }
}

/// <summary>
/// Shield360 feature flags: polls an environment's flags
/// (<c>GET /api/flags/rules</c>) in the background and evaluates them locally
/// with <see cref="FlagEngine"/>, the same engine as the server and the other
/// SDKs. Nothing here throws into the app: until rules arrive, for an unknown
/// flag, or on any error, the caller's default is returned. Thread-safe.
/// </summary>
public sealed class FlagsClient : IDisposable
{
    /// <summary>The rules route.</summary>
    public const string RulesPath = "/api/flags/rules";

    /// <summary>The Prompt Hub route <see cref="PromptAsync"/> fetches from.</summary>
    public const string PromptPath = "/api/prompt/get-compiled";

    /// <summary>Prefix of the Activity tag that records the served variation.</summary>
    public const string ActivityTagPrefix = "shield360.flag.";

    /// <summary>The default poll interval.</summary>
    public static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan s_minPollInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan s_defaultTimeout = TimeSpan.FromSeconds(10);

    private readonly object _lock = new();
    private readonly Func<string, string?> _env;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly string? _url;
    private readonly string? _apiKey;
    private readonly string? _applicationName;
    private readonly TimeSpan _pollInterval;
    private readonly TimeSpan _timeout;
    private readonly bool _recordOnActivity;
    private readonly Random _jitter = new();
    private readonly TaskCompletionSource<bool> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _disposed = new();

    private Rules? _rules;
    private Task<bool>? _inFlight;
    private CancellationTokenSource? _loopStop;
    private Task? _loop;
    private bool _closed;
    private bool _isDisposed;
    private int _warned;

    /// <summary>Creates a client that reads the SDK's settings and the environment.</summary>
    public FlagsClient()
        : this(null)
    {
    }

    /// <summary>Creates a client with these settings.</summary>
    public FlagsClient(FlagsOptions? options)
        : this(options, System.Environment.GetEnvironmentVariable)
    {
    }

    internal FlagsClient(FlagsOptions? options, Func<string, string?> env)
    {
        var o = options ?? new FlagsOptions();
        _env = env;
        _url = Trimmed(o.Url);
        _apiKey = Trimmed(o.ApiKey);
        _applicationName = Trimmed(o.ApplicationName);
        var interval = o.PollInterval ?? DefaultPollInterval;
        _pollInterval = interval < s_minPollInterval ? s_minPollInterval : interval;
        _timeout = o.Timeout is { } t && t > TimeSpan.Zero ? t : s_defaultTimeout;
        _recordOnActivity = o.RecordOnActivity;
        if (o.HttpClient is not null)
        {
            _http = o.HttpClient;
        }
        else
        {
            _http = o.HttpHandler is null
                ? new HttpClient { Timeout = System.Threading.Timeout.InfiniteTimeSpan }
                : new HttpClient(o.HttpHandler, disposeHandler: false) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
            _ownsHttp = true;
        }
    }

    /// <summary>Whether rules have been fetched at least once.</summary>
    public bool IsReady => Volatile.Read(ref _rules) is not null;

    // ---------------------------------------------------------------- polling

    /// <summary>Starts polling (once). Called on first use; call it at start-up to fetch early.</summary>
    public void Start()
    {
        lock (_lock)
        {
            if (_isDisposed || (_loop is not null && !_loop.IsCompleted))
            {
                return;
            }

            _closed = false;
            _loopStop = new CancellationTokenSource();
            var token = _loopStop.Token;
            _loop = Task.Run(() => RunAsync(token));
        }
    }

    private void EnsureStarted()
    {
        if (Volatile.Read(ref _loop) is null && !Volatile.Read(ref _closed))
        {
            Start();
        }
    }

    private async Task RunAsync(CancellationToken stop)
    {
        while (!stop.IsCancellationRequested)
        {
            await RefreshAsync().ConfigureAwait(false);
            double factor;
            lock (_jitter)
            {
                // ±10% jitter, so many processes started together do not poll together.
#pragma warning disable CA5394 // Jitter, not security.
                factor = 0.9 + (_jitter.NextDouble() * 0.2);
#pragma warning restore CA5394
            }

            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(_pollInterval.TotalMilliseconds * factor), stop).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>Stops polling. Rules already fetched keep being served; <see cref="Start"/> resumes.</summary>
    public void Close()
    {
        lock (_lock)
        {
            _closed = true;
            _loopStop?.Cancel();
            _loop = null;
        }
    }

    /// <summary>Stops polling and releases the HTTP client the client created.</summary>
    public void Dispose()
    {
        lock (_lock)
        {
            if (_isDisposed)
            {
                return;
            }

            _isDisposed = true;
            _closed = true;
            _loopStop?.Cancel();
            _loop = null;
            _disposed.Cancel();
        }

        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    /// <summary>Completes with true once rules have been fetched, or false after <paramref name="timeout"/> (default 10 seconds).</summary>
    public async Task<bool> WaitUntilReadyAsync(TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        Start();
        if (IsReady)
        {
            return true;
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var delay = Task.Delay(timeout is { } t && t >= TimeSpan.Zero ? t : s_defaultTimeout, cts.Token);
        var done = await Task.WhenAny(_ready.Task, delay).ConfigureAwait(false);
        cts.Cancel();
        return done == _ready.Task || IsReady;
    }

    /// <summary>Fetches the rules now. True when they are current; never throws.</summary>
    public Task<bool> RefreshAsync()
    {
        lock (_lock)
        {
            return _inFlight ??= FetchGuardedAsync();
        }
    }

    private async Task<bool> FetchGuardedAsync()
    {
        await Task.Yield();
        try
        {
            return await FetchAsync().ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Never throws into the app.
        catch (Exception e)
#pragma warning restore CA1031
        {
            Trace.TraceInformation("Shield360 flags: the rules fetch failed ({0}).", e.GetType().Name);
            return false;
        }
        finally
        {
            lock (_lock)
            {
                _inFlight = null;
            }
        }
    }

    private async Task<bool> FetchAsync()
    {
        var destination = Destination(RulesPath);
        if (destination is null)
        {
            return false;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, destination.Value.Endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", destination.Value.ApiKey);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var etag = Volatile.Read(ref _rules)?.ETag;
        if (etag is not null)
        {
            request.Headers.TryAddWithoutValidation("If-None-Match", etag);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_disposed.Token);
        timeout.CancelAfter(_timeout);
        using var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            Publish(Volatile.Read(ref _rules) ?? new Rules(new Dictionary<string, JsonObject>(StringComparer.Ordinal), new List<JsonNode?>(), etag));
            return true;
        }

        if (!response.IsSuccessStatusCode)
        {
            Trace.TraceInformation("Shield360 flags: the rules fetch answered {0}.", (int)response.StatusCode);
            return false;
        }

        var body = await Http.ReadBodyAsync(response.Content, timeout.Token).ConfigureAwait(false);
        if (JsonNode.Parse(body) is not JsonObject root || root["flags"] is not JsonArray flags)
        {
            return false;
        }

        var byKey = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var raw in flags)
        {
            // A flag that does not validate is left out: its callers get their default.
            // Validating also walks every node evaluation reads, so the shared tree
            // is fully built before other threads read it.
            if (FlagEngine.ValidateFlag(raw).Count > 0)
            {
                continue;
            }

            FlagEngine.TryString(raw!["key"], out var key);
            byKey[key] = (JsonObject)raw;
        }

        var segments = new List<JsonNode?>();
        if (root["segments"] is JsonArray rawSegments)
        {
            foreach (var s in rawSegments)
            {
                if (FlagEngine.ValidateSegment(s).Count == 0)
                {
                    segments.Add(s);
                }
            }
        }

        Publish(new Rules(byKey, segments, ReadETag(response)));
        return true;
    }

    private static string? ReadETag(HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues("ETag", out var values))
        {
            foreach (var v in values)
            {
                if (!string.IsNullOrEmpty(v))
                {
                    return v;
                }
            }
        }

        return null;
    }

    private void Publish(Rules rules)
    {
        Volatile.Write(ref _rules, rules);
        _ready.TrySetResult(true);
    }

    // ------------------------------------------------------------ destination

    private (Uri Endpoint, string ApiKey)? Destination(string path)
    {
        var runtime = Shield360Runtime.Current?.Options;
        var url = (_url ?? runtime?.Shield360Url ?? Trimmed(_env("SHIELD360_URL")))?.TrimEnd('/');
        var apiKey = _apiKey ?? runtime?.ApiKey ?? Trimmed(_env("SHIELD360_API_KEY"));
        if (url is null || apiKey is null)
        {
            WarnOnce("no Shield360 URL and API key (SHIELD360_URL, SHIELD360_API_KEY); every flag serves its default.");
            return null;
        }

        try
        {
            return (EndpointGuard.RequireSecure(url + path, "The Shield360 URL"), apiKey);
        }
        catch (Shield360Exception e)
        {
            WarnOnce(e.Message);
            return null;
        }
    }

    private string? ApplicationName() =>
        _applicationName ?? Shield360Runtime.Current?.Options.ApplicationName ?? Trimmed(_env("OTEL_SERVICE_NAME"));

    private string? EnvironmentName() =>
        Shield360Runtime.Current?.Options.Environment ?? Trimmed(_env("OTEL_DEPLOYMENT_ENVIRONMENT"));

    private void WarnOnce(string message)
    {
        if (Interlocked.Exchange(ref _warned, 1) == 0)
        {
            Trace.TraceWarning("Shield360 flags: {0}", message);
        }
    }

    // ------------------------------------------------------------- evaluation

    /// <summary>
    /// The flag's value for this context, with the variation and why. A served
    /// value of another kind than <paramref name="defaultValue"/> (when it is
    /// not null) gives WRONG_TYPE and the default. Never throws.
    /// </summary>
    public FlagDetail GetFlagDetail(string key, IDictionary<string, object?>? context = null, JsonNode? defaultValue = null)
    {
        try
        {
            EnsureStarted();
            var rules = Volatile.Read(ref _rules);
            if (rules is null)
            {
                return new FlagDetail(defaultValue, null, new FlagReason(FlagReasonKinds.NotReady));
            }

            if (key is null || !rules.Flags.TryGetValue(key, out var flag) || !ServedHere(flag))
            {
                return new FlagDetail(defaultValue, null, new FlagReason(FlagReasonKinds.FlagNotFound));
            }

            var result = FlagEngine.EvaluateWith(flag, FlagEngine.ContextOf(context), rules.Segments);
            if (result.Variation is null)
            {
                return new FlagDetail(defaultValue, null, result.Reason);
            }

            if (!SameKind(result.Value, defaultValue))
            {
                return new FlagDetail(defaultValue, null, new FlagReason(FlagReasonKinds.WrongType));
            }

            if (_recordOnActivity && Activity.Current is { IsAllDataRequested: true } activity)
            {
                activity.SetTag(ActivityTagPrefix + key, result.Variation);
            }

            return new FlagDetail(result.Value, result.Variation, result.Reason);
        }
#pragma warning disable CA1031 // Never throws into the app.
        catch (Exception)
#pragma warning restore CA1031
        {
            return new FlagDetail(defaultValue, null, new FlagReason(FlagReasonKinds.Error));
        }
    }

    /// <summary>A boolean flag's value, or <paramref name="defaultValue"/>. Never throws.</summary>
    public bool GetBool(string key, IDictionary<string, object?>? context, bool defaultValue) =>
        FlagEngine.TryBool(GetFlagDetail(key, context, JsonValue.Create(defaultValue)).Value, out var b) ? b : defaultValue;

    /// <summary>A string flag's value, or <paramref name="defaultValue"/>. Never throws.</summary>
    public string GetString(string key, IDictionary<string, object?>? context, string defaultValue)
    {
        var detail = GetFlagDetail(key, context, JsonValue.Create(defaultValue ?? string.Empty));
        return detail.Variation is not null && FlagEngine.TryString(detail.Value, out var s) ? s : defaultValue!;
    }

    /// <summary>A number flag's value, or <paramref name="defaultValue"/>. Never throws.</summary>
    public double GetNumber(string key, IDictionary<string, object?>? context, double defaultValue)
    {
        var detail = GetFlagDetail(key, context, JsonValue.Create(0d));
        return detail.Variation is not null && FlagEngine.TryNumber(detail.Value, out var d) ? d : defaultValue;
    }

    /// <summary>
    /// A JSON flag's value, or <paramref name="defaultValue"/>. An object or array
    /// default takes an object or array value; a null default takes any value. Never throws.
    /// </summary>
    public JsonNode? GetJson(string key, IDictionary<string, object?>? context, JsonNode? defaultValue) =>
        GetFlagDetail(key, context, defaultValue).Value;

    /// <summary>Whether a boolean flag is on for this context; false until rules arrive, for an unknown flag, or on error.</summary>
    public bool IsEnabled(string key, IDictionary<string, object?>? context = null) => GetBool(key, context, false);

    // ------------------------------------------------------------- AI helpers

    /// <summary>
    /// The model a string flag picks for this context, such as <c>openai/gpt-4o-mini</c>,
    /// or <paramref name="defaultModel"/>. Never throws.
    /// </summary>
    public string Model(string key, IDictionary<string, object?>? context, string defaultModel)
    {
        var model = GetString(key, context, defaultModel);
        return string.IsNullOrWhiteSpace(model) ? defaultModel : model;
    }

    /// <summary>
    /// Whether a kill switch is engaged, meaning the feature should stop: the
    /// boolean flag is false for this context. Not engaged until rules arrive,
    /// for an unknown flag, or on error. Never throws.
    /// </summary>
    public bool KillSwitch(string key, IDictionary<string, object?>? context = null) => !GetBool(key, context, true);

    /// <summary>
    /// Fetches the Prompt Hub prompt a flag picks for this context. The flag's
    /// value is <c>{"name": "...", "version": "..."}</c>, <c>"name"</c> or
    /// <c>"name@version"</c>; <paramref name="defaultRef"/> is used when the flag
    /// serves nothing usable. Never throws: a failed fetch sets <see cref="PromptResult.Error"/>.
    /// </summary>
    public async Task<PromptResult> PromptAsync(
        string key,
        IDictionary<string, object?>? context,
        PromptRef defaultRef,
        PromptOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        PromptRef? reference = null;
        string? variation = null;
        var detail = GetFlagDetail(key, context, null);
        if (detail.Variation is not null && PromptRef.TryParse(detail.Value, out var picked))
        {
            reference = picked;
            variation = detail.Variation;
        }

        reference ??= defaultRef;
        if (reference is null)
        {
            return new PromptResult { Error = "No prompt reference." };
        }

        PromptResult Result(JsonNode? prompt, string? error) => new()
        {
            Name = reference.Name,
            Version = reference.Version,
            Variation = variation,
            Prompt = prompt,
            Error = error,
        };

        try
        {
            var destination = Destination(PromptPath);
            if (destination is null)
            {
                return Result(null, "No Shield360 URL and API key (SHIELD360_URL, SHIELD360_API_KEY).");
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, destination.Value.Endpoint)
            {
                Content = new StringContent(PromptPayload(reference, options), Encoding.UTF8, "application/json"),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", destination.Value.ApiKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposed.Token);
            timeout.CancelAfter(options?.Timeout is { } t && t > TimeSpan.Zero ? t : _timeout);
            using var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return Result(null, "The Prompt Hub returned status " + ((int)response.StatusCode).ToString(System.Globalization.CultureInfo.InvariantCulture) + ".");
            }

            var body = await Http.ReadBodyAsync(response.Content, timeout.Token).ConfigureAwait(false);
            if (JsonNode.Parse(body) is not JsonObject root)
            {
                return Result(null, "The Prompt Hub response could not be read.");
            }

            // The route answers {err, res}; `data` is accepted too.
            var err = root["err"];
            if (err is not null && !(FlagEngine.TryString(err, out var e) && e.Length == 0))
            {
                return Result(null, FlagEngine.TryString(err, out var message) ? message : err.ToJsonString());
            }

            var prompt = root["res"] ?? root["data"];
            return prompt is null ? Result(null, "The Prompt Hub returned no prompt.") : Result(prompt.DeepClone(), null);
        }
        catch (OperationCanceledException)
        {
            return Result(null, cancellationToken.IsCancellationRequested ? "The prompt request was cancelled." : "The prompt request timed out.");
        }
#pragma warning disable CA1031 // Never throws into the app.
        catch (Exception e)
#pragma warning restore CA1031
        {
            // Only the exception type: the request (and its Authorization header) is not reported.
            return Result(null, "The prompt request failed (" + e.GetType().Name + ").");
        }
    }

    internal string PromptPayload(PromptRef reference, PromptOptions? options)
    {
        var payload = new JsonObject
        {
            ["name"] = reference.Name,
        };
        if (reference.Version is not null)
        {
            payload["version"] = reference.Version;
        }

        payload["shouldCompile"] = options?.ShouldCompile ?? options?.Variables is not null;
        payload["variables"] = options?.Variables is null ? new JsonObject() : FlagEngine.ContextOf(options.Variables);
        var meta = new JsonObject();
        if (ApplicationName() is { } app)
        {
            meta["applicationName"] = app;
        }

        if (EnvironmentName() is { } environment)
        {
            meta["environment"] = environment;
        }

        payload["metaProperties"] = meta;
        payload["source"] = "dotnet-sdk";
        return payload.ToJsonString();
    }

    // --------------------------------------------------------------- helpers

    /// <summary>A flag with a non-empty <c>appName</c> is served only to that application.</summary>
    private bool ServedHere(JsonObject flag)
    {
        if (!flag.TryGetPropertyValue("appName", out var appName) || !Truthy(appName))
        {
            return true;
        }

        return FlagEngine.TryString(appName, out var name) && name == ApplicationName();
    }

    private static bool Truthy(JsonNode? node)
    {
        switch (FlagEngine.KindOf(node))
        {
            case FlagEngine.Kind.Null:
                return false;
            case FlagEngine.Kind.Bool:
                FlagEngine.TryBool(node, out var b);
                return b;
            case FlagEngine.Kind.Number:
                FlagEngine.TryNumber(node, out var d);
                return d != 0 && !double.IsNaN(d);
            case FlagEngine.Kind.String:
                FlagEngine.TryString(node, out var s);
                return s.Length > 0;
            default:
                return true;
        }
    }

    /// <summary>Whether a served value is of the default's kind; a null default takes anything.</summary>
    private static bool SameKind(JsonNode? value, JsonNode? defaultValue)
    {
        var want = FlagEngine.KindOf(defaultValue);
        if (want == FlagEngine.Kind.Null)
        {
            return true;
        }

        var got = FlagEngine.KindOf(value);
        if (want is FlagEngine.Kind.Object or FlagEngine.Kind.Array)
        {
            return got is FlagEngine.Kind.Object or FlagEngine.Kind.Array;
        }

        return got == want;
    }

    private static string? Trimmed(string? value)
    {
        var t = value?.Trim();
        return string.IsNullOrEmpty(t) ? null : t;
    }

    private sealed class Rules
    {
        public Rules(Dictionary<string, JsonObject> flags, List<JsonNode?> segments, string? etag)
        {
            Flags = flags;
            Segments = segments;
            ETag = etag;
        }

        public Dictionary<string, JsonObject> Flags { get; }

        public List<JsonNode?> Segments { get; }

        public string? ETag { get; }
    }
}
