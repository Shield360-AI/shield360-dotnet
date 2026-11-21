#pragma warning disable CA1861, CA1870 // netstandard2.0 has no SearchValues; the small literal arrays are on cold paths
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;

namespace Shield360.Defend;

/// <summary>One reported decision.</summary>
internal sealed class DefendEvent
{
    public string Kind { get; set; } = string.Empty;

    public string? Decision { get; set; }

    public bool Monitored { get; set; }

    public string? ClientType { get; set; }

    public string? Ip { get; set; }

    public string Path { get; set; } = "/";

    public string Method { get; set; } = "GET";

    public List<string> Reasons { get; set; } = new();

    public List<string> RuleIds { get; set; } = new();

    public string At { get; set; } = string.Empty;

    public int Count { get; set; }

    public Dictionary<string, object?> Json()
    {
        var m = new Dictionary<string, object?> { ["kind"] = Kind };
        if (Decision is not null)
        {
            m["decision"] = Decision;
        }

        if (Monitored)
        {
            m["monitored"] = true;
        }

        if (ClientType is not null)
        {
            m["clientType"] = ClientType;
        }

        if (Ip is not null)
        {
            m["ip"] = Ip;
        }

        m["path"] = Path;
        m["method"] = Method;
        m["reasons"] = Reasons;
        m["ruleIds"] = RuleIds;
        m["at"] = At;
        m["count"] = Count;
        return m;
    }
}

/// <summary>
/// Defend's decisions to Shield360: deny, challenge and trap decisions and failed
/// sign-ins go to <c>POST /api/defend/report</c>, batched (at most 100 an HTTP call),
/// folded (the same event within 10 s adds to a count), at most 300 a minute, from a
/// background timer. Never a header, body, query string, user name or password.
/// </summary>
internal sealed class DefendReporter : IDisposable
{
    public const string ReportPath = "/api/defend/report";
    private const int PerMinute = 300;
    private const long FoldMs = 10_000;
    private const int Batch = 100;
    private const int MaxQueued = 1000;
    internal static readonly JsonSerializerOptions JsonOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly string _endpoint;
    private readonly string _apiKey;
    private readonly string _app;
    private readonly HttpClient _http;
    private readonly Func<long> _now;
    private readonly object _lock = new();
    private readonly List<DefendEvent> _queue = new();
    private readonly Dictionary<string, long[]> _folds = new(StringComparer.Ordinal);
    private long _windowStart;
    private int _sentInWindow;
    private Timer? _timer;

    public DefendReporter(string url, string apiKey, string app, HttpClient http, Func<long> now)
    {
        _endpoint = url.TrimEnd('/') + ReportPath;
        _apiKey = apiKey;
        _app = app;
        _http = http;
        _now = now;
    }

    public long Dropped { get; private set; }

    public void Add(DefendEvent e)
    {
        lock (_lock)
        {
            var t = _now();
            var key = string.Join("|", e.Kind, e.Decision ?? string.Empty, e.Monitored ? "1" : "0", e.Ip ?? string.Empty, e.Path, e.Method, string.Join(",", e.Reasons), string.Join(",", e.RuleIds));
            if (_folds.TryGetValue(key, out var f) && f[1] > t && f[0] < _queue.Count)
            {
                _queue[(int)f[0]].Count++;
                return;
            }

            if (t - _windowStart >= 60_000)
            {
                _windowStart = t;
                _sentInWindow = 0;
            }

            if (_sentInWindow >= PerMinute || _queue.Count >= MaxQueued)
            {
                Dropped++;
                return;
            }

            _sentInWindow++;
            e.Reasons = e.Reasons.Count > 16 ? e.Reasons.GetRange(0, 16) : new List<string>(e.Reasons);
            e.RuleIds = e.RuleIds.Count > 16 ? e.RuleIds.GetRange(0, 16) : new List<string>(e.RuleIds);
            e.At = DateTimeOffset.FromUnixTimeMilliseconds(t).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            e.Count = 1;
            _queue.Add(e);
            if (_folds.Count > 5000)
            {
                _folds.Clear();
            }

            _folds[key] = new long[] { _queue.Count - 1, t + FoldMs };
        }
    }

    public List<DefendEvent> Pending()
    {
        lock (_lock)
        {
            return new List<DefendEvent>(_queue);
        }
    }

    public void Flush()
    {
        List<DefendEvent> batch;
        lock (_lock)
        {
            batch = new List<DefendEvent>(_queue);
            _queue.Clear();
            _folds.Clear();
        }

        for (var i = 0; i < batch.Count; i += Batch)
        {
            var part = batch.GetRange(i, Math.Min(Batch, batch.Count - i));
            var events = new List<object>();
            foreach (var e in part)
            {
                events.Add(e.Json());
            }

            var body = new Dictionary<string, object?>
            {
                ["app"] = _app,
                ["sdk"] = "dotnet",
                ["sdkVersion"] = Shield360Sdk.Version,
                ["events"] = events,
            };
            bool ok;
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, _endpoint)
                {
                    Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json"),
                };
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var res = _http.SendAsync(req, cts.Token).GetAwaiter().GetResult();
                ok = res.IsSuccessStatusCode;
            }
#pragma warning disable CA1031 // reporting never breaks the app
            catch (Exception)
#pragma warning restore CA1031
            {
                ok = false;
            }

            if (!ok)
            {
                lock (_lock)
                {
                    Dropped += part.Count;
                }
            }
        }
    }

    public void Start()
    {
        lock (_lock)
        {
            _timer ??= new Timer(_ => FlushQuietly(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
        }
    }

    private void FlushQuietly()
    {
        try
        {
            Flush();
        }
#pragma warning disable CA1031 // reporting never breaks the app
        catch (Exception)
#pragma warning restore CA1031
        {
            // never
        }
    }

    public void Dispose()
    {
        Timer? t;
        lock (_lock)
        {
            t = _timer;
            _timer = null;
        }

        t?.Dispose();
        FlushQuietly();
    }
}
