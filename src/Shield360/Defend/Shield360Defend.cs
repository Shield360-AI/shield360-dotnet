#pragma warning disable CA1861, CA1870 // netstandard2.0 has no SearchValues; the small literal arrays are on cold paths
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using Shield360.Rasp;

namespace Shield360.Defend;

/// <summary>Shield360 Defend's options.</summary>
public sealed class DefendOptions
{
    /// <summary>The app's name in Shield360 (required).</summary>
    public string App { get; set; } = string.Empty;

    /// <summary>Shield360's URL; with the API key the policy is fetched and decisions reported.</summary>
    public string? Url { get; set; }

    /// <summary>The environment's API key.</summary>
    public string? ApiKey { get; set; }

    /// <summary>The policy-signing public key (JWK, JWKS or bare x); also SHIELD360_CONFIG_PUBLIC_KEY.</summary>
    public string? ConfigPublicKey { get; set; }

    /// <summary>Trust on first use, development only (also SHIELD360_CONFIG_TOFU=dev); refused in production.</summary>
    public bool AllowUnpinnedConfig { get; set; }

    /// <summary>Monitor never denies (also SHIELD360_DEFEND=monitor; off allows everything).</summary>
    public DefendMode Mode { get; set; } = DefendMode.Enforce;

    /// <summary>Without a usable policy: open (the default) or closed.</summary>
    public DefendFailMode FailMode { get; set; } = DefendFailMode.Open;

    /// <summary>How the client address and its location are read.</summary>
    public DefendFactsOptions Facts { get; set; } = new();

    /// <summary>Checks a request's agent proof; called only when the request carries one.</summary>
    public Func<DefendRequest, DefendFacts, AgentCheck?>? Agents { get; set; }

    /// <summary>A classifier of your own (default: the shared signatures, Edge's context and breadth).</summary>
    public Func<DefendFacts, ClientClassification?>? Classifier { get; set; }

    /// <summary>No client type classification.</summary>
    public bool ClassifyOff { get; set; }

    /// <summary>Sensitive data in the content: monitor (the default), block or off.</summary>
    public SensitiveDataMode SensitiveData { get; set; } = SensitiveDataMode.Monitor;

    /// <summary>No decision reports.</summary>
    public bool DisableReport { get; set; }

    /// <summary>Ask Shield360 for rate decisions shared by every instance, with this timeout (null: per process).</summary>
    public TimeSpan? SharedRateLimits { get; set; }

    /// <summary>Words from the app's own routes for crumb paths.</summary>
    public IReadOnlyList<string> HoneypotWords { get; set; } = Array.Empty<string>();

    /// <summary>No crumb header on allowed responses.</summary>
    public bool DisableHoneypotHeader { get; set; }

    /// <summary>No decoy files.</summary>
    public bool DisableHoneypotFiles { get; set; }

    /// <summary>A hand-built policy, used until a signed one arrives.</summary>
    public DefendPolicy? Policy { get; set; }

    /// <summary>Where the last verified policy is cached (default the temp directory + shield360-defend).</summary>
    public string? CacheDir { get; set; }

    /// <summary>The HTTP handler (tests, proxies).</summary>
    public HttpMessageHandler? Handler { get; set; }

    /// <summary>The environment (tests).</summary>
    public Func<string, string?> GetEnv { get; set; } = Environment.GetEnvironmentVariable;

    /// <summary>The clock (tests).</summary>
    public Func<DateTimeOffset> Now { get; set; } = () => DateTimeOffset.UtcNow;
}

/// <summary>What to answer instead of the app.</summary>
public sealed class DefendResponse
{
    internal DefendResponse(int status, IReadOnlyDictionary<string, string> headers, string body)
    {
        Status = status;
        Headers = headers;
        Body = body;
    }

    /// <summary>The status code.</summary>
    public int Status { get; }

    /// <summary>The headers.</summary>
    public IReadOnlyDictionary<string, string> Headers { get; }

    /// <summary>The body.</summary>
    public string Body { get; }
}

/// <summary>
/// Shield360 Defend: decide in the app whether a request may go on.
/// <code>
/// using var shield = Shield360Defend.Create(new DefendOptions { App = "checkout", Url = url, ApiKey = key });
/// var r = shield.Decide(request, DefendCall.WithContent(prompt));
/// var answer = Shield360Defend.ResponseFor(r); // null: go on
/// </code>
/// Or <c>app.UseShield360Defend(shield)</c> from Shield360.AspNetCore. The decision is
/// made locally from a signed policy (typ <c>shield360-defend+jws</c>,
/// <c>GET /api/defend/policy</c>) fetched and cached the way the RASP config is (same
/// key pinning, polled in the background): no network call on the request path unless
/// shared rate limits are on. Fails open by default. Port of sdk/typescript/src/defend
/// by way of the Go and Java SDKs (docs/latest/shield360/defend.mdx is the contract).
/// </summary>
public sealed class Shield360Defend : IDisposable
{
    /// <summary>Shared rate decisions.</summary>
    public const string DecidePath = "/api/defend/decide";

    /// <summary>The decisions feed.</summary>
    public const string DecisionsPath = "/api/defend/decisions";

    /// <summary>The body of Defend's 403 and 401.</summary>
    public const string BlockBody = "{\"error\":\"Forbidden\"}";

    private sealed class Current
    {
        public Current(DefendPolicy p)
        {
            P = p;
            C = new CompiledPolicy(p);
        }

        public DefendPolicy P { get; }

        public CompiledPolicy C { get; }
    }

    private readonly string _app;
    private readonly DefendOptions _o;
    private readonly bool _remote;
    private readonly HttpClient _http;
    private readonly DefendRateTable _rates = new();
    private readonly BreadthCounter _breadth = new();
    private readonly ConcurrentDictionary<string, long> _marks = new(StringComparer.Ordinal);
    private readonly EdgeReplayCache _replay = new();
    private readonly object _honeypotLock = new();
    private readonly DefendReporter? _reporter;
    private volatile Current? _current;
    private volatile string? _feedEtag;
    private Honeypots? _honeypots;
    private Timer? _feed;

    private Shield360Defend(DefendOptions o)
    {
        _o = o;
        _app = o.App.Trim();
        _remote = !string.IsNullOrEmpty(o.Url) && !string.IsNullOrEmpty(o.ApiKey);
        _http = o.Handler is null ? new HttpClient { Timeout = TimeSpan.FromSeconds(10) } : new HttpClient(o.Handler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(10) };
        if (o.Policy is not null)
        {
            _current = new Current(o.Policy);
        }

        if (!_remote)
        {
            return;
        }

        var pin = o.ConfigPublicKey ?? Env("SHIELD360_CONFIG_PUBLIC_KEY");
        var keys = RaspJws.ParsePublicKeys(pin);
        var tofu = keys.Count == 0 && RaspRuntime.TofuAllowed(o.AllowUnpinnedConfig, Env);
        if (keys.Count > 0 || tofu)
        {
            Client = new RaspConfigClient(new RaspConfigClientOptions
            {
                Url = o.Url!,
                ApiKey = o.ApiKey!,
                App = _app,
                Pinned = keys,
                AllowUnpinned = tofu,
                CacheDir = o.CacheDir ?? System.IO.Path.Combine(System.IO.Path.GetTempPath(), "shield360-defend"),
                Handler = o.Handler,
                Now = o.Now,
                Path = DefendPolicy.PolicyPath,
                JwsType = DefendPolicy.JwsType,
                OnConfig = claims =>
                {
                    var p = claims is null ? null : DefendPolicy.Parse(claims.Json);
                    _current = p is null ? null : new Current(p);
                },
                OnWarning = reason =>
                {
                    if (reason != "trust_on_first_use")
                    {
                        RaspRuntime.Warn("Shield360 Defend: a signed policy was refused (" + reason + "); the last verified policy stays in force.");
                    }
                },
            });
        }
        else if (o.Policy is null)
        {
            RaspRuntime.Warn("Shield360 Defend: the signed policy key is not pinned, so no policy is used and the fail mode applies. Set ConfigPublicKey (or SHIELD360_CONFIG_PUBLIC_KEY).");
        }

        if (!o.DisableReport)
        {
            _reporter = new DefendReporter(o.Url!, o.ApiKey!, _app, _http, NowMs);
        }
    }

    internal RaspConfigClient? Client { get; }

    /// <summary>Starts Defend; with a URL, an API key and a pinned key the policy is polled in the background.</summary>
    public static Shield360Defend Create(DefendOptions options)
    {
        var d = Build(options);
        d.Start();
        return d;
    }

    internal static Shield360Defend Build(DefendOptions options)
    {
        if (options is null || string.IsNullOrWhiteSpace(options.App))
        {
            throw new ArgumentException("Defend: App (the app name in Shield360) is required", nameof(options));
        }

        return new Shield360Defend(options);
    }

    private void Start()
    {
        if (Client is not null)
        {
            Client.Start();
            _feed = new Timer(_ => CheckFeed(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        _reporter?.Start();
    }

    private string? Env(string k)
    {
        try
        {
            return _o.GetEnv(k);
        }
#pragma warning disable CA1031 // a broken environment reads as unset
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    private long NowMs() => _o.Now().ToUnixTimeMilliseconds();

    private DefendMode? ModeNow() => (Env("SHIELD360_DEFEND") ?? string.Empty).Trim().ToLowerInvariant() switch
    {
        "off" => null,
        "monitor" => DefendMode.Monitor,
        "enforce" => DefendMode.Enforce,
        _ => _o.Mode,
    };

    /// <summary>The policy in force, or null.</summary>
    public DefendPolicy? Policy => _current?.P;

    /// <summary>Replaces the policy in force (a signed policy arriving later replaces it).</summary>
    public void SetPolicy(DefendPolicy? p) => _current = p is null ? null : new Current(p);

    private void Mark(string? ip, int ttlSeconds)
    {
        if (string.IsNullOrEmpty(ip))
        {
            return;
        }

        if (_marks.Count >= 10_000)
        {
            var now = NowMs();
            foreach (var e in _marks.Where(e => e.Value <= now).ToList())
            {
                _marks.TryRemove(e.Key, out _);
            }

            if (_marks.Count >= 10_000 && _marks.Keys.FirstOrDefault() is { } first)
            {
                _marks.TryRemove(first, out _);
            }
        }

        _marks[ip!] = NowMs() + (ttlSeconds * 1000L);
    }

    private bool Marked(string? ip)
    {
        if (string.IsNullOrEmpty(ip))
        {
            return false;
        }

        if (_marks.TryGetValue(ip!, out var until) && until <= NowMs())
        {
            _marks.TryRemove(ip!, out _);
            until = 0;
        }

        return until > 0 || RaspDeception.Table.IsSuspicious(ip!);
    }

    /// <summary>Checks the decisions feed now: the signed policy is read again only when its lists changed.</summary>
    internal void CheckFeed()
    {
        try
        {
            var cur = _current;
            if (Client is null || cur is null)
            {
                return;
            }

            using var req = new HttpRequestMessage(HttpMethod.Get, _o.Url!.TrimEnd('/') + DecisionsPath + "?app=" + Uri.EscapeDataString(_app));
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _o.ApiKey);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var etag = _feedEtag;
            if (etag is not null)
            {
                req.Headers.TryAddWithoutValidation("If-None-Match", etag);
            }

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var res = _http.SendAsync(req, cts.Token).GetAwaiter().GetResult();
            if (!res.IsSuccessStatusCode)
            {
                return;
            }

            _feedEtag = res.Headers.ETag?.ToString();
            var body = res.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            if (body.Length > 65536)
            {
                return;
            }

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("version", out var v)
                && v.ValueKind == JsonValueKind.String && v.GetString() != cur.P.ListsVersion)
            {
                Client.PollAsync().GetAwaiter().GetResult();
            }
        }
#pragma warning disable CA1031 // the feed never breaks the app
        catch (Exception)
#pragma warning restore CA1031
        {
            // next time
        }
    }

    private Dictionary<string, bool>? SharedOver(DefendPolicy p, DefendFacts f, DefendInput input)
    {
        if (_o.SharedRateLimits is not { } timeout || !_remote || f.Ip is null)
        {
            return null;
        }

        var ids = DefendEngine.RateRulesFor(input).Select(r => r.Id).ToList();
        if (ids.Count == 0)
        {
            return null;
        }

        try
        {
            var body = new Dictionary<string, object?> { ["app"] = _app, ["ip"] = f.Ip, ["ruleIds"] = ids, ["version"] = p.Version };
            using var req = new HttpRequestMessage(HttpMethod.Post, _o.Url!.TrimEnd('/') + DecidePath)
            {
                Content = new StringContent(JsonSerializer.Serialize(body, DefendReporter.JsonOptions), Encoding.UTF8, "application/json"),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _o.ApiKey);
            using var cts = new CancellationTokenSource(timeout < TimeSpan.FromMilliseconds(10) ? TimeSpan.FromMilliseconds(10) : timeout);
            using var res = _http.SendAsync(req, cts.Token).GetAwaiter().GetResult();
            if (!res.IsSuccessStatusCode)
            {
                return null;
            }

            using var doc = JsonDocument.Parse(res.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("over", out var over) || over.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var out_ = new Dictionary<string, bool>(StringComparer.Ordinal);
            foreach (var id in ids)
            {
                if (over.TryGetProperty(id, out var x) && (x.ValueKind == JsonValueKind.True || x.ValueKind == JsonValueKind.False))
                {
                    out_[id] = x.GetBoolean();
                }
            }

            return out_;
        }
#pragma warning disable CA1031 // shared limits that cannot answer fall back to the process's own
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    private static DefendEvent Event(string kind, DefendFacts f, IEnumerable<string> reasons) => new()
    {
        Kind = kind,
        Ip = f.Ip,
        Path = DefendFacts.FirstCodePoints(f.Path, 256),
        Method = f.Method,
        Reasons = reasons.ToList(),
    };

    private void Report(DefendResult r, DefendFacts f)
    {
        if (_reporter is null)
        {
            return;
        }

        var d = r.Effective;
        if (d == DefendVerdict.Allow && !r.Reasons.Contains("trap_hit") && !r.Reasons.Contains("rule:monitor"))
        {
            return;
        }

        var e = Event("decision", f, r.Reasons);
        e.Decision = DefendResult.Code(d);
        e.Monitored = r.WouldBe is not null;
        e.ClientType = r.ClientType;
        e.RuleIds = r.RuleIds.ToList();
        _reporter.Add(e);
    }

    private Honeypots? HoneypotsFor(DefendPolicy p)
    {
        var s = p.Honeypots;
        if (s is null)
        {
            return null;
        }

        lock (_honeypotLock)
        {
            if (_honeypots is not null && _honeypots.Settings.Same(s))
            {
                return _honeypots;
            }

            _honeypots = new Honeypots(s, _o.HoneypotWords, NowMs);
            return _honeypots;
        }
    }

    private DefendResult HoneypotStep(Honeypots hp, DefendPolicy p, DefendFacts f, DefendMode mode, DefendResult r)
    {
        var ip = f.Ip;
        var ua = f.Header("user-agent");
        var hit = hp.Check(f.Path, f.Query, f.Headers, Honeypots.Hex(Honeypots.Fingerprint(ip, ua)));
        var decoy = _o.DisableHoneypotFiles ? null : hp.Serve(f.Path, ip, ua);
        if (hit is null)
        {
            if (decoy is not null)
            {
                r.Decoy = decoy;
            }
            else if (!_o.DisableHoneypotHeader)
            {
                r.CrumbHeader = hp.CrumbsFor(ip, ua).HeaderValue;
            }

            return r;
        }

        var action = hp.ActionFor(hit.Level);
        var ttl = p.TrapTtlSeconds;
        if (action != "monitor")
        {
            Mark(ip, ttl);
        }

        var code = new StringBuilder();
        foreach (var c in hit.Decoy)
        {
            if (code.Length >= 40)
            {
                break;
            }

            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "_.:-".IndexOf(c) >= 0)
            {
                code.Append(c);
            }
        }

        var reasons = new List<string> { "trap:honeypot", "level:" + hit.Level, "crumb:" + hit.State };
        if (hit.Foreign)
        {
            reasons.Add("crumb:foreign");
        }

        reasons.Add("decoy:" + (code.Length == 0 ? "path" : code.ToString()));
        if (_reporter is not null)
        {
            var e = Event("trap_hit", f, reasons);
            e.ClientType = ClientType.SuspectedAiAgent;
            _reporter.Add(e);
        }

        r.Reasons.AddRange(reasons);
        r.ClientType = ClientType.SuspectedAiAgent;
        if (decoy is not null)
        {
            r.Decoy = decoy;
            return r;
        }

        var v = action == "block" ? DefendVerdict.Deny : DefendVerdict.Challenge;
        if (action == "monitor" || mode == DefendMode.Monitor)
        {
            if (action != "monitor")
            {
                r.WouldBe = v;
            }

            return r;
        }

        return new DefendResult(v, r.Reasons, r.RuleIds, ttl) { ClientType = r.ClientType };
    }

    /// <summary>The decision for a request. Never throws.</summary>
    public DefendResult Decide(DefendRequest request, DefendCall? call = null)
    {
        var mode = ModeNow();
        if (mode is not { } m)
        {
            return new DefendResult(DefendVerdict.Allow, new[] { "off" }, Array.Empty<string>(), 0);
        }

        try
        {
            var f = DefendFacts.Of(request, call, _o.Facts);
            var r = DecideFacts(request, f, m);
            Report(r, f);
            return r;
        }
#pragma warning disable CA1031 // a decision never throws: the fail mode applies
        catch (Exception)
#pragma warning restore CA1031
        {
            var r = DefendEngine.FailResult(_o.FailMode, "error", m);
            Report(r, new DefendFacts());
            return r;
        }
    }

    private DefendResult DecideFacts(DefendRequest req, DefendFacts f, DefendMode mode)
    {
        double now = NowMs();
        var cur = _current;
        if (cur is not null && cur.P.Exp + 60 <= now / 1000.0)
        {
            cur = null;
        }

        AgentCheck? agent = null;
        if (_o.Agents is not null && DefendFacts.CarriesAgentProof(f.Headers))
        {
            try
            {
                agent = _o.Agents(req, f);
            }
#pragma warning disable CA1031 // a verifier that throws verifies nothing
            catch (Exception)
#pragma warning restore CA1031
            {
                agent = null;
            }
        }

        // Protection triangle: Edge's verified context (Defend keeps its own replay cache).
        if (cur is not null && cur.P.EdgeKeys.Count > 0)
        {
            var value = f.Header(EdgeContext.ContextHeader);
            if (value.Length > 0)
            {
                var e = EdgeContext.Verify(cur.P.EdgeKeys, value, f.Method, f.RawPath, f.Header("x-request-id"), (long)Math.Floor(now / 1000.0), _replay);
                if (e is not null)
                {
                    f.Edge = new EdgeSignal(e.ClientType, e.Trap, e.Flagged, e.Risk);
                }
            }
        }

        var edgeCt = f.Edge?.ClientType ?? string.Empty;
        var edgeVerified = edgeCt == "verified_agent" || edgeCt == "verified_crawler";
        var trapHit = !edgeVerified && (Marked(f.Ip) || (f.Edge is not null && f.Edge.Trap >= 2));
        var verified = agent is { Verified: true };
        ClientClassification? cl = null;
        if (!verified && !trapHit && !_o.ClassifyOff)
        {
            if (_o.Classifier is not null)
            {
                try
                {
                    cl = _o.Classifier(f);
                }
#pragma warning disable CA1031 // a classifier that throws classifies nothing
                catch (Exception)
#pragma warning restore CA1031
                {
                    cl = null;
                }
            }
            else
            {
                var s = new ClientSignals { Edge = f.Edge };
                if (f.Ip is not null)
                {
                    s.Breadth = _breadth.See(f.Ip, f.Path, (long)now);
                }

                cl = ClientType.Classify(f.Headers, s);
            }
        }

        var input = new DefendInput
        {
            Facts = f,
            Mode = mode,
            FailMode = _o.FailMode,
            Agent = agent,
            TrapHit = trapHit,
            Classification = cl,
            Content = DefendContent.Check(f.Content, _o.SensitiveData),
            SensitiveData = _o.SensitiveData,
            Rates = _rates,
            NowMs = now,
        };
        if (cur is not null)
        {
            input.Policy = cur.P;
            input.Compiled = cur.C;
            input.SharedOver = SharedOver(cur.P, f, input);
        }

        var result = DefendEngine.Decide(input);
        if (cur is not null && f.Ip is not null && !verified && !DefendEngine.IsTrusted(cur.C, f.Ip) && !PrivateIp(f.Ip) && result.Decision == DefendVerdict.Allow
            && HoneypotsFor(cur.P) is { } hp)
        {
            result = HoneypotStep(hp, cur.P, f, mode, result);
        }

        return result;
    }

    /// <summary>Private, loopback and link-local addresses: never trapped.</summary>
    public static bool PrivateIp(string ip)
    {
        var v = ip.StartsWith("::ffff:", StringComparison.Ordinal) ? ip.Substring(7) : ip;
        foreach (var p in new[] { "10.", "127.", "192.168.", "169.254.", "0." })
        {
            if (v.StartsWith(p, StringComparison.Ordinal))
            {
                return true;
            }
        }

        if (v.StartsWith("172.", StringComparison.Ordinal))
        {
            var rest = v.Substring(4);
            var dot = rest.IndexOf('.');
            if (dot > 0 && dot <= 3 && rest.Substring(0, dot).All(c => c >= '0' && c <= '9'))
            {
                var n = int.Parse(rest.Substring(0, dot), System.Globalization.CultureInfo.InvariantCulture);
                if (n >= 16 && n <= 31)
                {
                    return true;
                }
            }
        }

        var l = v.ToLowerInvariant();
        return l == "::1" || l.StartsWith("fe80:", StringComparison.Ordinal) || l.StartsWith("fc", StringComparison.Ordinal) || l.StartsWith("fd", StringComparison.Ordinal);
    }

    /// <summary>The response to answer with instead of the app, or null to go on.</summary>
    public static DefendResponse? ResponseFor(DefendResult r)
    {
        var h = new Dictionary<string, string>(StringComparer.Ordinal);
        if (r.Decision == DefendVerdict.Allow)
        {
            if (r.Decoy is null)
            {
                return null;
            }

            h["Content-Type"] = r.Decoy.ContentType;
            h["Cache-Control"] = "no-store";
            return new DefendResponse(r.Decoy.Status, h, r.Decoy.Body);
        }

        h["Content-Type"] = "application/json";
        h["Shield360-Defend"] = DefendResult.Code(r.Decision);
        h["Cache-Control"] = "no-store";
        return new DefendResponse(r.Decision == DefendVerdict.RequireSignIn ? 401 : 403, h, BlockBody);
    }

    /// <summary>The app saw a trap hit by this request's client: it is marked suspected for the trap TTL and reported.</summary>
    public void TrapHit(DefendRequest request, string? trap, DefendCall? call = null)
    {
        try
        {
            var f = DefendFacts.Of(request, call, _o.Facts);
            Mark(f.Ip, Policy?.TrapTtlSeconds ?? DefendPolicy.DefaultTrapTtl);
            var ok = !string.IsNullOrEmpty(trap) && trap!.Length <= 48 && trap.All(c => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-');
            if (_reporter is not null)
            {
                var e = Event("trap_hit", f, new[] { "trap:" + (ok ? trap : "trap") });
                e.ClientType = ClientType.SuspectedAiAgent;
                _reporter.Add(e);
            }
        }
#pragma warning disable CA1031 // never breaks the app
        catch (Exception)
#pragma warning restore CA1031
        {
            // never
        }
    }

    /// <summary>The crumbs for this request's client; null while honeypots are off, and for trusted and private clients.</summary>
    public ClientCrumbs? Crumbs(DefendRequest request, DefendCall? call = null)
    {
        try
        {
            var cur = _current;
            if (cur is null)
            {
                return null;
            }

            var f = DefendFacts.Of(request, call, _o.Facts);
            if (f.Ip is null || PrivateIp(f.Ip) || DefendEngine.IsTrusted(cur.C, f.Ip))
            {
                return null;
            }

            return HoneypotsFor(cur.P)?.CrumbsFor(f.Ip, f.Header("user-agent"));
        }
#pragma warning disable CA1031 // never breaks the app
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    /// <summary>The app saw a failed sign-in from this request's client: reported (never the user name or password).</summary>
    public void FailedLogin(DefendRequest request, DefendCall? call = null)
    {
        try
        {
            _reporter?.Add(Event("failed_login", DefendFacts.Of(request, call, _o.Facts), new[] { "failed_login" }));
        }
#pragma warning disable CA1031 // never breaks the app
        catch (Exception)
#pragma warning restore CA1031
        {
            // never
        }
    }

    /// <summary>The events not sent yet (tests, diagnostics) as JSON objects.</summary>
    public IReadOnlyList<IReadOnlyDictionary<string, object?>> PendingEvents() =>
        _reporter is null ? Array.Empty<IReadOnlyDictionary<string, object?>>() : _reporter.Pending().Select(e => (IReadOnlyDictionary<string, object?>)e.Json()).ToList();

    /// <summary>Sends queued events now.</summary>
    public void Flush() => _reporter?.Flush();

    /// <summary>Stops polling the policy and sends queued events.</summary>
    public void Dispose()
    {
        _feed?.Dispose();
        Client?.Stop();
        Client?.Dispose();
        _reporter?.Dispose();
        _http.Dispose();
    }
}
