using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Shield360.Internal;

namespace Shield360.Rasp;

/// <summary>A pinned Ed25519 public key for the signed config.</summary>
internal sealed record PinnedKey(string? Kid, string X, Ed25519PublicKeyParameters Key);

/// <summary>The claims of a verified signed config.</summary>
internal sealed record RaspClaims(string Version, double Exp, JsonElement Json);

/// <summary>The outcome of <see cref="RaspJws.Verify(string?, IReadOnlyList{PinnedKey}, string, double)"/>: claims, or why the config was refused.</summary>
internal sealed record VerifyResult(RaspClaims? Claims, string? Kid, string? Reason)
{
    public bool Ok => Claims is not null;

    public static VerifyResult Fail(string reason) => new(null, null, reason);
}

/// <summary>
/// Compact JWS checks for the signed RASP config (sdk/rasp/README.md, "The signed config"
/// and "Key pinning"). A config is trusted only under a key the app pinned.
/// </summary>
internal static class RaspJws
{
    public const string JwsType = "shield360-rasp+jws";
    public const int SkewSeconds = 60;
    private const int MaxToken = 256 * 1024;
    private static readonly Regex s_b64url = new("^[A-Za-z0-9_-]+\\z", RegexOptions.CultureInvariant);

    private static bool IsB64Url(string s) => s.Length > 0 && s_b64url.IsMatch(s);

    /// <summary>A key from a JWK object, or null when it is not a usable Ed25519 key.</summary>
    public static PinnedKey? FromJwk(JsonElement j)
    {
        try
        {
            if (j.ValueKind != JsonValueKind.Object ||
                !j.TryGetProperty("kty", out var kty) || kty.ValueKind != JsonValueKind.String || kty.GetString() != "OKP" ||
                !j.TryGetProperty("crv", out var crv) || crv.ValueKind != JsonValueKind.String || crv.GetString() != "Ed25519" ||
                !j.TryGetProperty("x", out var xe) || xe.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            var kid = j.TryGetProperty("kid", out var k) && k.ValueKind == JsonValueKind.String && k.GetString()!.Length > 0 ? k.GetString() : null;
            return FromX(xe.GetString()!, kid);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    private static PinnedKey? FromX(string x, string? kid)
    {
        if (!IsB64Url(x))
        {
            return null;
        }

        var raw = RaspDetect.LenientBase64(x);
        if (raw.Length != 32)
        {
            return null;
        }

        try
        {
            return new PinnedKey(kid, x, new Ed25519PublicKeyParameters(raw, 0));
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses a pinned key: a JWK, a JWKS, or the bare base64url Ed25519 <c>x</c>.
    /// Unusable entries are left out; empty when none is usable.
    /// </summary>
    public static List<PinnedKey> ParsePublicKeys(string? input)
    {
        var output = new List<PinnedKey>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return output;
        }

        var s = JsText.Trim(input!);
        if (!JsText.Starts(s, "{") && !JsText.Starts(s, "["))
        {
            if (FromX(s, null) is { } bare)
            {
                output.Add(bare);
            }

            return output;
        }

        try
        {
            using var doc = JsonDocument.Parse(s);
            return ParsePublicKeys(doc.RootElement);
        }
        catch (JsonException)
        {
            return output;
        }
    }

    /// <summary>Keys from a parsed JWK, JWKS or array of JWKs.</summary>
    public static List<PinnedKey> ParsePublicKeys(JsonElement value)
    {
        IEnumerable<JsonElement> list = value.ValueKind switch
        {
            JsonValueKind.Array => value.EnumerateArray(),
            JsonValueKind.Object when value.TryGetProperty("keys", out var keys) && keys.ValueKind == JsonValueKind.Array => keys.EnumerateArray(),
            _ => new[] { value },
        };
        return list.Take(16).Select(FromJwk).Where(k => k is not null).Select(k => k!).ToList();
    }

    private static JsonElement? Header(string token)
    {
        try
        {
            var dot = token.IndexOf('.');
            var first = dot < 0 ? token : token.Substring(0, dot);
            using var doc = JsonDocument.Parse(RaspDetect.LenientBase64(first));
            return doc.RootElement.ValueKind == JsonValueKind.Object ? doc.RootElement.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? StringProp(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>The <c>kid</c> in a JWS header, or null.</summary>
    public static string? Kid(string? token) => token is null || Header(token) is not { } h ? null : StringProp(h, "kid");

    /// <summary>
    /// Verifies a compact JWS against the given keys only: <c>alg</c> EdDSA, <c>typ</c>
    /// shield360-rasp+jws, an Ed25519 signature by the pinned key whose kid matches the
    /// header (any pinned key when the header names none listed), <c>v</c> 1, <c>app</c>
    /// equal to ours, <c>exp</c> in the future (60 s skew), a non-empty <c>version</c>.
    /// </summary>
    public static VerifyResult Verify(string? token, IReadOnlyList<PinnedKey> keys, string app, double nowSeconds) =>
        Verify(token, keys, app, nowSeconds, JwsType);

    /// <summary>SHIELD: Defend — the same verification for a signed document of another JWS typ.</summary>
    public static VerifyResult Verify(string? token, IReadOnlyList<PinnedKey> keys, string app, double nowSeconds, string jwsType)
    {
        try
        {
            if (token is null || token.Length > MaxToken)
            {
                return VerifyResult.Fail("malformed");
            }

            var parts = token.Split('.');
            if (parts.Length != 3 || !parts.All(IsB64Url))
            {
                return VerifyResult.Fail("malformed");
            }

            if (Header(token) is not { } h)
            {
                return VerifyResult.Fail("malformed");
            }

            if (StringProp(h, "alg") != "EdDSA")
            {
                return VerifyResult.Fail("alg");
            }

            if (StringProp(h, "typ") != jwsType)
            {
                return VerifyResult.Fail("typ");
            }

            var kid = StringProp(h, "kid");
            var candidates = kid is null ? new List<PinnedKey>() : keys.Where(k => k.Kid == kid).ToList();
            if (candidates.Count == 0)
            {
                candidates = keys.ToList();
            }

            if (candidates.Count == 0)
            {
                return VerifyResult.Fail("no_key");
            }

            var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            var sig = RaspDetect.LenientBase64(parts[2]);
            if (!candidates.Any(k => VerifyEd25519(k.Key, signed, sig)))
            {
                return VerifyResult.Fail("signature");
            }

            using var doc = JsonDocument.Parse(RaspDetect.LenientBase64(parts[1]));
            var claims = doc.RootElement;
            if (claims.ValueKind != JsonValueKind.Object ||
                !claims.TryGetProperty("v", out var v) || v.ValueKind != JsonValueKind.Number || v.GetDouble() != 1)
            {
                return VerifyResult.Fail("version");
            }

            if (StringProp(claims, "app") != app)
            {
                return VerifyResult.Fail("app");
            }

            if (!claims.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number || exp.GetDouble() + SkewSeconds <= nowSeconds)
            {
                return VerifyResult.Fail("expired");
            }

            var version = StringProp(claims, "version");
            if (string.IsNullOrEmpty(version))
            {
                return VerifyResult.Fail("version");
            }

            return new VerifyResult(new RaspClaims(version!, exp.GetDouble(), claims.Clone()), kid, null);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return VerifyResult.Fail("malformed");
        }
    }

    private static bool VerifyEd25519(Ed25519PublicKeyParameters key, byte[] data, byte[] signature)
    {
        if (signature.Length != 64)
        {
            return false;
        }

        var verifier = new Ed25519Signer();
        verifier.Init(false, key);
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }
}

internal enum PollResult
{
    Updated,
    Unchanged,
    Rejected,
    Failed,
}

/// <summary>Settings for <see cref="RaspConfigClient"/>.</summary>
internal sealed class RaspConfigClientOptions
{
    public string Url { get; init; } = string.Empty;

    public string ApiKey { get; init; } = string.Empty;

    public string App { get; init; } = "default";

    /// <summary>Pinned keys (<see cref="RaspJws.ParsePublicKeys(string?)"/>).</summary>
    public IReadOnlyList<PinnedKey> Pinned { get; init; } = Array.Empty<PinnedKey>();

    /// <summary>Development only (the caller already refused it in production): pin the first kid the server sends.</summary>
    public bool AllowUnpinned { get; init; }

    public string CacheDir { get; init; } = string.Empty;

    /// <summary>A verified config, or null when the one in force expired.</summary>
    public Action<RaspClaims?> OnConfig { get; init; } = _ => { };

    /// <summary>Why a config was refused (once per reason).</summary>
    public Action<string>? OnWarning { get; init; }

    public HttpMessageHandler? Handler { get; init; }

    public Func<DateTimeOffset> Now { get; init; } = () => DateTimeOffset.UtcNow;

    /// <summary>A number in [0, 1) for the poll jitter.</summary>
    public Func<double>? Random { get; init; }

    /// <summary>SHIELD: Defend — the document's path (default the RASP config's).</summary>
    public string Path { get; init; } = "/api/rasp/config";

    /// <summary>SHIELD: Defend — the document's JWS typ (default the RASP config's).</summary>
    public string JwsType { get; init; } = RaspJws.JwsType;
}

/// <summary>
/// Signed RASP config client. <c>GET /api/rasp/config?app=</c> returns
/// <c>{ config: &lt;compact JWS&gt;, keys }</c>. The JWS is trusted only when it
/// verifies against a pinned key; the response's <c>keys</c> are never trusted on
/// their own. Only with trust on first use (development, never production) is the
/// first kid seen pinned; a config signed by another kid after that is rejected.
/// ETag polling every 60 s ± 10 s, 5 minutes after a failure; the last verified
/// config is kept in memory and in a cache file re-verified when loaded. Never
/// throws and never blocks start-up. Port of the TypeScript <c>config-client.ts</c>.
/// </summary>
internal sealed class RaspConfigClient : IDisposable
{
    public static readonly TimeSpan Poll = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan Jitter = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan Backoff = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan s_fetchTimeout = TimeSpan.FromSeconds(10);

    private readonly RaspConfigClientOptions _o;
    private readonly string _base;
    private readonly HttpClient _http;
    private readonly HashSet<string> _warned = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _stop = new();
    private readonly System.Random _random = new();
    private List<PinnedKey> _tofu = new();
    private string? _etag;
    private int _stopped;

    // Held while a config is applied or cached and while stopping: once Stop()
    // returns, this client never applies or caches a config again, so a poll that
    // was in flight when the runtime was re-initialized cannot install a config
    // for the old app or key through the shared callback.
    private readonly object _applyLock = new();

    public RaspConfigClient(RaspConfigClientOptions options)
    {
        _o = options;
        _base = options.Url.TrimEnd('/');
        _http = options.Handler is null
            ? new HttpClient { Timeout = Timeout.InfiniteTimeSpan }
            : new HttpClient(options.Handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <summary>The verified config in force, or null.</summary>
    public RaspClaims? Current { get; private set; }

    /// <summary>The background loop, once started (tests).</summary>
    internal Task Loop { get; private set; } = Task.CompletedTask;

    private double NowSeconds => _o.Now().ToUnixTimeMilliseconds() / 1000.0;

    /// <summary>The keys a config must verify against right now.</summary>
    private IReadOnlyList<PinnedKey> Trusted() => _o.Pinned.Count > 0 ? _o.Pinned : _o.AllowUnpinned ? _tofu : Array.Empty<PinnedKey>();

    public string CacheFile()
    {
        var sb = new StringBuilder();
        foreach (var c in _o.App)
        {
            sb.Append((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' ? c : '_');
        }

        var name = sb.Length > 128 ? sb.ToString(0, 128) : sb.ToString();
        return Path.Combine(_o.CacheDir, (name.Length == 0 ? "default" : name) + ".json");
    }

    private void Warn(string reason)
    {
        lock (_warned)
        {
            if (!_warned.Add(reason))
            {
                return;
            }
        }

        try
        {
            _o.OnWarning?.Invoke(reason);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // never
        }
    }

    private void Apply(RaspClaims? claims)
    {
        Current = claims;
        try
        {
            _o.OnConfig(claims);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>Loads the cached config and re-verifies it. Pinned keys are never read from the cache.</summary>
    public bool LoadCache()
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllBytes(CacheFile()));
            var root = doc.RootElement;
            if (_o.Pinned.Count == 0 && _o.AllowUnpinned && _tofu.Count == 0 && root.TryGetProperty("tofu", out var tofu))
            {
                _tofu = RaspJws.ParsePublicKeys(tofu);
            }

            var token = root.TryGetProperty("config", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
            var r = RaspJws.Verify(token, Trusted(), _o.App, NowSeconds, _o.JwsType);
            if (!r.Ok)
            {
                return false;
            }

            lock (_applyLock)
            {
                if (Volatile.Read(ref _stopped) == 1)
                {
                    return false;
                }

                Apply(r.Claims);
            }

            return true;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return false;
        }
    }

    private void SaveCache(string config)
    {
        try
        {
            CreatePrivateDirectory(_o.CacheDir);
            using var stream = new MemoryStream();
            using (var w = new Utf8JsonWriter(stream))
            {
                w.WriteStartObject();
                w.WriteString("config", config);
                if (_o.Pinned.Count == 0 && _tofu.Count > 0)
                {
                    w.WriteStartArray("tofu");
                    foreach (var k in _tofu)
                    {
                        w.WriteStartObject();
                        w.WriteString("kty", "OKP");
                        w.WriteString("crv", "Ed25519");
                        w.WriteString("x", k.X);
                        if (k.Kid is not null)
                        {
                            w.WriteString("kid", k.Kid);
                        }

                        w.WriteEndObject();
                    }

                    w.WriteEndArray();
                }

                w.WriteEndObject();
            }

            var file = CacheFile();
            var tmp = file + "." + Process.GetCurrentProcess().Id + ".tmp";
            File.WriteAllBytes(tmp, stream.ToArray());
            RestrictToOwner(tmp);
            if (File.Exists(file))
            {
                File.Replace(tmp, file, null);
            }
            else
            {
                File.Move(tmp, file);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or PlatformNotSupportedException or NotSupportedException)
        {
            // the cache is best effort
        }
    }

    private static void CreatePrivateDirectory(string dir)
    {
#if NET
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            return;
        }
#endif
        Directory.CreateDirectory(dir);
    }

    private static void RestrictToOwner(string file)
    {
#if NET
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
#endif
    }

    /// <summary>Drops the config in force once it has expired (the platform could not be reached for its whole lifetime).</summary>
    private void Expire()
    {
        if (Current is { } c && c.Exp + RaspJws.SkewSeconds <= NowSeconds)
        {
            lock (_applyLock)
            {
                if (Volatile.Read(ref _stopped) == 1)
                {
                    return;
                }

                _etag = null;
                Apply(null);
            }
        }
    }

    /// <summary>One poll. Never throws.</summary>
    public async Task<PollResult> PollAsync()
    {
        var result = await FetchOnceAsync().ConfigureAwait(false);
        Expire();
        return result;
    }

    private async Task<PollResult> FetchOnceAsync()
    {
        try
        {
            if (_o.Pinned.Count == 0 && !_o.AllowUnpinned)
            {
                Warn("unpinned");
                return PollResult.Rejected;
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, _base + _o.Path + "?app=" + Uri.EscapeDataString(_o.App));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _o.ApiKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (_etag is not null && Current is not null)
            {
                request.Headers.TryAddWithoutValidation("If-None-Match", _etag);
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            timeout.CancelAfter(s_fetchTimeout);
            using var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotModified)
            {
                return PollResult.Unchanged;
            }

            if (!response.IsSuccessStatusCode)
            {
                return PollResult.Failed;
            }

            var text = await Http.ReadBodyAsync(response.Content, timeout.Token).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(text);
            var body = doc.RootElement;
            var token = body.ValueKind == JsonValueKind.Object && body.TryGetProperty("config", out var c) && c.ValueKind == JsonValueKind.String
                ? c.GetString()!
                : string.Empty;
            if (_o.Pinned.Count == 0 && _o.AllowUnpinned && _tofu.Count == 0)
            {
                // Trust on first use (development only): pin the key the response names.
                var kid = RaspJws.Kid(token);
                var offered = body.ValueKind == JsonValueKind.Object && body.TryGetProperty("keys", out var keys) && keys.ValueKind == JsonValueKind.Array
                    ? RaspJws.ParsePublicKeys(keys)
                    : new List<PinnedKey>();
                var first = offered.FirstOrDefault(k => k.Kid == kid) ?? (offered.Count == 1 ? offered[0] : null);
                if (first is not null)
                {
                    _tofu = new List<PinnedKey> { first };
                    Warn("trust_on_first_use");
                }
            }

            var r = RaspJws.Verify(token, Trusted(), _o.App, NowSeconds, _o.JwsType);
            if (!r.Ok)
            {
                Warn(r.Reason!);
                return PollResult.Rejected;
            }

            lock (_applyLock)
            {
                // Stopped (or replaced by a re-init) while the request was in flight.
                if (Volatile.Read(ref _stopped) == 1)
                {
                    return PollResult.Failed;
                }

                _etag = response.Headers.TryGetValues("ETag", out var etags) ? etags.FirstOrDefault() : null;
                Apply(r.Claims);
                SaveCache(token);
            }

            return PollResult.Updated;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return PollResult.Failed;
        }
    }

    /// <summary>The delay before the next poll after a result.</summary>
    public TimeSpan NextDelay(PollResult r)
    {
        if (r is PollResult.Failed or PollResult.Rejected)
        {
            return Backoff;
        }

        double random;
        if (_o.Random is not null)
        {
            random = _o.Random();
        }
        else
        {
            lock (_random)
            {
                random = _random.NextDouble();
            }
        }

        return Poll + TimeSpan.FromMilliseconds(Math.Round(((random * 2) - 1) * Jitter.TotalMilliseconds));
    }

    /// <summary>Applies the cached config, then polls in the background. Returns at once.</summary>
    public void Start()
    {
        LoadCache();
        var token = _stop.Token;
        Loop = Task.Run(
            async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    var r = await PollAsync().ConfigureAwait(false);
                    try
                    {
                        await Task.Delay(NextDelay(r), token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
            },
            CancellationToken.None);
    }

    public void Stop()
    {
        lock (_applyLock)
        {
            if (Interlocked.Exchange(ref _stopped, 1) == 1)
            {
                return;
            }
        }

        try
        {
            _stop.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // already gone
        }
    }

    public void Dispose()
    {
        Stop();
        _http.Dispose();
    }
}
