using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>An Ed25519 key pair for signing test configs.</summary>
internal sealed class TestKey
{
    private static readonly SecureRandom s_random = new();

    public TestKey(string kid)
    {
        Kid = kid;
        Private = new Ed25519PrivateKeyParameters(s_random);
        X = B64(Private.GeneratePublicKey().GetEncoded());
    }

    private TestKey(string kid, Ed25519PrivateKeyParameters priv, string x)
    {
        Kid = kid;
        Private = priv;
        X = x;
    }

    public string Kid { get; }

    public Ed25519PrivateKeyParameters Private { get; }

    public string X { get; }

    public string Jwk => $$"""{"kty":"OKP","crv":"Ed25519","x":"{{X}}","kid":"{{Kid}}"}""";

    /// <summary>The SubjectPublicKeyInfo PEM: a format the pin does not accept.</summary>
    public string Pem
    {
        get
        {
            var spki = new byte[] { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 }
                .Concat(Private.GeneratePublicKey().GetEncoded()).ToArray();
            return "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String(spki) + "\n-----END PUBLIC KEY-----\n";
        }
    }

    public TestKey WithKid(string kid) => new(kid, Private, X);

    public static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string B64(string s) => B64(Encoding.UTF8.GetBytes(s));

    public string Sign(string claims, string? header = null)
    {
        var head = B64(header ?? $$"""{"alg":"EdDSA","typ":"shield360-rasp+jws","kid":"{{Kid}}"}""");
        var body = B64(claims);
        var data = Encoding.ASCII.GetBytes(head + "." + body);
        var signer = new Ed25519Signer();
        signer.Init(true, Private);
        signer.BlockUpdate(data, 0, data.Length);
        return head + "." + body + "." + B64(signer.GenerateSignature());
    }
}

public class RaspConfigClientTests : RaspStateTest
{
    private const long Now = 1_800_000_000;

    private static string Claims(
        string app = "orders-api",
        long exp = Now + 3600,
        string version = "abc123",
        int v = 1,
        bool killSwitch = false,
        string extra = "") =>
        $$"""{"v":{{v}},"app":"{{app}}","iat":{{Now}},"exp":{{exp}},"version":"{{version}}","killSwitch":{{(killSwitch ? "true" : "false")}},"snippets":false,"mode":"monitor","attacks":{},"allow":{"commands":[],"outboundHosts":[],"fileRoots":[]},"rules":null{{extra}}}""";

    private static string Header(TestKey k, string typ = "shield360-rasp+jws", string alg = "EdDSA") =>
        $$"""{"alg":"{{alg}}","typ":"{{typ}}","kid":"{{k.Kid}}"}""";

    private static string Body(string? config, params TestKey[] keys) =>
        JsonSerializer.Serialize(new { config, keys = keys.Select(k => TestJson.Parse(k.Jwk)).ToArray() });

    private static HttpResponseMessage Json(string body, string? etag = null)
    {
        var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (etag is not null)
        {
            r.Headers.TryAddWithoutValidation("ETag", etag);
        }

        return r;
    }

    // ---- verification -------------------------------------------------------

    private static readonly TestKey s_k1 = new("k1");
    private static readonly TestKey s_k2 = new("k2");

    [Fact]
    public void Accepts_a_config_signed_by_the_pinned_key()
    {
        var r = RaspJws.Verify(s_k1.Sign(Claims()), RaspJws.ParsePublicKeys(s_k1.Jwk), "orders-api", Now);
        Assert.True(r.Ok);
        Assert.Equal("abc123", r.Claims!.Version);
    }

    [Fact]
    public void Refuses_another_key_whatever_kid_it_names()
    {
        var pinned = RaspJws.ParsePublicKeys(s_k1.Jwk);
        Assert.Equal("signature", RaspJws.Verify(s_k2.Sign(Claims()), pinned, "orders-api", Now).Reason);
        Assert.Equal("signature", RaspJws.Verify(s_k2.WithKid("k1").Sign(Claims()), pinned, "orders-api", Now).Reason);
    }

    [Fact]
    public void Refuses_a_wrong_typ_alg_app_version_or_an_expired_config_with_60_s_skew()
    {
        var pinned = RaspJws.ParsePublicKeys(s_k1.Jwk);
        Assert.Equal("typ", RaspJws.Verify(s_k1.Sign(Claims(), Header(s_k1, typ: "JWT")), pinned, "orders-api", Now).Reason);
        Assert.Equal("alg", RaspJws.Verify(s_k1.Sign(Claims(), Header(s_k1, alg: "none")), pinned, "orders-api", Now).Reason);
        Assert.Equal("app", RaspJws.Verify(s_k1.Sign(Claims(app: "other")), pinned, "orders-api", Now).Reason);
        Assert.Equal("version", RaspJws.Verify(s_k1.Sign(Claims(v: 2)), pinned, "orders-api", Now).Reason);
        Assert.Equal("expired", RaspJws.Verify(s_k1.Sign(Claims(exp: Now - 61)), pinned, "orders-api", Now).Reason);
        Assert.True(RaspJws.Verify(s_k1.Sign(Claims(exp: Now - 30)), pinned, "orders-api", Now).Ok);
        Assert.Equal("version", RaspJws.Verify(s_k1.Sign(Claims(version: string.Empty)), pinned, "orders-api", Now).Reason);
    }

    [Fact]
    public void Refuses_a_tampered_payload()
    {
        var parts = s_k1.Sign(Claims()).Split('.');
        var forged = parts[0] + "." + TestKey.B64(Claims(killSwitch: true)) + "." + parts[2];
        Assert.Equal("signature", RaspJws.Verify(forged, RaspJws.ParsePublicKeys(s_k1.Jwk), "orders-api", Now).Reason);
        Assert.Equal("malformed", RaspJws.Verify("not.a.jws!", RaspJws.ParsePublicKeys(s_k1.Jwk), "orders-api", Now).Reason);
    }

    [Fact]
    public void Jwks_rotation_either_pinned_kid_verifies_and_an_unpinned_kid_does_not()
    {
        var k3 = new TestKey("k3");
        var jwks = RaspJws.ParsePublicKeys($$"""{"keys":[{{s_k1.Jwk}},{{s_k2.Jwk}}]}""");
        Assert.Equal(2, jwks.Count);
        Assert.True(RaspJws.Verify(s_k1.Sign(Claims()), jwks, "orders-api", Now).Ok);
        Assert.True(RaspJws.Verify(s_k2.Sign(Claims()), jwks, "orders-api", Now).Ok);
        Assert.False(RaspJws.Verify(k3.Sign(Claims()), jwks, "orders-api", Now).Ok);
    }

    [Fact]
    public void Parses_the_pin_as_a_jwk_a_jwks_or_the_bare_x_and_refuses_anything_else()
    {
        Assert.Single(RaspJws.ParsePublicKeys(s_k1.X));
        Assert.Equal("k1", RaspJws.ParsePublicKeys(s_k1.Jwk)[0].Kid);
        Assert.Equal(s_k1.X, RaspJws.ParsePublicKeys($$"""{"keys":[{{s_k1.Jwk}}]}""")[0].X);
        Assert.Empty(RaspJws.ParsePublicKeys(s_k1.Pem));
        Assert.Empty(RaspJws.ParsePublicKeys("not-a-key"));
        Assert.Empty(RaspJws.ParsePublicKeys($$"""{"kty":"RSA","crv":"x","x":"{{s_k1.X}}"}"""));
        Assert.Empty(RaspJws.ParsePublicKeys(null));

        // A bare key (no kid) verifies whatever kid the header names; so does a JWKS when the header's kid is not listed.
        Assert.True(RaspJws.Verify(s_k1.Sign(Claims()), RaspJws.ParsePublicKeys(s_k1.X), "orders-api", Now).Ok);
        Assert.True(RaspJws.Verify(s_k1.WithKid("unlisted").Sign(Claims()), RaspJws.ParsePublicKeys($$"""{"keys":[{{s_k2.Jwk}},{{s_k1.Jwk}}]}"""), "orders-api", Now).Ok);
    }

    // ---- client -------------------------------------------------------------

    private sealed class Harness : IDisposable
    {
        public Harness()
        {
            Dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "rasp-config-" + Guid.NewGuid().ToString("N"))).FullName;
        }

        public string Dir { get; }

        public List<RaspClaims?> Applied { get; } = new();

        public List<string> Warnings { get; } = new();

        public long NowMs { get; set; } = Now * 1000;

        public (RaspConfigClient Client, FakeHandler Handler) Client(
            Func<HttpRequestMessage, HttpResponseMessage> serve,
            IReadOnlyList<PinnedKey>? pinned = null,
            bool allowUnpinned = false,
            Func<double>? random = null,
            Func<DateTimeOffset>? now = null)
        {
            var handler = new FakeHandler(serve);
            var client = new RaspConfigClient(new RaspConfigClientOptions
            {
                Url = "https://shield.example.com/",
                ApiKey = "test-api-key",
                App = "orders-api",
                Pinned = pinned ?? RaspJws.ParsePublicKeys(s_k1.Jwk),
                AllowUnpinned = allowUnpinned,
                CacheDir = Dir,
                OnConfig = c => Applied.Add(c),
                OnWarning = w => Warnings.Add(w),
                Handler = handler,
                Now = now ?? (() => DateTimeOffset.FromUnixTimeMilliseconds(NowMs)),
                Random = random,
            });
            return (client, handler);
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Dir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    [Fact]
    public async Task Pinned_fetches_with_the_api_key_and_applies_a_verified_config()
    {
        using var h = new Harness();
        var (c, handler) = h.Client(_ => Json(Body(s_k1.Sign(Claims()), s_k1), "\"e1\""));
        using var _ = c;
        Assert.Equal(PollResult.Updated, await c.PollAsync());
        var request = handler.Requests[0].Request;
        Assert.Equal("https://shield.example.com/api/rasp/config?app=orders-api", request.RequestUri!.ToString());
        Assert.Equal("Bearer test-api-key", request.Headers.Authorization!.ToString());
        Assert.Equal("abc123", h.Applied[0]!.Version);
    }

    [Fact]
    public async Task Pinned_the_responses_own_key_is_not_trusted()
    {
        using var h = new Harness();
        var (c, _) = h.Client(_ => Json(Body(s_k2.Sign(Claims()), s_k2)));
        using var client = c;
        Assert.Equal(PollResult.Rejected, await c.PollAsync());
        Assert.Empty(h.Applied);
        Assert.Equal(new[] { "signature" }, h.Warnings);
    }

    [Fact]
    public async Task Unpinned_is_refused_without_fetching_and_nothing_is_applied()
    {
        using var h = new Harness();
        var (c, handler) = h.Client(_ => Json(Body(s_k1.Sign(Claims()), s_k1)), pinned: Array.Empty<PinnedKey>());
        using var client = c;
        Assert.Equal(PollResult.Rejected, await c.PollAsync());
        Assert.Empty(handler.Requests);
        Assert.Empty(h.Applied);
        Assert.Equal(new[] { "unpinned" }, h.Warnings);
    }

    [Fact]
    public async Task Allow_unpinned_trusts_the_first_key_then_refuses_a_different_one()
    {
        using var h = new Harness();
        var key = s_k1;
        var (c, _) = h.Client(_ => Json(Body(key.Sign(Claims()), key)), pinned: Array.Empty<PinnedKey>(), allowUnpinned: true);
        using var client = c;
        Assert.Equal(PollResult.Updated, await c.PollAsync());
        Assert.Contains("trust_on_first_use", h.Warnings);
        key = s_k2;
        Assert.Equal(PollResult.Rejected, await c.PollAsync());
    }

    [Fact]
    public async Task Etag_sends_if_none_match_and_keeps_the_config_on_304()
    {
        using var h = new Harness();
        var status = HttpStatusCode.OK;
        var (c, handler) = h.Client(_ => status == HttpStatusCode.NotModified
            ? new HttpResponseMessage(HttpStatusCode.NotModified)
            : Json(Body(s_k1.Sign(Claims())), "\"e1\""));
        using var client = c;
        await c.PollAsync();
        status = HttpStatusCode.NotModified;
        Assert.Equal(PollResult.Unchanged, await c.PollAsync());
        Assert.Equal("\"e1\"", handler.Requests[1].Request.Headers.GetValues("If-None-Match").Single());
        Assert.Equal("abc123", c.Current!.Version);
    }

    [Fact]
    public async Task Expiry_an_expired_config_is_refused_and_the_one_in_force_is_dropped_once_it_expires()
    {
        using var h = new Harness();
        var (stale, _) = h.Client(_ => Json(Body(s_k1.Sign(Claims(exp: Now - 3600)))));
        using (stale)
        {
            Assert.Equal(PollResult.Rejected, await stale.PollAsync());
        }

        var up = true;
        var (c, _) = h.Client(_ => up ? Json(Body(s_k1.Sign(Claims(exp: Now + 120)))) : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using var client = c;
        await c.PollAsync();
        up = false;
        h.NowMs += 600_000;
        Assert.Equal(PollResult.Failed, await c.PollAsync());
        Assert.Null(h.Applied[h.Applied.Count - 1]);
        Assert.Null(c.Current);
    }

    [Fact]
    public async Task A_poll_in_flight_when_the_client_stops_never_applies_or_caches()
    {
        using var h = new Harness();
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        var gate = 0;

        // The clock is read while verifying, after the response arrived: hold the poll
        // there, stop the client (a re-init), then let the poll go on.
        DateTimeOffset Clock()
        {
            if (Interlocked.Exchange(ref gate, 0) == 1)
            {
                entered.Set();
                release.Wait(TimeSpan.FromSeconds(10));
            }

            return DateTimeOffset.FromUnixTimeMilliseconds(Now * 1000);
        }

        var (c, _) = h.Client(_ => Json(Body(s_k1.Sign(Claims()))), now: Clock);
        using var client = c;
        Volatile.Write(ref gate, 1);
        var poll = Task.Run(c.PollAsync);
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
        c.Stop();
        release.Set();
        Assert.NotEqual(PollResult.Updated, await poll);
        Assert.Empty(h.Applied);
        Assert.Null(c.Current);
        Assert.False(File.Exists(c.CacheFile()));
    }

    [Fact]
    public void Failures_back_off_to_5_minutes_and_success_polls_about_every_minute()
    {
        using var h = new Harness();
        var (c, _) = h.Client(_ => new HttpResponseMessage(HttpStatusCode.OK), random: () => 1);
        using var client = c;
        Assert.Equal(RaspConfigClient.Backoff, c.NextDelay(PollResult.Failed));
        Assert.Equal(RaspConfigClient.Backoff, c.NextDelay(PollResult.Rejected));
        Assert.Equal(TimeSpan.FromSeconds(70), c.NextDelay(PollResult.Updated));
    }

    [Fact]
    public async Task Cache_is_re_verified_on_load_and_a_tampered_cache_is_refused()
    {
        using var h = new Harness();
        var (c, _) = h.Client(_ => Json(Body(s_k1.Sign(Claims(version: "cached")))));
        using (c)
        {
            Assert.Equal(PollResult.Updated, await c.PollAsync());
        }

        var (fresh, _) = h.Client(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using (fresh)
        {
            Assert.True(fresh.LoadCache());
            Assert.Equal("cached", fresh.Current!.Version);
            File.WriteAllText(fresh.CacheFile(), $$"""{"config":"{{s_k2.Sign(Claims(version: "forged"))}}","tofu":[{{s_k2.Jwk}}]}""");
        }

        var (other, _) = h.Client(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using (other)
        {
            Assert.False(other.LoadCache());
            Assert.Null(other.Current);
        }
    }

    [Fact]
    public async Task Never_throws_on_a_network_error_or_a_malformed_body()
    {
        using var h = new Harness();
        var (boom, _) = h.Client(_ => throw new HttpRequestException("offline"));
        using (boom)
        {
            Assert.Equal(PollResult.Failed, await boom.PollAsync());
        }

        var (c, _) = h.Client(_ => Json(Body("not.a.jws")));
        using (c)
        {
            Assert.Equal(PollResult.Rejected, await c.PollAsync());
        }

        var (junk, _) = h.Client(_ => Json("<html>"));
        using (junk)
        {
            Assert.Equal(PollResult.Failed, await junk.PollAsync());
        }
    }

    [Fact]
    public void To_remote_reads_modes_allow_lists_and_rules_and_ignores_sinks()
    {
        var claims = RaspJws.Verify(
            s_k1.Sign(Claims(extra: ""","sinks":[{"id":"sink.x"}]""").Replace("\"attacks\":{}", "\"attacks\":{\"sql_injection\":\"block\",\"bogus\":\"block\",\"xxe\":\"loud\"}")
                .Replace("\"commands\":[]", "\"commands\":[\"git\",\"\",3]")
                .Replace("\"rules\":null", "\"rules\":[{\"id\":\"vp.r\",\"match\":[{\"target\":\"method\",\"op\":\"present\"}]},{\"title\":\"no id\"}]")),
            RaspJws.ParsePublicKeys(s_k1.Jwk),
            "orders-api",
            Now).Claims!;
        var remote = RaspRuntime.ToRemote(claims);
        Assert.Equal(RaspMode.Monitor, remote.Mode);
        Assert.Equal(new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.SqlInjection] = RaspMode.Block }, remote.Attacks);
        Assert.Equal(new[] { "git" }, remote.AllowCommands);
        Assert.Empty(remote.AllowOutboundHosts!);
        Assert.Equal(new[] { "vp.r" }, remote.Rules!.Select(r => r.Id));
        Assert.False(remote.ReportTargets);
    }

    [Fact]
    public void To_remote_reads_report_targets_only_when_true()
    {
        RemoteConfig Parse(string extra) => RaspRuntime.ToRemote(RaspJws.Verify(s_k1.Sign(Claims(extra: extra)), RaspJws.ParsePublicKeys(s_k1.Jwk), "orders-api", Now).Claims!);
        Assert.True(Parse(",\"reportTargets\":true").ReportTargets);
        Assert.False(Parse(",\"reportTargets\":false").ReportTargets);
        Assert.False(Parse(",\"reportTargets\":\"true\"").ReportTargets);
    }

    // ---- start-up and the signed config ---------------------------------------

    private readonly List<string> _warnings = new();

    public RaspConfigClientTests()
    {
        RaspRuntime.ResetWarnings();
        RaspRuntime.Warn = m =>
        {
            lock (_warnings)
            {
                _warnings.Add(m);
            }
        };
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        RaspRuntime.Warn = m => System.Diagnostics.Trace.TraceWarning(m);
    }

    [Fact]
    public void Without_a_pin_no_config_fetch_monitor_only_and_one_log_line_per_process()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{}");
        var ctx = new RaspStartContext("orders-api", Url: "https://shield.example.com", ApiKey: "k", Env: Env.Empty, Handler: handler);
        var options = new RaspOptions
        {
            Mode = RaspMode.Block,
            Attacks = { [RaspAttackType.Ssrf] = RaspMode.Off },
            Components = false,
        };
        Assert.True(RaspRuntime.Start(options, ctx));
        Assert.Equal(RaspMode.Monitor, RaspEngine.ModeFor(RaspAttackType.SqlInjection));
        Assert.Equal(RaspMode.Off, RaspEngine.ModeFor(RaspAttackType.Ssrf));
        RaspRuntime.Start(new RaspOptions { Components = false }, ctx);
        RaspRuntime.Shutdown();
        Assert.DoesNotContain(handler.Requests, r => r.Request.RequestUri!.AbsolutePath == "/api/rasp/config");
        Assert.DoesNotContain(handler.Requests, r => r.Request.RequestUri!.AbsolutePath == "/api/guard/events");
        var line = Assert.Single(_warnings);
        Assert.Contains("ConfigPublicKey", line);
    }

    [Fact]
    public void Re_init_never_waits_on_the_network_to_flush_the_old_reporter()
    {
        using var release = new ManualResetEventSlim(false);
        var handler = new FakeHandler(req =>
        {
            if (req.RequestUri!.AbsolutePath == "/api/guard/events")
            {
                release.Wait(TimeSpan.FromSeconds(15));
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        var ctx = new RaspStartContext("orders-api", Url: "https://shield.example.com", ApiKey: "k", Env: Env.Empty, Handler: handler);
        try
        {
            Assert.True(RaspRuntime.Start(new RaspOptions { Components = false, Remote = false }, ctx));
            RaspEngine.HandleFinding(new RaspFinding(RaspAttackType.SqlInjection, "sqli.userinput"), "db");
            Assert.Single(RaspRuntime.Reporter!.Pending());

            var clock = System.Diagnostics.Stopwatch.StartNew();
            Assert.True(RaspRuntime.Start(new RaspOptions { Components = false, Remote = false }, ctx));
            clock.Stop();
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(2), $"re-init took {clock.Elapsed}");
        }
        finally
        {
            release.Set();
        }
    }

    [Fact]
    public void Trust_on_first_use_only_with_the_opt_in_and_never_in_production()
    {
        Assert.True(RaspRuntime.TofuAllowed(true, Env.Empty));
        Assert.True(RaspRuntime.TofuAllowed(false, Env.Of(("SHIELD360_CONFIG_TOFU", "dev"))));
        Assert.False(RaspRuntime.TofuAllowed(false, Env.Empty));
        Assert.False(RaspRuntime.TofuAllowed(true, Env.Of(("ASPNETCORE_ENVIRONMENT", "Production"))));
        Assert.False(RaspRuntime.TofuAllowed(true, Env.Of(("DOTNET_ENVIRONMENT", "production"))));
        Assert.False(RaspRuntime.TofuAllowed(false, Env.Of(("SHIELD360_CONFIG_TOFU", "dev"), ("ENVIRONMENT", "prod"))));
        Assert.False(RaspRuntime.TofuAllowed(true, Env.Of(("NODE_ENV", "production"))));

        var handler = new FakeHandler(HttpStatusCode.ServiceUnavailable, "{}");
        RaspRuntime.Start(
            new RaspOptions { Mode = RaspMode.Block, AllowUnpinnedConfig = true, Components = false },
            new RaspStartContext("a", Url: "https://s.example.com", ApiKey: "k", Env: Env.Of(("ASPNETCORE_ENVIRONMENT", "Production")), Handler: handler));
        Assert.Equal(RaspMode.Monitor, RaspEngine.ModeFor(RaspAttackType.SqlInjection));

        var dir = Path.Combine(Path.GetTempPath(), "rasp-tofu-" + Guid.NewGuid().ToString("N"));
        RaspRuntime.Start(
            new RaspOptions { Mode = RaspMode.Block, Components = false, CacheDir = dir },
            new RaspStartContext("a", Url: "https://s.example.com", ApiKey: "k", Env: Env.Of(("SHIELD360_CONFIG_TOFU", "dev")), Handler: handler));
        Assert.Equal(RaspMode.Block, RaspEngine.ModeFor(RaspAttackType.SqlInjection));
        Assert.Contains(_warnings, w => w.Contains("trust on first use", StringComparison.Ordinal));
        RaspRuntime.Shutdown();
        if (Directory.Exists(dir))
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task With_a_pin_from_the_environment_the_signed_kill_switch_turns_checks_off()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rasp-init-" + Guid.NewGuid().ToString("N"));
        using var gate = new ManualResetEventSlim(false);
        var exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 600;
        var handler = new FakeHandler(req =>
        {
            if (req.RequestUri!.AbsolutePath != "/api/rasp/config")
            {
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            gate.Wait(TimeSpan.FromSeconds(10));
            return Json(Body(s_k1.Sign(Claims(exp: exp, killSwitch: true))));
        });
        RaspRuntime.Start(
            new RaspOptions { Components = false, CacheDir = dir },
            new RaspStartContext(
                "orders-api",
                Url: "https://shield.example.com",
                ApiKey: "k",
                Env: Env.Of(("SHIELD360_CONFIG_PUBLIC_KEY", $$"""{"keys":[{{s_k1.Jwk}}]}""")),
                Handler: handler));

        // Start-up never waits for the config.
        Assert.True(RaspEngine.IsActive);
        gate.Set();
        for (var i = 0; i < 200 && RaspEngine.IsActive; i++)
        {
            await Task.Delay(25);
        }

        Assert.False(RaspEngine.IsActive);
        Assert.Equal("abc123", RaspEngine.Remote!.Version);
        RaspRuntime.Shutdown();
        Directory.Delete(dir, recursive: true);
    }

    [Fact]
    public void SHIELD360_RASP_off_wins_and_no_url_means_local_options_only()
    {
        Assert.False(RaspRuntime.Start(new RaspOptions(), new RaspStartContext("a", Env: Env.Of(("SHIELD360_RASP", "off")))));
        Assert.True(RaspRuntime.Start(new RaspOptions { Mode = RaspMode.Block }, new RaspStartContext("a", Env: Env.Empty)));
        Assert.Equal(RaspMode.Block, RaspEngine.ModeFor(RaspAttackType.SqlInjection));
        Assert.Null(RaspRuntime.Reporter);
        Assert.Null(RaspRuntime.Client);
        Assert.True(RaspRuntime.Start(null, new RaspStartContext("a", Env: Env.Of(("SHIELD360_RASP", "monitor")))));
        Assert.False(RaspRuntime.Start(null, new RaspStartContext("a", Env: Env.Empty)));
        Assert.False(RaspRuntime.Start(new RaspOptions { Enabled = false }, new RaspStartContext("a", Env: Env.Empty)));
    }

    [Fact]
    public void Always_allowed_hosts_are_the_shield360_url_and_the_otlp_endpoint()
    {
        RaspRuntime.Start(new RaspOptions(), new RaspStartContext("a", Url: "https://App.Shield360.ai/", OtlpEndpoint: "http://[::1]:4318", Env: Env.Empty));
        Assert.Equal(new[] { "app.shield360.ai", "::1" }, RaspEngine.AlwaysAllowedHosts);
    }

    [Fact]
    public void Init_with_rasp_options_turns_rasp_on_and_disposing_the_handle_turns_it_off()
    {
        using (Shield360Sdk.Init(
                   new Shield360Options { DisableTracing = true, DisableMetrics = true, ApplicationName = "init-rasp", Rasp = new RaspOptions { Mode = RaspMode.Block } },
                   Env.Empty))
        {
            Assert.True(Shield360Rasp.IsActive);
            Assert.Equal("init-rasp", RaspEngine.ApplicationName);
            Assert.Equal(RaspMode.Block, RaspEngine.ModeFor(RaspAttackType.CommandInjection));
        }

        Assert.False(Shield360Rasp.IsActive);

        using (Shield360Sdk.Init(new Shield360Options { DisableTracing = true, DisableMetrics = true }, Env.Empty))
        {
            Assert.False(Shield360Rasp.IsActive);
        }
    }

    [Fact]
    public void Add_shield360_starts_rasp_from_its_options_and_keeps_rasp_that_add_shield360_rasp_started()
    {
        try
        {
            var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
            Microsoft.Extensions.DependencyInjection.Shield360ServiceCollectionExtensions.AddShield360(
                services, o => o.Rasp = new RaspOptions { Mode = RaspMode.Block }, Env.Empty);
            Assert.True(Shield360Rasp.IsActive);
            Assert.Equal(RaspMode.Block, RaspEngine.ModeFor(RaspAttackType.PathTraversal));

            // Started first by AddShield360Rasp: AddShield360 without Rasp options leaves it on.
            Microsoft.Extensions.DependencyInjection.Shield360ServiceCollectionExtensions.AddShield360(services, null, Env.Empty);
            Assert.True(Shield360Rasp.IsActive);
        }
        finally
        {
            Shield360.Internal.Shield360Runtime.Current?.Deactivate();
        }
    }
}
