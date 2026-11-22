using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Shield360.Defend;
using Shield360.Rasp;
using Xunit;
using Xunit.Abstractions;

namespace Shield360.Tests.Rasp;

/// <summary>
/// AI attack agents (sdk/rasp/README.md "AI attack agents"): every case of the shared vectors
/// (testdata/ai-attack-agents.json), the tracker's bounds, and the ASP.NET Core middleware in a
/// real pipeline (TestServer). Port of attack-agents.test.ts.
/// </summary>
public class RaspAttackAgentsTests : RaspStateTest
{
    private const string EdgeSecret = "0123456789abcdef0123456789abcdef";
    private const string Browser = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";
    private static readonly JsonObject s_vectors = RaspCorpus.Load("testdata/ai-attack-agents.json");
    private readonly ITestOutputHelper _out;
    private ListSink _sink = new();

    public RaspAttackAgentsTests(ITestOutputHelper output)
    {
        _out = output;
        RaspAttackAgents.Tracker = new AttackAgentTracker();
        RaspDeception.Table = new RaspSuspiciousTable();
    }

    protected override void Dispose(bool disposing)
    {
        RaspAttackAgents.Tracker = new AttackAgentTracker();
        RaspDeception.Table = new RaspSuspiciousTable();
        EdgeContext.ResetReplay();
        base.Dispose(disposing);
    }

    private static JsonElement El(JsonNode? n) => JsonDocument.Parse(n is null ? "null" : n.ToJsonString()).RootElement.Clone();

    private static string? S(JsonNode? n) => n?.GetValue<string>();

    private static Dictionary<string, string> Headers(JsonNode? n) =>
        n is JsonObject o ? o.ToDictionary(kv => kv.Key, kv => kv.Value!.GetValue<string>(), StringComparer.Ordinal) : new Dictionary<string, string>(StringComparer.Ordinal);

    // ---- shared vectors ------------------------------------------------------------------

    [Fact]
    public void Reads_config_like_the_vectors()
    {
        var n = 0;
        foreach (var c in s_vectors["config"]!.AsArray())
        {
            var got = RaspAttackAgents.Parse(El(c!["value"]));
            var e = c["expect"]!;
            var want = new AttackAgentConfig(e["threshold"]!.GetValue<int>(), e["markTtlSeconds"]!.GetValue<int>(), e["retryAfterSeconds"]!.GetValue<int>(), e["tripwire"]!.GetValue<bool>(), S(e["tripwirePath"])!);
            Assert.True(want == got, $"{S(c["name"])}: {got}, want {want}");
            n++;
        }

        _out.WriteLine($"config {n}/{n}");
        Assert.Equal(s_vectors["config"]!.AsArray().Count, n);

        // The local option is read the same way; malformed JSON is the defaults.
        Assert.Equal(AttackAgentConfig.Default, RaspAttackAgents.ParseJson("{not json"));
        Assert.Equal(30, RaspAttackAgents.ParseJson("{\"threshold\":30}").Threshold);
        Assert.Null(RaspAttackAgents.ParseSigned(El(JsonValue.Create("strict"))));
    }

    [Fact]
    public void Client_and_user_keys_like_the_vectors()
    {
        foreach (var c in s_vectors["clientKey"]!.AsArray())
        {
            Assert.True(S(c!["key"]) == RaspAttackAgents.ClientKey(S(c["ip"])), $"{S(c["ip"])}: {RaspAttackAgents.ClientKey(S(c["ip"]))}");
        }

        foreach (var c in s_vectors["userKey"]!.AsArray())
        {
            Assert.Equal(S(c!["key"]), RaspAttackAgents.UserKey(S(c["user"])));
        }

        _out.WriteLine($"clientKey {s_vectors["clientKey"]!.AsArray().Count}, userKey {s_vectors["userKey"]!.AsArray().Count}");
    }

    [Fact]
    public void Fingerprints_like_the_vectors()
    {
        foreach (var c in s_vectors["fingerprint"]!.AsArray())
        {
            var got = RaspAttackAgents.Fingerprint(Headers(c!["headers"]));
            var e = c["expect"];
            Assert.True(e is null ? got is null : got is { } g && g.Kind == S(e["kind"]) && g.Id == S(e["id"]), $"{S(c["name"])}: {got}");
        }

        _out.WriteLine($"fingerprint {s_vectors["fingerprint"]!.AsArray().Count}");
    }

    [Fact]
    public void Finds_callback_domains_like_the_vectors()
    {
        foreach (var c in s_vectors["oast"]!.AsArray())
        {
            Assert.True(S(c!["expect"]) == RaspAttackAgents.FindCallbackDomain(S(c["value"])), $"{S(c["value"])}: {RaspAttackAgents.FindCallbackDomain(S(c["value"]))}");
        }

        _out.WriteLine($"oast {s_vectors["oast"]!.AsArray().Count}");
    }

    [Fact]
    public void Client_type_rules_like_the_vectors()
    {
        foreach (var c in s_vectors["clientTypeRules"]!.AsArray())
        {
            var rule = c!["rule"]!.AsArray().Select(x => x!.GetValue<string>()).ToList();
            var type = S(c["clientType"]);
            Assert.True(c["match"]!.GetValue<bool>() == ClientType.RuleMatches(rule, type), $"[{string.Join(",", rule)}] vs {type}");

            // Defend's rule matcher applies the same rule.
            var policy = DefendPolicy.Parse("{\"version\":\"v1\",\"exp\":1e10,\"rules\":[{\"id\":\"r\",\"action\":\"block\",\"clientTypes\":" + c["rule"]!.ToJsonString() + "}]}")!;
            Assert.Single(policy.Rules);
            var input = new DefendInput
            {
                Policy = policy,
                Compiled = new CompiledPolicy(policy),
                Facts = DefendFacts.Of(new DefendRequest { Method = "GET", Target = "/", RemoteAddr = "192.0.2.1" }),
                Classification = type is null ? null : new ClientClassification(type, Array.Empty<string>(), "high"),
            };
            Assert.Equal(c["match"]!.GetValue<bool>(), DefendEngine.Decide(input).RuleIds.Contains("r"));
        }

        _out.WriteLine($"clientTypeRules {s_vectors["clientTypeRules"]!.AsArray().Count}");
    }

    [Fact]
    public void Runs_every_sequence_like_the_vectors()
    {
        var defaults = Headers(s_vectors["defaultHeaders"]);
        var kinds = new HashSet<string>();
        var passed = 0;
        var sequences = s_vectors["sequences"]!.AsArray();
        var failures = new List<string>();
        foreach (var sq in sequences)
        {
            var kind = S(sq!["kind"])!;
            kinds.Add(kind);
            var merged = new JsonObject
            {
                ["threshold"] = 20, ["markTtlSeconds"] = 1800, ["retryAfterSeconds"] = 300, ["tripwire"] = false, ["tripwirePath"] = "/_debug/console",
            };
            if (sq["config"] is JsonObject over)
            {
                foreach (var kv in over)
                {
                    merged[kv.Key] = kv.Value?.DeepClone();
                }
            }

            var cfg = RaspAttackAgents.Parse(El(merged));
            var tracker = new AttackAgentTracker();
            var marked = false;
            var ok = true;
            var i = 0;
            foreach (var st in sq["steps"]!.AsArray())
            {
                var at = (long)st!["at"]!.GetValue<double>() * 1000;
                var r = new AgentRequest
                {
                    Ip = S(st["ip"]),
                    User = S(st["user"]),
                    Path = S(st["path"])!,
                    Headers = st["headers"] is null ? defaults : Headers(st["headers"]),
                    Inputs = st["inputs"]?.AsArray().Select(x => x!.GetValue<string>()).ToList(),

                    // A step's redTeam (Edge's verified rt) is left alone exactly like a verified client.
                    Verified = st["verified"]?.GetValue<bool>() == true || st["redTeam"]?.GetValue<bool>() == true,
                };
                var status = st["status"]!.GetValue<int>();
                var deter = false;
                AttackMark? mark;
                if (st["decoy"]?.GetValue<bool>() == true)
                {
                    mark = tracker.After(r, new AgentResponse { Status = status, Decoy = true }, cfg, at);
                }
                else
                {
                    var b = tracker.Before(r, cfg, at);
                    deter = b.Marked is not null;
                    mark = b.Mark;
                    if (!deter && !b.Tripwire)
                    {
                        mark = tracker.After(r, new AgentResponse { Status = status, Route = S(st["route"]), Finding = st["finding"]?.GetValue<bool>() == true }, cfg, at) ?? mark;
                    }
                }

                marked |= mark is not null;
                var e = st["expect"]!;
                var wantMark = e["mark"] is JsonObject m ? new AttackMark(S(m["kind"])!, S(m["reason"])!) : null;
                if (deter != e["deter"]!.GetValue<bool>() || !Equals(mark, wantMark))
                {
                    ok = false;
                    failures.Add($"{S(sq["name"])} step {i}: deter {deter} mark {mark}, want deter {e["deter"]} mark {wantMark}");
                }

                i++;
            }

            if (marked != (kind == "attack"))
            {
                ok = false;
                failures.Add($"{S(sq["name"])} ({kind}): marked {marked}");
            }

            passed += ok ? 1 : 0;
        }

        _out.WriteLine($"sequences {passed}/{sequences.Count}");
        Assert.True(failures.Count == 0, string.Join("\n", failures));
        Assert.Contains("attack", kinds);
        Assert.Contains("benign", kinds);
    }

    // ---- tracker -------------------------------------------------------------------------

    [Fact]
    public void The_tracker_is_bounded_and_marks_expire()
    {
        var cfg = AttackAgentConfig.Default;
        var t = new AttackAgentTracker(50, 20);
        for (var i = 0; i < 500; i++)
        {
            t.After(new AgentRequest { Ip = $"10.0.{i >> 8}.{i & 255}", Path = "/x" + i }, new AgentResponse { Status = 404 }, cfg, 1_000_000_000);
            t.Before(new AgentRequest { Ip = $"10.1.{i >> 8}.{i & 255}", Path = "/", Headers = new Dictionary<string, string> { ["user-agent"] = "sqlmap/1" } }, cfg, 1_000_000_000);
        }

        var (keys, marks) = t.Sizes;
        Assert.True(keys <= 50 && marks <= 20, $"{keys} {marks}");
        Assert.Equal(50, keys);
        Assert.Equal(20, marks);

        // The 20 newest marks are kept (oldest made first out).
        Assert.NotNull(t.MarkOf(new[] { "ip:10.1.1.243" }, 1_000_000_000));
        Assert.Null(t.MarkOf(new[] { "ip:10.1.0.0" }, 1_000_000_000));

        t = new AttackAgentTracker();
        var nikto = new AgentRequest { Ip = "192.0.2.1", Path = "/", Headers = new Dictionary<string, string> { ["user-agent"] = "nikto/2.5" } };
        Assert.Equal(new AttackMark("scanner", "fingerprint"), t.Before(nikto, cfg, 0).Marked);
        var later = new AgentRequest { Ip = "192.0.2.1", Path = "/", Headers = new Dictionary<string, string> { ["user-agent"] = "Mozilla/5.0" } };
        Assert.NotNull(t.Before(later, cfg, 1_799_999).Marked);
        Assert.Null(t.Before(later, cfg, 1_800_000).Marked);
        Assert.Equal(0, t.Sizes.Marks);
    }

    [Fact]
    public void A_mark_is_never_downgraded_and_tool_only_evidence_stays_scanner()
    {
        var cfg = AttackAgentConfig.Default;
        var t = new AttackAgentTracker();
        var oast = new AgentRequest { Ip = "192.0.2.2", Path = "/", Headers = new Dictionary<string, string> { ["user-agent"] = Browser }, Inputs = new[] { "http://x1.oast.fun/a" } };
        Assert.Equal(new AttackMark("ai_attack_agent", "oast"), t.Before(oast, cfg, 0).Mark);
        var tool = new AgentRequest { Ip = "192.0.2.2", Path = "/", Headers = new Dictionary<string, string> { ["user-agent"] = "sqlmap/1.8" } };
        Assert.Equal(new AttackMark("ai_attack_agent", "fingerprint"), t.Before(tool, cfg, 1000).Mark);
        var other = new AgentRequest { Ip = "192.0.2.3", Path = "/", Headers = tool.Headers };
        Assert.Equal(new AttackMark("scanner", "fingerprint"), t.Before(other, cfg, 0).Mark);
    }

    [Fact]
    public void The_tripwire_page_hides_the_url_twice_and_tokens_are_per_client()
    {
        var p = RaspAttackAgents.TripwirePage("/_debug/console/abc");
        Assert.Contains("<div hidden aria-hidden=\"true\">", p, StringComparison.Ordinal);
        Assert.Contains("<!-- ", p, StringComparison.Ordinal);
        Assert.Equal(2, Regex.Count(p, "/_debug/console/abc"));
        var a = RaspAttackAgents.TripwireToken("ip:192.0.2.1");
        Assert.Matches("^[A-Za-z0-9_-]{16}$", a);
        Assert.Equal(a, RaspAttackAgents.TripwireToken("ip:192.0.2.1"));
        Assert.NotEqual(a, RaspAttackAgents.TripwireToken("ip:192.0.2.2"));
        Assert.Null(RaspAttackAgents.TripwirePageFor("192.0.2.1", AttackAgentConfig.Default));
        Assert.Null(RaspAttackAgents.TripwirePageFor(null, AttackAgentConfig.Default with { Tripwire = true }));
        Assert.Null(RaspAttackAgents.TripwirePageFor("192.0.2.1", AttackAgentConfig.Default with { Tripwire = true }, verified: true));
    }

    [Fact]
    public void The_classifier_names_attack_agents_and_scanners_right_after_verified_clients()
    {
        var c = ClientType.Classify(new Dictionary<string, string> { ["user-agent"] = string.Empty, ["x-artex-replay-nonce"] = "1" });
        Assert.Equal(ClientType.AiAttackAgent, c.ClientType);
        Assert.Equal("attack_agent_header:artex-replay", c.Reasons[0]);
        Assert.Equal("high", c.Confidence);
        c = ClientType.Classify(new Dictionary<string, string> { ["user-agent"] = "sqlmap/1.8" });
        Assert.Equal(ClientType.Scanner, c.ClientType);
        Assert.Equal("ua_attack_tool:sqlmap", c.Reasons[0]);
        Assert.Equal(ClientType.VerifiedAgent, ClientType.Classify(new Dictionary<string, string> { ["user-agent"] = "sqlmap/1.8" }, new ClientSignals { VerifiedAgent = true }).ClientType);
        Assert.Equal(ClientType.AiAttackAgent, ClientType.Classify(new Dictionary<string, string> { ["user-agent"] = "Mozilla/5.0" }, new ClientSignals { AttackMark = ClientType.AiAttackAgent }).ClientType);
        Assert.Equal(ClientType.UnverifiedAutomation, ClientType.Classify(new Dictionary<string, string> { ["user-agent"] = "python-httpx/0.27" }).ClientType);
        Assert.Contains(ClientType.Scanner, ClientType.Types);
        Assert.Contains(ClientType.AiAttackAgent, ClientType.Types);
    }

    [Fact]
    public void The_deter_exception_is_a_429_with_its_own_body()
    {
        var e = new Shield360RaspBlockedException("attack_agent.fingerprint", new string('a', 32), 120);
        Assert.Equal(429, e.StatusCode);
        Assert.Equal(120, e.RetryAfterSeconds);
        Assert.Equal("ai_attack_agent", e.Attack);
        Assert.Equal("{\"error\":\"Too Many Requests\"}", e.ToResponseJson());
        Assert.Null(new Shield360RaspBlockedException(RaspAttackType.Xss, "x", "e").RetryAfterSeconds);
    }

    [Fact]
    public void Ai_attack_agent_is_an_attack_type_defaulting_to_monitor()
    {
        Assert.True(RaspNames.TryAttack("ai_attack_agent", out var a));
        Assert.Equal(RaspAttackType.AiAttackAgent, a);
        Assert.Equal("ai_attack_agent", RaspNames.Of(RaspAttackType.AiAttackAgent));
        Configure(new EngineSettings(true, "orders-api"));
        Assert.Equal(RaspMode.Monitor, RaspEngine.ModeFor(RaspAttackType.AiAttackAgent));
        Configure(new EngineSettings(true, "orders-api", Attacks: new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.AiAttackAgent] = RaspMode.Block }, MonitorOnly: true));
        Assert.Equal(RaspMode.Monitor, RaspEngine.ModeFor(RaspAttackType.AiAttackAgent));
    }

    [Fact]
    public void A_finding_feeds_the_score_and_a_block_is_never_an_auth_failure()
    {
        Configure(new EngineSettings(true, "orders-api", Attacks: new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.SqlInjection] = RaspMode.Block }));
        var ctx = new RaspContext(inRequest: true);
        RaspScope.Enter(ctx);
        Assert.Throws<Shield360RaspBlockedException>(() => RaspEngine.HandleFinding(new RaspFinding(RaspAttackType.SqlInjection, "sqli.userinput"), "db"));
        Assert.True(ctx.AgentFinding);
        Assert.True(ctx.OwnBlock);
        var other = new RaspContext(inRequest: true);
        RaspScope.Enter(other);
        RaspEngine.HandleFinding(new RaspFinding(RaspAttackType.Baseline, "baseline.x"), "start");
        Assert.False(other.AgentFinding);
    }

    // ---- middleware ----------------------------------------------------------------------

    private sealed class App
    {
        public WebApplication Web = null!;
        public List<string> Called { get; } = new();
    }

    private static async Task<App> Serve()
    {
        var app = new App();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var web = builder.Build();
        web.UseShield360Rasp();
        void Called(HttpContext c)
        {
            lock (app.Called)
            {
                app.Called.Add(c.Request.Path.Value!);
            }
        }

        web.MapGet("/", (HttpContext c) =>
        {
            Called(c);
            return "ok";
        });
        web.MapGet("/items/{id}", (HttpContext c) =>
        {
            Called(c);
            return Results.NotFound();
        });
        web.MapGet("/me", (HttpContext c) =>
        {
            Called(c);
            Shield360Rasp.IdentifyUser("alice");
            return Results.Unauthorized();
        });
        web.MapGet("/wp-admin", (HttpContext c) =>
        {
            Called(c);
            return "admin";
        });
        await web.StartAsync();
        app.Web = web;
        return app;
    }

    private void Arm(RaspMode mode, string? attackAgents = null, bool edge = false, bool deception = false, AttackAgentConfig? signed = null)
    {
        _sink = Configure(new EngineSettings(
            true,
            "orders-api",
            Attacks: new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.AiAttackAgent] = mode },
            AttackAgents: RaspAttackAgents.ParseJson(attackAgents)));
        if (edge || deception || signed is not null)
        {
            RaspEngine.SetRemoteConfig(new RemoteConfig
            {
                Version = "v9",
                Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
                Mode = RaspMode.Monitor,
                Attacks = new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.AiAttackAgent] = mode },
                EdgeKeys = edge ? EdgeContext.ParseKeys(JsonDocument.Parse("{\"keys\":[{\"kid\":\"0a1b2c3d\",\"key\":\"" + B64(Encoding.ASCII.GetBytes(EdgeSecret)) + "\"}]}").RootElement.Clone()) : Array.Empty<EdgeKey>(),
                Deception = deception ? RaspDeception.Parse(JsonDocument.Parse("{\"paths\":[\"/wp-admin\"],\"action\":\"monitor\"}").RootElement.Clone()) : null,
                AttackAgents = signed,
            });
        }
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A signed Edge context for GET <paramref name="path"/> with a fresh request id, and that id.</summary>
    private static (string Header, string Rid) EdgeHeader(string path, string ct = "unknown", string? rt = null)
    {
        var rid = "req_" + Guid.NewGuid().ToString("N").Substring(0, 12);
        var over = new Dictionary<string, object> { ["rid"] = rid, ["ct"] = ct };
        if (rt is not null)
        {
            over["rt"] = rt;
        }

        return (EdgeTriangleTests.CtxHeader(path, over), rid);
    }

    private static Dictionary<string, string> Via(string path, string ua, string ct = "unknown", string? rt = null)
    {
        var (header, rid) = EdgeHeader(path, ct, rt);
        return new Dictionary<string, string> { ["User-Agent"] = ua, [EdgeContext.ContextHeader] = header, [EdgeRequest.RequestIdHeader] = rid };
    }

    private static async Task<HttpContext> Send(App app, string target, string ip = "203.0.113.9", Dictionary<string, string>? headers = null)
    {
        return await app.Web.GetTestServer().SendAsync(c =>
        {
            c.Request.Method = "GET";
            var q = target.IndexOf('?');
            c.Request.Path = PathString.FromUriComponent(q >= 0 ? target.Substring(0, q) : target);
            if (q >= 0)
            {
                c.Request.QueryString = new QueryString(target.Substring(q));
            }

            c.Features.Get<IHttpRequestFeature>()!.RawTarget = target;
            c.Connection.RemoteIpAddress = IPAddress.Parse(ip);
            foreach (var kv in headers ?? new Dictionary<string, string> { ["User-Agent"] = Browser })
            {
                c.Request.Headers[kv.Key] = kv.Value;
            }
        });
    }

    private static string Body(HttpContext c)
    {
        if (c.Response.Body.CanSeek)
        {
            c.Response.Body.Position = 0;
        }

        return new System.IO.StreamReader(c.Response.Body).ReadToEnd();
    }

    private List<IReadOnlyDictionary<string, string>> Agent(string? rule = null) =>
        _sink.Events.Select(e => e.Attrs).Where(a => a["shield360.rasp.attack"] == "ai_attack_agent" && (rule is null || a["shield360.rasp.rule"] == rule)).ToList();

    private static string Payload(string verdict) =>
        Encoding.UTF8.GetString(Convert.FromBase64String(Pad(verdict.Split('.')[2].Replace('-', '+').Replace('_', '/'))));

    private static string Pad(string s) => s + new string('=', (4 - (s.Length % 4)) % 4);

    [Fact]
    public async Task Block_mode_deters_an_attack_tool_with_429_and_Retry_After()
    {
        Arm(RaspMode.Block);
        var app = await Serve();
        await using var _ = app.Web;
        var c = await Send(app, "/", headers: new() { ["User-Agent"] = "sqlmap/1.8.2#stable (https://sqlmap.org)" });
        Assert.Equal(429, c.Response.StatusCode);
        Assert.Equal("300", c.Response.Headers.RetryAfter.ToString());
        Assert.Equal("application/json", c.Response.ContentType);
        Assert.Equal("no-store", c.Response.Headers.CacheControl.ToString());
        Assert.Equal("{\"error\":\"Too Many Requests\"}", Body(c));
        Assert.Empty(app.Called);
        var e = Assert.Single(Agent());
        Assert.Equal("attack_agent.fingerprint", e["shield360.rasp.rule"]);
        Assert.Equal("http.attack_agent", e["shield360.rasp.sink"]);
        Assert.Equal("blocked", e["shield360.rasp.decision"]);
        Assert.Equal("scanner", e["shield360.rasp.client_kind"]);
        Assert.Equal("fingerprint", e["shield360.rasp.reason"]);
        Assert.False(e.ContainsKey("shield360.rasp.input_key"));

        // The marked address is deterred with any User-Agent; another address is not.
        var next = await Send(app, "/");
        Assert.Equal(429, next.Response.StatusCode);
        Assert.Equal("attack_agent.marked", Agent().Last()["shield360.rasp.rule"]);
        Assert.Equal(200, (await Send(app, "/", ip: "203.0.113.10")).Response.StatusCode);
    }

    [Fact]
    public async Task Monitor_mode_only_reports()
    {
        Arm(RaspMode.Monitor, attackAgents: "{\"retryAfterSeconds\":60}");
        var app = await Serve();
        await using var _ = app.Web;
        var c = await Send(app, "/?callback=http%3A%2F%2Fab12.oast.fun%2Fx");
        Assert.Equal(200, c.Response.StatusCode);
        Assert.Equal("ok", Body(c));
        var e = Assert.Single(Agent());
        Assert.Equal("attack_agent.oast", e["shield360.rasp.rule"]);
        Assert.Equal("monitored", e["shield360.rasp.decision"]);
        Assert.Equal("ai_attack_agent", e["shield360.rasp.client_kind"]);
        var next = await Send(app, "/");
        Assert.Equal(200, next.Response.StatusCode);
        Assert.Equal("attack_agent.marked", Agent().Last()["shield360.rasp.rule"]);
        Assert.Equal("oast", Agent().Last()["shield360.rasp.reason"]);
        Assert.Equal(2, app.Called.Count);
    }

    [Fact]
    public async Task Behavior_crosses_the_threshold_then_the_client_is_deterred()
    {
        Arm(RaspMode.Block);
        var app = await Serve();
        await using var _ = app.Web;
        for (var i = 0; i < 19; i++)
        {
            Assert.Equal(404, (await Send(app, "/fuzz/word" + i)).Response.StatusCode);
        }

        Assert.Empty(Agent());
        Assert.Equal(404, (await Send(app, "/fuzz/word19")).Response.StatusCode);
        var e = Assert.Single(Agent());
        Assert.Equal("attack_agent.behavior", e["shield360.rasp.rule"]);
        Assert.Equal("ai_attack_agent", e["shield360.rasp.client_kind"]);
        Assert.Equal("behavior", e["shield360.rasp.reason"]);
        Assert.Equal(429, (await Send(app, "/")).Response.StatusCode);
        Assert.Empty(app.Called);
    }

    [Fact]
    public async Task Auth_failures_and_enumeration_score_the_signed_in_user_too()
    {
        Arm(RaspMode.Block);
        var app = await Serve();
        await using var _ = app.Web;

        // 401s from the app (2 points each) for the user alice across addresses.
        for (var i = 0; i < 9; i++)
        {
            Assert.Equal(401, (await Send(app, "/me", ip: "198.51.100." + (i + 1))).Response.StatusCode);
        }

        Assert.Empty(Agent());
        Assert.Equal(401, (await Send(app, "/me", ip: "198.51.100.77")).Response.StatusCode);
        Assert.Equal("attack_agent.behavior", Assert.Single(Agent())["shield360.rasp.rule"]);

        // Enumeration: a matched route answering 404 for many ids.
        RaspAttackAgents.Tracker = new AttackAgentTracker();
        _sink.Events.Clear();
        for (var i = 0; i < 20; i++)
        {
            await Send(app, "/items/" + i, ip: "192.0.2.50");
        }

        Assert.Equal("attack_agent.behavior", Assert.Single(Agent())["shield360.rasp.rule"]);
    }

    [Fact]
    public async Task A_verified_Edge_context_gets_the_signed_block_verdict()
    {
        Arm(RaspMode.Block, edge: true);
        var app = await Serve();
        await using var _ = app.Web;
        var c = await Send(app, "/", headers: Via("/", "nuclei/3.3"));
        Assert.Equal(429, c.Response.StatusCode);
        var p = Payload(c.Response.Headers[EdgeContext.VerdictHeader].ToString());
        Assert.Contains("\"act\":\"block\"", p, StringComparison.Ordinal);
        Assert.Contains("\"cat\":\"scanner\"", p, StringComparison.Ordinal);
        Assert.Contains("\"src\":\"rasp\"", p, StringComparison.Ordinal);
        Assert.Contains("\"ttl\":1800", p, StringComparison.Ordinal);

        // A behavior mark sets the verdict on the response that crossed the threshold.
        RaspAttackAgents.Tracker = new AttackAgentTracker();
        HttpContext last = null!;
        for (var i = 0; i < 20; i++)
        {
            last = await Send(app, "/fuzz/w" + i, ip: "192.0.2.60", headers: Via("/fuzz/w" + i, Browser));
            if (i < 19)
            {
                Assert.False(last.Response.Headers.ContainsKey(EdgeContext.VerdictHeader));
            }
        }

        Assert.Equal(404, last.Response.StatusCode);
        Assert.Contains("\"cat\":\"ai_attack_agent\"", Payload(last.Response.Headers[EdgeContext.VerdictHeader].ToString()), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_client_Edge_verified_is_left_alone()
    {
        Arm(RaspMode.Block, edge: true);
        var app = await Serve();
        await using var _ = app.Web;
        foreach (var ct in new[] { "verified_crawler", "verified_agent" })
        {
            var c = await Send(app, "/?u=http%3A%2F%2Fcb.oast.fun", headers: Via("/", "nuclei/3.3", ct));
            Assert.Equal(200, c.Response.StatusCode);
        }

        Assert.Empty(Agent());
        Assert.Equal((0, 0), RaspAttackAgents.Tracker.Sizes);
    }

    [Fact]
    public async Task A_red_team_request_is_left_alone_even_from_a_marked_address()
    {
        Arm(RaspMode.Block, edge: true, attackAgents: "{\"tripwire\":true}");
        var app = await Serve();
        await using var _ = app.Web;
        Assert.Equal(429, (await Send(app, "/", headers: Via("/", "sqlmap/1.8"))).Response.StatusCode);
        var events = Agent().Count;

        // The same address, with a red team run id in Edge's verified context: through, unscored.
        var rt = await Send(app, "/", headers: Via("/", "sqlmap/1.8", rt: "run0123abcd"));
        Assert.Equal(200, rt.Response.StatusCode);
        Assert.False(rt.Response.Headers.ContainsKey(EdgeContext.VerdictHeader));
        for (var i = 0; i < 25; i++)
        {
            Assert.Equal(404, (await Send(app, "/fuzz/r" + i, headers: Via("/fuzz/r" + i, Browser, rt: "run0123abcd"))).Response.StatusCode);
        }

        // Even the tripwire URL is not a hit for it: the app answers.
        Assert.Equal(404, (await Send(app, "/_debug/console/x", ip: "198.51.100.200", headers: Via("/_debug/console/x", Browser, rt: "run0123abcd"))).Response.StatusCode);
        Assert.Equal(events, Agent().Count);
        Assert.Null(RaspAttackAgents.Tracker.MarkOf(new[] { "ip:198.51.100.200" }, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));

        // The same address without rt is deterred.
        Assert.Equal(429, (await Send(app, "/", headers: Via("/", Browser))).Response.StatusCode);
    }

    [Fact]
    public async Task Off_does_nothing()
    {
        Arm(RaspMode.Off, attackAgents: "{\"tripwire\":true}");
        var app = await Serve();
        await using var _ = app.Web;
        Assert.Equal(200, (await Send(app, "/", headers: new() { ["User-Agent"] = "sqlmap/1.8" })).Response.StatusCode);
        Assert.Equal(404, (await Send(app, "/_debug/console")).Response.StatusCode);
        for (var i = 0; i < 25; i++)
        {
            await Send(app, "/fuzz/" + i);
        }

        Assert.Equal(200, (await Send(app, "/")).Response.StatusCode);
        Assert.Empty(Agent());
        Assert.Equal((0, 0), RaspAttackAgents.Tracker.Sizes);
    }

    [Fact]
    public async Task A_decoy_serves_the_tripwire_page_and_a_client_that_follows_it_is_marked()
    {
        Arm(RaspMode.Block, deception: true, signed: AttackAgentConfig.Default with { Tripwire = true });
        var app = await Serve();
        await using var _ = app.Web;
        var decoy = await Send(app, "/wp-admin");
        Assert.Equal(404, decoy.Response.StatusCode);
        Assert.Equal("text/html; charset=utf-8", decoy.Response.ContentType);
        Assert.Equal("no-store", decoy.Response.Headers.CacheControl.ToString());
        var page = Body(decoy);
        var token = RaspAttackAgents.TripwireToken("ip:203.0.113.9");
        Assert.Equal(RaspAttackAgents.TripwirePage("/_debug/console/" + token), page);
        Assert.Empty(app.Called);
        Assert.Empty(Agent()); // a decoy is 10 points, under the threshold

        var url = Regex.Match(page, "console at (/_debug/console/[A-Za-z0-9_-]+) before").Groups[1].Value;
        var hit = await Send(app, url);
        Assert.Equal(429, hit.Response.StatusCode);
        var e = Assert.Single(Agent());
        Assert.Equal("attack_agent.tripwire", e["shield360.rasp.rule"]);
        Assert.Equal("tripwire", e["shield360.rasp.reason"]);
        Assert.Equal("ai_attack_agent", e["shield360.rasp.client_kind"]);
        Assert.Equal(429, (await Send(app, "/")).Response.StatusCode);

        // Monitor mode: the tripwire URL answers 404 and the handler never runs.
        Arm(RaspMode.Monitor, deception: true, signed: AttackAgentConfig.Default with { Tripwire = true });
        RaspAttackAgents.Tracker = new AttackAgentTracker();
        var monitored = await Send(app, "/_debug/console/anything", ip: "192.0.2.77");
        Assert.Equal(404, monitored.Response.StatusCode);
        Assert.Equal(string.Empty, Body(monitored));
        Assert.Equal("monitored", Agent().Last()["shield360.rasp.decision"]);
    }
}
