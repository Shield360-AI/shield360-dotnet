using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using Shield360.Internal;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>The protection triangle (sdk/rasp/testdata/triangle.json) and request correlation (sdk/rasp/testdata/request-correlation.json).</summary>
public class EdgeTriangleTests : RaspStateTest
{
    private const string Key = "0123456789abcdef0123456789abcdef";
    private static readonly JsonObject s_triangle = RaspCorpus.Load("testdata/triangle.json");
    private static readonly JsonObject s_correlation = RaspCorpus.Load("testdata/request-correlation.json");

    protected override void Dispose(bool disposing)
    {
        RaspScope.Enter(null);
        EdgeContext.ResetReplay();
        base.Dispose(disposing);
    }

    private static JsonElement El(JsonNode? n) => JsonDocument.Parse(n is null ? "null" : n.ToJsonString()).RootElement.Clone();

    private static string? S(JsonNode? n) => n?.GetValue<string>();

    private static long L(JsonNode? n) => (long)n!.GetValue<double>();

    [Fact]
    public void Parses_keys_like_the_corpus()
    {
        foreach (var c in s_triangle["parseKeys"]!.AsArray())
        {
            var kids = EdgeContext.ParseKeys(El(c!["config"])).Select(k => k.Kid).ToList();
            Assert.Equal(c["kids"]!.AsArray().Select(k => k!.GetValue<string>()).ToList(), kids);
        }
    }

    [Fact]
    public void Verifies_contexts_like_the_corpus()
    {
        var keys = EdgeContext.ParseKeys(El(s_triangle["edgeContext"]));
        var caches = new Dictionary<string, EdgeReplayCache>();
        var n = 0;
        foreach (var c in s_triangle["context"]!.AsArray())
        {
            var group = c!["replayGroup"]?.ToJsonString();
            EdgeReplayCache? cache = null;
            if (group is not null && !caches.TryGetValue(group, out cache))
            {
                caches[group] = cache = new EdgeReplayCache();
            }

            var got = EdgeContext.Verify(keys, S(c["header"]), S(c["method"])!, S(c["path"])!, S(c["requestId"]), L(c["now"]), cache);
            var name = S(c["name"]);
            if (c["expect"] is null)
            {
                Assert.True(got is null, name);
            }
            else
            {
                Assert.True(got is not null, name);
                var e = c["expect"]!;
                Assert.Equal(S(e["rid"]), got!.Rid);
                Assert.Equal(L(e["iat"]), got.Iat);
                Assert.Equal(L(e["exp"]), got.Exp);
                Assert.Equal(S(e["m"]), got.Method);
                Assert.Equal(S(e["ph"]), got.PathHash);
                Assert.Equal(S(e["ct"]), got.ClientType);
                Assert.Equal(L(e["risk"]), got.Risk);
                Assert.Equal(L(e["trap"]), got.Trap);
                Assert.Equal(e["fl"]!.GetValue<bool>(), got.Flagged);
                Assert.Equal(e["waf"]?.AsArray().Select(w => w!.GetValue<string>()).ToList(), got.Waf?.ToList());
                Assert.Equal(S(e["tp"]), got.Traceparent);
                Assert.Equal(S(e["rt"]), got.RedTeam);
                Assert.Equal(S(e["sid"]), got.Session);
                Assert.Equal(S(e["fp"]), got.Fingerprint);
            }

            n++;
        }

        Assert.True(n >= 40);
    }

    [Fact]
    public void Signs_verdicts_marks_and_hashes_like_the_corpus()
    {
        var keys = EdgeContext.ParseKeys(El(s_triangle["edgeContext"]));
        foreach (var c in s_triangle["verdict"]!.AsArray())
        {
            Assert.Equal(S(c!["expect"]), EdgeContext.SignVerdict(keys, S(c["rid"])!, S(c["act"])!, S(c["cat"])!, S(c["src"])!, L(c["ttl"]), L(c["iat"])));
        }

        foreach (var c in s_triangle["suspect"]!.AsArray())
        {
            var x = c!["context"]!;
            var ctx = new EdgeRequestContext("req_00000000", 0, 0, "GET", string.Empty, S(x["ct"])!, (int)L(x["risk"]), (int)L(x["trap"]), x["fl"]!.GetValue<bool>(), null, null);
            Assert.Equal(c["expect"]!.GetValue<bool>(), EdgeContext.SaysSuspect(ctx));
        }

        foreach (var c in s_triangle["pathHash"]!.AsArray())
        {
            Assert.Equal(S(c!["hex"]), EdgeContext.PathHash(S(c["path"])!));
        }
    }

    [Fact]
    public void Request_ids_and_traceparents_like_the_corpus()
    {
        foreach (var c in s_correlation["requestId"]!.AsArray())
        {
            Assert.Equal(S(c!["expect"]), EdgeRequest.RequestIdOf(S(c["value"])));
        }

        foreach (var c in s_correlation["traceparent"]!.AsArray())
        {
            Assert.Equal(S(c!["expect"]), EdgeRequest.TraceIdOf(S(c["value"])));
        }
    }

    internal static string CtxHeader(string path, Dictionary<string, object> over)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var p = new Dictionary<string, object>
        {
            ["rid"] = "req_" + Guid.NewGuid().ToString("N").Substring(0, 12),
            ["iat"] = now,
            ["exp"] = now + 30,
            ["m"] = "GET",
            ["ph"] = EdgeContext.PathHash(path),
            ["ct"] = "unknown",
            ["risk"] = 0,
            ["trap"] = 0,
            ["fl"] = false,
        };
        foreach (var kv in over)
        {
            p[kv.Key] = kv.Value;
        }

        var payload = B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(p)));
        using var h = new HMACSHA256(Encoding.ASCII.GetBytes(Key));
        return "v1.0a1b2c3d." + payload + "." + B64(h.ComputeHash(Encoding.UTF8.GetBytes("s360-ctx|v1|" + payload)));
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void EdgeKeys() => RaspEngine.SetRemoteConfig(new RemoteConfig
    {
        Version = "cfg-1",
        Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
        EdgeKeys = EdgeContext.ParseKeys(JsonDocument.Parse("{\"keys\":[{\"kid\":\"0a1b2c3d\",\"key\":\"" + B64(Encoding.ASCII.GetBytes(Key)) + "\"}]}").RootElement.Clone()),
    });

    private static RaspContext Request(Dictionary<string, string> headers, Dictionary<string, string> sent, string url = "/api/x?id=1")
    {
        // Edge sends its own X-Request-Id (the signed rid) with every context; a test that sets none gets that one.
        if (headers.TryGetValue(EdgeContext.ContextHeader, out var edge) && !headers.ContainsKey(EdgeRequest.RequestIdHeader) && edge.Split('.') is { Length: 4 } parts)
        {
            using var doc = JsonDocument.Parse(Convert.FromBase64String(Pad(parts[2].Replace('-', '+').Replace('_', '/'))));
            if (doc.RootElement.TryGetProperty("rid", out var rid) && rid.ValueKind == JsonValueKind.String)
            {
                headers[EdgeRequest.RequestIdHeader] = rid.GetString()!;
            }
        }

        var ctx = RaspCapture.CaptureRequest(new RequestShape { Framework = "test", Method = "GET", Url = url, Headers = headers });
        ctx.SetHeader = (k, v) => sent[k] = v;
        return ctx;
    }

    [Fact]
    public void A_context_without_Edges_request_id_is_not_trusted()
    {
        EdgeKeys();
        var headers = new Dictionary<string, string> { [EdgeContext.ContextHeader] = CtxHeader("/api/x", new() { ["fl"] = true, ["rid"] = "req_lifted_0001" }) };
        Assert.Null(RaspCapture.CaptureRequest(new RequestShape { Framework = "test", Method = "GET", Url = "/api/x", Headers = headers }).Edge);
    }

    private static readonly RaspFinding s_sqli = new(RaspAttackType.SqlInjection, "sqli.userinput", new RaspInput("1 or 1=1", "query.id"));

    private static string Payload(string verdict) => Encoding.UTF8.GetString(Convert.FromBase64String(Pad(verdict.Split('.')[2].Replace('-', '+').Replace('_', '/'))));

    private static string Pad(string s) => s + new string('=', (4 - (s.Length % 4)) % 4);

    [Fact]
    public void A_flagged_client_is_blocked_for_injection_the_app_only_monitors()
    {
        var sink = Configure(new EngineSettings(true, "orders-api", RaspMode.Monitor));
        EdgeKeys();
        var sent = new Dictionary<string, string>();
        var ctx = Request(new() { [EdgeContext.ContextHeader] = CtxHeader("/api/x", new() { ["ct"] = "suspected_agent", ["fl"] = true, ["rid"] = "req_flagged_0001" }) }, sent);
        Assert.NotNull(ctx.Edge);
        RaspScope.Enter(ctx);
        Assert.Throws<Shield360RaspBlockedException>(() => RaspEngine.HandleFinding(s_sqli, "db"));
        var a = sink.Events.Last().Attrs;
        Assert.Equal("true", a["shield360.rasp.tightened_by_edge"]);
        Assert.Equal("req_flagged_0001", a["shield360.edge.request_id"]);
        var p = Payload(sent[EdgeContext.VerdictHeader]);
        Assert.Contains("\"act\":\"block\"", p);
        Assert.Contains("\"cat\":\"sql_injection\"", p);
    }

    [Fact]
    public void An_unmarked_client_is_monitored_and_flagged_once()
    {
        var sink = Configure(new EngineSettings(true, "orders-api", RaspMode.Monitor));
        EdgeKeys();
        var sent = new Dictionary<string, string>();
        RaspScope.Enter(Request(new() { [EdgeContext.ContextHeader] = CtxHeader("/api/x", new()) }, sent));
        Assert.Equal(RaspDecision.Monitored, RaspEngine.HandleFinding(s_sqli, "db"));
        Assert.Contains("\"act\":\"flag\"", Payload(sent[EdgeContext.VerdictHeader]));
        sent.Clear();
        RaspEngine.HandleFinding(s_sqli, "db");
        Assert.Empty(sent);
        Assert.False(sink.Events.Last().Attrs.ContainsKey("shield360.rasp.tightened_by_edge"));
    }

    [Fact]
    public void Verified_crawlers_forged_contexts_and_a_mismatched_request_id_change_nothing()
    {
        var sink = Configure(new EngineSettings(true, "orders-api", RaspMode.Monitor));
        EdgeKeys();
        var forged = CtxHeader("/api/x", new() { ["fl"] = true });
        forged = forged.Substring(0, forged.Length - 2) + "xx";
        foreach (var h in new[]
        {
            new Dictionary<string, string> { [EdgeContext.ContextHeader] = CtxHeader("/api/x", new() { ["ct"] = "verified_crawler", ["fl"] = true }) },
            new Dictionary<string, string> { [EdgeContext.ContextHeader] = forged },
            new Dictionary<string, string> { [EdgeContext.ContextHeader] = CtxHeader("/api/x", new() { ["fl"] = true, ["rid"] = "req_aaaaaaaaaa" }), [EdgeRequest.RequestIdHeader] = "req_bbbbbbbbbb" },
        })
        {
            RaspScope.Enter(Request(h, new Dictionary<string, string>()));
            Assert.Equal(RaspDecision.Monitored, RaspEngine.HandleFinding(s_sqli, "db"));
            Assert.False(sink.Events.Last().Attrs.ContainsKey("shield360.rasp.tightened_by_edge"));
        }
    }

    [Fact]
    public void Puts_the_ids_on_log_records_like_the_corpus()
    {
        Configure(new EngineSettings(true, "orders-api", RaspMode.Monitor));
        using var source = new ActivitySource("edge-tests");
        using var listener = new ActivityListener { ShouldListenTo = s => s.Name == "edge-tests", Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded };
        ActivitySource.AddActivityListener(listener);
        foreach (var c in s_correlation["resolve"]!.AsArray())
        {
            EdgeContext.ResetReplay();
            EdgeKeys();
            var headers = new Dictionary<string, string>();
            if (S(c!["xRequestId"]) is { } x)
            {
                headers[EdgeRequest.RequestIdHeader] = x;
            }

            if (S(c["traceparent"]) is { } tp)
            {
                headers["traceparent"] = tp;
            }

            if (S(c["edgeRid"]) is { } rid)
            {
                headers[EdgeContext.ContextHeader] = CtxHeader("/a", new() { ["rid"] = rid });
                // A context verifies only with Edge's own X-Request-Id (the same id).
                headers.TryAdd(EdgeRequest.RequestIdHeader, rid);
            }

            var exporter = new AppLogsTests.CapturingExporter();
            var resolved = ResolvedOptions.Resolve(new Shield360Options { ApplicationName = "logs-test", CaptureLogs = true }, Env.Empty);
            using (var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddShield360Logs(resolved, setResource: true, new Shield360LogProcessor(new OpenTelemetry.SimpleLogRecordExportProcessor(exporter), LogLevel.Information))))
            {
                using var span = c["spanActive"]!.GetValue<bool>() ? source.StartActivity("GET /a") : null;
                RaspScope.Enter(RaspCapture.CaptureRequest(new RequestShape { Framework = "test", Method = "GET", Url = "/a", Headers = headers }));
                factory.CreateLogger("tests.app").LogInformation("served");
                RaspScope.Enter(null);
            }

            var attrs = exporter.Records.Single().Attributes.Where(kv => kv.Key.StartsWith("shield360.edge.", StringComparison.Ordinal)).ToDictionary(kv => kv.Key, kv => (string?)kv.Value);
            var expect = c["expect"]!.AsObject().ToDictionary(kv => kv.Key, kv => (string?)kv.Value!.GetValue<string>());
            Assert.Equal(expect, attrs);
        }
    }

    [Fact]
    public void Tags_the_server_span_and_carries_the_id_to_logs_in_child_spans()
    {
        using var source = new ActivitySource("edge-tests-2");
        using var listener = new ActivityListener { ShouldListenTo = s => s.Name == "edge-tests-2", Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded };
        ActivitySource.AddActivityListener(listener);
        using var server = source.StartActivity("GET /a")!;
        EdgeRequest.TagServerSpan(server, EdgeRequest.RequestIdOf("3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6"));
        using var child = source.StartActivity("db")!;
        Assert.Equal("3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6", server.GetTagItem(EdgeRequest.RequestIdAttr));
        Assert.Equal("3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6", EdgeRequest.Current().RequestId);
    }
}
