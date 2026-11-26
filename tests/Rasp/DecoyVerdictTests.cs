using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Shield360.Defend;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// SHIELD: decoy and trap verdicts (agent-guides/edge-deception-spec.md, "What each layer does";
/// sdk/rasp/README.md "Deception"): a decoy or Defend trap hit behind Edge carries a signed
/// X-Shield360-Verdict, so Edge blocks the client fleet-wide; never without a verified context,
/// for a verified crawler, a red team run or the simulated client.
/// </summary>
public class DecoyVerdictTests : RaspStateTest
{
    private const string Key = "0123456789abcdef0123456789abcdef";

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static IReadOnlyList<EdgeKey> Keys() =>
        EdgeContext.ParseKeys(JsonDocument.Parse("{\"keys\":[{\"kid\":\"0a1b2c3d\",\"key\":\"" + B64(Encoding.ASCII.GetBytes(Key)) + "\"}]}").RootElement.Clone());

    private static string Payload(string verdict)
    {
        var s = verdict.Split('.')[2].Replace('-', '+').Replace('_', '/');
        return Encoding.UTF8.GetString(Convert.FromBase64String(s + new string('=', (4 - (s.Length % 4)) % 4)));
    }

    private static string Rid(string header)
    {
        using var doc = JsonDocument.Parse(Payload(header));
        return doc.RootElement.GetProperty("rid").GetString()!;
    }

    private static void Arm(string action, bool keyed = true)
    {
        Configure(new EngineSettings(true, "orders-api", Attacks: new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.AiAttackAgent] = RaspMode.Off }));
        RaspDeception.Table = new RaspSuspiciousTable();
        using var doc = JsonDocument.Parse("{\"paths\":[\"/wp-admin\"],\"action\":\"" + action + "\",\"ttlSeconds\":1200}");
        RaspEngine.SetRemoteConfig(new RemoteConfig
        {
            Version = "v-dv",
            Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
            Deception = RaspDeception.Parse(doc.RootElement.Clone()),
            EdgeKeys = keyed ? Keys() : Array.Empty<EdgeKey>(),
        });
    }

    private static async Task<WebApplication> Serve()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var web = builder.Build();
        web.UseShield360Rasp();
        web.MapGet("/{**any}", () => "app");
        await web.StartAsync();
        return web;
    }

    private static async Task<HttpContext> Send(WebApplication web, string path, string ip, Dictionary<string, object>? over)
    {
        string? header = over is null ? null : EdgeTriangleTests.CtxHeader(path, over);
        return await web.GetTestServer().SendAsync(c =>
        {
            c.Request.Method = "GET";
            c.Request.Path = path;
            c.Connection.RemoteIpAddress = IPAddress.Parse(ip);
            if (header is not null)
            {
                c.Request.Headers[EdgeContext.ContextHeader] = header;
                c.Request.Headers[EdgeRequest.RequestIdHeader] = Rid(header);
            }
        });
    }

    [Fact]
    public async Task A_decoy_hit_behind_Edge_carries_a_block_verdict_with_the_deception_ttl()
    {
        Arm("block");
        await using var web = await Serve();
        var c = await Send(web, "/wp-admin/setup.php", "203.0.113.7", new());
        Assert.Equal(404, c.Response.StatusCode);
        var p = Payload(c.Response.Headers[EdgeContext.VerdictHeader].ToString());
        Assert.Contains("\"act\":\"block\"", p, StringComparison.Ordinal);
        Assert.Contains("\"cat\":\"deception\"", p, StringComparison.Ordinal);
        Assert.Contains("\"src\":\"rasp\"", p, StringComparison.Ordinal);
        Assert.Contains("\"ttl\":1200", p, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_monitored_hit_still_blocks_at_Edge_and_exempt_or_unverified_hits_send_nothing()
    {
        Arm("monitor");
        await using (var web = await Serve())
        {
            var c = await Send(web, "/wp-admin", "203.0.113.8", new());
            Assert.Equal(404, c.Response.StatusCode);
            var mp = Payload(c.Response.Headers[EdgeContext.VerdictHeader].ToString());
            Assert.Contains("\"act\":\"block\"", mp, StringComparison.Ordinal);
            Assert.Contains("\"cat\":\"deception\"", mp, StringComparison.Ordinal);
        }

        Arm("block");
        await using var web2 = await Serve();
        var cases = new (string Ip, Dictionary<string, object>? Over)[]
        {
            ("203.0.113.9", null),
            ("203.0.113.10", new() { ["ct"] = "verified_crawler" }),
            ("203.0.113.11", new() { ["rt"] = "crun12345678" }),
            (EdgeContext.SimulatedClient, new()),
        };
        foreach (var (ip, over) in cases)
        {
            var c = await Send(web2, "/wp-admin", ip, over);
            Assert.Equal(404, c.Response.StatusCode);
            Assert.False(c.Response.Headers.ContainsKey(EdgeContext.VerdictHeader), ip);
        }
    }

    [Fact]
    public void A_Defend_trap_hit_behind_Edge_carries_a_block_verdict_cat_trap_src_defend()
    {
        var secret = B64(Encoding.ASCII.GetBytes(Key));
        var p = DefendPolicy.Parse("{\"version\":\"v1\",\"exp\":1e10,\"traps\":{\"action\":\"block\",\"ttlSeconds\":1800},\"honeypots\":{\"enabled\":true,\"mode\":\"block\",\"secret\":\"" + secret + "\"},\"edgeContext\":{\"keys\":[{\"kid\":\"0a1b2c3d\",\"key\":\"" + secret + "\"}]}}")!;
        using var d = Shield360Defend.Build(new DefendOptions { App = "shop", Policy = p });
        DefendResult Hit(string ip, Dictionary<string, object>? over)
        {
            var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["user-agent"] = "agent/1" };
            var path = d.Crumbs(new DefendRequest { Method = "GET", Target = "/", Headers = h, RemoteAddr = ip })!.Path;
            if (over is not null)
            {
                var header = EdgeTriangleTests.CtxHeader(path, over);
                h[EdgeContext.ContextHeader] = header;
                h["x-request-id"] = Rid(header);
            }

            return d.Decide(new DefendRequest { Method = "GET", Target = path, Headers = h, RemoteAddr = ip });
        }

        var r = Hit("198.51.100.30", new());
        Assert.NotNull(r.Decoy);
        var v = Payload(r.Verdict!);
        Assert.Contains("\"act\":\"block\"", v, StringComparison.Ordinal);
        Assert.Contains("\"cat\":\"trap\"", v, StringComparison.Ordinal);
        Assert.Contains("\"src\":\"defend\"", v, StringComparison.Ordinal);
        Assert.Contains("\"ttl\":1800", v, StringComparison.Ordinal);
        Assert.Equal(r.Verdict, Shield360Defend.ResponseFor(r)!.Headers[EdgeContext.VerdictHeader]);
        Assert.Null(Hit("198.51.100.31", null).Verdict);
        Assert.Null(Hit("198.51.100.32", new() { ["ct"] = "verified_crawler" }).Verdict);
        Assert.Null(Hit("198.51.100.33", new() { ["rt"] = "crun12345678" }).Verdict);
        Assert.Null(Hit(EdgeContext.SimulatedClient, new()).Verdict);
        Assert.Contains("trap:honeypot", Hit("198.51.100.34", null).Reasons);
    }

    [Theory]
    [InlineData("monitor", false)]
    [InlineData("block", true)]
    public void A_Defend_trap_hit_in_monitor_still_blocks_at_Edge(string honeypotMode, bool monitorMode)
    {
        var secret = B64(Encoding.ASCII.GetBytes(Key));
        var p = DefendPolicy.Parse("{\"version\":\"v1\",\"exp\":1e10,\"traps\":{\"action\":\"block\",\"ttlSeconds\":1800},\"honeypots\":{\"enabled\":true,\"mode\":\"" + honeypotMode + "\",\"secret\":\"" + secret + "\"},\"edgeContext\":{\"keys\":[{\"kid\":\"0a1b2c3d\",\"key\":\"" + secret + "\"}]}}")!;
        using var d = Shield360Defend.Build(new DefendOptions { App = "shop", Policy = p, Mode = monitorMode ? DefendMode.Monitor : DefendMode.Enforce });
        var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["user-agent"] = "agent/1" };
        var path = d.Crumbs(new DefendRequest { Method = "GET", Target = "/", Headers = h, RemoteAddr = "198.51.100.50" })!.Path;
        var header = EdgeTriangleTests.CtxHeader(path, new());
        h[EdgeContext.ContextHeader] = header;
        h["x-request-id"] = Rid(header);
        var r = d.Decide(new DefendRequest { Method = "GET", Target = path, Headers = h, RemoteAddr = "198.51.100.50" });
        Assert.NotEqual(DefendVerdict.Deny, r.Decision);
        var v = Payload(r.Verdict!);
        Assert.Contains("\"act\":\"block\"", v, StringComparison.Ordinal);
        Assert.Contains("\"cat\":\"trap\"", v, StringComparison.Ordinal);
        Assert.Contains("\"src\":\"defend\"", v, StringComparison.Ordinal);
    }
}
