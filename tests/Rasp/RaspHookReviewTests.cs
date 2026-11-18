using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Shield360.AspNetCore;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Regressions from the review of the .NET sink hooks: the address check on every path a
/// request can take (pooled connections, proxies, handlers without RASP's connect
/// callback, redirects), SqlClient and EF Core state after a block, the client span of a
/// blocked request, and when the XSS check listens.
/// </summary>
public class RaspHookReviewTests : RaspStateTest
{
    private static RaspInput[] Inputs(params string[] values) => values.Select((v, i) => new RaspInput(v, "query.k" + i)).ToArray();

    private static RaspContext Request(params string[] values) => new(Inputs(values), inRequest: true);

    private static ListSink Mode(RaspMode mode, RaspAllowOptions? allow = null) => Configure(new EngineSettings(true, "review", mode, Allow: allow));

    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolve = RaspHttpCheck.Resolve;

    protected override void Dispose(bool disposing)
    {
        RaspHttpCheck.Resolve = _resolve;
        base.Dispose(disposing);
    }

    private static void ResolveAs(string host, IPAddress address) =>
        RaspHttpCheck.Resolve = (h, _) => Task.FromResult(h == host ? new[] { address } : Array.Empty<IPAddress>());

    // 1. A tainted request that would reuse a pooled connection is still address-checked.
    [Fact]
    public async Task A_tainted_request_on_a_pooled_connection_is_address_checked()
    {
        var sink = Mode(RaspMode.Block);
        using var server = new TinyHttpServer { KeepAlive = true };
        ResolveAs("pool.test", IPAddress.Loopback);
        using var client = Shield360RaspHttp.CreateClient();
        var url = new Uri($"http://pool.test:{server.Port}/");

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(url)).StatusCode);
        var e = await Assert.ThrowsAsync<Shield360RaspBlockedException>(() => RaspScope.Run(Request("pool.test"), () => client.GetAsync(url)));
        Assert.Equal("ssrf.internal", e.Rule);
        Assert.Equal(1, server.Accepted);
        Assert.Single(sink.Events);
    }

    // 2. Through a proxy, the destination is still address-checked (by the lookup before sending).
    [Fact]
    public async Task A_tainted_request_through_a_proxy_is_address_checked_before_it_reaches_the_proxy()
    {
        Mode(RaspMode.Block);
        using var proxy = new TinyHttpServer();
        ResolveAs("proxied.test", IPAddress.Parse("10.0.0.5"));
        var primary = new SocketsHttpHandler { Proxy = new WebProxy($"http://127.0.0.1:{proxy.Port}"), UseProxy = true };
        Shield360RaspHttp.UseConnectCheck(primary);
        using var client = new HttpClient(new Shield360RaspHttpHandler(primary));
        var e = await Assert.ThrowsAsync<Shield360RaspBlockedException>(() =>
            RaspScope.Run(Request("proxied.test"), () => client.GetAsync(new Uri("http://proxied.test/admin"))));
        Assert.Equal("ssrf.internal", e.Rule);
        Assert.Equal(0, proxy.Accepted);
    }

    // 3. A handler RASP's connect callback never sees (HTTP/3, another primary handler) still gets the address check.
    [Fact]
    public async Task A_tainted_request_is_address_checked_without_the_connect_callback()
    {
        Mode(RaspMode.Block);
        ResolveAs("h3.test", IPAddress.Parse("169.254.169.254"));
        using var client = new HttpClient(new Shield360RaspHttpHandler(new SocketsHttpHandler()));
        var e = await Assert.ThrowsAsync<Shield360RaspBlockedException>(() =>
            RaspScope.Run(Request("h3.test"), () => client.GetAsync(new Uri("https://h3.test/latest/meta-data"))));
        Assert.Equal("ssrf.metadata", e.Rule);
    }

    [Fact]
    public async Task An_untainted_request_costs_no_lookup()
    {
        var sink = Mode(RaspMode.Block);
        var lookups = 0;
        RaspHttpCheck.Resolve = (_, _) =>
        {
            lookups++;
            return Task.FromResult(new[] { IPAddress.Loopback });
        };
        var inner = new OkHandler();
        using var client = new HttpClient(new Shield360RaspHttpHandler(inner));
        await RaspScope.Run(Request("orders"), () => client.GetAsync(new Uri("https://api.test/orders")));
        Assert.Equal(0, lookups);
        Assert.Equal(1, inner.Calls);
        Assert.Empty(sink.Events);
    }

    private sealed class OkHandler : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    // 4. A redirect to a host outside the allow-list is refused, with RASP's handler and with the diagnostic hook alone.
    [Fact]
    public async Task A_redirect_outside_the_allow_list_is_refused_by_the_connect_check()
    {
        Mode(RaspMode.Block, new RaspAllowOptions { OutboundHosts = { "127.0.0.1" } });
        using var server = new TinyHttpServer { RedirectPath = "/go" };
        server.RedirectTo = $"http://localhost:{server.Port}/landing";
        using var client = Shield360RaspHttp.CreateClient();
        var e = await Assert.ThrowsAnyAsync<Exception>(() => client.GetAsync(new Uri($"http://127.0.0.1:{server.Port}/go")));
        Assert.Equal("outbound.not_allowed", Shield360RaspMiddleware.Blocked(e)?.Rule);
        Assert.Equal(1, server.Accepted);
    }

    [Fact]
    public async Task A_redirect_outside_the_allow_list_is_refused_by_the_diagnostic_hook()
    {
        Mode(RaspMode.Block, new RaspAllowOptions { OutboundHosts = { "127.0.0.1" } });
        Assert.True(RaspDiagnosticHooks.Install());
        using var server = new TinyHttpServer { RedirectPath = "/go" };
        server.RedirectTo = $"http://localhost:{server.Port}/landing";
        using var client = new HttpClient(new SocketsHttpHandler());
        var e = await Assert.ThrowsAnyAsync<Exception>(() => client.GetAsync(new Uri($"http://127.0.0.1:{server.Port}/go")));
        Assert.Equal("outbound.not_allowed", Shield360RaspMiddleware.Blocked(e)?.Rule);
        Assert.Equal(1, server.Accepted);
    }

    // 6. A command EF Core's check refused is not left marked as checked.
    [Fact]
    public void A_refused_command_is_not_marked_checked()
    {
        Mode(RaspMode.Block);
        using var command = new SqliteCommand("SELECT * FROM t WHERE a = 'x' OR '1'='1'");
        RaspScope.Run(Request("x' OR '1'='1"), () =>
        {
            Assert.Throws<Shield360RaspBlockedException>(() => RaspSql.CheckCommand("efcore.ExecuteReader", command, RaspSqlDialect.Sqlite));
            return 0;
        });
        Assert.False(RaspSql.TakeChecked(command));
    }

    [Fact]
    public void The_EF_Core_mark_ends_with_the_execution()
    {
        Mode(RaspMode.Monitor);
        using var command = new SqliteCommand("SELECT 1");
        RaspScope.Run(Request("orders"), () =>
        {
            RaspSql.CheckCommand("efcore.ExecuteReader", command, RaspSqlDialect.Sqlite);
            return 0;
        });
        new Shield360.EntityFrameworkCore.Shield360RaspCommandInterceptor().CommandFailed(command, null!);
        Assert.False(RaspSql.TakeChecked(command));
    }

    // 7. A block at SqlClient's event leaves the command checkable by its next async call.
    [Fact]
    public async Task A_blocked_SqlClient_async_call_leaves_the_next_one_checked()
    {
        Mode(RaspMode.Block);
        Assert.True(RaspDiagnosticHooks.Install());
        using var connection = new Microsoft.Data.SqlClient.SqlConnection("Server=127.0.0.1,9;Encrypt=false;Connect Timeout=1");
        using var command = new Microsoft.Data.SqlClient.SqlCommand("SELECT 1 WHERE a = 'x' OR '1'='1'", connection);
        await RaspScope.Run(Request("x' OR '1'='1"), async () =>
        {
            await Assert.ThrowsAsync<Shield360RaspBlockedException>(() => command.ExecuteScalarAsync());
            await Assert.ThrowsAsync<Shield360RaspBlockedException>(() => command.ExecuteReaderAsync());
            await Assert.ThrowsAsync<Shield360RaspBlockedException>(() => command.ExecuteXmlReaderAsync());
            await Assert.ThrowsAsync<Shield360RaspBlockedException>(() => command.ExecuteReaderAsync());
            return 0;
        });
    }

    // 9. The client span of a request blocked at the diagnostic event is stopped, as an error.
    [Fact]
    public async Task A_request_blocked_at_the_diagnostic_event_stops_its_client_activity()
    {
        Mode(RaspMode.Block);
        var stopped = new List<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == "System.Net.Http",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a =>
            {
                lock (stopped)
                {
                    stopped.Add(a);
                }
            },
        };
        ActivitySource.AddActivityListener(listener);
        Assert.True(RaspDiagnosticHooks.Install());
        using var client = new HttpClient(new SocketsHttpHandler());
        await Assert.ThrowsAsync<Shield360RaspBlockedException>(() =>
            RaspScope.Run(Request("http://127.0.0.1:9/"), () => client.GetAsync(new Uri("http://127.0.0.1:9/"))));
        var activity = Assert.Single(stopped, a => a.OperationName == RaspDiagnosticHooks.HttpClientActivity);
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
        Assert.Equal("ssrf.internal", activity.GetTagItem("shield360.rasp.rule"));
    }

    // 8 and 10: the XSS check.
    private static async Task<WebApplication> Serve(Action<WebApplication> map)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.UseShield360Rasp();
        map(app);
        await app.StartAsync();
        return app;
    }

    [Fact]
    public async Task A_streaming_response_gets_its_headers_on_flush_while_the_XSS_check_listens()
    {
        Mode(RaspMode.Monitor);
        var gate = new TaskCompletionSource();
        await using var app = await Serve(a => a.MapGet("/events", async (HttpContext c) =>
        {
            c.Response.ContentType = "text/event-stream";
            await c.Response.BodyWriter.FlushAsync();
            await gate.Task;
            await c.Response.WriteAsync("data: done\n\n");
        }));
        var client = app.GetTestClient();
        var q = Uri.EscapeDataString("<script>alert(1)</script>");
        var send = client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/events?q=" + q), HttpCompletionOption.ResponseHeadersRead);
        // Cancel the timeout once the headers arrive, so its timer does not outlive the test (CA2027).
        using var timeout = new CancellationTokenSource();
        var first = await Task.WhenAny(send, Task.Delay(TimeSpan.FromSeconds(5), timeout.Token));
        timeout.Cancel();
        gate.TrySetResult();
        Assert.Same(send, first);
        using var response = await send;
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("data: done\n\n", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Reflection_of_a_route_value_or_of_model_output_is_reported()
    {
        var sink = Mode(RaspMode.Monitor);
        const string modelSays = "<img src=x onerror=alert(document.domain)>";
        await using var app = await Serve(a =>
        {
            a.MapGet("/u/{name}", (string name) => Results.Content("<h1>" + name + "</h1>", "text/html"));
            a.MapGet("/chat", () =>
            {
                Shield360Rasp.RecordModelOutput(modelSays);
                return Results.Content("<div>" + modelSays + "</div>", "text/html");
            });
        });
        var client = app.GetTestClient();
        await client.GetStringAsync(new Uri("/u/" + Uri.EscapeDataString("<b onmouseover=alert(1)>x</b>"), UriKind.Relative));
        await client.GetStringAsync(new Uri("/chat", UriKind.Relative));
        Assert.Equal(new[] { "request", "model_output" }, sink.Events.Select(e => e.Attrs["shield360.rasp.source"]));
        Assert.All(sink.Events, e => Assert.Equal("xss.reflected", e.Attrs["shield360.rasp.rule"]));
    }
}
