using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Shield360.Rasp;

namespace Shield360.Tests.Rasp;

/// <summary>A loopback HTTP/1.1 server that answers 200 to anything and counts connections.</summary>
internal sealed class TinyHttpServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private int _accepted;

    public TinyHttpServer()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = Task.Run(AcceptLoop);
    }

    public int Port { get; }

    public int Accepted => Volatile.Read(ref _accepted);

    private async Task AcceptLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception)
            {
                return;
            }

            Interlocked.Increment(ref _accepted);
            _ = Task.Run(() => Serve(client));
        }
    }

    /// <summary>Keep connections open between requests (HTTP/1.1 keep-alive), so the client pools them.</summary>
    public bool KeepAlive { get; init; }

    /// <summary>A path that answers 302 to <see cref="RedirectTo"/>.</summary>
    public string? RedirectPath { get; init; }

    public string? RedirectTo { get; set; }

    private async Task Serve(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var buffer = new byte[4096];
                var seen = new StringBuilder();
                while (true)
                {
                    var text = seen.ToString();
                    var end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    if (end < 0)
                    {
                        var n = await stream.ReadAsync(buffer);
                        if (n == 0)
                        {
                            return;
                        }

                        seen.Append(Encoding.ASCII.GetString(buffer, 0, n));
                        continue;
                    }

                    var head = text.Substring(0, end);
                    seen.Remove(0, end + 4);
                    var path = head.Split(' ').Length > 1 ? head.Split(' ')[1] : "/";
                    var connection = KeepAlive ? string.Empty : "Connection: close\r\n";
                    var response = RedirectPath is not null && path == RedirectPath
                        ? $"HTTP/1.1 302 Found\r\nLocation: {RedirectTo}\r\nContent-Length: 0\r\n{connection}\r\n"
                        : $"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{connection}\r\nok";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(response));
                    if (!KeepAlive)
                    {
                        return;
                    }
                }
            }
            catch (IOException)
            {
                // the client went away
            }
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        _stop.Dispose();
    }
}

/// <summary>An EF Core context with nothing in it: the kit only runs raw SQL.</summary>
internal sealed class KitDb : DbContext
{
    public KitDb(DbContextOptions<KitDb> options)
        : base(options)
    {
    }
}

/// <summary>Records that a command really executed (runs after RASP's interceptor).</summary>
internal sealed class ExecutedFlag : DbCommandInterceptor
{
    private readonly Action _ran;

    public ExecutedFlag(Action ran)
    {
        _ran = ran;
    }

    public override int NonQueryExecuted(DbCommand command, CommandExecutedEventData eventData, int result)
    {
        _ran();
        return result;
    }
}

/// <summary>The hooks the contract kit runs, each with a harmless trigger its detector flags.</summary>
internal static class RaspHookSpecs
{
    private static readonly string[] s_all =
    {
        "http.handler", "http.diagnostic", "http.connect", "sql.helper", "sqlclient.diagnostic", "efcore.interceptor",
        "mongo.helper", "process.start", "file.write", "code.helper", "template.helper", "deser.helper", "xml.reader", "xss.middleware",
    };

    /// <summary>Every hook (process.start needs a POSIX shell, so not on Windows).</summary>
    public static IEnumerable<string> Names => s_all.Where(n => n != "process.start" || !RuntimeInformation.IsOSPlatform(OSPlatform.Windows));

    /// <summary>Hooks installed for the whole process.</summary>
    public static IEnumerable<string> Installed => new[] { "http.diagnostic", "sqlclient.diagnostic" };

    private static RaspInput[] Inputs(params string[] values) => values.Select((v, i) => new RaspInput(v, "query.k" + i)).ToArray();

    public static HookSpec Create(string name) => name switch
    {
        "http.handler" => HttpHandler(),
        "http.diagnostic" => HttpDiagnostic(),
        "http.connect" => HttpConnect(),
        "sql.helper" => SqlHelper(),
        "sqlclient.diagnostic" => SqlClientDiagnostic(),
        "efcore.interceptor" => EfCore(),
        "mongo.helper" => Mongo(),
        "process.start" => ProcessStart(),
        "file.write" => FileWrite(),
        "code.helper" => Helper(RaspAttackType.CodeInjection, Inputs("x); fetch(document.cookie"), () => Shield360Rasp.CheckCode("return f(x); fetch(document.cookie);")),
        "template.helper" => Helper(RaspAttackType.CodeInjection, Inputs("{{ 7 * 7 }}"), () => Shield360Rasp.CheckTemplate("scriban", "Hello {{ 7 * 7 }}")),
        "deser.helper" => Helper(RaspAttackType.Deserialization, Inputs(Convert.ToBase64String(s_payload)), () => Shield360Rasp.CheckDeserialization(RaspDeserializer.BinaryFormatter, s_payload)),
        "xml.reader" => XmlReaderSpec(),
        "xss.middleware" => Xss(),
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, null),
    };

    private static readonly byte[] s_payload = { 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00 };

    /// <summary>An explicit check: the "underlying call" is the line after it.</summary>
    private static HookSpec Helper(RaspAttackType attack, RaspInput[] inputs, Action check, Func<RaspContext>? context = null)
    {
        var ran = false;
        return new HookSpec(
            "helper",
            attack,
            () =>
            {
                check();
                ran = true;
                return Task.CompletedTask;
            },
            () => ran)
        {
            Inputs = inputs,
            Context = context,
            Reset = () => ran = false,
        };
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private static HookSpec HttpHandler()
    {
        var inner = new CountingHandler();
        var client = new HttpClient(new Shield360RaspHttpHandler(inner));
        return new HookSpec("http.handler", RaspAttackType.Ssrf, () => client.GetAsync(new Uri("http://127.0.0.1:9/admin")), () => inner.Calls > 0)
        {
            Inputs = Inputs("http://127.0.0.1:9/admin"),
            Reset = () => inner.Calls = 0,
            Cleanup = client.Dispose,
        };
    }

    private static HookSpec HttpDiagnostic()
    {
        var server = new TinyHttpServer();
        var client = new HttpClient(new SocketsHttpHandler());
        var url = $"http://127.0.0.1:{server.Port}/admin";
        var before = 0;
        return new HookSpec("http.diagnostic", RaspAttackType.Ssrf, () => client.GetAsync(new Uri(url)), () => server.Accepted > before)
        {
            Inputs = Inputs(url),
            Install = RaspDiagnosticHooks.Install,
            Uninstall = RaspDiagnosticHooks.Uninstall,
            Reset = () => before = server.Accepted,
            Cleanup = () =>
            {
                client.Dispose();
                server.Dispose();
            },
        };
    }

    private static HookSpec HttpConnect()
    {
        var server = new TinyHttpServer();
        var previous = RaspHttpCheck.Resolve;

        // A rebinding name: public for the lookup before sending, loopback for the connection.
        // The connection's lookup is the one with the request's (cancelable) token.
        RaspHttpCheck.Resolve = (host, ct) => Task.FromResult(
            host != "rebind.test" ? Array.Empty<IPAddress>()
            : ct.CanBeCanceled ? new[] { IPAddress.Loopback }
            : new[] { IPAddress.Parse("93.184.216.34") });
        var client = Shield360RaspHttp.CreateClient();
        var url = $"http://rebind.test:{server.Port}/admin";
        var before = 0;
        return new HookSpec("http.connect", RaspAttackType.Ssrf, () => client.GetAsync(new Uri(url)), () => server.Accepted > before)
        {
            Inputs = Inputs("rebind.test"),
            Reset = () => before = server.Accepted,
            Cleanup = () =>
            {
                RaspHttpCheck.Resolve = previous;
                client.Dispose();
                server.Dispose();
            },
        };
    }

    private const string SqlInput = "x' OR '1'='1";

    private static HookSpec SqlHelper() =>
        Helper(RaspAttackType.SqlInjection, Inputs(SqlInput), () => Shield360Rasp.CheckSql("SELECT * FROM users WHERE name = '" + SqlInput + "'", RaspSqlDialect.Postgres));

    private static HookSpec SqlClientDiagnostic()
    {
        var ran = false;
        return new HookSpec(
            "sqlclient.diagnostic",
            RaspAttackType.SqlInjection,
            () =>
            {
                // A closed connection: SqlClient raises WriteCommandBefore, then refuses to run.
                using var connection = new SqlConnection("Server=127.0.0.1,9;Encrypt=false;Connect Timeout=1");
                using var command = new SqlCommand("SELECT * FROM users WHERE name = '" + SqlInput + "'", connection);
                try
                {
                    command.ExecuteNonQuery();
                }
                catch (InvalidOperationException)
                {
                    ran = true;
                }

                return Task.CompletedTask;
            },
            () => ran)
        {
            Inputs = Inputs(SqlInput),
            Install = RaspDiagnosticHooks.Install,
            Uninstall = RaspDiagnosticHooks.Uninstall,
            Reset = () => ran = false,
        };
    }

    private static HookSpec EfCore()
    {
        var ran = false;
        var options = new DbContextOptionsBuilder<KitDb>()
            .UseSqlite("Data Source=:memory:")
            .AddShield360Rasp()
            .AddInterceptors(new ExecutedFlag(() => ran = true))
            .Options;
        var sql = string.Concat("SELECT count(*) FROM sqlite_master WHERE name = '", SqlInput, "'");
        return new HookSpec(
            "efcore.interceptor",
            RaspAttackType.SqlInjection,
            () =>
            {
                using var db = new KitDb(options);
                db.Database.ExecuteSqlRaw(sql);
                return Task.CompletedTask;
            },
            () => ran)
        {
            Inputs = Inputs(SqlInput),
            Reset = () => ran = false,
        };
    }

    private static HookSpec Mongo()
    {
        var inputs = Inputs("admin");
        return Helper(
            RaspAttackType.NoSqlInjection,
            inputs,
            () => Shield360Rasp.CheckMongo(new Dictionary<string, object?> { ["user"] = new Dictionary<string, object?> { ["$ne"] = "" } }),
            () =>
            {
                var ctx = new RaspContext(inputs, inRequest: true);
                ctx.Mutate((_, trees) => trees.Add(JsonNode.Parse("""{"user":{"$ne":""}}""")));
                return ctx;
            });
    }

    private static HookSpec ProcessStart()
    {
        var marker = Path.Combine(Path.GetTempPath(), "shield360-kit-" + Guid.NewGuid().ToString("N") + ".txt");
        const string input = "hello; echo pwned";
        return new HookSpec(
            "process.start",
            RaspAttackType.CommandInjection,
            async () =>
            {
                using var p = Shield360Rasp.StartProcess("/bin/sh", "-c", "echo " + input + " > '" + marker + "'");
                await p!.WaitForExitAsync();
            },
            () => File.Exists(marker))
        {
            Inputs = Inputs(input),
            Reset = () => File.Delete(marker),
            Cleanup = () => File.Delete(marker),
        };
    }

    private static HookSpec FileWrite()
    {
        var root = Path.Combine(Path.GetTempPath(), "shield360-kit-" + Guid.NewGuid().ToString("N"));
        var dir = Path.Combine(root, "uploads");
        Directory.CreateDirectory(dir);
        const string input = "../kit-file.txt";
        var path = Path.Combine(dir, input);
        var written = Path.GetFullPath(path);
        return new HookSpec(
            "file.write",
            RaspAttackType.PathTraversal,
            () =>
            {
                RaspFile.WriteAllText(path, "x");
                return Task.CompletedTask;
            },
            () => File.Exists(written))
        {
            Inputs = Inputs(input),
            Reset = () => File.Delete(written),
            Cleanup = () => Directory.Delete(root, recursive: true),
        };
    }

    private static HookSpec XmlReaderSpec()
    {
        const string xml = "<!DOCTYPE r [<!ENTITY x SYSTEM \"http://evil.example/x\">]><r>&x;</r>";
        var ran = false;
        return new HookSpec(
            "xml.reader",
            RaspAttackType.Xxe,
            () =>
            {
                // The reader is created, never read: nothing is fetched.
                using var reader = RaspXml.CreateReader(xml, new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() });
                ran = reader is not null;
                return Task.CompletedTask;
            },
            () => ran)
        {
            Inputs = Inputs(xml),
            Reset = () => ran = false,
        };
    }

    private static HookSpec Xss()
    {
        const string payload = "<script>alert(1)</script>";
        const string expected = "<p>" + payload + "</p>";
        WebApplication? app = null;
        string? body = null;
        return new HookSpec(
            "xss.middleware",
            RaspAttackType.Xss,
            async () =>
            {
                if (app is null)
                {
                    var builder = WebApplication.CreateBuilder();
                    builder.WebHost.UseTestServer();
                    app = builder.Build();
                    app.UseShield360Rasp();
                    app.MapGet("/echo", (string q) => Results.Content("<p>" + q + "</p>", "text/html; charset=utf-8"));
                    await app.StartAsync();
                }

                body = await app.GetTestClient().GetStringAsync(new Uri("/echo?q=" + Uri.EscapeDataString(payload), UriKind.Relative));
            },
            () => body == expected)
        {
            OwnContext = true,
            NeverBlocks = true,
            Reset = () => body = null,
            Cleanup = () => app?.DisposeAsync().AsTask().GetAwaiter().GetResult(),
        };
    }
}
