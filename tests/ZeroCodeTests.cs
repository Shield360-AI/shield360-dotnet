using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Shield360.Internal;
using Shield360.Rasp;
using Shield360.Tests.Rasp;
using Xunit;

namespace Shield360.Tests;

/// <summary>
/// The zero-code start, end to end: apps that never reference Shield360 are started
/// with <c>DOTNET_STARTUP_HOOKS</c> naming the Shield360 startup hook, and Shield360
/// starts from SHIELD360_* variables alone. In a plain minimal-API app the RASP
/// middleware is in the pipeline too (the hook adds the Shield360.AspNetCore hosting
/// startup), so a virtual patch answers 403.
/// </summary>
public class ZeroCodeTests
{
    private const string AttackHeader = "x-shield360-rasp-test";

    private static readonly string s_testDir = Path.GetDirectoryName(typeof(ZeroCodeTests).Assembly.Location)!;

    // tests/bin/<Configuration>/<tfm>/
    private static readonly string s_configuration = new DirectoryInfo(s_testDir).Parent!.Name;
    private static readonly string s_testsRoot = Path.GetFullPath(Path.Combine(s_testDir, "..", "..", ".."));
    private static readonly string s_hookDir = Path.GetFullPath(Path.Combine(s_testsRoot, "..", "src", "Shield360.StartupHook", "bin", s_configuration, "net8.0"));
    private static readonly string s_hook = Path.Combine(s_hookDir, "Shield360.StartupHook.dll");

    // The dotnet that runs the apps: ZEROCODE_TEST_DOTNET picks another runtime install (a .NET 9 one, say).
    private static readonly string s_dotnet = Environment.GetEnvironmentVariable("ZEROCODE_TEST_DOTNET") is { Length: > 0 } d ? d : "dotnet";
    private static readonly string s_consoleApp = Path.Combine(s_testsRoot, "ZeroCodeApps", "ZeroCodeConsole", "bin", "app", "ZeroCodeConsole.dll");
    private static readonly string s_webApp = Path.Combine(s_testsRoot, "ZeroCodeApps", "ZeroCodeWeb", "bin", "app", "ZeroCodeWeb.dll");

    private static ProcessStartInfo Start(string app, IDictionary<string, string?> env, params string[] args)
    {
        var psi = new ProcessStartInfo(s_dotnet)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(app);
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        foreach (var key in psi.Environment.Keys.ToList())
        {
            if (key.StartsWith("SHIELD360_", StringComparison.Ordinal) || key.StartsWith("OTEL_", StringComparison.Ordinal)
                || key.StartsWith("ASPNETCORE_HOSTINGSTARTUP", StringComparison.Ordinal)
                || key is "DOTNET_STARTUP_HOOKS" or "DOTNET_ADDITIONAL_DEPS" or "DOTNET_SHARED_STORE")
            {
                psi.Environment.Remove(key);
            }
        }

        psi.Environment["OTEL_SERVICE_NAME"] = "zero-code-e2e";
        // Nothing listens there: export fails quietly and the app is unaffected.
        psi.Environment["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://127.0.0.1:9";
        psi.Environment["SHIELD360_RASP"] = "block";
        psi.Environment["DOTNET_STARTUP_HOOKS"] = s_hook;
        // What the README asks for: the newer framework assemblies for apps on .NET 8 and 9.
        psi.Environment["DOTNET_ADDITIONAL_DEPS"] = Path.Combine(s_hookDir, "Shield360.AdditionalDeps.deps.json");
        psi.Environment["DOTNET_SHARED_STORE"] = Path.Combine(s_hookDir, "store");
        foreach (var kv in env)
        {
            psi.Environment[kv.Key] = kv.Value;
        }

        return psi;
    }

    private static async Task<(int Exit, string Stdout, string Stderr)> RunConsole(IDictionary<string, string?>? env = null, params string[] args)
    {
        Assert.True(File.Exists(s_hook), $"startup hook not built: {s_hook}");
        using var p = Process.Start(Start(s_consoleApp, env ?? new Dictionary<string, string?>(), args))!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(60));
        return (p.ExitCode, await stdout, await stderr);
    }

    private static string Result(string stdout) =>
        stdout.Split('\n').Select(l => l.Trim()).Last(l => l.StartsWith("RESULT ", StringComparison.Ordinal));

    private static int Runtime(string stdout) =>
        int.Parse(stdout.Split('\n').Select(l => l.Trim()).Last(l => l.StartsWith("RUNTIME ", StringComparison.Ordinal)).Substring(8), System.Globalization.CultureInfo.InvariantCulture);

    private static int Count(string text, string part) =>
        (text.Length - text.Replace(part, string.Empty, StringComparison.Ordinal).Length) / part.Length;

    [Fact]
    public async Task Console_app_starts_with_Shield360_and_RASP_from_the_environment_alone()
    {
        var (exit, stdout, stderr) = await RunConsole();
        Assert.Equal(0, exit);
        Assert.Equal("RESULT loaded=True initialized=True rasp=True second=none", Result(stdout));
        Assert.DoesNotContain("Shield360:", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RASP_is_on_in_monitor_mode_when_SHIELD360_RASP_is_unset()
    {
        var (exit, stdout, stderr) = await RunConsole(new Dictionary<string, string?> { ["SHIELD360_RASP"] = null });
        Assert.Equal(0, exit);
        Assert.Equal("RESULT loaded=True initialized=True rasp=True second=none", Result(stdout));
        Assert.DoesNotContain("Shield360:", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SHIELD360_RASP_off_still_turns_RASP_off()
    {
        var (exit, stdout, _) = await RunConsole(new Dictionary<string, string?> { ["SHIELD360_RASP"] = "off" });
        Assert.Equal(0, exit);
        Assert.Equal("RESULT loaded=True initialized=True rasp=False second=none", Result(stdout));
    }

    [Fact]
    public async Task Without_the_hook_the_app_has_no_Shield360()
    {
        var (exit, stdout, _) = await RunConsole(new Dictionary<string, string?> { ["DOTNET_STARTUP_HOOKS"] = null });
        Assert.Equal(0, exit);
        Assert.Equal("RESULT loaded=False initialized=False rasp=False second=none", Result(stdout));
    }

    [Fact]
    public async Task The_hook_alone_starts_on_NET_10_and_fails_open_with_a_hint_on_8_and_9()
    {
        var (exit, stdout, stderr) = await RunConsole(new Dictionary<string, string?> { ["DOTNET_ADDITIONAL_DEPS"] = null, ["DOTNET_SHARED_STORE"] = null });
        Assert.Equal(0, exit);
        if (Runtime(stdout) >= 10)
        {
            Assert.Equal("RESULT loaded=True initialized=True rasp=True second=none", Result(stdout));
        }
        else
        {
            Assert.Equal("RESULT loaded=True initialized=False rasp=False second=none", Result(stdout));
            Assert.Equal(1, Count(stderr, "the app runs without Shield360"));
            Assert.Contains("DOTNET_ADDITIONAL_DEPS", stderr, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_later_Init_in_app_code_is_a_no_op()
    {
        var (exit, stdout, stderr) = await RunConsole(null, "--init-again");
        Assert.Equal(0, exit);
        Assert.Equal("RESULT loaded=True initialized=True rasp=True second=ok", Result(stdout));
        Assert.Equal(1, Count(stderr, "this Shield360Sdk.Init() call is ignored"));
    }

    [Fact]
    public async Task Fails_open_with_one_warning_when_the_configuration_is_invalid()
    {
        var (exit, stdout, stderr) = await RunConsole(new Dictionary<string, string?> { ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "not-a-url" });
        Assert.Equal(0, exit);
        Assert.Equal("RESULT loaded=True initialized=False rasp=False second=none", Result(stdout));
        Assert.Equal(1, Count(stderr, "the app runs without Shield360"));
        Assert.Single(stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries));
    }

    private static async Task<(HttpStatusCode Plain, HttpStatusCode Attack)> RunWeb(IDictionary<string, string?>? env = null)
    {
        Assert.True(File.Exists(s_hook), $"startup hook not built: {s_hook}");
        using var p = Process.Start(Start(s_webApp, env ?? new Dictionary<string, string?>()))!;
        var stderr = new StringBuilder();
        p.ErrorDataReceived += (_, e) =>
        {
            lock (stderr)
            {
                stderr.AppendLine(e.Data);
            }
        };
        p.BeginErrorReadLine();
        try
        {
            string? address = null;
            var deadline = DateTime.UtcNow.AddSeconds(60);
            while (address is null && DateTime.UtcNow < deadline)
            {
                var line = await p.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(60));
                if (line is null)
                {
                    break;
                }

                if (line.StartsWith("LISTENING ", StringComparison.Ordinal))
                {
                    address = line.Substring("LISTENING ".Length).Trim();
                }
            }

            Assert.True(address is not null, $"the web app did not start: {stderr}");
            using var client = new HttpClient { BaseAddress = new Uri(address!) };
            var plain = await client.GetAsync(new Uri("/", UriKind.Relative));
            using var attack = new HttpRequestMessage(HttpMethod.Get, new Uri("/", UriKind.Relative));
            attack.Headers.Add(AttackHeader, "exploit");
            var blocked = await client.SendAsync(attack);
            return (plain.StatusCode, blocked.StatusCode);
        }
        finally
        {
            if (!p.HasExited)
            {
                p.Kill(entireProcessTree: true);
            }
        }
    }

    [Fact]
    public async Task Minimal_api_app_requests_are_traces_by_route_without_health_probes()
    {
        // SHIELD: a local OTLP endpoint; the request spans' names are plain UTF-8 in the protobuf body.
        using var sink = new System.Net.HttpListener();
        var port = FreePort();
        sink.Prefixes.Add($"http://127.0.0.1:{port}/");
        sink.Start();
        var received = new StringBuilder();
        var receiving = Task.Run(async () =>
        {
            while (sink.IsListening)
            {
                System.Net.HttpListenerContext ctx;
                try
                {
                    ctx = await sink.GetContextAsync();
                }
#pragma warning disable CA1031 // The listener stopping ends the loop.
                catch (Exception)
#pragma warning restore CA1031
                {
                    break;
                }

                using var reader = new StreamReader(ctx.Request.InputStream, Encoding.Latin1);
                var body = await reader.ReadToEndAsync();
                lock (received)
                {
                    received.Append(ctx.Request.Url!.AbsolutePath).Append(' ').Append(body).Append('\n');
                }

                ctx.Response.StatusCode = 200;
                ctx.Response.Close();
            }
        });

        var env = new Dictionary<string, string?>
        {
            ["OTEL_EXPORTER_OTLP_ENDPOINT"] = $"http://127.0.0.1:{port}",
            ["OTEL_BSP_SCHEDULE_DELAY"] = "200",
        };
        Assert.True(File.Exists(s_hook), $"startup hook not built: {s_hook}");
        using var p = Process.Start(Start(s_webApp, env))!;
        try
        {
            string? address = null;
            while (address is null)
            {
                var line = await p.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(60));
                if (line is null)
                {
                    break;
                }

                if (line.StartsWith("LISTENING ", StringComparison.Ordinal))
                {
                    address = line.Substring("LISTENING ".Length).Trim();
                }
            }

            Assert.NotNull(address);
            using var client = new HttpClient { BaseAddress = new Uri(address!) };
            (await client.GetAsync(new Uri("/orders/42", UriKind.Relative))).EnsureSuccessStatusCode();
            (await client.GetAsync(new Uri("/healthz", UriKind.Relative))).EnsureSuccessStatusCode();

            var deadline = DateTime.UtcNow.AddSeconds(20);
            string seen;
            do
            {
                await Task.Delay(250);
                lock (received)
                {
                    seen = received.ToString();
                }
            }
            while (!seen.Contains("/orders/{id}", StringComparison.Ordinal) && DateTime.UtcNow < deadline);

            Assert.Contains("/v1/traces", seen, StringComparison.Ordinal);
            Assert.Contains("GET /orders/{id}", seen, StringComparison.Ordinal);
            Assert.DoesNotContain("/healthz", seen, StringComparison.Ordinal);
        }
        finally
        {
            if (!p.HasExited)
            {
                p.Kill(entireProcessTree: true);
            }

            sink.Stop();
            await receiving;
        }
    }

    private static int FreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [Fact]
    public async Task Minimal_api_app_gets_the_RASP_middleware_with_no_code_change()
    {
        var (plain, attack) = await RunWeb();
        Assert.Equal(HttpStatusCode.OK, plain);
        Assert.Equal(HttpStatusCode.Forbidden, attack);
    }

    [Fact]
    public async Task The_hosting_startup_can_be_excluded()
    {
        var (plain, attack) = await RunWeb(new Dictionary<string, string?> { ["ASPNETCORE_HOSTINGSTARTUPEXCLUDEASSEMBLIES"] = "Shield360.AspNetCore" });
        Assert.Equal(HttpStatusCode.OK, plain);
        Assert.Equal(HttpStatusCode.OK, attack);
    }
}

/// <summary>The in-process side of the zero-code start: no double init, and the hosting startup on its own.</summary>
public class ZeroCodeInProcessTests : RaspStateTest
{
    [Fact]
    public void Init_and_AddShield360_after_the_zero_code_start_add_nothing()
    {
        var env = Env.Of(("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9"));
        var handle = Shield360Sdk.InitZeroCode(env);
        try
        {
            Assert.True(Shield360Sdk.StartedByZeroCode);
            var runtime = Shield360Runtime.Current;

            Assert.Same(handle, Shield360Sdk.Init(new Shield360Options { ApplicationName = "ignored" }, env));

            var services = new ServiceCollection();
            services.AddShield360(o => o.ApplicationName = "ignored-too", env);
            Assert.Same(runtime, Shield360Runtime.Current);
            Assert.DoesNotContain(services, d => d.ServiceType == typeof(Shield360Runtime));
        }
        finally
        {
            Shield360Sdk.Shutdown();
        }

        Assert.False(Shield360Sdk.StartedByZeroCode);
        // After shutdown a second Init is an ordinary one again.
        using var again = Shield360Sdk.Init(new Shield360Options { OtlpEndpoint = "http://127.0.0.1:9" }, Env.Empty);
        Assert.Throws<InvalidOperationException>(() => Shield360Sdk.Init(null, Env.Empty));
    }

    [Fact]
    public async Task Hosting_startup_adds_the_middleware_without_AddShield360Rasp()
    {
        RaspEngine.Configure(new EngineSettings(true, "orders-api",
            Attacks: new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.VirtualPatch] = RaspMode.Block }, Env: Env.Empty));

        // Hosting startups run while the builder is created, so the setting goes in through its arguments.
        var builder = WebApplication.CreateBuilder(new[] { $"--{WebHostDefaults.HostingStartupAssembliesKey}=Shield360.AspNetCore" });
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapGet("/", () => "ok");
        await app.StartAsync();
        var client = app.GetTestClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(new Uri("/", UriKind.Relative))).StatusCode);
        using var attack = new HttpRequestMessage(HttpMethod.Get, new Uri("/", UriKind.Relative));
        attack.Headers.Add("x-shield360-rasp-test", "exploit");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(attack)).StatusCode);
    }

    [Fact]
    public async Task Hosting_startup_fails_open_when_the_settings_are_invalid()
    {
        Shield360Runtime.Current?.Deactivate();
        var saved = new Dictionary<string, string?>();
        foreach (var name in new[] { "SHIELD360_URL", "SHIELD360_API_KEY", "SHIELD360_RASP", "OTEL_EXPORTER_OTLP_ENDPOINT" })
        {
            saved[name] = Environment.GetEnvironmentVariable(name);
        }

        // A plain-http Shield360 URL that is not localhost is refused when the settings are resolved.
        Environment.SetEnvironmentVariable("SHIELD360_URL", "http://shield360.example.com");
        Environment.SetEnvironmentVariable("SHIELD360_API_KEY", "zero-code-test");
        Environment.SetEnvironmentVariable("SHIELD360_RASP", null);
        Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", null);
        try
        {
            var builder = WebApplication.CreateBuilder(new[] { $"--{WebHostDefaults.HostingStartupAssembliesKey}=Shield360.AspNetCore" });
            builder.WebHost.UseTestServer();
            await using var app = builder.Build();
            app.MapGet("/", () => "ok");
            await app.StartAsync();
            Assert.Equal(HttpStatusCode.OK, (await app.GetTestClient().GetAsync(new Uri("/", UriKind.Relative))).StatusCode);
        }
        finally
        {
            foreach (var kv in saved)
            {
                Environment.SetEnvironmentVariable(kv.Key, kv.Value);
            }
        }
    }
}
