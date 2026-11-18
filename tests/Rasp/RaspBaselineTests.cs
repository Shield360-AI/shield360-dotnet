using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>Keeps the baseline out of every test that starts RASP; <see cref="RaspBaselineTests"/> runs it on purpose.</summary>
internal static class BaselineOffInTests
{
#pragma warning disable CA2255 // a test assembly: the baseline reads real process facts, so it is off unless a test asks.
    [ModuleInitializer]
#pragma warning restore CA2255
    internal static void Init() => RaspBaseline.MarkRan();
}

/// <summary>
/// Security baseline: each rule from what it reads (pure), nothing for a sound set-up,
/// monitor only even in block mode, once per process, and no setting's value in an event.
/// Port of baseline.test.ts.
/// </summary>
public class RaspBaselineTests : RaspStateTest
{
    private static readonly BaselineInput s_sound = new()
    {
        Env = Env.Of(("ASPNETCORE_ENVIRONMENT", "Production")),
        Environment = "production",
        RemoteWanted = true,
        Pinned = true,
        FrameworkDescription = ".NET 10.0.1",
        Elevated = false,
        DebuggerAttached = false,
        TlsCallbackAcceptsAll = false,
        Now = new DateTimeOffset(2026, 10, 29, 0, 0, 0, TimeSpan.Zero),
    };

    private static List<string> Rules(BaselineInput i) => RaspBaseline.Findings(i).Select(f => f.Rule).ToList();

    protected override void Dispose(bool disposing)
    {
        RaspBaseline.MarkRan();
        base.Dispose(disposing);
    }

    [Fact]
    public void Finds_nothing_for_a_sound_production_set_up()
    {
        Assert.Empty(Rules(s_sound));
    }

    private static readonly Dictionary<string, (BaselineInput Input, string Rule)> s_risky = new()
    {
        ["a callback that accepts every certificate"] = (s_sound with { TlsCallbackAcceptsAll = true }, "baseline.tls_verify_off"),
        ["a debugger attached in production"] = (s_sound with { DebuggerAttached = true }, "baseline.inspector_in_production"),
        ["ASPNETCORE_ENVIRONMENT=Development under a production SDK"] = (s_sound with { Env = Env.Of(("ASPNETCORE_ENVIRONMENT", "Development")) }, "baseline.development_mode_in_production"),
        ["DOTNET_ENVIRONMENT=development under ENVIRONMENT=prod"] = (s_sound with { Environment = null, Env = Env.Of(("ENVIRONMENT", "prod"), ("DOTNET_ENVIRONMENT", "development")) }, "baseline.development_mode_in_production"),
        ["running elevated"] = (s_sound with { Elevated = true }, "baseline.running_as_root"),
        ["an unpinned config key in production"] = (s_sound with { Pinned = false }, "baseline.config_key_unpinned"),
        ["an end-of-life .NET line"] = (s_sound with { FrameworkDescription = ".NET 6.0.36" }, "baseline.runtime_end_of_life"),
        ["a .NET Core line"] = (s_sound with { FrameworkDescription = ".NET Core 3.1.32" }, "baseline.runtime_end_of_life"),
    };

    public static IEnumerable<object[]> Risky() => s_risky.Keys.Select(k => new object[] { k });

    [Theory]
    [MemberData(nameof(Risky))]
    public void Reports_each_risky_setting(string label)
    {
        var (input, rule) = s_risky[label];
        Assert.Equal(new[] { rule }, Rules(input));
    }

    [Fact]
    public void Leaves_development_set_ups_alone_where_the_rule_is_about_production()
    {
        var dev = s_sound with
        {
            Env = Env.Of(("ASPNETCORE_ENVIRONMENT", "Development")),
            Environment = "development",
            DebuggerAttached = true,
            Pinned = false,
        };
        Assert.Empty(Rules(dev));

        // The SDK's default environment name is not production, so Development alone is not a finding.
        Assert.Empty(Rules(dev with { Environment = "default" }));
    }

    [Theory]
    [InlineData("Development", "Production")]
    [InlineData("Production", "Development")]
    public void Conflicting_host_variables_are_not_judged_without_the_hosts_own_environment(string aspnetcore, string dotnet)
    {
        // WebApplication and HostApplicationBuilder let DOTNET_ENVIRONMENT win; ConfigureWebHostDefaults lets ASPNETCORE_ENVIRONMENT win.
        Assert.Empty(Rules(s_sound with { Env = Env.Of(("ASPNETCORE_ENVIRONMENT", aspnetcore), ("DOTNET_ENVIRONMENT", dotnet)) }));
    }

    [Fact]
    public void The_hosts_own_environment_wins_over_the_variables()
    {
        var conflicting = Env.Of(("ASPNETCORE_ENVIRONMENT", "Production"), ("DOTNET_ENVIRONMENT", "Development"));
        Assert.Equal(new[] { "baseline.development_mode_in_production" }, Rules(s_sound with { Env = conflicting, HostEnvironment = "Development" }));
        Assert.Empty(Rules(s_sound with { Env = Env.Of(("ASPNETCORE_ENVIRONMENT", "Development")), HostEnvironment = "Production" }));
        Assert.Equal("Development", RaspBaseline.HostEnvironmentFromVariables(Env.Of(("DOTNET_ENVIRONMENT", "Development"))));
        Assert.Equal("Development", RaspBaseline.HostEnvironmentFromVariables(Env.Of(("ASPNETCORE_ENVIRONMENT", "Development"), ("DOTNET_ENVIRONMENT", "development"))));
        Assert.Null(RaspBaseline.HostEnvironmentFromVariables(conflicting));
    }

    [Fact]
    public void Reads_the_host_environment_a_host_builder_registered()
    {
        var builder = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder(new Microsoft.AspNetCore.Builder.WebApplicationOptions { EnvironmentName = "Staging" });
        Assert.Equal("Staging", RaspStartContext.HostEnvironmentOf(builder.Services));
        Assert.Null(RaspStartContext.HostEnvironmentOf(new Microsoft.Extensions.DependencyInjection.ServiceCollection()));
    }

    [Fact]
    public void A_release_line_still_in_support_passes_and_one_past_its_date_does_not()
    {
        var net8 = s_sound with { FrameworkDescription = ".NET 8.0.11" };
        Assert.Empty(Rules(net8 with { Now = new DateTimeOffset(2026, 11, 10, 23, 0, 0, TimeSpan.Zero) }));
        Assert.Equal(new[] { "baseline.runtime_end_of_life" }, Rules(net8 with { Now = new DateTimeOffset(2026, 11, 11, 0, 0, 0, TimeSpan.Zero) }));
    }

    [Theory]
    [InlineData(".NET Framework 4.8.9290.0")]
    [InlineData("Mono 6.12.0.200")]
    [InlineData(".NET 11.0.0")]
    [InlineData(".NET 99.0.0")]
    [InlineData("")]
    public void Runtimes_it_cannot_date_are_not_judged(string description)
    {
        Assert.Null(RaspBaseline.EndOfLife(description));
        Assert.Empty(Rules(s_sound with { FrameworkDescription = description, Now = DateTimeOffset.MaxValue }));
    }

    [Fact]
    public void Reads_production_from_the_host_variables_or_the_SDK_environment()
    {
        Assert.True(RaspBaseline.ProductionEnv(null, Env.Of(("ASPNETCORE_ENVIRONMENT", "Production"))));
        Assert.True(RaspBaseline.ProductionEnv(null, Env.Of(("DOTNET_ENVIRONMENT", "prod"))));
        Assert.True(RaspBaseline.ProductionEnv(null, Env.Of(("ENVIRONMENT", "Prod"))));
        Assert.True(RaspBaseline.ProductionEnv("production", Env.Empty));
        Assert.False(RaspBaseline.ProductionEnv("qa", Env.Of(("ASPNETCORE_ENVIRONMENT", "Staging"))));
    }

#pragma warning disable SYSLIB0014 // the legacy process-wide callback is what the rule reads.
    [Fact]
    public void Tells_a_callback_that_accepts_everything_from_one_that_validates()
    {
        var prior = ServicePointManager.ServerCertificateValidationCallback;
        try
        {
            ServicePointManager.ServerCertificateValidationCallback = null;
            Assert.False(RaspBaseline.TlsCallbackAcceptsAll());
            ServicePointManager.ServerCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.None;
            Assert.False(RaspBaseline.TlsCallbackAcceptsAll());
            ServicePointManager.ServerCertificateValidationCallback = (_, cert, _, _) => cert!.Subject.Length > 0;
            Assert.False(RaspBaseline.TlsCallbackAcceptsAll());
#pragma warning disable CA5359 // the insecure setting is the fixture, restored below.
            ServicePointManager.ServerCertificateValidationCallback = (_, _, _, _) => true;
#pragma warning restore CA5359
            Assert.True(RaspBaseline.TlsCallbackAcceptsAll());
        }
        finally
        {
            ServicePointManager.ServerCertificateValidationCallback = prior;
        }
    }
#pragma warning restore SYSLIB0014

    [Fact]
    public void Knows_whether_the_process_is_elevated()
    {
        Assert.Equal(Environment.IsPrivilegedProcess, RaspBaseline.Elevated());
    }

    [Fact]
    public void Baseline_never_blocks()
    {
        Configure(new EngineSettings(true, "orders-api", RaspMode.Block));
        Assert.Equal(RaspMode.Monitor, RaspEngine.ModeFor(RaspAttackType.Baseline));
        Assert.Equal(RaspMode.Block, RaspEngine.ModeFor(RaspAttackType.SqlInjection));
    }

    [Fact]
    public void Reports_each_finding_once_per_process_monitored_even_in_block_mode_without_the_setting_values()
    {
        var sink = Configure(new EngineSettings(true, "orders-api", RaspMode.Block));
        RaspBaseline.Reset();
        var input = s_sound with
        {
            Env = Env.Of(("ASPNETCORE_ENVIRONMENT", "Development")),
            TlsCallbackAcceptsAll = true,
            Pinned = false,
        };
        RaspBaseline.Run(input);
        RaspBaseline.Run(input);
        var got = sink.Events.Select(e => e.Attrs["shield360.rasp.rule"]).ToList();
        Assert.Equal(new[] { "baseline.tls_verify_off", "baseline.development_mode_in_production", "baseline.config_key_unpinned" }, got);
        foreach (var e in sink.Events)
        {
            Assert.Equal("baseline", e.Attrs["shield360.rasp.attack"]);
            Assert.Equal("monitored", e.Attrs["shield360.rasp.decision"]);
            Assert.Equal("startup", e.Attrs["shield360.rasp.sink"]);
            Assert.False(e.Attrs.ContainsKey("shield360.rasp.input_key"));
            Assert.DoesNotContain("Development", JsonSerializer.Serialize(e.Attrs), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Does_nothing_while_RASP_is_off()
    {
        var sink = Configure(new EngineSettings(false, "orders-api"));
        RaspBaseline.Reset();
        RaspBaseline.Run(s_sound with { TlsCallbackAcceptsAll = true });
        Assert.Empty(sink.Events);
    }

    [Fact]
    public void Starting_RASP_starts_the_baseline_and_a_disabled_RASP_does_not()
    {
        RaspBaseline.Reset();
        Assert.False(RaspRuntime.Start(new RaspOptions { Enabled = false }, new RaspStartContext("orders-api", Env: Env.Empty)));
        Assert.False(RaspBaseline.HasRun);
        Assert.True(RaspRuntime.Start(new RaspOptions { Components = false }, new RaspStartContext("orders-api", Env: Env.Empty)));
        Assert.True(RaspBaseline.HasRun);
    }

    [Fact]
    public async Task Start_runs_it_once_on_the_thread_pool_with_the_process_facts()
    {
        var sink = Configure(new EngineSettings(true, "orders-api"));
        RaspBaseline.Reset();
        var env = Env.Of(("ENVIRONMENT", "production"), ("ASPNETCORE_ENVIRONMENT", "Development"));
        var first = RaspBaseline.Start(null, env, remoteWanted: false, pinned: false);
        var second = RaspBaseline.Start(null, env, remoteWanted: false, pinned: false);
        Assert.Same(Task.CompletedTask, second);
        await first;
        var rules = sink.Events.Select(e => e.Attrs["shield360.rasp.rule"]).ToList();
        Assert.Contains("baseline.development_mode_in_production", rules);
        Assert.Equal(rules.Count, rules.Distinct().Count());
    }
}
