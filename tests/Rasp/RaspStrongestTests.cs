using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Several checks for one call: the finding with the strongest decision wins, so a finding
/// for an attack type in monitor or off mode never hides one that blocks. Only harmless
/// fixture values; nothing is started or sent.
/// </summary>
public class RaspStrongestTests : RaspStateTest
{
    private const string Injected = "ok; echo rasp-test";

    private static ListSink Mode(RaspMode mode, Dictionary<RaspAttackType, RaspMode> attacks, RaspAllowOptions? allow = null) =>
        Configure(new EngineSettings(true, "strongest", mode, attacks, allow));

    private static T InRequest<T>(string input, Func<T> fn) =>
        RaspScope.Run(new RaspContext(new[] { new RaspInput(input, "query.q") }, inRequest: true), fn);

    private static string[] Attacks(ListSink sink) =>
        sink.Events.Select(e => e.Attrs["shield360.rasp.attack"] + "/" + e.Attrs["shield360.rasp.decision"]).ToArray();

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }

    [Fact]
    public void Strongest_prefers_block_ignores_off_and_keeps_the_order_on_ties()
    {
        var cmdi = new RaspFinding(RaspAttackType.CommandInjection, "cmdi.userinput");
        var shell = new RaspFinding(RaspAttackType.ShellSpawn, "shell_spawn.shell");

        Mode(RaspMode.Block, new() { [RaspAttackType.CommandInjection] = RaspMode.Monitor });
        Assert.Same(shell, RaspEngine.Strongest(cmdi, shell));

        Mode(RaspMode.Monitor, new() { [RaspAttackType.CommandInjection] = RaspMode.Off });
        Assert.Same(shell, RaspEngine.Strongest(cmdi, shell));

        Mode(RaspMode.Block, new() { [RaspAttackType.CommandInjection] = RaspMode.Off, [RaspAttackType.ShellSpawn] = RaspMode.Off });
        Assert.Null(RaspEngine.Strongest(cmdi, shell));

        Mode(RaspMode.Block, new());
        Assert.Same(cmdi, RaspEngine.Strongest(null, cmdi, shell));
        Assert.Same(shell, RaspEngine.Strongest(new RaspFinding(RaspAttackType.VirtualPatch, "vp", Action: RaspMode.Monitor), shell));
    }

    [Theory]
    [InlineData(RaspMode.Off)]
    [InlineData(RaspMode.Monitor)]
    public void A_command_injection_not_blocking_does_not_hide_a_shell_spawn_block(RaspMode cmdi)
    {
        // Both fire: the input spans shell tokens (command_injection) and a shell starts during a request (shell_spawn).
        var sink = Mode(RaspMode.Block, new() { [RaspAttackType.CommandInjection] = cmdi, [RaspAttackType.ShellSpawn] = RaspMode.Block });
        var line = Assert.Throws<Shield360RaspBlockedException>(() => InRequest(Injected, () =>
        {
            Shield360Rasp.CheckCommand("bash -c true " + Injected);
            return 0;
        }));
        Assert.Equal("shell_spawn.shell", line.Rule);
        var argv = Assert.Throws<Shield360RaspBlockedException>(() => InRequest(Injected, () =>
        {
            Shield360Rasp.CheckProcess(new ProcessStartInfo("sh", "-c \"true " + Injected + "\""));
            return 0;
        }));
        Assert.Equal("shell_spawn.shell", argv.Rule);
        Assert.Equal(new[] { "shell_spawn/blocked", "shell_spawn/blocked" }, Attacks(sink));
    }

    [Theory]
    [InlineData("copy")]
    [InlineData("move")]
    public void A_copy_or_move_reports_only_the_strongest_of_its_two_paths(string api)
    {
        var dir = Directory.CreateTempSubdirectory("rasp-strongest-").FullName;
        try
        {
            Directory.CreateDirectory(Path.Combine(dir, "sub"));
            File.WriteAllText(Path.Combine(dir, "kit.txt"), "kit");
            var sink = Mode(RaspMode.Block, new() { [RaspAttackType.PathTraversal] = RaspMode.Monitor, [RaspAttackType.FileWrite] = RaspMode.Block });
            var source = dir + "/sub/../kit.txt";
            var target = Path.Combine(dir, "shell.php");
            var inputs = new[] { new RaspInput("../kit.txt", "query.file"), new RaspInput("shell.php", "body.name") };
            var e = Assert.Throws<Shield360RaspBlockedException>(() => RaspScope.Run(new RaspContext(inputs, inRequest: true), () =>
            {
                if (api == "copy")
                {
                    RaspFile.Copy(source, target);
                }
                else
                {
                    RaspFile.Move(source, target);
                }

                return 0;
            }));
            Assert.Equal("file_write.script", e.Rule);
            Assert.False(File.Exists(target));
            Assert.Equal(new[] { "file_write/blocked" }, Attacks(sink));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task An_outbound_finding_in_monitor_does_not_skip_the_resolved_address_check()
    {
        var sink = Mode(
            RaspMode.Block,
            new() { [RaspAttackType.Outbound] = RaspMode.Monitor, [RaspAttackType.Ssrf] = RaspMode.Block },
            new RaspAllowOptions { OutboundHosts = { "api.example.com" } });
        var previous = RaspHttpCheck.Resolve;
        // An unlisted, tainted name that resolves to a loopback address.
        RaspHttpCheck.Resolve = (_, _) => Task.FromResult(new[] { System.Net.IPAddress.Loopback });
        try
        {
            const string url = "http://rebind.test:9/admin";
            var inner = new CountingHandler();
            using var client = new HttpClient(new Shield360RaspHttpHandler(inner));
            var e = await Assert.ThrowsAsync<Shield360RaspBlockedException>(() => InRequest(url, () => client.GetAsync(new Uri(url))));
            Assert.Equal("ssrf.internal", e.Rule);
            Assert.Equal(0, inner.Calls);
            Assert.Equal(new[] { "outbound/monitored", "ssrf/blocked" }, Attacks(sink));
        }
        finally
        {
            RaspHttpCheck.Resolve = previous;
        }
    }

    [Fact]
    public async Task An_outbound_finding_in_monitor_does_not_hide_an_ssrf_block()
    {
        var sink = Mode(
            RaspMode.Block,
            new() { [RaspAttackType.Outbound] = RaspMode.Monitor, [RaspAttackType.Ssrf] = RaspMode.Block },
            new RaspAllowOptions { OutboundHosts = { "api.example.com" } });
        const string url = "http://127.0.0.1:9/admin";
        var inner = new CountingHandler();
        using var client = new HttpClient(new Shield360RaspHttpHandler(inner));

        var e = await Assert.ThrowsAsync<Shield360RaspBlockedException>(() => InRequest(url, () => client.GetAsync(new Uri(url))));
        Assert.Equal("ssrf.internal", e.Rule);
        Assert.Equal(0, inner.Calls);

        var direct = Assert.Throws<Shield360RaspBlockedException>(() => InRequest(url, () =>
        {
            Shield360Rasp.CheckUrl(new Uri(url));
            return 0;
        }));
        Assert.Equal("ssrf.internal", direct.Rule);
        Assert.Equal(new[] { "ssrf/blocked", "ssrf/blocked" }, Attacks(sink));
    }
}
