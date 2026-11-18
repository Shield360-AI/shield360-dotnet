using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Shield360.AspNetCore;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// One sink hook as the contract kit sees it. Port of the TypeScript hook kit
/// (sdk/typescript/src/rasp/__tests__/hook-kit.ts), for what applies in .NET: hooks
/// are explicit helpers, handlers, interceptors and diagnostic subscriptions rather
/// than replaced functions, so "keeps name and length" and "a wrapper on top" do not
/// apply; "uninstall restores exactly" becomes "uninstall leaves nothing behind".
/// </summary>
internal sealed class HookSpec : IDisposable
{
    public HookSpec(string name, RaspAttackType attack, Func<Task> trigger, Func<bool> underlyingRan)
    {
        Name = name;
        Attack = attack;
        Trigger = trigger;
        UnderlyingRan = underlyingRan;
    }

    public string Name { get; }

    public RaspAttackType Attack { get; }

    /// <summary>A harmless call the hook flags under <see cref="Inputs"/>. May return or throw.</summary>
    public Func<Task> Trigger { get; }

    /// <summary>Whether the call the hook guards (the send, the query, the write) happened.</summary>
    public Func<bool> UnderlyingRan { get; }

    public IReadOnlyList<RaspInput> Inputs { get; init; } = Array.Empty<RaspInput>();

    /// <summary>Builds the request context the trigger runs in (default: a request holding <see cref="Inputs"/>).</summary>
    public Func<RaspContext>? Context { get; init; }

    /// <summary>The hook makes its own context (the ASP.NET Core middleware): the trigger runs outside one.</summary>
    public bool OwnContext { get; init; }

    /// <summary>For hooks installed for the process; null for explicit helpers and per-object hooks.</summary>
    public Func<bool>? Install { get; init; }

    public Action? Uninstall { get; init; }

    /// <summary>Before each trigger (clear the underlying flag, temp files).</summary>
    public Action? Reset { get; init; }

    /// <summary>XSS never blocks: block mode reports a monitored event.</summary>
    public bool NeverBlocks { get; init; }

    public Action? Cleanup { get; init; }

    public void Dispose()
    {
        Uninstall?.Invoke();
        Cleanup?.Invoke();
    }
}

/// <summary>What happened when the kit fired a trigger.</summary>
internal sealed record HookOutcome(bool Blocked, Exception? Error, bool UnderlyingRan);

/// <summary>The contract checks every RASP sink hook must pass, applied to each hook in <see cref="RaspHookSpecs"/>.</summary>
public class RaspHookContractTests : RaspStateTest
{
    private ListSink _sink = new();

    public static IEnumerable<object[]> AllHooks => RaspHookSpecs.Names.Select(n => new object[] { n });

    public static IEnumerable<object[]> InstalledHooks => RaspHookSpecs.Installed.Select(n => new object[] { n });

    protected override void Dispose(bool disposing)
    {
        RaspHooks.DetectorProbe = null;
        base.Dispose(disposing);
    }

    private void SetMode(RaspMode? mode)
    {
        _sink = mode is null
            ? Configure(new EngineSettings(false, "kit"))
            : Configure(new EngineSettings(true, "kit", mode.Value));
    }

    private List<RaspEvent> Ours(HookSpec spec) =>
        _sink.Events.Where(e => e.Attrs["shield360.rasp.attack"] == RaspNames.Of(spec.Attack)).ToList();

    private static async Task<HookOutcome> Fire(HookSpec spec)
    {
        spec.Reset?.Invoke();
        try
        {
            if (spec.OwnContext)
            {
                await spec.Trigger();
            }
            else
            {
                var ctx = spec.Context?.Invoke() ?? new RaspContext(spec.Inputs, inRequest: true);
                await RaspScope.Run(ctx, spec.Trigger);
            }

            return new HookOutcome(false, null, spec.UnderlyingRan());
        }
        catch (Exception e)
        {
            return new HookOutcome(Shield360RaspMiddleware.Blocked(e) is not null, e, spec.UnderlyingRan());
        }
    }

    private static HookSpec Installed(string name)
    {
        var spec = RaspHookSpecs.Create(name);
        if (spec.Install is not null)
        {
            Assert.True(spec.Install());
        }

        return spec;
    }

    [Theory]
    [MemberData(nameof(AllHooks))]
    public async Task Block_refuses_before_the_underlying_call_and_reports_once(string name)
    {
        SetMode(RaspMode.Block);
        using var spec = Installed(name);
        var outcome = await Fire(spec);
        var ours = Ours(spec);
        Assert.Single(ours);
        if (spec.NeverBlocks)
        {
            Assert.False(outcome.Blocked);
            Assert.True(outcome.UnderlyingRan);
            Assert.Equal("monitored", ours[0].Attrs["shield360.rasp.decision"]);
            return;
        }

        Assert.True(outcome.Blocked, $"{name}: expected a block, got {outcome.Error?.GetType().Name ?? "no exception"}");
        Assert.False(outcome.UnderlyingRan);
        Assert.Equal("blocked", ours[0].Attrs["shield360.rasp.decision"]);
    }

    [Theory]
    [MemberData(nameof(AllHooks))]
    public async Task Monitor_lets_the_call_through_and_reports_exactly_once(string name)
    {
        SetMode(RaspMode.Monitor);
        using var spec = Installed(name);
        var outcome = await Fire(spec);
        Assert.False(outcome.Blocked);
        Assert.True(outcome.UnderlyingRan, $"{name}: the underlying call did not run ({outcome.Error?.GetType().Name})");
        var ours = Ours(spec);
        Assert.Single(ours);
        Assert.Equal("monitored", ours[0].Attrs["shield360.rasp.decision"]);
    }

    [Theory]
    [MemberData(nameof(AllHooks))]
    public async Task Rasp_off_checks_and_reports_nothing(string name)
    {
        SetMode(null);
        var probed = 0;
        RaspHooks.DetectorProbe = _ => probed++;
        using var spec = Installed(name);
        var outcome = await Fire(spec);
        Assert.False(outcome.Blocked);
        Assert.True(outcome.UnderlyingRan);
        Assert.Equal(0, probed);
        Assert.Empty(_sink.Events);
    }

    [Theory]
    [MemberData(nameof(AllHooks))]
    public async Task A_failing_detector_fails_open(string name)
    {
        SetMode(RaspMode.Block);
        var probed = 0;
        RaspHooks.DetectorProbe = _ =>
        {
            probed++;
            throw new InvalidOperationException("detector unavailable");
        };
        using var spec = Installed(name);
        var outcome = await Fire(spec);
        Assert.True(probed > 0, $"{name}: the detector never ran");
        Assert.False(outcome.Blocked);
        Assert.True(outcome.UnderlyingRan);
        Assert.Empty(_sink.Events);
    }

    [Theory]
    [MemberData(nameof(InstalledHooks))]
    public async Task Install_is_idempotent_and_uninstall_leaves_nothing_behind(string name)
    {
        SetMode(RaspMode.Block);
        using var spec = RaspHookSpecs.Create(name);
        Assert.True(spec.Install!());
        Assert.True(spec.Install!());
        spec.Uninstall!();
        spec.Uninstall!();
        var probed = 0;
        RaspHooks.DetectorProbe = _ => probed++;
        var outcome = await Fire(spec);
        Assert.False(outcome.Blocked);
        Assert.True(outcome.UnderlyingRan);
        Assert.Equal(0, probed);
        Assert.Empty(_sink.Events);
    }
}
