using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>Collects engine events.</summary>
internal sealed class ListSink : IRaspEventSink
{
    public List<RaspEvent> Events { get; } = new();

    public void Add(RaspEvent e, string foldKey)
    {
        lock (Events)
        {
            Events.Add(e);
        }
    }
}

/// <summary>Resets the process-wide RASP state around a test.</summary>
public abstract class RaspStateTest : IDisposable
{
    protected RaspStateTest()
    {
        Reset();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        Reset();
    }

    internal static void Reset()
    {
        RaspRuntime.Shutdown();
        RaspEngine.Configure(new EngineSettings(false, "default", Env: Env.Empty));
        RaspEngine.SetEventSink(null);
        RaspIast.Reset();
        RaspCustomRules.ResetWarnings();
        RaspScope.Enter(null);
    }

    internal static ListSink Configure(EngineSettings settings)
    {
        RaspEngine.Configure(settings with { Env = settings.Env ?? Env.Empty });
        var sink = new ListSink();
        RaspEngine.SetEventSink(sink);
        return sink;
    }
}

/// <summary>
/// Virtual patches: each built-in rule matches a request built from the shape its own
/// rule file documents, and stops matching when one clause is missing. Then the
/// engine: modes, caps, kill switches, events. Port of vpatch-engine.test.ts.
/// </summary>
public class RaspVirtualPatchEngineTests : RaspStateTest
{
    public static IEnumerable<object[]> RuleIds() => RaspVirtualPatches.BuiltIn.Select(r => new object[] { r.Id });

    private static VirtualPatch Rule(string id) => RaspVirtualPatches.BuiltIn.Single(r => r.Id == id);

    private static string RuntimeOf(VirtualPatch r) => r.Runtimes is { Count: > 0 } runtimes ? runtimes[0] : RaspVirtualPatches.Runtime;

    private static string VersionIn(VirtualPatch r, string runtime) =>
        r.RuntimeVersions is not null && r.RuntimeVersions.TryGetValue(runtime, out var ranges) && ranges is { Count: > 0 }
            ? ranges[0].From
            : RaspVirtualPatches.RuntimeVersion;

    private static VpRequest Without(VirtualPatch rule, int i) =>
        RaspCorpus.RequestFor(new VirtualPatch { Id = rule.Id, Match = rule.Match.Where((_, k) => k != i).ToList() });

    [Theory]
    [MemberData(nameof(RuleIds))]
    public void Built_in_rule_matches_its_documented_request_shape(string id)
    {
        var rule = Rule(id);
        var runtime = RuntimeOf(rule);
        var f = RaspVirtualPatches.Match(RaspCorpus.RequestFor(rule), new[] { rule }, VpPhase.All, runtime, VersionIn(rule, runtime));
        Assert.NotNull(f);
        Assert.Equal(RaspAttackType.VirtualPatch, f!.Attack);
        Assert.Equal(rule.Id, f.Rule);
        Assert.Equal(rule.Action == "monitor" ? RaspMode.Monitor : RaspMode.Block, f.Action);
        if (rule.Cves.Count > 0)
        {
            Assert.Equal(rule.Cves[0], f.Cve);
        }
    }

    [Theory]
    [MemberData(nameof(RuleIds))]
    public void Built_in_rule_needs_every_clause(string id)
    {
        var rule = Rule(id);
        var runtime = RuntimeOf(rule);
        for (var i = 0; i < rule.Match.Count; i++)
        {
            var req = Without(rule, i);

            // A clause on a target the remaining clauses also fill can still be met; only check clauses that are not.
            if (RaspVirtualPatches.ClauseMatches(req, rule.Match[i]))
            {
                continue;
            }

            Assert.Null(RaspVirtualPatches.Match(req, new[] { rule }, VpPhase.All, runtime, VersionIn(rule, runtime)));
        }
    }

    [Fact]
    public void Runtime_versions_are_half_open_ranges_and_other_runtimes_skip_node_rules()
    {
        var rule = RaspVirtualPatches.BuiltIn.First(r => r.RuntimeVersions?.ContainsKey("node") == true);
        var (from, to) = rule.RuntimeVersions!["node"]![0];
        Assert.True(RaspVirtualPatches.RuleApplies(rule, "node", from));
        Assert.False(RaspVirtualPatches.RuleApplies(rule, "node", to));
        Assert.False(RaspVirtualPatches.RuleApplies(rule, "dotnet", from));
    }

    [Fact]
    public void Dotnet_rules_apply_by_runtime_and_runtime_version()
    {
        using var doc = JsonDocument.Parse("""
            [{"id":"vp.dotnet-range","runtimes":["dotnet"],"runtimeVersions":{"dotnet":[["8.0.0","8.0.11"],["9.0.0","9.0.1"]]},
              "match":[{"target":"method","op":"equals","values":["GET"]}]},
             {"id":"vp.node-only","runtimes":["node"],"match":[{"target":"method","op":"equals","values":["GET"]}]}]
            """);
        var rules = VirtualPatch.ListFromJson(doc.RootElement);
        Assert.True(RaspVirtualPatches.RuleApplies(rules[0], "dotnet", "8.0.10"));
        Assert.False(RaspVirtualPatches.RuleApplies(rules[0], "dotnet", "8.0.11"));
        Assert.True(RaspVirtualPatches.RuleApplies(rules[0], "dotnet", "9.0.0"));
        Assert.False(RaspVirtualPatches.RuleApplies(rules[0], "dotnet", "10.0.0"));
        Assert.False(RaspVirtualPatches.RuleApplies(rules[1], "dotnet", "8.0.10"));
        Assert.Equal("vp.dotnet-range", RaspVirtualPatches.Match(new VpRequest(), rules, VpPhase.All, "dotnet", "8.0.5")?.Rule);
        Assert.Null(RaspVirtualPatches.Match(new VpRequest(), rules, VpPhase.All, "dotnet", "10.0.13"));

        // The example rule names no runtime, so it applies in .NET with the real runtime version.
        var example = RaspVirtualPatches.BuiltIn.Single(r => r.Example);
        Assert.Equal(example.Id, RaspVirtualPatches.Match(RaspCorpus.RequestFor(example), RaspVirtualPatches.BuiltIn)?.Rule);
    }

    [Fact]
    public void Phases_head_rules_never_read_the_body_and_body_rules_wait_for_it()
    {
        var bodyRule = RaspVirtualPatches.BuiltIn.First(RaspVirtualPatches.NeedsBody);
        var runtime = RuntimeOf(bodyRule);
        var req = RaspCorpus.RequestFor(bodyRule);
        Assert.Null(RaspVirtualPatches.Match(req, new[] { bodyRule }, VpPhase.Head, runtime, VersionIn(bodyRule, runtime)));
        Assert.Equal(bodyRule.Id, RaspVirtualPatches.Match(req, new[] { bodyRule }, VpPhase.Body, runtime, VersionIn(bodyRule, runtime))?.Rule);
    }

    [Fact]
    public void Refuses_patterns_with_backreferences_or_lookaround()
    {
        var req = new VpRequest { Path = "/aa" };
        MatchClause Re(string p) => new("path", "regex", Array.Empty<string>(), p, false);
        Assert.True(RaspVirtualPatches.ClauseMatches(req, Re("^/a+$")));
        Assert.False(RaspVirtualPatches.ClauseMatches(req, Re("(a)\\1")));
        Assert.False(RaspVirtualPatches.ClauseMatches(req, Re("a(?=a)")));
    }

    [Fact]
    public void Clause_ops_equals_ignores_case_contains_any_does_not_unless_asked()
    {
        var req = new VpRequest { Method = "post", Body = "Hello World" };
        Assert.True(RaspVirtualPatches.ClauseMatches(req, new MatchClause("method", "equals", new[] { "POST" }, null, false)));
        Assert.False(RaspVirtualPatches.ClauseMatches(req, new MatchClause("body", "contains_any", new[] { "hello" }, null, false)));
        Assert.True(RaspVirtualPatches.ClauseMatches(req, new MatchClause("body", "contains_any", new[] { "hello" }, null, true)));
        Assert.False(RaspVirtualPatches.ClauseMatches(req, new MatchClause("header:x-missing", "present", Array.Empty<string>(), null, false)));
    }

    // ---- engine ---------------------------------------------------------------

    private static readonly RaspFinding s_finding = new(RaspAttackType.SqlInjection, "sqli.userinput", new RaspInput("v", "query.id"));

    private static RemoteConfig Remote(
        bool killSwitch = false,
        bool snippets = false,
        Dictionary<RaspAttackType, RaspMode>? attacks = null,
        IReadOnlyList<VirtualPatch>? rules = null) => new()
    {
        Version = "v1",
        Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
        KillSwitch = killSwitch,
        Snippets = snippets,
        Attacks = attacks ?? new Dictionary<RaspAttackType, RaspMode>(),
        Rules = rules,
    };

    [Fact]
    public void Monitor_by_default_reports_and_never_throws()
    {
        var sink = Configure(new EngineSettings(true, "orders-api"));
        Assert.Equal(RaspDecision.Monitored, RaspEngine.HandleFinding(s_finding, "SqlClient.ExecuteReader"));
        var a = Assert.Single(sink.Events).Attrs;
        Assert.Matches("^[a-f0-9]{32}$", a["shield360.rasp.event_id"]);
        Assert.Equal("query.id", a["shield360.rasp.input_key"]);
        Assert.Equal("local", a["shield360.rasp.config_version"]);
        Assert.Equal("dotnet", a["shield360.rasp.language"]);
        Assert.Equal("orders-api", a["shield360.rasp.app"]);
        Assert.Equal("request", a["shield360.rasp.source"]);
        Assert.DoesNotContain(a.Values, v => v == "v");
    }

    [Fact]
    public void Block_mode_throws_the_typed_exception_with_the_event_id()
    {
        var sink = Configure(new EngineSettings(true, "a", Attacks: new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.SqlInjection] = RaspMode.Block }));
        var e = Assert.Throws<Shield360RaspBlockedException>(() => RaspEngine.HandleFinding(s_finding, "SqlClient.ExecuteReader"));
        Assert.Equal(sink.Events[0].Attrs["shield360.rasp.event_id"], e.EventId);
        Assert.Equal(403, e.StatusCode);
        Assert.Equal("sql_injection", e.Attack);
        Assert.Equal("sqli.userinput", e.Rule);
        Assert.Equal(
            "{\"error\":\"Request blocked by Shield360 runtime protection\",\"attack\":\"sql_injection\",\"rule\":\"sqli.userinput\",\"event\":\"" + e.EventId + "\"}",
            e.ToResponseJson());
    }

    [Fact]
    public void Xss_never_blocks()
    {
        Configure(new EngineSettings(true, "a", RaspMode.Block));
        Assert.Equal(RaspMode.Monitor, RaspEngine.ModeFor(RaspAttackType.Xss));
        Assert.Equal(RaspDecision.Monitored, RaspEngine.HandleFinding(new RaspFinding(RaspAttackType.Xss, "xss.reflected"), "http.response"));
    }

    [Fact]
    public void A_virtual_patch_is_capped_by_its_own_action_and_by_the_virtual_patch_mode()
    {
        Configure(new EngineSettings(true, "a", Attacks: new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.VirtualPatch] = RaspMode.Block }));
        Assert.Equal(RaspDecision.Monitored, RaspEngine.HandleFinding(new RaspFinding(RaspAttackType.VirtualPatch, "vp.x", Action: RaspMode.Monitor), "server.request"));
        Configure(new EngineSettings(true, "a"));
        Assert.Equal(RaspDecision.Monitored, RaspEngine.HandleFinding(new RaspFinding(RaspAttackType.VirtualPatch, "vp.x", Action: RaspMode.Block), "server.request"));
        Assert.Null(RaspEngine.HandleFinding(new RaspFinding(RaspAttackType.VirtualPatch, "vp.x", Action: RaspMode.Off), "server.request"));
    }

    [Fact]
    public void The_signed_config_overrides_local_modes_except_a_local_off()
    {
        Configure(new EngineSettings(true, "a", Attacks: new Dictionary<RaspAttackType, RaspMode>
        {
            [RaspAttackType.SqlInjection] = RaspMode.Monitor,
            [RaspAttackType.Ssrf] = RaspMode.Off,
        }));
        RaspEngine.SetRemoteConfig(Remote(attacks: new Dictionary<RaspAttackType, RaspMode>
        {
            [RaspAttackType.SqlInjection] = RaspMode.Block,
            [RaspAttackType.Ssrf] = RaspMode.Block,
        }));
        Assert.Equal(RaspMode.Block, RaspEngine.ModeFor(RaspAttackType.SqlInjection));
        Assert.Equal(RaspMode.Off, RaspEngine.ModeFor(RaspAttackType.Ssrf));
        Assert.Equal(RaspMode.Monitor, RaspEngine.ModeFor(RaspAttackType.Xxe));
    }

    [Fact]
    public void Monitor_only_caps_block_when_no_key_is_pinned()
    {
        Configure(new EngineSettings(true, "a", RaspMode.Block, MonitorOnly: true));
        Assert.Equal(RaspMode.Monitor, RaspEngine.ModeFor(RaspAttackType.SqlInjection));
    }

    [Fact]
    public void Kill_switch_order_env_off_then_signed_kill_switch_then_runtime_call()
    {
        Configure(new EngineSettings(true, "a", Env: Env.Of(("SHIELD360_RASP", "off"))));
        Assert.False(RaspEngine.IsActive);
        Configure(new EngineSettings(true, "a"));
        RaspEngine.SetRemoteConfig(Remote(killSwitch: true));
        Assert.False(RaspEngine.IsActive);
        Assert.Equal(RaspMode.Off, RaspEngine.ModeFor(RaspAttackType.SqlInjection));
        RaspEngine.SetRemoteConfig(Remote());
        Shield360Rasp.Disable();
        Assert.False(Shield360Rasp.IsActive);
        Shield360Rasp.Enable();
        Assert.True(Shield360Rasp.IsActive);
    }

    [Fact]
    public void SHIELD360_RASP_block_sets_the_default_mode()
    {
        Configure(new EngineSettings(true, "a", Env: Env.Of(("SHIELD360_RASP", "block"))));
        Assert.Equal(RaspMode.Block, RaspEngine.ModeFor(RaspAttackType.CommandInjection));
    }

    [Fact]
    public void The_signed_config_rules_replace_the_built_in_list_and_null_keeps_it()
    {
        Configure(new EngineSettings(true, "a"));
        var only = new VirtualPatch { Id = "vp.only", Match = new[] { new MatchClause("method", "equals", new[] { "GET" }, null, false) } };
        RaspEngine.SetRemoteConfig(Remote(rules: new[] { only }));
        Assert.Equal(new[] { "vp.only" }, RaspEngine.VirtualPatches().Select(r => r.Id));
        RaspEngine.SetRemoteConfig(Remote());
        Assert.Same(RaspVirtualPatches.BuiltIn, RaspEngine.VirtualPatches());
    }

    [Fact]
    public void Snippets_only_with_the_signed_flag_masked_and_at_most_64_characters()
    {
        var sink = Configure(new EngineSettings(true, "a"));
        var secret = "token=" + new string('s', 30);
        RaspEngine.HandleFinding(s_finding with { Input = new RaspInput(secret, "body.t") }, "db");
        Assert.False(sink.Events[0].Attrs.ContainsKey("shield360.rasp.snippet"));
        RaspEngine.SetRemoteConfig(Remote(snippets: true));
        RaspEngine.HandleFinding(s_finding with { Rule = "sqli.stacked", Input = new RaspInput(secret, "body.t") }, "db");
        Assert.Equal("token=***", sink.Events[1].Attrs["shield360.rasp.snippet"]);
        Assert.Equal("v1", sink.Events[1].Attrs["shield360.rasp.config_version"]);
        Assert.True(RaspEngine.MaskSnippet(new string('a', 200)).Length <= 64);
    }

    [Fact]
    public void Events_carry_the_route_template_or_the_path_with_ids_replaced_and_shaped_keys()
    {
        Assert.Equal("/api/orders/:id/items/:id", RaspScope.RouteOf("/api/orders/12345/items/3f2a9c1e-0b1d-4e6f-8a7b-9c0d1e2f3a4b"));
        Assert.Equal("/api/orders/:id/deadbeef", RaspScope.RouteOf("/api/orders/deadbeef1/deadbeef"));
        var sink = Configure(new EngineSettings(true, "a"));
        var ctx = new RaspContext(inRequest: true) { Method = "get", Path = "/api/orders/42", Framework = "aspnetcore" };
        RaspScope.Run(ctx, () => RaspEngine.HandleFinding(s_finding with { Input = new RaspInput("v", "query.a b") }, "db"));
        var a = sink.Events[0].Attrs;
        Assert.Equal("/api/orders/:id", a["shield360.rasp.route"]);
        Assert.Equal("GET", a["shield360.rasp.method"]);
        Assert.Equal("aspnetcore", a["shield360.rasp.framework"]);
        Assert.Equal("query.a_b", a["shield360.rasp.input_key"]);
        Assert.Null(RaspScope.Current);
    }

    [Fact]
    public void Check_fails_open_on_detector_errors_and_rethrows_only_the_block()
    {
        Configure(new EngineSettings(true, "a"));
        Assert.Null(RaspEngine.Check("db", () => throw new InvalidOperationException("detector bug")));
        Configure(new EngineSettings(true, "a", RaspMode.Block));
        Assert.Throws<Shield360RaspBlockedException>(() => RaspEngine.Check("db", () => s_finding));
    }

    [Fact]
    public void Inactive_findings_are_dropped()
    {
        var sink = Configure(new EngineSettings(false, "a"));
        Assert.Null(RaspEngine.HandleFinding(s_finding, "db"));
        Assert.Empty(sink.Events);
    }

    [Fact]
    public async System.Threading.Tasks.Task Run_with_inputs_scopes_inputs_to_the_call_and_what_it_awaits()
    {
        var inputs = new[] { new RaspInput("x", "job.id") };
        var seen = await Shield360Rasp.RunWithInputs(inputs, async () =>
        {
            await System.Threading.Tasks.Task.Yield();
            return RaspScope.InputsOf(RaspScope.Current!).Select(i => i.Key).ToList();
        });
        Assert.Equal(new[] { "job.id" }, seen);
        Assert.Null(RaspScope.Current);
        Assert.False(Shield360Rasp.RunInScope(() => RaspScope.Current!.InRequest));
    }

    [Fact]
    public void Event_attribute_shapes_match_the_platform_checks()
    {
        var sink = Configure(new EngineSettings(true, "a"));
        RaspEngine.HandleFinding(
            new RaspFinding(RaspAttackType.VirtualPatch, "vp.x", Cve: "CVE-2025-55182", Action: RaspMode.Monitor),
            "server.request",
            new FindingExtra("aspnetcore", "orders/{id}", "DELETEXXXXXXX", "/x"));
        var a = sink.Events[0].Attrs;
        Assert.Equal("CVE-2025-55182", a["shield360.rasp.cve"]);
        Assert.False(a.ContainsKey("shield360.rasp.route"));
        Assert.False(a.ContainsKey("shield360.rasp.method"));
        Assert.Matches(new Regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{12}Z$"), sink.Events[0].Time);
    }
}
