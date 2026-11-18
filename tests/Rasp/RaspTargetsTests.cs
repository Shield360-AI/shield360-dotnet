using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Allow-list targets and the SQL dialect (contract "Events", "Allow-list targets"):
/// the shared targets.json fixture, then the engine's gating, masking and cap.
/// </summary>
public class RaspTargetsTests : RaspStateTest
{
    private static readonly JsonObject s_fixture = RaspCorpus.Load("testdata/targets.json");

    public static IEnumerable<object?[]> MaskCases() =>
        ((JsonArray)s_fixture["mask"]!).Select(c => new object?[] { RaspCorpus.Str(c!["raw"]), c["target"]?.GetValue<string>() });

    public static IEnumerable<object[]> DirectoryCases() =>
        ((JsonArray)s_fixture["directory"]!).Select(c => new object[] { RaspCorpus.Str(c!["resolved"]), RaspCorpus.Str(c["directory"]) });

    [Theory]
    [MemberData(nameof(MaskCases))]
    public void Mask_matches_the_fixture(string raw, string? target) => Assert.Equal(target, RaspEngine.MaskTarget(raw));

    [Theory]
    [MemberData(nameof(DirectoryCases))]
    public void Directory_matches_the_fixture(string resolved, string directory) => Assert.Equal(directory, RaspDetect.TargetDirectory(resolved));

    private static RemoteConfig Remote(bool reportTargets) => new()
    {
        Version = "v1",
        Exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
        ReportTargets = reportTargets,
    };

    private static IReadOnlyDictionary<string, string> Report(ListSink sink, RaspFinding f)
    {
        RaspEngine.HandleFinding(f, "sink");
        return sink.Events[sink.Events.Count - 1].Attrs;
    }

    [Fact]
    public void Detectors_set_the_raw_target_the_rule_compared()
    {
        Assert.Equal("bash", RaspDetect.ShellSpawn("/bin/BASH.exe", null, true, Array.Empty<string>())!.Target);
        Assert.Equal("evil.example.com", RaspDetect.Outbound("https://EVIL.example.com:8443/x?y=1", new[] { "api.example.com" })!.Target);
        var path = RaspDetect.FilePath("/etc/app/report.txt", FileOp.Read, new[] { new RaspInput("report.txt", "query.f") }, new[] { "/srv/app" });
        Assert.Equal("path.outside_root", path!.Rule);
        Assert.Equal("/etc/app", path.Target);
    }

    [Fact]
    public void Target_only_with_report_targets_true()
    {
        var sink = Configure(new EngineSettings(true, "a"));
        var f = new RaspFinding(RaspAttackType.Outbound, "outbound.not_allowed", Target: "api.example.com");
        Assert.False(Report(sink, f).ContainsKey("shield360.rasp.target"));
        RaspEngine.SetRemoteConfig(Remote(false));
        Assert.False(Report(sink, f).ContainsKey("shield360.rasp.target"));
        RaspEngine.SetRemoteConfig(Remote(true));
        Assert.Equal("api.example.com", Report(sink, f)["shield360.rasp.target"]);
        Assert.Equal("bash", Report(sink, new RaspFinding(RaspAttackType.ShellSpawn, "shell_spawn.shell", Target: "bash"))["shield360.rasp.target"]);
        Assert.Equal("/var/data", Report(sink, new RaspFinding(RaspAttackType.PathTraversal, "path.outside_root", Target: "/var/data"))["shield360.rasp.target"]);
    }

    [Fact]
    public void Target_absent_for_other_rules()
    {
        var sink = Configure(new EngineSettings(true, "a"));
        RaspEngine.SetRemoteConfig(Remote(true));
        Assert.False(Report(sink, new RaspFinding(RaspAttackType.PathTraversal, "path.traversal", new RaspInput("../x", "query.f"), Target: "/var/data")).ContainsKey("shield360.rasp.target"));
    }

    [Fact]
    public void Target_is_masked_and_capped()
    {
        var sink = Configure(new EngineSettings(true, "a"));
        RaspEngine.SetRemoteConfig(Remote(true));
        var masked = new RaspFinding(RaspAttackType.Outbound, "outbound.not_allowed", Target: "abcdefghijklmnopqrstuvwxyz0123.example.com");
        Assert.Equal("***.example.com", Report(sink, masked)["shield360.rasp.target"]);
        var longPath = string.Concat(Enumerable.Repeat("/ab", 90));
        var capped = new RaspFinding(RaspAttackType.PathTraversal, "path.outside_root", Target: longPath);
        Assert.False(Report(sink, capped).ContainsKey("shield360.rasp.target"));
    }

    [Fact]
    public void Sql_findings_carry_the_dialect()
    {
        var f = RaspDetect.Sql("SELECT * FROM t WHERE id = 1 OR 1=1", new[] { new RaspInput("1 OR 1=1", "query.id") }, SqlDialect.Postgres);
        Assert.Equal("postgres", f!.Dialect);
        var sink = Configure(new EngineSettings(true, "a"));
        Assert.Equal("postgres", Report(sink, f)["shield360.rasp.sql.dialect"]);
        Assert.False(Report(sink, f).ContainsKey("shield360.rasp.target"));
        Assert.Equal("generic", RaspDetect.Sql("SELECT 1; DROP TABLE t", new[] { new RaspInput("1; DROP TABLE t", "query.id") })!.Dialect);
        Assert.False(Report(sink, new RaspFinding(RaspAttackType.SqlInjection, "sqli.userinput", Dialect: "nope")).ContainsKey("shield360.rasp.sql.dialect"));
    }
}
