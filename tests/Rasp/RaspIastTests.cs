using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Passive IAST (contract "Passive IAST"): the shared conformance corpus
/// (testdata/iast.json), the thresholds, and how the engine arms, samples, dedupes and
/// reports vulnerabilities without ever blocking. Port of iast.test.ts.
/// </summary>
public class RaspIastTests : RaspStateTest
{
    private static readonly Lazy<JsonObject> s_corpus = new(() => RaspCorpus.Load("testdata/iast.json"));

    private static JsonObject Corpus => s_corpus.Value;

    public static IEnumerable<object[]> CaseNames() => ((JsonArray)Corpus["cases"]!).Select(c => new object[] { RaspCorpus.Str(c!["name"]) });

    public static IEnumerable<object[]> Fingerprints() => ((JsonArray)Corpus["fingerprints"]!).Select(f => new object[] { RaspCorpus.Str(f!["fingerprint"]) });

    private static string? Text(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private static FileOp Op(string name) => name switch
    {
        "write" => FileOp.Write,
        "append" => FileOp.Append,
        "delete" => FileOp.Delete,
        "rename" => FileOp.Rename,
        "list" => FileOp.List,
        "open" => FileOp.Open,
        _ => FileOp.Read,
    };

    /// <summary>Runs one corpus case through the detectors with an IAST slot armed.</summary>
    private static (RaspFinding? Finding, RaspVuln? Vuln) RunCase(JsonObject c)
    {
        var inputs = RaspCorpus.Normalize(c["inputs"]);
        return RaspIastScope.Capture(() =>
        {
            switch (RaspCorpus.Str(c["check"]))
            {
                case "sql":
                    return RaspDetect.Sql(RaspCorpus.Str(c["query"]), inputs, RaspLexers.Dialect(Text(c["dialect"])));
                case "command":
                {
                    if (Text(c["command"]) is { } command)
                    {
                        return RaspDetect.Command(command, inputs) ?? RaspDetect.ShellSpawn(null, command, true, Array.Empty<string>());
                    }

                    var argv = RaspCorpus.Strings(c["argv"]);
                    var script = RaspDetect.ShellScriptOf(argv);
                    return RaspDetect.Argv(argv, inputs)
                        ?? (script is null ? null : RaspDetect.Command(script, inputs))
                        ?? RaspDetect.ShellSpawn(argv[0], null, true, Array.Empty<string>());
                }

                case "path":
                    return RaspDetect.FilePath(RaspCorpus.Str(c["path"]), Op(RaspCorpus.Str(c["op"])), inputs, RaspCorpus.Strings(c["fileRoots"]));
                case "ssrf":
                    return RaspDetect.Ssrf(RaspCorpus.Str(c["url"]), inputs, RaspCorpus.Strings(c["resolved"]));
                case "code":
                    return RaspDetect.Code(RaspCorpus.Str(c["code"]), inputs);
                case "include":
                    return RaspDetect.Include(RaspCorpus.Str(c["specifier"]), inputs);
                case "deser":
                    return RaspDetect.Deserialization(RaspDetect.Format(RaspCorpus.Str(c["format"]))!.Value, RaspCorpus.Str(c["data"]), inputs);
                case "xml":
                    return RaspDetect.Xml(RaspCorpus.Str(c["xml"]), inputs, c["resolvesExternal"]?.GetValue<bool>() == true);
                default:
                    throw new ArgumentException("unknown check " + RaspCorpus.Str(c["check"]));
            }
        });
    }

    [Fact]
    public void Corpus_is_version_1_with_cases_for_every_rule()
    {
        Assert.Equal(1, Corpus["version"]!.GetValue<int>());
        var rules = ((JsonArray)Corpus["cases"]!).Select(c => Text(c!["expect"]!["rule"])).Where(r => r is not null).Distinct().OrderBy(r => r, StringComparer.Ordinal);
        Assert.Equal(RaspIastRules.Rules.OrderBy(r => r, StringComparer.Ordinal), rules);
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void Conformance(string name)
    {
        var c = (JsonObject)((JsonArray)Corpus["cases"]!).First(x => RaspCorpus.Str(x!["name"]) == name)!;
        var (finding, vuln) = RunCase(c);

        // Every case is harmless: the attack checks fire nothing.
        Assert.Null(finding);
        var expect = c["expect"]!;
        if (Text(expect["rule"]) is not { } rule)
        {
            Assert.Null(vuln);
            return;
        }

        Assert.Equal(rule, vuln?.Rule);
        if (Text(expect["position"]) is { } position)
        {
            Assert.Equal(position, vuln!.Position);
        }

        if (Text(expect["input_key"]) is { } key)
        {
            Assert.Equal(key, vuln!.Input.Key);
        }
    }

    [Theory]
    [MemberData(nameof(Fingerprints))]
    public void Fingerprint(string fingerprint)
    {
        var f = ((JsonArray)Corpus["fingerprints"]!).First(x => RaspCorpus.Str(x!["fingerprint"]) == fingerprint)!;
        Assert.Equal(fingerprint, RaspIast.Fingerprint(RaspCorpus.Str(f["route"]), RaspCorpus.Str(f["sink"]), RaspCorpus.Str(f["input_key"]), RaspCorpus.Str(f["rule"])));
    }

    [Fact]
    public void Notes_nothing_when_no_slot_is_armed()
    {
        Assert.False(RaspIastScope.Armed);
        var inputs = new[] { new RaspInput("alice@example.com", "query.email") };
        Assert.Null(RaspDetect.Sql("SELECT 1 FROM t WHERE e = 'alice@example.com'", inputs));
        Assert.False(RaspIastScope.Armed);
    }

    [Theory]
    [InlineData("1", false)]
    [InlineData("42", false)]
    [InlineData("100", false)]
    [InlineData("true", false)]
    [InlineData("active", false)]
    [InlineData("desc", false)]
    [InlineData("aaaaaaaaaa", false)]
    [InlineData("----", false)]
    [InlineData("1234", true)]
    [InlineData("created_at", true)]
    [InlineData("en-GB", true)]
    [InlineData("alice@example.com", true)]
    [InlineData("Saint Paul", true)]
    [InlineData("password", true)]
    [InlineData("٣٤٥", true)]
    [InlineData("😀😀x", true)]
    public void Thresholds(string value, bool expected) => Assert.Equal(expected, RaspIastRules.Qualifies(value));

    // ---- in the engine --------------------------------------------------------------

    private readonly List<RaspEvent> _events = new();
    private ListSink _attacks = new();
    private long _clock = 1_000_000;
    private static readonly RaspInput[] s_email = { new("alice@example.com", "query.email") };
    private const string Query = "SELECT id FROM orders WHERE customer_email = 'alice@example.com'";

    private bool Collect(RaspEvent e, string foldKey)
    {
        _events.Add(e);
        return true;
    }

    private void Setup(bool? iast = null, double? rate = null, Func<string, string?>? env = null, RaspMode mode = RaspMode.Block, string? environment = null, Func<double>? random = null)
    {
        _attacks = Configure(new EngineSettings(true, "orders-api", mode));
        RaspIast.Configure(new IastSettings(iast, rate, "orders-api", environment, env ?? Env.Empty, () => _clock, random));
        RaspIast.SetSink(Collect);
    }

    private static RaspContext Ctx(IEnumerable<RaspInput> inputs, string? route = "/api/orders/:id", string? path = null) =>
        new(inputs, inRequest: true) { Method = "get", Route = route, Path = path, Framework = "aspnetcore" };

    private static RaspDecision? RunSql(IReadOnlyList<RaspInput>? inputs = null, string query = Query, RaspContext? ctx = null)
    {
        var ins = inputs ?? s_email;
        return RaspScope.Run(ctx ?? Ctx(ins), () => RaspEngine.Check("pg.query", () => RaspDetect.Sql(query, ins, SqlDialect.Postgres)));
    }

    private List<RaspEvent> Vulns() => _events.Where(e => e.Name == RaspIast.EventName).ToList();

    [Fact]
    public void Is_off_by_default()
    {
        Setup();
        Assert.False(RaspIast.Enabled);
        Assert.Null(RunSql());
        Assert.Empty(Vulns());
    }

    [Fact]
    public void Reports_a_vulnerability_once_with_locations_and_no_value_and_never_blocks()
    {
        Setup(iast: true, mode: RaspMode.Block);
        Assert.Null(RunSql());
        var a = Assert.Single(Vulns()).Attrs;
        var expected = new Dictionary<string, string>
        {
            ["shield360.rasp.kind"] = "vulnerability",
            ["shield360.rasp.app"] = "orders-api",
            ["shield360.rasp.rule"] = "vuln.sql_concat",
            ["shield360.rasp.sink"] = "pg.query",
            ["shield360.rasp.source"] = "request",
            ["shield360.rasp.input_key"] = "query.email",
            ["shield360.rasp.route"] = "/api/orders/:id",
            ["shield360.rasp.method"] = "GET",
            ["shield360.rasp.framework"] = "aspnetcore",
            ["shield360.rasp.language"] = "dotnet",
            ["shield360.rasp.config_version"] = "local",
            ["shield360.rasp.vuln.position"] = "string",
            ["shield360.rasp.count"] = "1",
        };
        foreach (var kv in expected)
        {
            Assert.Equal(kv.Value, a[kv.Key]);
        }

        Assert.Equal(RaspIast.Fingerprint("/api/orders/:id", "pg.query", "query.email", "vuln.sql_concat"), a["shield360.rasp.vuln.fingerprint"]);
        Assert.Matches("^[a-f0-9]{32}$", a["shield360.rasp.event_id"]);

        // This test file is the app's code here (the test binaries run outside the source tree: the last three segments).
        Assert.Matches(@"^tests/Rasp/RaspIastTests\.cs:\d+$", a["shield360.rasp.vuln.location"]);
        Assert.DoesNotContain("alice@example.com", JsonSerializer.Serialize(Vulns().Select(e => e.Attrs)), StringComparison.Ordinal);
        Assert.False(a.ContainsKey("shield360.rasp.snippet"));
        Assert.Empty(_attacks.Events);
    }

    [Fact]
    public void Reports_each_fingerprint_at_most_once_an_hour_with_the_count_seen_since()
    {
        Setup(iast: true);
        RunSql();
        RunSql();
        RunSql();
        Assert.Single(Vulns());
        _clock += RaspIast.ReportEveryMs;
        RunSql();
        Assert.Equal(2, Vulns().Count);
        Assert.Equal("3", Vulns()[1].Attrs["shield360.rasp.count"]);
    }

    [Fact]
    public void Reports_nothing_for_an_attack()
    {
        Setup(iast: true, mode: RaspMode.Monitor);
        var attack = new[] { new RaspInput("x' OR '1'='1", "query.q") };
        RunSql(attack, "SELECT * FROM t WHERE a = 'x' OR '1'='1'");
        Assert.Empty(Vulns());
        Assert.Single(_attacks.Events);
    }

    [Fact]
    public void Works_whatever_the_attack_mode_even_off()
    {
        _attacks = Configure(new EngineSettings(true, "orders-api", Attacks: new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.SqlInjection] = RaspMode.Off }));
        RaspIast.Configure(new IastSettings(true, null, "orders-api", null, Env.Empty, () => _clock));
        RaspIast.SetSink(Collect);
        RunSql();
        Assert.Single(Vulns());
    }

    [Fact]
    public void Stands_down_with_the_kill_switch()
    {
        Setup(iast: true);
        RaspEngine.SetRuntimeDisabled(true);
        RunSql();
        RaspEngine.SetRuntimeDisabled(false);
        Assert.Empty(Vulns());
    }

    [Fact]
    public void Does_nothing_without_request_input_in_scope()
    {
        Setup(iast: true);
        RaspEngine.Check("pg.query", () => RaspDetect.Sql(Query, s_email, SqlDialect.Postgres));
        RaspScope.Run(new RaspContext(inRequest: true), () => RaspEngine.Check("pg.query", () => RaspDetect.Sql(Query, s_email, SqlDialect.Postgres)));
        Assert.Empty(Vulns());
    }

    [Fact]
    public void Samples_checks()
    {
        Setup(rate: 0.5, random: () => 0.9);
        RunSql();
        Assert.Empty(Vulns());
        Setup(rate: 0.5, random: () => 0.1);
        RunSql();
        Assert.Single(Vulns());
    }

    [Fact]
    public void Defaults_to_every_check_a_tenth_in_production()
    {
        Setup(iast: true);
        Assert.Equal(1, RaspIast.SampleRate);
        Setup(iast: true, environment: "production");
        Assert.Equal(0.1, RaspIast.SampleRate);
        Setup(iast: true, env: Env.Of(("ASPNETCORE_ENVIRONMENT", "Production"), ("SHIELD360_IAST_SAMPLE_RATE", "0.5")));
        Assert.Equal(0.5, RaspIast.SampleRate);
        Setup(iast: true, env: Env.Of(("SHIELD360_IAST_SAMPLE_RATE", "7")));
        Assert.Equal(1, RaspIast.SampleRate);
        Setup(iast: true, rate: 2);
        Assert.Equal(1, RaspIast.SampleRate);
    }

    [Fact]
    public void Is_switched_by_the_env_and_the_signed_config_env_off_winning()
    {
        Setup(env: Env.Of(("SHIELD360_IAST", "on")));
        Assert.True(RaspIast.Enabled);
        RaspIast.SetRemote(new IastRemote("off", null, "v2"));
        Assert.False(RaspIast.Enabled);
        Setup(random: () => 0.1);
        RaspIast.SetRemote(new IastRemote("on", 0.25, "v3"));
        Assert.True(RaspIast.Enabled);
        Assert.Equal(0.25, RaspIast.SampleRate);
        RunSql();
        Assert.Equal("v3", Vulns()[0].Attrs["shield360.rasp.config_version"]);
        Setup(iast: true, env: Env.Of(("SHIELD360_IAST", "off")));
        RaspIast.SetRemote(new IastRemote("on", null, "v4"));
        Assert.False(RaspIast.Enabled);
        RaspIast.SetRemote(null);
        Assert.False(RaspIast.Enabled);
    }

    [Fact]
    public void Reads_the_switch_and_rate_from_the_signed_claims()
    {
        var claims = new RaspClaims("cfg-9", 0, TestJson.Parse("{\"iast\":\"on\",\"iastSampleRate\":0.3}"));
        Assert.Equal(new IastRemote("on", 0.3, "cfg-9"), RaspIast.RemoteOf(claims));
        Assert.Equal(new IastRemote(null, null, "cfg-9"), RaspIast.RemoteOf(new RaspClaims("cfg-9", 0, TestJson.Parse("{\"iast\":true}"))));
    }

    [Fact]
    public void Fails_open_when_a_rule_throws()
    {
        Setup(iast: true);
        var ctx = Ctx(s_email);
        var ex = Record.Exception(() => RaspScope.Run(ctx, () => RaspEngine.Check("pg.query", () =>
        {
            RaspIastScope.Note(() => throw new InvalidOperationException("boom"));
            return RaspDetect.Sql(Query, s_email);
        })));
        Assert.Null(ex);
        Assert.Single(Vulns());
    }

    [Fact]
    public void Never_exports_a_secret_looking_path_segment_when_the_framework_gives_no_route_template()
    {
        Setup(iast: true);
        RunSql(ctx: Ctx(s_email, route: null, path: "/api/v2/reset/AbCdEfGhIjKlMnOpQrSt/confirm"));
        var v = Assert.Single(Vulns());
        Assert.Equal("/api/v2/reset/:id/confirm", v.Attrs["shield360.rasp.route"]);
        Assert.DoesNotContain("AbCdEfGhIjKlMnOpQrSt", JsonSerializer.Serialize(Vulns().Select(e => e.Attrs)), StringComparison.Ordinal);
    }

    [Fact]
    public void Retries_a_report_the_reporter_refused_keeping_the_count()
    {
        Setup(iast: true);
        var accepted = new List<RaspEvent>();
        var refuse = true;
        RaspIast.SetSink((e, _) =>
        {
            if (refuse)
            {
                return false;
            }

            accepted.Add(e);
            return true;
        });
        RunSql();
        Assert.Empty(accepted);
        refuse = false;
        _clock += 61_000;
        RunSql();
        Assert.Single(accepted);
        Assert.Equal("2", accepted[0].Attrs["shield360.rasp.count"]);
        RunSql();
        Assert.Single(accepted);
    }

    [Fact]
    public void A_refused_report_retried_inside_the_reporters_fold_window_is_sent_once_with_every_sighting()
    {
        Setup(iast: true);
        var now = 0L;
        using var reporter = new RaspReporter(new RaspReporterOptions { Url = "https://shield360.invalid", ApiKey = "k", ApplicationName = "orders-api", NowMs = () => now });
        RaspIast.SetSink(RaspRuntime.IastSink(reporter));

        // The minute's 100 events are spent, so the first report is refused.
        for (var i = 0; i < RaspReporter.PerMinute; i++)
        {
            reporter.Add(new RaspEvent(RaspReporter.EventName, "t", new Dictionary<string, string>()), "attack" + i);
        }

        RunSql();
        now += 1_000;
        RunSql(); // a retry within 10 s of the refused one: refused again
        now += 60_000;
        RunSql(); // capacity is back
        // Exactly one event, carrying every sighting: the reporter never folded or kept the refused ones.
        now += RaspReporter.FoldMs;
        reporter.Add(new RaspEvent(RaspReporter.EventName, "t", new Dictionary<string, string>()), "close-folds");
        var vulns = reporter.Pending().Where(e => e.Name == RaspIast.EventName).ToList();
        var v = Assert.Single(vulns);
        Assert.Equal("3", v.Attrs["shield360.rasp.count"]);
        now += 60_000;
        RunSql(); // within the hour: counted, not sent
        Assert.Single(reporter.Pending(), e => e.Name == RaspIast.EventName);
    }

    [Fact]
    public void Reaches_the_real_file_hook()
    {
        Setup(iast: true);
        var inputs = new[] { new RaspInput("invoice-2026-0193", "query.file") };
        var path = Path.Combine(Path.GetTempPath(), "nonexistent-shield360-iast", "invoice-2026-0193.pdf");
        RaspScope.Run(Ctx(inputs, route: "/files/{name}"), () =>
        {
            try
            {
                return RaspFile.ReadAllText(path);
            }
            catch (IOException)
            {
                return null; // missing on purpose
            }
        });
        var found = Vulns().Where(e => e.Attrs["shield360.rasp.rule"] == "vuln.path_from_input").ToList();
        Assert.NotEmpty(found);
        Assert.Equal("query.file", found[0].Attrs["shield360.rasp.input_key"]);
        Assert.Equal("File.ReadAllText", found[0].Attrs["shield360.rasp.sink"]);
    }

    [Fact]
    public void A_blocking_attack_still_blocks_with_IAST_on()
    {
        Setup(iast: true, mode: RaspMode.Block);
        var attack = new[] { new RaspInput("x' OR '1'='1", "query.q") };
        Assert.Throws<Shield360RaspBlockedException>(() => RunSql(attack, "SELECT * FROM t WHERE a = 'x' OR '1'='1'"));
        Assert.False(RaspIastScope.Armed);
    }

    [Fact]
    public void Remembers_at_most_ten_thousand_fingerprints_forgetting_the_oldest()
    {
        Setup(iast: true);
        for (var i = 0; i <= RaspIast.MaxFingerprints; i++)
        {
            RunSql(ctx: Ctx(s_email, route: "/r/" + i.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        Assert.Equal(RaspIast.MaxFingerprints + 1, Vulns().Count);
        RunSql(ctx: Ctx(s_email, route: "/r/0")); // forgotten: reported again at once
        RunSql(ctx: Ctx(s_email, route: "/r/1")); // forgotten too (the oldest went when /r/0 came back)
        RunSql(ctx: Ctx(s_email, route: "/r/" + RaspIast.MaxFingerprints.ToString(System.Globalization.CultureInfo.InvariantCulture))); // still remembered
        Assert.Equal(RaspIast.MaxFingerprints + 3, Vulns().Count);
    }

    // ---- code location -----------------------------------------------------------

    [Fact]
    public void Code_location_takes_the_first_app_frame_outside_the_SDK_and_the_framework()
    {
        var frames = new[]
        {
            new IastFrame("Shield360", "/src/sdk/Rasp/RaspIast.cs", 10),
            new IastFrame("Microsoft.Data.SqlClient", "/build/SqlCommand.cs", 500),
            new IastFrame("System.Private.CoreLib", null, 0),
            new IastFrame("OrdersApi", null, 0),
            new IastFrame("OrdersApi", "/srv/app/Routes/Orders.cs", 42),
            new IastFrame("OrdersApi", "/srv/app/Program.cs", 7),
        };
        Assert.Equal("Routes/Orders.cs:42", RaspIast.CodeLocation(frames, "/srv/app"));
    }

    [Fact]
    public void Code_location_keeps_the_last_three_segments_outside_the_working_directory()
    {
        Assert.Equal("lib/db/Run.cs:3", RaspIast.CodeLocation(new[] { new IastFrame("Other", "/opt/other/app/lib/db/Run.cs", 3) }, "/srv/app"));
        Assert.Equal("src/Orders_Api/Run.cs:3", RaspIast.CodeLocation(new[] { new IastFrame("Other", @"C:\work\src\Orders Api\Run.cs", 3) }, "/srv/app"));
    }

    [Fact]
    public void Code_location_is_empty_when_there_is_no_app_frame()
    {
        Assert.Equal(string.Empty, RaspIast.CodeLocation(new[] { new IastFrame("Shield360.AspNetCore", "/x/a.cs", 1), new IastFrame("System.Linq", "/x/b.cs", 2) }, "/srv"));
        Assert.False(RaspIast.IsAppFrame(new IastFrame("mscorlib", "/x.cs", 1)));
        Assert.True(RaspIast.IsAppFrame(new IastFrame("Shield360.Tests", "/x.cs", 1)));
    }

    [Fact]
    public void The_route_fallback_keeps_only_short_words_and_versions()
    {
        Assert.Equal("/api/v2/reset/:id/confirm", RaspIast.RouteOf("/api/v2/reset/AbCdEfGhIjKlMnOpQrSt/confirm"));
        Assert.Equal("/users/:id/orders/:id", RaspIast.RouteOf("/users/Alice/orders/42?x=1"));
        Assert.Matches(new Regex("^/files/:id$"), RaspIast.RouteOf("/files/invoice-2026-0193.pdf"));
    }
}
