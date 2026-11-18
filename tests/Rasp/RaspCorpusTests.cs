using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using Shield360.Rasp;
using Xunit;
using Xunit.Abstractions;

namespace Shield360.Tests.Rasp;

/// <summary>
/// The shared RASP corpus (sdk/rasp/testdata): every benign case must fire nothing
/// (false positives per section, must be 0), every entry of attack-examples.json
/// must be detected as it says, and the embedded data files must stay
/// byte-identical to the contract's copies.
/// </summary>
public class RaspCorpusTests
{
    private static readonly JsonObject s_benign = RaspCorpus.Load("testdata/benign.json");
    private static readonly JsonObject s_attacks = RaspCorpus.Load("testdata/attack-examples.json");
    private static readonly JsonObject s_templateAttacks = RaspCorpus.Load("testdata/template-attack-examples.json");
    private static readonly JsonObject s_lexer = RaspCorpus.Load("testdata/sql-lexer.json");
    private readonly ITestOutputHelper _output;

    public RaspCorpusTests(ITestOutputHelper output)
    {
        _output = output;
    }

    public static IEnumerable<object[]> SectionNames() => RaspCorpus.Sections.Select(s => new object[] { s });

    public static IEnumerable<object[]> LexerCases() =>
        ((JsonArray)s_lexer["cases"]!).Select((c, i) => new object[] { i, RaspCorpus.Str(c!["name"]) });

    public static IEnumerable<object[]> AttackCases() =>
        ((JsonArray)s_attacks["cases"]!).Select((c, i) => new object[] { i, RaspCorpus.Str(c!["name"]) })
            .Concat(((JsonArray)s_templateAttacks["cases"]!).Select((c, i) => new object[] { -1 - i, RaspCorpus.Str(c!["name"]) }));

    /// <summary>attack-examples.json at a non-negative index; template-attack-examples.json at <c>-1 - i</c>.</summary>
    private static JsonObject AttackCase(int index) =>
        (JsonObject)(index >= 0 ? ((JsonArray)s_attacks["cases"]!)[index] : ((JsonArray)s_templateAttacks["cases"]!)[-1 - index])!;

    [Fact]
    public void Benign_corpus_is_the_generated_version_1_with_every_section()
    {
        Assert.Equal(1, s_benign["version"]!.GetValue<int>());
        foreach (var s in RaspCorpus.Sections)
        {
            Assert.NotEmpty((JsonArray)s_benign[s]!);
        }
    }

    [Theory]
    [MemberData(nameof(SectionNames))]
    public void Benign_section_has_no_false_positives(string section)
    {
        var cases = ((JsonArray)s_benign[section]!).Select(c => (JsonObject)c!).ToList();
        var fired = cases
            .Select(c => (Name: RaspCorpus.Str(c["name"]), Finding: RaspCorpus.RunCase(section, c)))
            .Where(x => x.Finding is not null)
            .Select(x => $"{x.Name}: {x.Finding!.Rule}")
            .ToList();

        // The report the contract asks each SDK for: false positives per section.
        _output.WriteLine($"RASP false positives (.NET) {section}: {fired.Count}/{cases.Count} ({100.0 * fired.Count / cases.Count:0.00}%)");
        Assert.Empty(fired);
    }

    [Fact]
    public void Attack_examples_file_has_cases()
    {
        Assert.IsType<JsonArray>(s_attacks["cases"]);
        Assert.NotEmpty((JsonArray)s_templateAttacks["cases"]!);
    }

    [Theory]
    [MemberData(nameof(LexerCases))]
    public void Sql_lexer_matches_the_contract_fixture(int index, string name)
    {
        var c = (JsonObject)((JsonArray)s_lexer["cases"]!)[index]!;
        var want = ((JsonArray)c["tokens"]!).Select(t => RaspCorpus.Str(t![0]) + " " + RaspCorpus.Str(t[1])).ToList();
        var got = RaspLexers.SqlTokens(RaspCorpus.Str(c["query"]), RaspLexers.Dialect(RaspCorpus.Str(c["dialect"]))).Select(t => t.Kind + " " + t.Text).ToList();
        Assert.True(want.SequenceEqual(got), $"{name}: got [{string.Join(" | ", got)}]");
    }

    [Theory]
    [MemberData(nameof(AttackCases))]
    public void Attack_example_is_detected(int index, string name)
    {
        var c = AttackCase(index);
        var f = RaspCorpus.RunCase(RaspCorpus.Str(c["check"]), c);
        Assert.True(f is not null, $"not detected: {name}");
        var expect = (JsonObject)c["expect"]!;
        Assert.Equal(RaspCorpus.Str(expect["attack"]), RaspNames.Of(f!.Attack));
        if (expect["rule"] is { } rule)
        {
            Assert.Equal(RaspCorpus.Str(rule), f.Rule);
        }

        _output.WriteLine($"{name}: {RaspNames.Of(f.Attack)} / {f.Rule}");
    }

    [Fact]
    public void Embedded_default_rules_are_byte_identical_to_the_contract_copy()
    {
        Assert.Equal(
            File.ReadAllBytes(Path.Combine(RaspCorpus.RaspDir, "rules", "default-rules.json")),
            RaspData.Resource(RaspData.RulesResource));
    }

    [Fact]
    public void Embedded_dnslog_domains_are_byte_identical_to_the_contract_copy()
    {
        Assert.Equal(
            File.ReadAllBytes(Path.Combine(RaspCorpus.RaspDir, "testdata", "dnslog-domains.json")),
            RaspData.Resource(RaspData.DnslogResource));
    }

    [Fact]
    public void Built_in_rules_load_from_the_embedded_file()
    {
        Assert.NotEmpty(RaspData.BuiltInVersion);
        Assert.Contains(RaspVirtualPatches.BuiltIn, r => r.Id == "vp.example-test-header");
        Assert.NotEmpty(RaspData.DnslogSuffixes);
    }
}
