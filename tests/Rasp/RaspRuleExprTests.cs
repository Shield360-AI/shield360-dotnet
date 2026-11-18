using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Custom rule expressions (contract "Custom rules"): the shared conformance corpus
/// (testdata/custom-rules.json), the limits, the safe regex subset and its linear-time
/// matcher, CIDR matching, and fail-open evaluation. Port of rule-expr.test.ts.
/// </summary>
public class RaspRuleExprTests
{
    private static readonly Lazy<JsonObject> s_corpus = new(() => RaspCorpus.Load("testdata/custom-rules.json"));

    private static JsonObject Corpus => s_corpus.Value;

    public static IEnumerable<object[]> ValidNames() => ((JsonArray)Corpus["valid"]!).Select(c => new object[] { RaspCorpus.Str(c!["name"]) });

    public static IEnumerable<object[]> InvalidNames() => ((JsonArray)Corpus["invalid"]!).Select(c => new object[] { RaspCorpus.Str(c!["name"]) });

    private static JsonObject Case(string section, string name) =>
        (JsonObject)((JsonArray)Corpus[section]!).First(c => RaspCorpus.Str(c!["name"]) == name)!;

    private static string? Text(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private static Dictionary<string, string>? Map(JsonNode? n) =>
        n is JsonObject o ? o.Where(kv => Text(kv.Value) is not null).ToDictionary(kv => kv.Key, kv => Text(kv.Value)!, StringComparer.Ordinal) : null;

    /// <summary>A corpus subject (a name in <c>subjects</c>, or inline) as the language's subject.</summary>
    internal static RuleSubject SubjectOf(JsonNode? s)
    {
        var o = s is JsonValue ? (JsonObject)Corpus["subjects"]![RaspCorpus.Str(s)]! : (JsonObject)s!;
        var subject = new RuleSubject
        {
            App = Text(o["app"]),
            Sink = Text(o["sink"]),
            AttackType = Text(o["attack"]?["type"]),
            AttackRule = Text(o["attack"]?["rule"]),
        };
        if (o["request"] is JsonObject r)
        {
            subject.Request = new RuleRequest
            {
                Method = Text(r["method"]),
                Path = Text(r["path"]),
                Route = Text(r["route"]),
                Ip = Text(r["ip"]),
                Headers = Map(r["headers"]),
                Query = Map(r["query"]),
                Body = Map(r["body"]),
            };
        }

        if (o["inputs"] is JsonArray inputs)
        {
            subject.Inputs = inputs.Select(i => new RuleInput(RaspCorpus.Str(i!["value"]), RaspCorpus.Str(i["key"]), RaspCorpus.Str(i["source"]))).ToList();
        }

        return subject;
    }

    private static CompiledRuleExpr Compiled(string src) =>
        RaspRuleExpr.Compile(src, out var error) ?? throw new InvalidOperationException(src + ": " + error!.Code);

    private static bool Run(string src, RuleSubject subject) => RaspRuleExpr.Evaluate(Compiled(src), subject).Matched;

    [Fact]
    public void Corpus_is_version_1_and_states_the_same_limits_as_the_language()
    {
        Assert.Equal(1, Corpus["version"]!.GetValue<int>());
        var limits = (JsonObject)Corpus["limits"]!;
        var expected = new Dictionary<string, int>
        {
            ["expressionBytes"] = RaspRuleExpr.ExpressionBytes,
            ["depth"] = RaspRuleExpr.MaxDepth,
            ["nodes"] = RaspRuleExpr.MaxNodes,
            ["stringBytes"] = RaspRuleExpr.StringBytes,
            ["listItems"] = RaspRuleExpr.ListItems,
            ["regexes"] = RaspRuleExpr.Regexes,
            ["regexBytes"] = RaspRuleExpr.RegexBytes,
            ["regexAtoms"] = RaspRuleExpr.RegexAtoms,
            ["regexRepeat"] = RaspRuleExpr.RegexRepeat,
            ["matchCodePoints"] = RaspRuleExpr.MatchCodePoints,
        };
        Assert.Equal(expected.OrderBy(kv => kv.Key), limits.Select(kv => new KeyValuePair<string, int>(kv.Key, kv.Value!.GetValue<int>())).OrderBy(kv => kv.Key));
        Assert.True(((JsonArray)Corpus["valid"]!).Count > 60);
        Assert.True(((JsonArray)Corpus["invalid"]!).Count > 60);
    }

    [Theory]
    [MemberData(nameof(ValidNames))]
    public void Valid(string name)
    {
        var c = Case("valid", name);
        var expr = RaspRuleExpr.Compile(RaspCorpus.Str(c["expression"]), out var error);
        Assert.Equal("ok", expr is null ? error!.Code : "ok");
        if (c["phase"] is { } phase)
        {
            Assert.Equal(RaspCorpus.Str(phase), expr!.Phase);
        }

        if (c["usesInput"] is { } usesInput)
        {
            Assert.Equal(usesInput.GetValue<bool>(), expr!.UsesInput);
        }

        if (c["usesBody"] is { } usesBody)
        {
            Assert.Equal(usesBody.GetValue<bool>(), expr!.UsesBody);
        }

        var k = 0;
        foreach (var x in (JsonArray)c["cases"]!)
        {
            var got = RaspRuleExpr.Evaluate(expr!, SubjectOf(x!["subject"])).Matched;
            Assert.True(x["expect"]!.GetValue<bool>() == got, $"case {k}: expected {x["expect"]}, got {got}");
            k++;
        }
    }

    [Theory]
    [MemberData(nameof(InvalidNames))]
    public void Invalid(string name)
    {
        var c = Case("invalid", name);
        var expr = RaspRuleExpr.Compile(Text(c["expression"]), out var error);
        Assert.Equal(RaspCorpus.Str(c["error"]), expr is null ? error!.Code : "ok");
    }

    [Fact]
    public void The_corpus_is_the_generator_output()
    {
        var gen = File.ReadAllText(Path.Combine(RaspCorpus.RaspDir, "scripts", "gen-custom-rules.mjs"));
        Assert.Contains("testdata\", \"custom-rules.json\"", gen, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_anything_but_a_string()
    {
        foreach (var v in new object?[] { null, 1, new object(), Array.Empty<string>() })
        {
            Assert.Null(RaspRuleExpr.Compile(v, out var error));
            Assert.Equal("empty", error!.Code);
        }

        Assert.Equal("empty", Err(" \t\n ﻿"));

        // U+0085 is .NET white space but not JavaScript's: a syntax error, as in the reference.
        Assert.Equal("syntax", Err("\u0085"));
    }

    private static string Err(string src) => RaspRuleExpr.Compile(src, out var error) is null ? error!.Code : "ok";

    [Fact]
    public void Reports_where_a_syntax_error_is()
    {
        Assert.Null(RaspRuleExpr.Compile("request.method == \"GET\" &&& true", out var error));
        Assert.Equal("syntax", error!.Code);
        Assert.True(error.Pos > 20);
    }

    [Fact]
    public void Classifies_the_phase_from_the_fields_read()
    {
        Assert.Equal("request", Compiled("request.path == \"/\"").Phase);
        Assert.Equal("finding", Compiled("attack.type == \"ssrf\"").Phase);
        var e = Compiled("sink.name == \"fs.readFile\" && input.key == \"query.f\"");
        Assert.Equal(("finding", true, false), (e.Phase, e.UsesInput, e.UsesBody));
        Assert.True(Compiled("request.body[\"a\"] == \"b\"").UsesBody);
        Assert.Equal(new[] { "app.name", "request.headers" }, Compiled("request.headers[\"X-A\"] == \"1\" && app.name == \"a\"").Fields);
    }

    [Fact]
    public void Guards_parser_recursion_before_the_AST_is_built()
    {
        Assert.Equal("depth", Err(new string('(', 1000) + "true" + new string(')', 1000)));
        Assert.Equal("depth", Err(new string('!', 2000) + "true"));
    }

    [Fact]
    public void Short_circuits_left_to_right()
    {
        var get = SubjectOf(JsonValue.Create("get"));
        Assert.True(Run("request.method == \"GET\" || request.path.matches(\"x\")", get));
        Assert.False(Run("request.method == \"PUT\" && request.path.matches(\"x\")", get));
    }

    [Fact]
    public void Returns_the_input_that_matched()
    {
        var r = RaspRuleExpr.Evaluate(Compiled("input.key == \"query.sort\""), SubjectOf(JsonValue.Create("get")));
        Assert.True(r.Matched);
        Assert.Equal(("name desc", "query.sort", "request"), (r.Input!.Value, r.Input.Key, r.Input.Source));
    }

    [Fact]
    public void Fails_open_on_a_sparse_subject()
    {
        var e = Compiled("request.headers[\"a\"] == \"b\" && input.value == \"x\"");
        foreach (var s in new[] { new RuleSubject(), new RuleSubject { Request = new RuleRequest() }, new RuleSubject { Inputs = new RuleInput[] { null!, null! } } })
        {
            Assert.False(RaspRuleExpr.Evaluate(e, s).Matched);
        }

        Assert.True(Run("request.headers[\"constructor\"] == null", new RuleSubject { Request = new RuleRequest { Headers = new Dictionary<string, string>() } }));
    }

    [Fact]
    public void Stops_at_the_budget_and_reports_no_match()
    {
        var e = Compiled("input.value.matches(\"a{100}x\")");
        var big = new RuleSubject { App = "a", Inputs = Enumerable.Range(0, 256).Select(i => new RuleInput(new string('a', 4096), "query.k" + i, "request")).ToList() };
        var budget = new RuleBudget(10_000);
        var r = RaspRuleExpr.Evaluate(e, big, budget);
        Assert.Equal((false, true), (r.Matched, r.Exhausted));
        Assert.True(budget.Steps < 0);
    }

    [Fact]
    public void Matches_in_time_linear_in_the_subject()
    {
        var watch = Stopwatch.StartNew();
        Assert.False(Run("app.name.matches(\"^(?:a|a)*b$\")", new RuleSubject { App = new string('a', 4000) }));
        Assert.False(Run("app.name.matches(\".*.*.*.*.*.*x\")", new RuleSubject { App = new string('a', 4096) }));
        Assert.True(watch.ElapsedMilliseconds < 2000);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("^a$")]
    [InlineData("[a-z0-9_]+")]
    [InlineData("(?:x|y){1,3}")]
    [InlineData("\\d{3}-\\d{4}")]
    [InlineData(".*")]
    [InlineData("a|")]
    [InlineData("(?:)")]
    [InlineData("[\\s\\S]")]
    public void Regex_subset_accepts(string pattern) => Assert.True(RaspRuleExpr.IsSafeRegex(pattern));

    [Theory]
    [InlineData("(a+)+")]
    [InlineData("(a*)*")]
    [InlineData("(a|b+)*")]
    [InlineData("a{0,1000}")]
    [InlineData("\\1")]
    [InlineData("(?=x)")]
    [InlineData("(?!x)")]
    [InlineData("(?<=x)")]
    [InlineData("(?P<n>x)")]
    [InlineData("\\Z")]
    [InlineData("\\A")]
    [InlineData("\\cA")]
    [InlineData("a{1,2}{3}")]
    [InlineData("[a-\\d]")]
    [InlineData("x{")]
    [InlineData("\\")]
    public void Regex_subset_refuses(string pattern) => Assert.False(RaspRuleExpr.IsSafeRegex(pattern));

    [Fact]
    public void Parses_addresses_strictly()
    {
        Assert.Equal(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4 }, RaspRuleExpr.ParseIpBytes("1.2.3.4"));
        Assert.Equal(Enumerable.Repeat((byte)0, 15).Concat(new byte[] { 1 }), RaspRuleExpr.ParseIpBytes("::1"));
        Assert.Equal(new byte[] { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 1, 2, 3, 4 }, RaspRuleExpr.ParseIpBytes("1:2:3:4:5:6:1.2.3.4"));
        foreach (var bad in new[] { "1.2.3", "1.2.3.256", "01.2.3.4", ":1", "1:::2", "1:2:3:4:5:6:7:8:9", "12345::", "g::", "1.2.3.4::", "", "١.2.3.4" })
        {
            Assert.Null(RaspRuleExpr.ParseIpBytes(bad));
        }
    }

    [Fact]
    public void Keeps_IPv4_prefixes_in_IPv4_mapped_space()
    {
        Assert.Equal(104, RaspRuleExpr.ParseCidr("10.0.0.0/8")!.Prefix);
        Assert.Equal(0, RaspRuleExpr.ParseCidr("::/0")!.Prefix);
        Assert.Equal(128, RaspRuleExpr.ParseCidr("1.2.3.4")!.Prefix);
    }
}
