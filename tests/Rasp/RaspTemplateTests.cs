using System;
using System.Linq;
using System.Text.Json.Nodes;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Template source (<c>code.template_injection</c>): the embedded engine table, the
/// detector's structural checks (port of template-hook.test.ts) and the explicit
/// <see cref="Shield360Rasp.CheckTemplate"/> helper.
/// </summary>
public class RaspTemplateTests : RaspStateTest
{
    private static RaspInput[] Input(string value) => new[] { new RaspInput(value, "query.q") };

    private static string? Hit(string source, string value, string engine) => RaspTemplate.Detect(source, Input(value), engine)?.Rule;

    private static ListSink Mode(RaspMode mode) =>
        Configure(new EngineSettings(true, "template", RaspMode.Block, Attacks: new System.Collections.Generic.Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.CodeInjection] = mode }));

    private static void InRequest(string value, Action fn) =>
        RaspScope.Run(new RaspContext(Input(value), inRequest: true), () =>
        {
            fn();
            return 0;
        });

    private static JsonNode Syntax(TemplateSyntax s)
    {
        static string Mode(TemplateCloseMode m) => m.ToString().ToLowerInvariant();
        static JsonArray Strings(string[] xs) => new(xs.Select(x => (JsonNode)JsonValue.Create(x)!).ToArray());
        static JsonArray Pairs((string, string)[] xs) => new(xs.Select(x => (JsonNode)new JsonArray(x.Item1, x.Item2)).ToArray());
        return new JsonObject
        {
            ["pairs"] = new JsonArray(s.Pairs.Select(p => (JsonNode)new JsonArray(p.Open, p.Close, Mode(p.Mode))).ToArray()),
            ["literal"] = Pairs(s.Literal.Select(p => (p.Open, p.Close)).ToArray()),
            ["tags"] = Pairs(s.Tags.Select(p => (p.Prefix, p.Close)).ToArray()),
            ["directives"] = Strings(s.Directives),
            ["lineComment"] = Strings(s.LineComment),
            ["lineCode"] = Strings(s.LineCode),
            ["attrs"] = Strings(s.Attrs),
            ["escape"] = s.Escape,
            ["spaceLiteral"] = s.SpaceLiteral,
            ["pug"] = s.Pug,
        };
    }

    [Fact]
    public void Embedded_engine_table_equals_the_contract_file()
    {
        var file = (JsonObject)RaspCorpus.Load("rules/template-engines.json")["engines"]!;
        Assert.Equal(file.Select(kv => kv.Key), RaspTemplate.Engines.Select(e => e.Name));
        foreach (var (name, syntax) in RaspTemplate.Engines)
        {
            var want = file[name]!;
            var got = Syntax(syntax);
            Assert.Equal(((JsonObject)want).Select(kv => kv.Key), ((JsonObject)got).Select(kv => kv.Key));
            Assert.True(JsonNode.DeepEquals(want, got), $"{name}: {got.ToJsonString()} != {want.ToJsonString()}");
        }
    }

    [Fact]
    public void Structure_overlap_minimum_length_and_single_expression_tokens()
    {
        Assert.Equal("code.template_injection", Hit("Hello {{ 7 * 7 }}", "{{ 7 * 7 }}", "handlebars"));
        Assert.Equal("code.template_injection", Hit("<%= 7 * 7 %>", "7 * 7", "ejs"));
        Assert.Equal("code.template_injection", Hit("p\n  - 7 + 7", "- 7 + 7", "pug"));
        Assert.Null(Hit("Hello {{name}}", "name", "handlebars"));
        Assert.Null(Hit("<%= \"ordinary prose\" %>", "ordinary prose", "ejs"));
        Assert.Null(Hit("Hello 7 + 7", "7 + 7", "ejs"));
        Assert.Null(Hit("{{name}}", "absent", "ejs"));
        Assert.Null(Hit("{{x}}", "x", "ejs"));
    }

    [Fact]
    public void Pug_attribute_values_are_expression_regions()
    {
        Assert.Equal("code.template_injection", Hit("a(href=url + \"x\") Link", "url + \"x\"", "pug"));
        Assert.Equal("code.template_injection", Hit("a(class=\"c\" href=url)= label + 1", "label + 1", "pug"));
        Assert.Null(Hit("a(href=url) Link", "url", "pug"));
        Assert.Null(Hit("a(title=\"O'Brien here\") Link", "O'Brien here", "pug"));
        Assert.Null(Hit("p Hello (see the notes) today", "see the notes", "pug"));
    }

    [Fact]
    public void A_dotted_path_in_a_fixed_template_is_one_reference()
    {
        Assert.Null(Hit("Hello {{user.name}}", "user.name", "handlebars"));
        Assert.Null(Hit("Hello <%= user.name %>", "user.name", "ejs"));
        Assert.Equal("code.template_injection", Hit("Hello {{ user.name }}", "user.name }}", "nunjucks"));
    }

    [Fact]
    public void Quoted_closing_delimiters_stay_inside_their_token_where_the_engine_lexes_strings()
    {
        Assert.Null(Hit("{{shout \"a }} b\"}} done", "a }} b", "handlebars"));
        Assert.Null(Hit("{{ \"a }} b\" | upper }} done", "a }} b", "nunjucks"));
        Assert.Null(Hit("p #{\"a } b\"} done", "a } b", "pug"));
    }

    [Fact]
    public void Escaped_handlebars_mustaches_and_nunjucks_comments_are_literal_text()
    {
        Assert.Null(Hit("Show \\{{name}} literally", "{{name}}", "handlebars"));
        Assert.Equal("code.template_injection", Hit("Show \\\\{{name}} live", "{{name}}", "handlebars"));
        Assert.Null(Hit("Hi {# note {{ a + b }} #}", "{{ a + b }}", "nunjucks"));
    }

    [Fact]
    public void Shared_engine_table_tags_directives_line_code_attributes_and_pairs_are_regions()
    {
        const string rule = "code.template_injection";
        Assert.Equal(rule, Hit("<#if x>${a}</#if>", "x>${a}", "freemarker"));
        Assert.Equal(rule, Hit("<#assign x = 7 * 7>", "7 * 7", "freemarker"));
        Assert.Equal(rule, Hit("#set($x = 7 * 7)", "7 * 7", "velocity"));
        Assert.Equal(rule, Hit("Hi\n% if a + b:\nx", "a + b", "mako"));
        Assert.Equal(rule, Hit("<%def name=\"x()\">y</%def>", "name=\"x()\"", "mako"));
        Assert.Equal(rule, Hit("<p th:text=\"a + b\">x</p>", "a + b", "thymeleaf"));
        Assert.Equal(rule, Hit("@if($a + $b) y @endif", "$a + $b", "blade"));
        Assert.Equal(rule, Hit("{{ printf \"%d\" 7 }}", "printf \"%d\"", "gotemplate"));
        Assert.Equal(rule, Hit("Hi {$a + $b}", "$a + $b", "smarty"));
        Assert.Equal(rule, Hit("{% raw %}x{% endraw %}{{ a }}", "{% endraw %}{{ a }}", "jinja2"));
        Assert.Null(Hit("{{ a }}", "{{ a }}", "unknown"));
    }

    [Fact]
    public void Review_fixes_literal_whitespace_control_floor_division_spaced_attributes_and_thymeleaf_text()
    {
        const string rule = "code.template_injection";
        Assert.Equal(rule, Hit("{% raw %}x{%endraw%}{{ 7 * 7 }}", "{{ 7 * 7 }}", "jinja2"));
        Assert.Equal(rule, Hit("{% raw %}x{%- endraw -%}{{ 7 * 7 }}", "{{ 7 * 7 }}", "nunjucks"));
        Assert.Null(Hit("{%- raw -%}{{ a + b }}{% endraw %}", "{{ a + b }}", "jinja2"));
        Assert.Equal(rule, Hit("{{ 10 // a + b }}", "a + b", "jinja2"));
        Assert.Equal(rule, Hit("<p th:text = \"a + b\">x</p>", "a + b", "thymeleaf"));
        Assert.Null(Hit("<p>${a + b}</p>", "${a + b}", "thymeleaf"));
    }

    [Fact]
    public void The_dotnet_engines_flag_source_and_pass_data_shaped_input()
    {
        Assert.Equal("code.template_injection", Hit("Hello {{ 7 * 7 }}", "{{ 7 * 7 }}", "scriban"));
        Assert.Equal("code.template_injection", Hit("Hi {% if a %}x{% endif %}", "{% if a %}", "liquid"));
        Assert.Equal("code.template_injection", Hit("Hi {{name}}", "{{name}}", "handlebars"));
        Assert.Null(Hit("Hello {{ name }}", "name", "scriban"));
        Assert.Null(Hit("{%{ {{ 7 * 7 }} }%}", "{{ 7 * 7 }}", "scriban"));
        Assert.Null(Hit("{% raw %}{{ a + b }}{% endraw %}", "{{ a + b }}", "liquid"));
    }

    [Fact]
    public void Helper_blocks_in_block_mode_before_the_engine_call()
    {
        var sink = Mode(RaspMode.Block);
        var ran = false;
        Assert.Throws<Shield360RaspBlockedException>(() => InRequest("{{ 7 * 7 }}", () =>
        {
            Shield360Rasp.CheckTemplate("scriban", "Hello {{ 7 * 7 }}");
            ran = true;
        }));
        Assert.False(ran);
        var e = Assert.Single(sink.Events);
        Assert.Equal("code.template_injection", e.Attrs["shield360.rasp.rule"]);
        Assert.Equal("code_injection", e.Attrs["shield360.rasp.attack"]);
    }

    [Fact]
    public void Helper_reports_once_in_monitor_mode_and_names_the_sink()
    {
        var sink = Mode(RaspMode.Monitor);
        InRequest("{{name}}", () => Shield360Rasp.CheckTemplate("handlebars", "Hi {{name}}"));
        InRequest("{% if a %}", () => Shield360Rasp.CheckTemplate("liquid", "Hi {% if a %}x{% endif %}", "fluid.TryParse"));
        Assert.Equal(2, sink.Events.Count);
        Assert.Equal("handlebars.Compile", sink.Events[0].Attrs["shield360.rasp.sink"]);
        Assert.Equal("fluid.TryParse", sink.Events[1].Attrs["shield360.rasp.sink"]);
        Assert.Equal("scriban.Parse", RaspCodeSinks.TemplateSinkOf("scriban"));
    }

    [Fact]
    public void Helper_skips_the_detector_when_off_unknown_or_without_input_and_fails_open()
    {
        var probed = 0;
        RaspHooks.DetectorProbe = _ => probed++;
        try
        {
            var sink = Mode(RaspMode.Off);
            InRequest("{{name}}", () => Shield360Rasp.CheckTemplate("scriban", "Hi {{name}}"));
            Assert.Empty(sink.Events);
            sink = Mode(RaspMode.Block);
            InRequest("{{name}}", () => Shield360Rasp.CheckTemplate("razor", "Hi {{name}}"));
            InRequest("{{name}}", () => Shield360Rasp.CheckTemplate("scriban", null));
            Shield360Rasp.CheckTemplate("scriban", "Hi {{name}}");
            Assert.Equal(0, probed);

            // Data-shaped input with a fixed template passes.
            InRequest("{{ 7 * 7 }}", () => Shield360Rasp.CheckTemplate("scriban", "Hello {{ name }}"));
            Assert.Equal(1, probed);

            RaspHooks.DetectorProbe = _ => throw new InvalidOperationException("detector unavailable");
            InRequest("{{name}}", () => Shield360Rasp.CheckTemplate("scriban", "Hi {{name}}"));
            Assert.Empty(sink.Events);
        }
        finally
        {
            RaspHooks.DetectorProbe = null;
        }
    }
}
