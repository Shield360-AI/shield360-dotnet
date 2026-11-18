using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Each structural check, proved with one value built from the structure it tests,
/// beside the safe counterpart that must not fire. No payload lists: every value is
/// assembled from the property under test. Port of the TypeScript detect.test.ts.
/// </summary>
public class RaspDetectTests
{
    private static List<RaspInput> Req(string value, string key = "query.q")
    {
        var output = new List<RaspInput>();
        RaspNormalize.AddInput(output, value, key);
        return output;
    }

    private static List<RaspInput> Model(string text)
    {
        var output = new List<RaspInput>();
        RaspNormalize.AddModelOutput(output, text);
        return output;
    }

    private static string SqlQuote(string v) => "'" + v.Replace("'", "''") + "'";

    private static string ShQuote(string v) => "'" + v.Replace("'", "'\\''") + "'";

    private static string Tmp() => Path.GetTempPath().TrimEnd('/', '\\');

    // ---- lexers -------------------------------------------------------------

    [Fact]
    public void Sql_lexer_keeps_a_qualified_name_and_a_doubled_quote_string_as_one_token()
    {
        var q = $"SELECT {string.Join(".", "db", "tbl")} FROM t WHERE a = {SqlQuote("x'y")}";
        Assert.Equal(new[] { "word", "name", "word", "word", "word", "word", "op", "string" }, RaspLexers.SqlTokens(q).Select(t => t.Kind));
    }

    [Theory]
    [InlineData("?")]
    [InlineData("$1")]
    [InlineData(":name")]
    [InlineData("@name")]
    [InlineData("%s")]
    [InlineData("%(name)s")]
    public void Sql_placeholders_are_single_tokens(string p)
    {
        Assert.Equal(new[] { "word", "op", "placeholder" }, RaspLexers.SqlTokens("a = " + p).Select(t => t.Kind));
    }

    [Fact]
    public void Shell_lexer_keeps_a_quoted_segment_inside_one_word()
    {
        var (tokens, _) = RaspLexers.ShellTokens($"grep {ShQuote("a b|c")} f");
        Assert.Equal(new[] { "word", "word", "word" }, tokens.Select(t => t.Kind));
    }

    [Fact]
    public void Overlap_uses_half_open_ranges()
    {
        var toks = RaspLexers.CodeTokens("ab cd");
        Assert.Single(RaspLexers.Overlapping(toks, 0, 2));
        Assert.Equal(2, RaspLexers.Overlapping(toks, 1, 3).Count);
    }

    [Fact]
    public void Percent_decoding_is_lenient_and_adds_decoded_forms_once_and_twice()
    {
        Assert.Equal("a/b%zz", RaspNormalize.PercentDecode("a%2Fb%zz"));
        Assert.Equal("a+b", RaspNormalize.PercentDecode("a+b"));
        Assert.Equal("\uFFFD", RaspNormalize.PercentDecode("%FF"));
        var once = Uri.EscapeDataString("a/b");
        var twice = Uri.EscapeDataString(once);
        Assert.Equal(new[] { twice, once, "a/b" }, Req(twice).Select(i => i.Value));
    }

    [Fact]
    public void Model_output_splits_into_fenced_blocks_then_lines()
    {
        var fence = new string('`', 3);
        Assert.Equal(
            new[] { "line one\nline two", "intro", "line one", "line two", "outro" },
            RaspNormalize.ModelFragments($"intro\n{fence}\nline one\nline two\n{fence}\noutro"));
    }

    [Fact]
    public void Inputs_are_capped_in_count_and_length()
    {
        var list = new List<RaspInput>();
        RaspNormalize.AddInput(list, new string('a', 5000), "query.a");
        Assert.Equal(RaspNormalize.MaxValue, list[0].Value.Length);
        for (var i = 0; i < 300; i++)
        {
            RaspNormalize.AddInput(list, "v" + i, "query.v");
        }

        Assert.Equal(RaspNormalize.MaxInputs, list.Count);
    }

    [Fact]
    public void Flatten_keys_nested_json_leaves_and_skips_numbers()
    {
        var list = new List<RaspInput>();
        RaspNormalize.Flatten(list, JsonNode.Parse("""{"user":{"name":"O'Brien"},"tags":["a1","b2"],"n":3}"""), "body");
        Assert.Equal(new[] { "body.user.name", "body.tags.0", "body.tags.1" }, list.Select(i => i.Key));
    }

    // ---- sql_injection ------------------------------------------------------

    // A value made of three non-keyword tokens: identifier, operator, identifier.
    private static readonly string s_spanning = string.Join(" ", "col", "=", "col");

    [Fact]
    public void Sqli_userinput_an_input_spanning_several_tokens()
    {
        Assert.Equal("sqli.userinput", RaspDetect.Sql($"SELECT * FROM t WHERE a = {s_spanning}", Req(s_spanning))?.Rule);
    }

    [Fact]
    public void Sql_safe_the_same_input_bound_as_one_string_literal()
    {
        Assert.Null(RaspDetect.Sql($"SELECT * FROM t WHERE a = {SqlQuote(s_spanning)}", Req(s_spanning)));
    }

    [Fact]
    public void Sql_safe_a_sort_parameter_of_anti_detect_keywords_and_one_identifier()
    {
        var sort = string.Join(" ", "name", "desc");
        Assert.Null(RaspDetect.Sql($"SELECT * FROM t ORDER BY {sort}", Req(sort)));
    }

    [Fact]
    public void Sqli_stacked_a_separator_inside_the_input_followed_by_another_token()
    {
        // Keywords only, so the token-structure rule's anti-detect filter lets it pass.
        const string kw = "desc";
        var value = string.Join(";", kw, kw);
        Assert.Equal("sqli.stacked", RaspDetect.Sql($"SELECT * FROM t ORDER BY a {value}", Req(value))?.Rule);
        Assert.Null(RaspDetect.Sql($"SELECT * FROM t ORDER BY a {kw}", Req(kw)));
    }

    [Fact]
    public void Sqli_model_output_a_fragment_spanning_tokens_or_a_whole_write_statement()
    {
        Assert.Equal("sqli.model_output", RaspDetect.Sql($"SELECT * FROM t WHERE {s_spanning}", Model(s_spanning))?.Rule);
        var write = string.Join(" ", "UPDATE", "t", "SET", "a", "=", "1");
        Assert.Equal("sqli.model_output", RaspDetect.Sql(write, Model(write))?.Rule);
    }

    [Fact]
    public void Sql_safe_a_read_only_select_the_model_wrote_whole()
    {
        var read = string.Join(" ", "SELECT", "a", "FROM", "t");
        Assert.Null(RaspDetect.Sql(read, Model(read)));
    }

    [Fact]
    public void Sql_safe_the_whole_query_equal_to_an_input()
    {
        var q = $"SELECT * FROM t WHERE {s_spanning}";
        Assert.Null(RaspDetect.Sql(q, Req(q)));
    }

    // ---- nosql_injection ----------------------------------------------------

    private static readonly string s_op = "$" + "ne";

    [Fact]
    public void Nosqli_operator_an_operator_object_from_the_body_reaches_the_filter()
    {
        var body = new JsonObject { ["user"] = new JsonObject { [s_op] = string.Empty } };
        var filter = new JsonObject { ["user"] = body["user"]!.DeepClone() };
        Assert.Equal("nosqli.operator", RaspDetect.NoSql(filter, new JsonNode?[] { body }, Array.Empty<RaspInput>())?.Rule);
    }

    [Fact]
    public void Nosql_safe_the_server_builds_the_operator_itself()
    {
        var body = new JsonObject { ["user"] = "alice" };
        var filter = new JsonObject { ["user"] = new JsonObject { [s_op] = "alice" } };
        Assert.Null(RaspDetect.NoSql(filter, new JsonNode?[] { body }, Array.Empty<RaspInput>()));
    }

    [Fact]
    public void Nosqli_where_a_tainted_fragment_spanning_code_tokens()
    {
        var value = string.Join(" ", "a", "||", "b");
        var tainted = new JsonObject { ["$where"] = $"this.x == {value}" };
        Assert.Equal("nosqli.where", RaspDetect.NoSql(tainted, new JsonNode?[] { new JsonObject() }, Req(value))?.Rule);
        var quoted = new JsonObject { ["$where"] = $"this.x == {JsonSerializer.Serialize(value)}" };
        Assert.Null(RaspDetect.NoSql(quoted, new JsonNode?[] { new JsonObject() }, Req(value)));
    }

    // ---- command_injection and shell_spawn ----------------------------------

    private static readonly string s_twoCommands = string.Join(";", "a", "b");

    [Fact]
    public void Cmdi_userinput_an_input_spanning_several_shell_tokens()
    {
        Assert.Equal("cmdi.userinput", RaspDetect.Command($"ls {s_twoCommands}", Req(s_twoCommands))?.Rule);
        Assert.Null(RaspDetect.Command($"ls {ShQuote(s_twoCommands)}", Req(s_twoCommands)));
    }

    [Fact]
    public void Cmdi_substitution_a_word_splitting_variable_inside_one_word()
    {
        var v = string.Join("${IFS}", "a", "b");
        Assert.Equal("cmdi.substitution", RaspDetect.Command($"echo {v}", Req(v))?.Rule);
        Assert.Null(RaspDetect.Command("echo a_b", Req("a_b")));
    }

    [Fact]
    public void Cmdi_full_the_command_equals_an_input()
    {
        Assert.Equal("cmdi.full", RaspDetect.Command("uptime", Req("uptime"))?.Rule);
    }

    [Fact]
    public void Cmdi_model_output_a_whole_model_command_with_more_than_one_command()
    {
        var two = string.Join(" && ", "git status", "git log");
        Assert.Equal("cmdi.model_output", RaspDetect.Command(two, Model(two))?.Rule);
        Assert.Null(RaspDetect.Command("git status", Model("git status")));
    }

    [Fact]
    public void Cmdi_executable_argv0_equals_an_input()
    {
        Assert.Equal("cmdi.executable", RaspDetect.Argv(new[] { "report-tool", "-x" }, Req("report-tool"))?.Rule);
        Assert.Null(RaspDetect.Argv(new[] { "convert", "report-tool" }, Req("report-tool")));
    }

    [Fact]
    public void Shell_spawn_during_a_request_unless_allowed_and_download_exec_at_any_time()
    {
        Assert.Equal("shell_spawn.shell", RaspDetect.ShellSpawn("/bin/sh", null, true, Array.Empty<string>())?.Rule);
        Assert.Equal("shell_spawn.shell", RaspDetect.ShellSpawn(@"C:\Windows\System32\cmd.exe", null, true, Array.Empty<string>())?.Rule);
        Assert.Null(RaspDetect.ShellSpawn("/bin/sh", null, true, new[] { "sh" }));
        Assert.Null(RaspDetect.ShellSpawn("/bin/sh", null, false, Array.Empty<string>()));
        var pipe = string.Join(" | ", "curl -s https://example.com/x", "sh");
        Assert.Equal("shell_spawn.download_exec", RaspDetect.ShellSpawn(null, pipe, false, Array.Empty<string>())?.Rule);
    }

    [Fact]
    public void Shell_script_of_reads_sh_c_and_cmd_c()
    {
        Assert.Equal("echo hi", RaspDetect.ShellScriptOf(new[] { "/bin/sh", "-c", "echo hi" }));
        Assert.Equal("dir x", RaspDetect.ShellScriptOf(new[] { "cmd.exe", "/C", "dir", "x" }));
        Assert.Null(RaspDetect.ShellScriptOf(new[] { "git", "-c", "x" }));
    }

    // ---- path_traversal and file_write --------------------------------------

    private const string Root = "/srv/app/uploads";

    [Fact]
    public void Path_traversal_the_input_climbs_out_of_its_directory()
    {
        var climb = string.Join("/", "..", "..", "x.txt");
        Assert.Equal("path.traversal", RaspDetect.FilePath($"{Root}/{climb}", FileOp.Read, Req(climb))?.Rule);
        Assert.Null(RaspDetect.FilePath($"{Root}/x.txt", FileOp.Read, Req("x.txt")));
    }

    [Fact]
    public void Path_absolute_the_input_is_an_absolute_path_the_call_uses()
    {
        var abs = string.Join("/", string.Empty, "srv", "other", "x.txt");
        Assert.Equal("path.absolute", RaspDetect.FilePath(abs, FileOp.Read, Req(abs))?.Rule);
    }

    [Fact]
    public void Path_nullbyte_the_input_carries_a_nul_and_the_path_holds_what_comes_before()
    {
        var v = string.Join("\0.", "x.txt", "png");
        Assert.Equal("path.nullbyte", RaspDetect.FilePath($"{Root}/x.txt", FileOp.Read, Req(v))?.Rule);
    }

    [Fact]
    public void Path_outside_root_a_tainted_path_outside_every_allowed_root()
    {
        Assert.Equal("path.outside_root", RaspDetect.FilePath("/srv/app/other/x.txt", FileOp.Read, Req("x.txt"), new[] { Root })?.Rule);
        Assert.Null(RaspDetect.FilePath($"{Root}/x.txt", FileOp.Read, Req("x.txt"), new[] { Root }));
    }

    [Fact]
    public void Path_sensitive_a_tainted_path_that_resolves_to_a_well_known_secret_file()
    {
        Assert.Equal("path.sensitive", RaspDetect.FilePath("/etc/" + "passwd", FileOp.Read, Req("passwd"))?.Rule);
        Assert.Null(RaspDetect.FilePath("/etc/" + "passwd", FileOp.Read, Req("report.pdf")));
    }

    [Fact]
    public void File_write_script_and_ntfs_streams()
    {
        var name = string.Join(".", "upload", "js");
        Assert.Equal("file_write.script", RaspDetect.FilePath($"{Tmp()}/{name}", FileOp.Write, Req(name))?.Rule);
        Assert.Null(RaspDetect.FilePath($"{Tmp()}/{name}", FileOp.Read, Req(name)));
        Assert.Equal("file_write.ntfs", RaspDetect.FilePath($"{Root}/x.txt" + "::$DATA", FileOp.Write, Array.Empty<RaspInput>())?.Rule);
    }

    [Fact]
    public void Resolve_path_removes_dot_segments_lexically()
    {
        Assert.Equal("/srv/x.txt", RaspDetect.ResolvePath("/srv/app/../x.txt"));
        Assert.Equal("/", RaspDetect.ResolvePath("/../.."));
        Assert.Equal("C:/a/c", RaspDetect.ResolvePath(@"C:\a\b\..\c"));
        Assert.Equal("/w/d/f", RaspDetect.ResolvePath("d/./f", "/w"));
        Assert.Equal("//srv/share/x", RaspDetect.NormPath(@"\\srv\share\.\x"));
    }

    // ---- ssrf and outbound --------------------------------------------------

    private static string Url(string host, string scheme = "http") => $"{scheme}://{host}/";

    [Fact]
    public void Ssrf_internal_a_tainted_host_in_a_private_range_by_literal_or_resolved_address()
    {
        var host = string.Join(".", 10, 0, 0, 5);
        Assert.Equal("ssrf.internal", RaspDetect.Ssrf(Url(host), Req(host))?.Rule);
        Assert.Equal("ssrf.internal", RaspDetect.Ssrf(Url("svc.example.com"), Req("svc.example.com"), new[] { host })?.Rule);
        Assert.Null(RaspDetect.Ssrf(Url(host), Req("report.pdf")));
        var pub = string.Join(".", 93, 184, 216, 34);
        Assert.Null(RaspDetect.Ssrf(Url(pub), Req(pub)));
    }

    [Fact]
    public void Address_classes_decode_ipv4_mapped_ipv6_first()
    {
        Assert.True(RaspDetect.IsPrivateAddress("::ffff:" + string.Join(".", 127, 0, 0, 1)));
        Assert.False(RaspDetect.IsPrivateAddress("::ffff:" + string.Join(".", 93, 184, 216, 34)));
        Assert.True(RaspDetect.IsPrivateAddress("fe80::1"));
        Assert.True(RaspDetect.IsPrivateAddress("[::1]"));
        Assert.True(RaspDetect.IsPrivateAddress("fd12:3456::1"));
        Assert.False(RaspDetect.IsPrivateAddress("2606:4700::1111"));
    }

    [Fact]
    public void Ssrf_metadata_a_tainted_cloud_metadata_host_while_untainted_sdk_calls_pass()
    {
        var host = RaspDetect.MetadataHosts[0];
        Assert.Equal("ssrf.metadata", RaspDetect.Ssrf(Url(host), Req(host))?.Rule);
        Assert.Null(RaspDetect.Ssrf(Url(host), Req("report.pdf")));
    }

    [Fact]
    public void Ssrf_obfuscated_a_loopback_address_written_as_one_decimal_number()
    {
        var dec = ((127u << 24) | 1u).ToString(System.Globalization.CultureInfo.InvariantCulture);
        Assert.Equal("ssrf.obfuscated", RaspDetect.Ssrf(Url(dec), Req(dec))?.Rule);
    }

    [Fact]
    public void Ssrf_protocol_a_tainted_host_under_a_non_http_scheme()
    {
        Assert.Equal("ssrf.protocol", RaspDetect.Ssrf(Url("files.example.com", "gopher"), Req("files.example.com"))?.Rule);
        Assert.Null(RaspDetect.Ssrf(Url("files.example.com", "https"), Req("files.example.com")));
    }

    [Fact]
    public void Ssrf_dnslog_a_tainted_host_under_a_known_out_of_band_domain()
    {
        var host = "probe" + RaspData.DnslogSuffixes[0];
        Assert.Equal("ssrf.dnslog", RaspDetect.Ssrf(Url(host), Req(host))?.Rule);
    }

    [Fact]
    public void Outbound_not_allowed_only_with_a_non_empty_allow_list()
    {
        Assert.Equal("outbound.not_allowed", RaspDetect.Outbound(Url("api.example.com"), new[] { "*.example.org" })?.Rule);
        Assert.Null(RaspDetect.Outbound(Url("api.example.org"), new[] { "*.example.org" }));
        Assert.Null(RaspDetect.Outbound(Url("api.example.com"), Array.Empty<string>()));
        Assert.Null(RaspDetect.Outbound(Url("ingest.example.com"), new[] { "*.example.org" }, new[] { "ingest.example.com" }));
    }

    // ---- deserialization and code_injection ---------------------------------

    [Fact]
    public void Deser_pickle_tainted_data_always_fires_untainted_never()
    {
        var data = "\u0080\u0004\u0095" + "payload-bytes";
        Assert.Equal("deser.pickle", RaspDetect.Deserialization(DeserFormat.Pickle, data, Req(data))?.Rule);
        Assert.Null(RaspDetect.Deserialization(DeserFormat.Pickle, data, Req("report.pdf")));
    }

    [Fact]
    public void Deser_binaryformatter_tainted_through_a_base64_input()
    {
        var data = "\u0000\u0001\u0000\u0000\u0000\u00ff\u00ff\u00ff\u00ff" + "binary-formatter";
        var b64 = Convert.ToBase64String(data.Select(c => (byte)c).ToArray());
        Assert.Equal("deser.binaryformatter", RaspDetect.Deserialization(DeserFormat.BinaryFormatter, data, Req(b64, "body"))?.Rule);
    }

    [Fact]
    public void Deser_typename_tainted_json_that_names_a_type_while_plain_json_passes()
    {
        var typed = JsonSerializer.Serialize(new Dictionary<string, object> { ["$" + "type"] = "Some.Type", ["v"] = 1 });
        Assert.Equal("deser.typename", RaspDetect.Deserialization(DeserFormat.TypeName, typed, Req(typed))?.Rule);
        var plain = JsonSerializer.Serialize(new Dictionary<string, object> { ["name"] = "x", ["v"] = 1 });
        Assert.Null(RaspDetect.Deserialization(DeserFormat.TypeName, plain, Req(plain)));
    }

    [Fact]
    public void Deser_java_tainted_object_stream_always_fires_untainted_never()
    {
        var data = "\u00ac\u00ed\u0000\u0005" + "payload-bytes";
        Assert.Equal("deser.java", RaspDetect.Deserialization(DeserFormat.Java, data, Req(data))?.Rule);
        Assert.Null(RaspDetect.Deserialization(DeserFormat.Java, data, Req("report.pdf")));
    }

    [Fact]
    public void Deser_snakeyaml_tainted_class_tag_fires_while_standard_tags_pass()
    {
        var tagged = "a: !!java.util.ArrayList []";
        Assert.Equal("deser.yaml", RaspDetect.Deserialization(DeserFormat.SnakeYaml, tagged, Req(tagged))?.Rule);
        Assert.Null(RaspDetect.Deserialization(DeserFormat.SnakeYaml, tagged, Req("report.pdf")));
        var standard = "name: !!str 12345";
        Assert.Null(RaspDetect.Deserialization(DeserFormat.SnakeYaml, standard, Req(standard)));
    }

    [Fact]
    public void Code_eval_a_tainted_value_spanning_code_tokens_while_a_string_literal_passes()
    {
        var value = string.Join(" ", "a", "+", "b");
        Assert.Equal("code.eval", RaspDetect.Code($"f({value})", Req(value))?.Rule);
        Assert.Null(RaspDetect.Code($"f({JsonSerializer.Serialize(value)})", Req(value)));
    }

    // ---- xxe ----------------------------------------------------------------

    private static string Doc(string subset) => $"<?xml version=\"1.0\"?><!DOCTYPE r [{subset}]><r>&e;</r>";

    private static string External(string uri) => Doc($"<!ENTITY e SYSTEM \"{uri}\">");

    [Fact]
    public void Xxe_external_entity_when_the_parser_resolves_them_else_doctype()
    {
        var x = External("https://example.com/defs.dtd");
        Assert.Equal("xxe.external_entity", RaspDetect.Xml(x, Req(x, "body"), true)?.Rule);
        Assert.Equal("xxe.doctype", RaspDetect.Xml(x, Req(x, "body"), false)?.Rule);
        Assert.Null(RaspDetect.Xml(x, Req("report.pdf"), true));
    }

    [Fact]
    public void Xxe_file_an_external_entity_naming_an_absolute_file_that_is_not_a_dtd()
    {
        var x = External("file://" + string.Join("/", string.Empty, "srv", "data", "x.txt"));
        Assert.Equal("xxe.file", RaspDetect.Xml(x, Req(x, "body"), true)?.Rule);
    }

    [Fact]
    public void Xxe_protocol_an_external_entity_under_a_non_http_scheme()
    {
        var x = External("ftp://files.example.com/x");
        Assert.Equal("xxe.protocol", RaspDetect.Xml(x, Req(x, "body"), true)?.Rule);
    }

    [Fact]
    public void Xxe_billion_laughs_three_internal_entities_that_expand_other_entities()
    {
        var chain = "<!ENTITY e0 \"x\">" + string.Concat(Enumerable.Range(1, 3).Select(i => $"<!ENTITY e{i} \"&e{i - 1};&e{i - 1};\">"));
        var x = Doc(chain);
        Assert.Equal("xxe.billion_laughs", RaspDetect.Xml(x, Req(x, "body"), true)?.Rule);
        var one = Doc("<!ENTITY e \"Acme\">");
        Assert.Null(RaspDetect.Xml(one, Req(one, "body"), true));
    }

    // ---- xss ----------------------------------------------------------------

    private static readonly string s_markup = $"<b>{new string('x', 16)}</b>";

    [Fact]
    public void Xss_reflected_a_markup_shaped_input_of_15_or_more_characters_reflected_into_html()
    {
        Assert.Equal("xss.reflected", RaspDetect.Xss("text/html", $"<p>{s_markup}</p>", Req(s_markup))?.Rule);
    }

    [Fact]
    public void Xss_safe_when_escaped_or_not_html()
    {
        var escaped = s_markup.Replace("<", "&lt;").Replace(">", "&gt;");
        Assert.Null(RaspDetect.Xss("text/html", $"<p>{escaped}</p>", Req(s_markup)));
        Assert.Null(RaspDetect.Xss("application/json", JsonSerializer.Serialize(new { value = s_markup }), Req(s_markup)));
    }
}
