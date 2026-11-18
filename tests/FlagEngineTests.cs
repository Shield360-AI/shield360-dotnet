using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using Shield360.Flags;
using Xunit;

namespace Shield360.Tests;

/// <summary>Holds the .NET engine to sdk/flags-core/testdata/vectors.json, like every other implementation.</summary>
public class FlagEngineTests
{
    private static readonly Lazy<JsonObject> s_vectors = new(() =>
        (JsonObject)JsonNode.Parse(File.ReadAllText(VectorsPath()))!);

    /// <summary>
    /// Walks up from the test binaries to the vectors: <c>sdk/flags-core</c> in
    /// the monorepo, <c>flags-core</c> at the root of the public mirror.
    /// </summary>
    internal static string VectorsPath()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            foreach (var candidate in new[]
            {
                Path.Combine(dir.FullName, "sdk", "flags-core", "testdata", "vectors.json"),
                Path.Combine(dir.FullName, "flags-core", "testdata", "vectors.json"),
            })
            {
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        throw new FileNotFoundException("flags-core/testdata/vectors.json not found above " + AppContext.BaseDirectory);
    }

    private static JsonArray Section(string name) => (JsonArray)s_vectors.Value[name]!;

    public static IEnumerable<object[]> Cases(string section) =>
        Enumerable.Range(0, Section(section).Count).Select(i => new object[] { i });

    public static IEnumerable<object[]> Murmur3Cases() => Cases("murmur3");

    public static IEnumerable<object[]> TextCases() => Cases("text");

    public static IEnumerable<object[]> EvaluationCases() => Cases("evaluations");

    public static IEnumerable<object[]> ValidationCases() => Cases("validation");

    public static IEnumerable<object[]> SegmentValidationCases() => Cases("segmentValidation");

    [Fact]
    public void Every_section_has_vectors()
    {
        foreach (var name in new[] { "murmur3", "text", "evaluations", "validation", "segmentValidation" })
        {
            Assert.NotEmpty(Section(name));
        }
    }

    [Theory]
    [MemberData(nameof(Murmur3Cases))]
    public void Murmur3_vector(int index)
    {
        var v = (JsonObject)Section("murmur3")[index]!;
        Assert.Equal(v["murmur3"]!.GetValue<double>(), FlagEngine.Murmur3(v["input"]!.GetValue<string>()));
    }

    [Theory]
    [MemberData(nameof(TextCases))]
    public void Text_vector(int index)
    {
        var v = (JsonObject)Section("text")[index]!;
        var expected = v["text"] is null ? null : v["text"]!.GetValue<string>();
        Assert.Equal(expected, FlagEngine.TextOf(v["value"]));
    }

    [Theory]
    [MemberData(nameof(EvaluationCases))]
    public void Evaluation_vector(int index)
    {
        var v = (JsonObject)Section("evaluations")[index]!;
        var result = FlagEngine.Evaluate(v["flag"], v["context"], v["segments"]);
        AssertJson.Equal(v["expect"], result.ToJson(), (string)v["name"]!);
    }

    [Theory]
    [MemberData(nameof(ValidationCases))]
    public void Validation_vector(int index)
    {
        var v = (JsonObject)Section("validation")[index]!;
        AssertJson.Equal(v["errors"], Errors(FlagEngine.ValidateFlag(v["flag"])), (string)v["name"]!);
    }

    [Theory]
    [MemberData(nameof(SegmentValidationCases))]
    public void Segment_validation_vector(int index)
    {
        var v = (JsonObject)Section("segmentValidation")[index]!;
        AssertJson.Equal(v["errors"], Errors(FlagEngine.ValidateSegment(v["segment"])), (string)v["name"]!);
    }

    private static JsonArray Errors(IReadOnlyList<FlagValidationError> errors) =>
        new(errors.Select(e => (JsonNode?)new JsonObject { ["path"] = e.Path, ["code"] = e.Code }).ToArray());

    // ------------------------------------------------------------ beyond the vectors

    private static JsonNode Rollout(int onWeight) => JsonNode.Parse(
        """
        {"key":"split","type":"boolean","salt":"s1","on":true,"offVariation":"off","rules":[],
         "variations":[{"key":"on","value":true},{"key":"off","value":false}],
         "fallthrough":{"rollout":{"weights":[{"variation":"on","weight":ON},{"variation":"off","weight":OFF}]}}}
        """.Replace("ON", onWeight.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal)
           .Replace("OFF", (100000 - onWeight).ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal))!;

    [Fact]
    public void A_rollout_splits_users_close_to_its_weights()
    {
        var flag = Rollout(25000);
        var on = 0;
        const int users = 20000;
        for (var i = 0; i < users; i++)
        {
            var r = FlagEngine.Evaluate(flag, new JsonObject { ["key"] = "user-" + i });
            if (r.Variation == "on")
            {
                on++;
            }

            Assert.True(r.Reason.InRollout);
            Assert.InRange(r.Reason.Bucket!.Value, 0, FlagEngine.Buckets - 1);
        }

        Assert.InRange(on / (double)users, 0.235, 0.265);
    }

    [Fact]
    public void A_user_keeps_their_variation_as_the_rollout_grows()
    {
        for (var i = 0; i < 2000; i++)
        {
            var ctx = new JsonObject { ["key"] = "user-" + i };
            var small = FlagEngine.Evaluate(Rollout(10000), ctx);
            var large = FlagEngine.Evaluate(Rollout(50000), ctx);
            Assert.Equal(small.Reason.Bucket, large.Reason.Bucket);
            if (small.Variation == "on")
            {
                Assert.Equal("on", large.Variation);
            }
        }
    }

    [Theory]
    [InlineData(1e21, "1e+21")]
    [InlineData(1e20, "100000000000000000000")]
    [InlineData(1e-7, "1e-7")]
    [InlineData(0.000015, "0.000015")]
    [InlineData(-0.0, "0")]
    [InlineData(-1.5e-10, "-1.5e-10")]
    [InlineData(123e300, "1.23e+302")]
    [InlineData(5e-324, "5e-324")]
    [InlineData(0.1 + 0.2, "0.30000000000000004")]
    [InlineData(-42.0, "-42")]
    public void Numbers_print_as_JavaScript_prints_them(double value, string text) =>
        Assert.Equal(text, FlagEngine.JsNumber(value));

    [Fact]
    public void Lone_surrogates_hash_as_U_FFFD()
    {
        Assert.Equal(new byte[] { 0xef, 0xbf, 0xbd }, FlagEngine.Utf8("\ud800"));
        Assert.Equal(FlagEngine.Murmur3("a�b"), FlagEngine.Murmur3("a\udc00b"));
        Assert.Equal(new byte[] { 0xf0, 0x9f, 0x98, 0x80 }, FlagEngine.Utf8("😀"));
    }

    [Fact]
    public void Evaluate_never_throws_on_garbage()
    {
        foreach (var raw in new[] { "null", "1", "\"x\"", "[]", "{}", """{"key":"a","rules":[1,2]}""" })
        {
            var r = FlagEngine.Evaluate(JsonNode.Parse(raw), JsonNode.Parse(raw), JsonNode.Parse(raw));
            Assert.Null(r.Variation);
            Assert.Equal(FlagReasonKinds.Error, r.Reason.Kind);
            Assert.Equal(FlagReasonKinds.MalformedFlag, r.Reason.ErrorKind);
        }
    }

    [Fact]
    public void A_dictionary_context_reads_like_JSON()
    {
        var flag = JsonNode.Parse("""
            {"key":"f","type":"string","salt":"s","on":true,"offVariation":"a","fallthrough":{"variation":"a"},
             "variations":[{"key":"a","value":"A"},{"key":"b","value":"B"}],
             "rules":[{"id":"r","conditions":[{"attribute":"age","operator":"gte","values":[18]},
                                               {"attribute":"groups","operator":"in","values":["beta"]}],
                       "serve":{"variation":"b"}}]}
            """);
        var ctx = FlagEngine.ContextOf(new Dictionary<string, object?> { ["age"] = 21, ["groups"] = new[] { "staff", "beta" } });
        Assert.Equal("b", FlagEngine.Evaluate(flag, ctx).Variation);
        var under = FlagEngine.ContextOf(new Dictionary<string, object?> { ["age"] = 17L, ["groups"] = new List<string> { "beta" } });
        Assert.Equal("a", FlagEngine.Evaluate(flag, under).Variation);
        var nan = FlagEngine.ContextOf(new Dictionary<string, object?> { ["age"] = double.NaN, ["groups"] = "beta" });
        Assert.Equal("a", FlagEngine.Evaluate(flag, nan).Variation);
    }

    [Fact]
    public void A_trailing_newline_does_not_pass_a_pattern()
    {
        var errors = FlagEngine.ValidateSegment(JsonNode.Parse("""{"key":"beta\n","conditions":[{"attribute":"a","operator":"in","values":["x"]}]}"""));
        Assert.Contains(errors, e => e.Path == "key" && e.Code == "key_invalid");
    }
}

/// <summary>Structural JSON equality: object member order is ignored, numbers compare by value.</summary>
internal static class AssertJson
{
    public static void Equal(JsonNode? expected, JsonNode? actual, string name)
    {
        if (!DeepEqual(expected, actual))
        {
            Assert.Fail($"{name}\n expected: {expected?.ToJsonString() ?? "null"}\n   actual: {actual?.ToJsonString() ?? "null"}");
        }
    }

    public static bool DeepEqual(JsonNode? a, JsonNode? b)
    {
        if (a is null || b is null)
        {
            return a is null && b is null;
        }

        switch (a)
        {
            case JsonObject oa when b is JsonObject ob:
                return oa.Count == ob.Count && oa.All(kv => ob.TryGetPropertyValue(kv.Key, out var v) && DeepEqual(kv.Value, v));
            case JsonArray aa when b is JsonArray ab:
                return aa.Count == ab.Count && aa.Zip(ab, DeepEqual).All(x => x);
            case JsonValue va when b is JsonValue vb:
                var ka = va.GetValueKind();
                if (ka != vb.GetValueKind())
                {
                    return false;
                }

                return ka switch
                {
                    System.Text.Json.JsonValueKind.Number => Number(va) == Number(vb),
                    System.Text.Json.JsonValueKind.String => va.GetValue<string>() == vb.GetValue<string>(),
                    _ => true,
                };
            default:
                return false;
        }
    }

    private static double Number(JsonValue v) =>
        double.Parse(v.ToJsonString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture);
}
