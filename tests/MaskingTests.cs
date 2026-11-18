using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Shield360.Internal;
using Xunit;

namespace Shield360.Tests;

/// <summary>
/// The masking contract (sdk/rasp/README.md, "Masking"), held to the shared
/// cases in sdk/rasp/testdata/masking.json like every other SDK.
/// </summary>
public class MaskingTests
{
    private static readonly Lazy<JsonElement> s_cases = new(() =>
        TestJson.Parse(File.ReadAllText(CasesPath())));

    internal static string CasesPath()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            foreach (var candidate in new[]
            {
                Path.Combine(dir.FullName, "sdk", "rasp", "testdata", "masking.json"),
                Path.Combine(dir.FullName, "rasp", "testdata", "masking.json"),
            })
            {
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        throw new FileNotFoundException("rasp/testdata/masking.json not found above " + AppContext.BaseDirectory);
    }

    private static JsonElement Section(string name) => s_cases.Value.GetProperty(name);

    public static IEnumerable<object[]> Cases(string section) =>
        Enumerable.Range(0, Section(section).GetArrayLength()).Select(i => new object[] { i });

    private static JsonElement Case(string section, int i) => Section(section)[i];

    [Theory]
    [MemberData(nameof(Cases), "text")]
    public void Text(int i)
    {
        var c = Case("text", i);
        Assert.Equal(c.GetProperty("out").GetString(), Masking.MaskSecrets(c.GetProperty("in").GetString()!));
    }

    [Theory]
    [MemberData(nameof(Cases), "limited")]
    public void Limited(int i)
    {
        var c = Case("limited", i);
        Assert.Equal(
            c.GetProperty("out").GetString(),
            Masking.MaskText(c.GetProperty("in").GetString()!, c.GetProperty("limit").GetInt32()));
    }

    [Theory]
    [MemberData(nameof(Cases), "keys")]
    public void Keys(int i)
    {
        var c = Case("keys", i);
        Assert.Equal(c.GetProperty("sensitive").GetBoolean(), Masking.IsSensitiveKey(c.GetProperty("key").GetString()!));
    }

    [Theory]
    [MemberData(nameof(Cases), "values")]
    public void Values(int i)
    {
        var c = Case("values", i);
        var masked = Masking.MaskValue(c.GetProperty("key").GetString()!, Decode(c.GetProperty("value")), 4096);
        Assert.Equal(Canonical(Decode(c.GetProperty("out"))), Canonical(masked));
    }

    [Theory]
    [MemberData(nameof(Cases), "snippets")]
    public void Snippets(int i)
    {
        var c = Case("snippets", i);
        Assert.Equal(c.GetProperty("out").GetString(), Masking.MaskSnippet(c.GetProperty("in").GetString()!));
    }

    /// <summary>JSON as plain .NET values: dictionaries, lists, long or double, bool, string, null.</summary>
    internal static object? Decode(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => Decode(p.Value)),
        JsonValueKind.Array => e.EnumerateArray().Select(Decode).ToList(),
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.TryGetInt64(out var l) ? l : e.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null,
    };

    /// <summary>A structural rendering, so values compare whatever collection types hold them.</summary>
    private static string Canonical(object? v) => v switch
    {
        null => "null",
        string s => JsonSerializer.Serialize(s),
        bool b => b ? "true" : "false",
        System.Collections.IDictionary d => "{" + string.Join(",", d.Keys.Cast<object>()
            .Select(k => JsonSerializer.Serialize(k.ToString()) + ":" + Canonical(d[k]))) + "}",
        System.Collections.IEnumerable list => "[" + string.Join(",", list.Cast<object?>().Select(Canonical)) + "]",
        IFormattable f => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
        _ => v.ToString() ?? "null",
    };
}
