using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using Shield360.Rasp;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Shared-corpus runner (sdk/rasp/testdata, contract "Fixtures"): runs one case
/// of a section through the detectors and returns what fired, if anything.
/// Request inputs go through the normalizer (percent-decoded forms added);
/// model_output inputs through the model-output fragmenter.
/// </summary>
internal static class RaspCorpus
{
    public static readonly string[] Sections = { "sql", "nosql", "command", "path", "ssrf", "code", "xml", "deser", "xss", "requests", "template" };

    private static readonly Lazy<string> s_dir = new(FindRaspDir);

    /// <summary>
    /// Walks up from the test binaries to the contract's directory: <c>sdk/rasp</c> in the
    /// monorepo, <c>rasp</c> at the root of the public mirror.
    /// </summary>
    public static string RaspDir => s_dir.Value;

    private static string FindRaspDir()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            foreach (var candidate in new[] { Path.Combine(dir.FullName, "sdk", "rasp"), Path.Combine(dir.FullName, "rasp") })
            {
                if (File.Exists(Path.Combine(candidate, "testdata", "benign.json")))
                {
                    return candidate;
                }
            }
        }

        throw new FileNotFoundException("rasp/testdata/benign.json not found above " + AppContext.BaseDirectory);
    }

    public static JsonObject Load(string relative) => (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(RaspDir, relative)))!;

    public static string Str(JsonNode? n) => n?.GetValue<string>() ?? string.Empty;

    public static List<string> Strings(JsonNode? n) => n is JsonArray a ? a.Select(Str).ToList() : new List<string>();

    public static List<RaspInput> Normalize(JsonNode? raw)
    {
        var output = new List<RaspInput>();
        if (raw is not JsonArray list)
        {
            return output;
        }

        foreach (var i in list)
        {
            var value = Str(i!["value"]);
            var key = Str(i["key"]);
            if (Str(i["source"]) == "model_output")
            {
                RaspNormalize.AddModelOutput(output, value, key);
            }
            else
            {
                RaspNormalize.AddInput(output, value, key);
            }
        }

        return output;
    }

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

    /// <summary>The runtimes the request cases run under: .NET, and Node at the start of each Node version range (so every built-in rule is exercised).</summary>
    public static List<(string Runtime, string Version)> Runtimes()
    {
        var output = new List<(string, string)> { (RaspVirtualPatches.Runtime, RaspVirtualPatches.RuntimeVersion), ("node", "1.0.0") };
        foreach (var r in RaspVirtualPatches.BuiltIn)
        {
            if (r.RuntimeVersions is not null && r.RuntimeVersions.TryGetValue("node", out var ranges) && ranges is not null)
            {
                output.AddRange(ranges.Select(x => ("node", x.From)));
            }
        }

        return output.Distinct().ToList();
    }

    /// <summary>Runs one case; returns the first finding (null when nothing fired).</summary>
    public static RaspFinding? RunCase(string section, JsonObject c)
    {
        var inputs = Normalize(c["inputs"]);
        switch (section)
        {
            case "sql":
                return RaspDetect.Sql(Str(c["query"]), inputs, RaspLexers.Dialect(c["dialect"]?.GetValue<string>()));
            case "nosql":
            {
                var ins = new List<RaspInput>();
                RaspNormalize.Flatten(ins, c["body"], "body");
                RaspNormalize.Flatten(ins, c["query"], "query");
                var trees = new List<JsonNode?> { c["body"], c["query"] };
                return RaspDetect.NoSql(c["filter"], trees, ins) ?? (c["update"] is { } update ? RaspDetect.NoSql(update, trees, ins) : null);
            }

            case "command":
            {
                if (c["command"] is JsonValue)
                {
                    var command = Str(c["command"]);
                    return RaspDetect.Command(command, inputs) ?? RaspDetect.ShellSpawn(null, command, true, Array.Empty<string>());
                }

                var argv = Strings(c["argv"]);
                var script = RaspDetect.ShellScriptOf(argv);
                return RaspDetect.Argv(argv, inputs)
                    ?? (script is null ? null : RaspDetect.Command(script, inputs))
                    ?? RaspDetect.ShellSpawn(argv.FirstOrDefault(), null, true, Array.Empty<string>());
            }

            case "path":
                return RaspDetect.FilePath(Str(c["path"]), Op(Str(c["op"])), inputs, Strings(c["fileRoots"]));
            case "ssrf":
                return RaspDetect.Ssrf(Str(c["url"]), inputs, Strings(c["resolved"]));
            case "code":
                return RaspDetect.Code(Str(c["code"]), inputs);
            case "xml":
                return RaspDetect.Xml(Str(c["xml"]), inputs, c["resolvesExternal"]?.GetValue<bool>() == true);
            case "deser":
            {
                var data = c["dataEncoding"]?.GetValue<string>() == "base64"
                    ? RaspDetect.Latin1(Convert.FromBase64String(Str(c["data"])))
                    : Str(c["data"]);
                return RaspDetect.Deserialization(RaspDetect.Format(Str(c["format"]))!.Value, data, inputs);
            }

            case "template":
                return RaspTemplate.Detect(Str(c["template"]), inputs, Str(c["engine"]));
            case "xss":
                return RaspDetect.Xss(c["contentType"]?.GetValue<string>(), Str(c["body"]), inputs);
            case "requests":
            {
                var req = new VpRequest
                {
                    Method = Str(c["method"]),
                    Path = Str(c["path"]),
                    Query = Str(c["query"]),
                    Cookie = Str(c["cookie"]),
                    Body = Str(c["body"]),
                };
                if (c["headers"] is JsonObject headers)
                {
                    foreach (var kv in headers)
                    {
                        req.Headers[kv.Key.ToLowerInvariant()] = Str(kv.Value);
                    }
                }

                foreach (var (runtime, version) in Runtimes())
                {
                    if (RaspVirtualPatches.Match(req, RaspVirtualPatches.BuiltIn, VpPhase.All, runtime, version) is { } f)
                    {
                        return f;
                    }
                }

                return null;
            }

            default:
                throw new ArgumentException("unknown section " + section);
        }
    }

    /// <summary>A request that satisfies a rule's clauses, built from the rule itself.</summary>
    public static VpRequest RequestFor(VirtualPatch rule)
    {
        var req = new VpRequest();
        foreach (var c in rule.Match)
        {
            var value = c.Values.Count > 0 ? c.Values[0] : c.Value ?? "x";
            if (c.Target == "method")
            {
                req.Method = value;
            }
            else if (c.Target.StartsWith("header:", StringComparison.Ordinal))
            {
                req.Headers[c.Target.Substring(7)] = c.Op == "present" ? "x" : value;
            }
            else if (c.Target is "body" or "request")
            {
                req.Body += value;
            }
            else if (c.Target == "query")
            {
                req.Query += value;
            }
            else if (c.Target == "cookie")
            {
                req.Cookie += value;
            }
            else if (c.Target == "path")
            {
                req.Path = value;
            }
        }

        return req;
    }
}
