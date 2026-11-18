using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Shield360.Rasp;

/// <summary>A request, framework-neutral.</summary>
internal sealed class RequestShape
{
    public string Framework { get; init; } = "unknown";

    public string Method { get; init; } = "GET";

    /// <summary>Path and query as received (<c>/a/b?x=1</c>).</summary>
    public string Url { get; init; } = "/";

    /// <summary>Lower-case header names; repeated headers joined with <c>", "</c>.</summary>
    public Dictionary<string, string> Headers { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Route or path parameters.</summary>
    public IEnumerable<KeyValuePair<string, object?>>? Params { get; init; }

    /// <summary>The route template, when known.</summary>
    public string? Route { get; init; }

    /// <summary>The client address as the framework reports it (custom rules' <c>request.ip</c>).</summary>
    public string? Ip { get; init; }
}

/// <summary>
/// What is known about the body: raw text or bytes, or an already parsed <see cref="JsonNode"/>,
/// and the uploaded files' names that a multipart parser read (<see cref="Uploads"/>).
/// </summary>
internal sealed record BodyShape(object? Body, string? ContentType, IReadOnlyList<RaspUpload>? Uploads = null);

/// <summary>An uploaded file's form field and file name, as sent (README "Path", <c>file_write.upload</c>).</summary>
internal sealed record RaspUpload(string Field, string Name);

/// <summary>
/// Request capture shared by the framework middleware: turns a request into the
/// context's inputs (sdk/rasp/README.md, "Sources of untrusted input") and runs
/// the virtual patches. Inputs stay in memory, in the request's context only.
/// Port of the TypeScript <c>capture.ts</c>.
/// </summary>
internal static class RaspCapture
{
    /// <summary>Headers the contract treats as input (OpenRASP's headerInjection).</summary>
    public static readonly string[] InputHeaders = { "user-agent", "referer", "x-forwarded-for" };

    public const string VpSink = "server.request";

    /// <summary>The sink of the <c>file_write.upload</c> check.</summary>
    public const string UploadSink = "request.upload";

    /// <summary>At most this many upload file names are read per request.</summary>
    public const int MaxUploads = 32;

    /// <summary>File names are read from at most this much of a multipart body.</summary>
    public const int MaxUploadScan = 1024 * 1024;
    private const int MaxFormText = 1024 * 1024;

    private static string Header(Dictionary<string, string> h, string name) => h.TryGetValue(name, out var v) ? v : string.Empty;

    public static (string Path, string Query) SplitUrl(string url)
    {
        var q = url.IndexOf('?');
        var hash = url.IndexOf('#');
        var end = hash >= 0 ? hash : url.Length;
        return q >= 0 && q < end ? (url.Substring(0, q), url.Substring(q + 1, end - q - 1)) : (url.Substring(0, end), string.Empty);
    }

    /// <summary>Builds the request's context: query, params, cookies, the input headers.</summary>
    public static RaspContext CaptureRequest(RequestShape shape)
    {
        var (path, query) = SplitUrl(string.IsNullOrEmpty(shape.Url) ? "/" : shape.Url);
        var ctx = new RaspContext(inRequest: true)
        {
            Method = shape.Method,
            Path = path,
            Route = shape.Route,
            Framework = shape.Framework,
            Ip = string.IsNullOrEmpty(shape.Ip) ? null : shape.Ip,
        };
        var cookie = Header(shape.Headers, "cookie");
        ctx.Mutate((inputs, trees) =>
        {
            if (query.Length > 0)
            {
                var tree = new JsonObject();
                foreach (var kv in RaspNormalize.ParseUrlEncoded(query))
                {
                    RaspNormalize.AddInput(inputs, kv.Value, "query." + kv.Key);
                    if (!tree.TryGetPropertyValue(kv.Key, out var prev))
                    {
                        tree[kv.Key] = kv.Value;
                    }
                    else if (prev is JsonArray a)
                    {
                        a.Add(kv.Value);
                    }
                    else
                    {
                        tree[kv.Key] = new JsonArray(JsonValue.Create(prev!.GetValue<string>()), kv.Value);
                    }
                }

                trees.Add(tree);
            }

            if (shape.Params is not null)
            {
                foreach (var kv in shape.Params)
                {
                    RaspNormalize.Flatten(inputs, kv.Value, "params." + kv.Key, 1);
                }
            }

            foreach (var kv in RaspNormalize.ParseCookies(cookie))
            {
                RaspNormalize.AddInput(inputs, kv.Value, "cookie." + kv.Key);
            }

            foreach (var h in InputHeaders)
            {
                var v = Header(shape.Headers, h);
                if (v.Length > 0)
                {
                    RaspNormalize.AddInput(inputs, v, "header." + h);
                }
            }
        });
        ctx.Vp = new VpState(new VpRequest
        {
            Method = shape.Method,
            Path = path,
            Query = query,
            Headers = shape.Headers,
            Cookie = cookie,
            Body = string.Empty,
        });
        return ctx;
    }

    private static bool IsFormType(string ct) => JsText.Has(ct, "application/x-www-form-urlencoded");

    /// <summary>
    /// Adds the body to the context: string leaves of a parsed body (<c>body.a.b</c>),
    /// form fields, or the raw text when it is text, unparsed and at most 8 KiB.
    /// Also gives the virtual patches the body text.
    /// </summary>
    public static void CaptureBody(RaspContext ctx, BodyShape b)
    {
        CaptureBodyText(ctx, b);
        CaptureUploads(ctx, b.Uploads);
    }

    /// <summary>
    /// Records uploaded file names as request input (<c>body.&lt;field&gt;.filename</c>) and
    /// checks each full name (<c>file_write.upload</c>, sink <c>request.upload</c>). Throws the
    /// block exception when blocking.
    /// </summary>
    public static void CaptureUploads(RaspContext ctx, IReadOnlyList<RaspUpload>? uploads)
    {
        if (uploads is null || uploads.Count == 0)
        {
            return;
        }

        var extra = new FindingExtra(ctx.Framework, ctx.ResolvedRoute(), ctx.Method, ctx.Path, ctx);
        for (var i = 0; i < uploads.Count && i < MaxUploads; i++)
        {
            var u = uploads[i];
            if (u is null || string.IsNullOrEmpty(u.Name))
            {
                continue;
            }

            var key = "body." + (string.IsNullOrEmpty(u.Field) ? "file" : u.Field) + ".filename";
            ctx.Mutate((inputs, _) => RaspNormalize.AddInput(inputs, u.Name, key));

            // The full name, not the input entry (which may be cut at 4096 characters).
            RaspEngine.Check(UploadSink, () => RaspDetect.Upload(new RaspInput(u.Name, key)), extra);
        }
    }

    private static void CaptureBodyText(RaspContext ctx, BodyShape b)
    {
        var body = b.Body;
        if (body is null)
        {
            return;
        }

        var ct = JsText.Lower(b.ContentType ?? string.Empty);
        var raw = string.Empty;
        if (body is string or byte[] or ReadOnlyMemory<byte>)
        {
            raw = body switch
            {
                string s => s,
                byte[] bytes => Encoding.UTF8.GetString(bytes),
                ReadOnlyMemory<byte> m => Encoding.UTF8.GetString(m.ToArray()),
                _ => string.Empty,
            };
            JsonNode? parsed = null;
            if (JsText.Has(ct, "json"))
            {
                try
                {
                    parsed = JsonNode.Parse(raw);
                }
                catch (JsonException)
                {
                    parsed = null;
                }
            }
            else if (IsFormType(ct))
            {
                var tree = new JsonObject();
                foreach (var kv in RaspNormalize.ParseUrlEncoded(raw.Length > MaxFormText ? raw.Substring(0, MaxFormText) : raw))
                {
                    tree[kv.Key] = kv.Value;
                }

                parsed = tree;
            }

            var text = raw;
            ctx.Mutate((inputs, trees) =>
            {
                if (parsed is JsonObject or JsonArray)
                {
                    RaspNormalize.Flatten(inputs, parsed, "body");
                    trees.Add(parsed);
                }
                else if (text.Length <= RaspNormalize.MaxRawBody)
                {
                    RaspNormalize.AddInput(inputs, text, "body");
                }
            });
        }
        else if (body is JsonNode node)
        {
            ctx.Mutate((inputs, trees) =>
            {
                RaspNormalize.Flatten(inputs, node, "body");
                trees.Add(node);
            });
            try
            {
                raw = node.ToJsonString();
            }
            catch (InvalidOperationException)
            {
                raw = string.Empty;
            }
        }

        if (ctx.Vp is { } vp)
        {
            vp.Req.Body = raw.Length > RaspVirtualPatches.MaxVpText ? raw.Substring(0, RaspVirtualPatches.MaxVpText) : raw;
            vp.BodyKnown = true;
        }
    }

    /// <summary>
    /// Records that the request has no body (or an empty one): the body is known and empty,
    /// so body-phase rules still run, with no body inputs.
    /// </summary>
    public static void CaptureEmptyBody(RaspContext ctx)
    {
        if (ctx.Vp is { } vp)
        {
            vp.Req.Body = string.Empty;
            vp.BodyKnown = true;
        }
    }

    /// <summary>
    /// Runs the virtual patches the request can be judged by so far: rules that do
    /// not read the body at once, rules that do once the body is known. Each set
    /// runs once. Throws the block exception when a blocking rule matches; any
    /// other failure lets the request through.
    /// </summary>
    public static void RunVirtualPatches(RaspContext ctx)
    {
        var vp = ctx.Vp;
        if (vp is null)
        {
            return;
        }

        var phases = new List<VpPhase>();
        if (!vp.RanHead)
        {
            vp.RanHead = true;
            phases.Add(VpPhase.Head);
        }

        if (vp.BodyKnown && !vp.RanBody)
        {
            vp.RanBody = true;
            phases.Add(VpPhase.Body);
        }

        foreach (var phase in phases)
        {
            RaspFinding? finding;
            try
            {
                finding = RaspVirtualPatches.Match(vp.Req, RaspEngine.VirtualPatches(), phase);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                finding = null;
            }

            // A monitored match is reported and the next phase still runs; a blocked one throws.
            if (finding is not null)
            {
                RaspEngine.HandleFinding(finding, VpSink, new FindingExtra(ctx.Framework, ctx.ResolvedRoute(), ctx.Method, ctx.Path, ctx));
            }

            RunRequestRules(ctx, phase == VpPhase.Head ? RulePhase.Head : RulePhase.Body);
        }
    }

    /// <summary>
    /// Judges the request rules that read <c>request.ip</c> again once the client address is
    /// final (the framework applied forwarded headers, or a deferral ended): rules that waited,
    /// and rules that did not match the earlier address. Throws the block exception when one blocks.
    /// </summary>
    public static void RunIpRules(RaspContext ctx)
    {
        ctx.IpPending = false;
        RunRequestRules(ctx, RulePhase.Ip);
    }

    /// <summary>
    /// Custom request rules (README "Custom rules"): each match is reported in order; the
    /// first that blocks throws the block exception. Any other failure lets the request through.
    /// </summary>
    public static void RunRequestRules(RaspContext ctx, RulePhase phase)
    {
        List<RuleMatch> matches;
        try
        {
            var rules = RaspEngine.CustomRules;
            if (rules.Count == 0 || RaspEngine.ModeFor(RaspAttackType.CustomRule) == RaspMode.Off)
            {
                return;
            }

            matches = RaspCustomRules.MatchRequestRules(rules, ctx, phase, RaspCustomRules.Subject(ctx, RaspEngine.ApplicationName, phase == RulePhase.Head));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return;
        }

        var extra = new FindingExtra(ctx.Framework, ctx.ResolvedRoute(), ctx.Method, ctx.Path, ctx);
        foreach (var m in matches)
        {
            RaspEngine.HandleFinding(RaspCustomRules.Finding(m.Rule, RaspCustomRules.InputOf(m.Input)), VpSink, extra);
        }
    }

    /// <summary>Sets up late body capture: when a sink first reads the inputs, a body that appeared since is captured and judged.</summary>
    public static void CaptureLater(RaspContext ctx, Func<BodyShape?> read)
    {
        if (ctx.Vp?.BodyKnown == true)
        {
            return;
        }

        ctx.Late = () =>
        {
            try
            {
                var b = read();
                if (b?.Body is null)
                {
                    return false;
                }

                CaptureBody(ctx, b);
            }
            catch (Shield360RaspBlockedException)
            {
                throw;
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return true;
            }

            RunVirtualPatches(ctx);
            return true;
        };
    }
}
