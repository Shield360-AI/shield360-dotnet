using System;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Shield360.Rasp;

/// <summary>
/// SHIELD: request correlation — Shield360 Edge's request id and the trace id on everything the
/// app records while it serves that request, so Shield360 joins the app's log records and spans
/// to Edge's record of the request, even when the app does not trace. Port of
/// sdk/typescript/src/otel/edge-request.ts; passes sdk/rasp/testdata/request-correlation.json.
/// <para>
/// Edge's id is taken from its signed context header when RASP verified one (<see cref="EdgeContext"/>),
/// else from the request's <c>X-Request-Id</c> (Edge always sends its own there). It goes on the
/// server span (<c>shield360.edge.request_id</c>; the ASP.NET Core instrumentation's enrich hook
/// and the RASP capture) and on every log record written during the request (the Shield360 log
/// processor), with the trace id as <c>shield360.edge.trace_id</c> when no span is active. Only an
/// id-shaped value is used: letters, digits, <c>.</c>, <c>_</c> and <c>-</c>, 8 to 128 characters.
/// </para>
/// </summary>
internal static class EdgeRequest
{
    public const string RequestIdAttr = "shield360.edge.request_id";
    public const string TraceIdAttr = "shield360.edge.trace_id";
    public const string RequestIdHeader = "x-request-id";

    private static readonly TimeSpan s_rx = TimeSpan.FromMilliseconds(100);
    private static readonly Regex s_requestId = new("^[A-Za-z0-9._-]{8,128}\\z", RegexOptions.CultureInvariant, s_rx);
    private static readonly Regex s_traceparent = new("^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}\\z", RegexOptions.CultureInvariant, s_rx);

    /// <summary>An id-shaped request id, or null.</summary>
    public static string? RequestIdOf(string? value) => value is not null && s_requestId.IsMatch(value) ? value : null;

    /// <summary>The trace id in a W3C traceparent, or null.</summary>
    public static string? TraceIdOf(string? traceparent)
    {
        if (traceparent is null)
        {
            return null;
        }

        var m = s_traceparent.Match(traceparent);
        return m.Success && m.Groups[1].Value != new string('0', 32) ? m.Groups[1].Value : null;
    }

    /// <summary>Records the request id on the request's server span (child spans find it through their parents). Never throws.</summary>
    public static void TagServerSpan(Activity? span, string? requestId)
    {
        if (span is null || requestId is null)
        {
            return;
        }

        try
        {
            span.SetTag(RequestIdAttr, requestId);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // never breaks the request
        }
    }

    /// <summary>Edge's request id and the trace id for what the app is doing now (either may be null).</summary>
    public static (string? RequestId, string? TraceId, bool SpanActive) Current()
    {
        try
        {
            var ctx = RaspScope.Current;
            var span = Activity.Current;
            var active = span is not null && span.TraceId != default;
            var rid = ctx?.Edge?.Rid ?? ctx?.RequestId;
            for (var a = span; rid is null && a is not null; a = a.Parent)
            {
                rid = a.GetTagItem(RequestIdAttr) as string;
            }

            var tid = active ? span!.TraceId.ToHexString() : TraceIdOf(ctx?.Edge?.Traceparent) ?? ctx?.TraceId;
            return (rid, tid, active);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return (null, null, false);
        }
    }
}
