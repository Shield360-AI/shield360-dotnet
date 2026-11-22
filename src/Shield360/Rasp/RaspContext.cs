using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;

namespace Shield360.Rasp;

/// <summary>Virtual-patch state of a request: the request as the rules see it, and which phases ran.</summary>
internal sealed class VpState
{
    public VpState(VpRequest req)
    {
        Req = req;
    }

    public VpRequest Req { get; }

    public bool BodyKnown { get; set; }

    public bool RanHead { get; set; }

    public bool RanBody { get; set; }
}

/// <summary>
/// The RASP context of the request (or worker job) being served, kept in an
/// <see cref="AsyncLocal{T}"/>. Inputs live here, in memory, for the life of
/// the request only; nothing in this type sends or stores them anywhere else.
/// Thread-safe: parallel work inside one request may record model output.
/// </summary>
internal sealed class RaspContext
{
    private readonly object _lock = new();
    private readonly List<RaspInput> _inputs;
    private readonly List<JsonNode?> _trees = new();

    public RaspContext(IEnumerable<RaspInput>? inputs = null, bool inRequest = false)
    {
        _inputs = inputs is null ? new List<RaspInput>() : new List<RaspInput>(inputs);
        InRequest = inRequest;
    }

    public bool InRequest { get; }

    public string? Method { get; set; }

    public string? Path { get; set; }

    /// <summary>The route template when the framework knows it.</summary>
    public string? Route { get; set; }

    /// <summary>Resolves the route template later (ASP.NET Core picks the endpoint after the middleware ran).</summary>
    public Func<string?>? RouteSource { get; set; }

    public string? Framework { get; set; }

    /// <summary>The client address as the framework reports it (custom rules' <c>request.ip</c>); null when unknown.</summary>
    public string? Ip { get; set; }

    /// <summary>Reads the client address when a rule needs it (the framework may rewrite it after capture, e.g. forwarded headers).</summary>
    public Func<string?>? IpSource { get; set; }

    /// <summary>
    /// Rules that read <c>request.ip</c> wait: the address is expected to change (a trusted
    /// proxy's forwarded header the app's forwarded-headers middleware has not applied yet).
    /// </summary>
    public bool IpPending { get; set; }

    /// <summary>The client address now: <see cref="IpSource"/>, else <see cref="Ip"/>.</summary>
    public string? CurrentIp()
    {
        if (IpSource is { } source)
        {
            try
            {
                return source() ?? Ip;
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return Ip;
            }
        }

        return Ip;
    }

    public VpState? Vp { get; set; }

    /// <summary>Custom-rule state for this request (<see cref="RaspCustomRules"/>).</summary>
    public CustomRuleState? Rules { get; set; }

    /// <summary>Guards lazily created per-request state.</summary>
    public object SyncRoot => _lock;

    /// <summary>
    /// Captures a body that became available after the middleware ran. Called
    /// when a sink reads the inputs, until it returns other than false.
    /// </summary>
    public Func<bool>? Late { get; set; }

    /// <summary>SHIELD: protection triangle — Edge's verified context for this request (EdgeContext).</summary>
    public EdgeRequestContext? Edge { get; set; }

    /// <summary>SHIELD: request correlation — Edge's request id (verified context, else X-Request-Id) and the traceparent's trace id (EdgeRequest).</summary>
    public string? RequestId { get; set; }

    public string? TraceId { get; set; }

    /// <summary>SHIELD: protection triangle — sets a response header while the headers are not sent (the verdict for Edge).</summary>
    public Action<string, string>? SetHeader { get; set; }

    public bool VerdictSent { get; set; }

    /// <summary>SHIELD: AI attack agents — the signed-in user the app named (<c>Shield360Rasp.IdentifyUser</c>).</summary>
    public string? User { get; set; }

    /// <summary>SHIELD: AI attack agents — a RASP finding (other than ai_attack_agent, deception, baseline) happened in this request.</summary>
    public bool AgentFinding { get; set; }

    /// <summary>SHIELD: AI attack agents — Shield360 answered this request itself (a block): its status is never scored.</summary>
    public bool OwnBlock { get; set; }

    /// <summary>SHIELD: AI attack agents — the before-handler check ran.</summary>
    public bool AgentsChecked { get; set; }

    private int _agentsScored;

    /// <summary>SHIELD: AI attack agents — claims the after-handler scoring; true only the first time.</summary>
    public bool ClaimAgentsScoring() => Interlocked.Exchange(ref _agentsScored, 1) == 0;

    /// <summary>SHIELD: AI attack agents — the headers and client address the after-handler scoring uses.</summary>
    public IReadOnlyDictionary<string, string>? AgentHeaders { get; set; }

    public string? AgentIp { get; set; }

    /// <summary>SHIELD: AI attack agents — left alone: Edge verified the client, or a red team run sent it.</summary>
    public bool AgentLeftAlone { get; set; }

    /// <summary>The route template, resolved now if it was deferred.</summary>
    public string? ResolvedRoute()
    {
        if (Route is null && RouteSource is not null)
        {
            try
            {
                return RouteSource();
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return null;
            }
        }

        return Route;
    }

    /// <summary>Changes the inputs and trees under the context's lock.</summary>
    public void Mutate(Action<List<RaspInput>, List<JsonNode?>> change)
    {
        lock (_lock)
        {
            change(_inputs, _trees);
        }
    }

    /// <summary>Whether any input is recorded (cheaper than a snapshot).</summary>
    public bool HasInputs
    {
        get
        {
            lock (_lock)
            {
                return _inputs.Count > 0;
            }
        }
    }

    public IReadOnlyList<RaspInput> InputsSnapshot()
    {
        lock (_lock)
        {
            return _inputs.ToArray();
        }
    }

    public IReadOnlyList<JsonNode?> TreesSnapshot()
    {
        lock (_lock)
        {
            return _trees.ToArray();
        }
    }
}

/// <summary>The current RASP context (AsyncLocal) and the helpers that scope one.</summary>
internal static class RaspScope
{
    private static readonly AsyncLocal<RaspContext?> s_current = new();

    private static readonly Regex s_idSegment = new(
        "^([0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?=[0-9a-f]*[0-9])[0-9a-f]{8,})\\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private static readonly Regex s_keptSegment = new(
        "^(?:[a-z][a-z_.-]{0,15}|v[0-9]{1,2})\\z",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    public static RaspContext? Current => s_current.Value;

    /// <summary>
    /// Makes <paramref name="ctx"/> current for the rest of the calling flow (the
    /// caller's async method, and what it awaits). Called from a synchronous
    /// method, it reaches the caller; inside an async method it ends with it.
    /// </summary>
    public static void Enter(RaspContext? ctx) => s_current.Value = ctx;

    /// <summary>Runs <paramref name="fn"/> with <paramref name="ctx"/> current; work it starts keeps it.</summary>
    public static T Run<T>(RaspContext ctx, Func<T> fn)
    {
        var previous = s_current.Value;
        s_current.Value = ctx;
        try
        {
            return fn();
        }
        finally
        {
            s_current.Value = previous;
        }
    }

    /// <summary>The current context, or a new non-request one entered into the calling flow.</summary>
    public static RaspContext Ensure()
    {
        var ctx = s_current.Value;
        if (ctx is null)
        {
            ctx = new RaspContext();
            s_current.Value = ctx;
        }

        return ctx;
    }

    /// <summary>
    /// The context's inputs, after any late body capture. Sinks call this rather
    /// than reading the inputs directly. A virtual patch matched by the late body
    /// throws the block exception from here.
    /// </summary>
    public static IReadOnlyList<RaspInput> InputsOf(RaspContext ctx)
    {
        var late = ctx.Late;
        if (late is not null)
        {
            ctx.Late = null;
            if (!late())
            {
                ctx.Late = late;
            }
        }

        return ctx.InputsSnapshot();
    }

    /// <summary>Route fallback: all-digit, UUID and hex (8+, with a digit) segments become <c>:id</c>.</summary>
    public static string RouteOf(string path)
    {
        var q = path.IndexOf('?');
        var p = q >= 0 ? path.Substring(0, q) : path;
        return string.Join("/", p.Split('/').Select(s => s_idSegment.IsMatch(s) ? ":id" : s));
    }

    /// <summary>
    /// The route every event carries when the framework gave no template (README
    /// "Event route"): the route fallback, then every segment that is not a short
    /// lower-case word (or an API version such as <c>v2</c>) becomes <c>:id</c>, so a
    /// token, name or other value in the path never reaches an event.
    /// </summary>
    public static string EventRouteOf(string path) =>
        string.Join("/", RouteOf(path).Split('/').Select(s => s.Length == 0 || s == ":id" || s_keptSegment.IsMatch(s) ? s : ":id"));
}
