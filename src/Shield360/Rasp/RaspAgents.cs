using System;
using System.Collections.Generic;
using System.Linq;

namespace Shield360.Rasp;

/// <summary>A request as the tripwire and the decoy scoring see it, before any capture.</summary>
internal sealed class AgentEarlyRequest
{
    public string Framework { get; init; } = "unknown";

    public string Method { get; init; } = "GET";

    /// <summary>The raw target, path and query as received.</summary>
    public string Url { get; init; } = "/";

    /// <summary>The client address (deception's "Client address"), read when needed.</summary>
    public Func<string?> Ip { get; init; } = () => null;

    /// <summary>A request header by lower-case name, or null.</summary>
    public Func<string, string?> Header { get; init; } = _ => null;
}

/// <summary>
/// SHIELD: AI attack agents — the request glue (sdk/rasp/README.md "AI attack agents",
/// "Decision"). <see cref="RaspAttackAgents"/> holds the pure parts; this runs them for the request
/// in the context: the before-handler check (tripwire, agent header, OAST, tool User-Agent, an
/// earlier mark), the scoring once the app answered, and the events, deter answers and Edge
/// verdicts that follow. A request Edge verified (<c>ct</c> verified_agent or verified_crawler) or
/// that belongs to an authorized red team run (<c>rt</c> in Edge's verified context) is left alone.
/// Every entry point fails open; only the deter exception leaves on purpose. Port of
/// sdk/typescript/src/rasp/agents.ts.
/// </summary>
internal static class RaspAgents
{
    public const string TripwireRule = "attack_agent.tripwire";
    public const string BehaviorRule = "attack_agent.behavior";
    public const string MarkedRule = "attack_agent.marked";

    private static readonly IReadOnlyDictionary<string, string> s_noHeaders = new Dictionary<string, string>(StringComparer.Ordinal);

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>
    /// Whether the request is left alone: Edge verified the client (<c>verified_agent</c>,
    /// <c>verified_crawler</c>) or the request belongs to an authorized red team run (<c>rt</c>).
    /// </summary>
    public static bool LeftAlone(EdgeRequestContext? edge) =>
        edge is not null && (!string.IsNullOrEmpty(edge.RedTeam) || edge.ClientType == "verified_agent" || edge.ClientType == "verified_crawler");

    /// <summary>Names the signed-in user of the current request (1 to 128 characters; anything else is ignored). Never throws.</summary>
    public static void IdentifyUser(string? id)
    {
        try
        {
            if (RaspScope.Current is { InRequest: true } ctx && id is { Length: >= 1 and <= 128 })
            {
                ctx.User = id;
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    private static IEnumerable<string> RequestValues(RaspContext ctx) =>
        ctx.InputsSnapshot().Where(i => i.Source == RaspInputSource.Request).Select(i => i.Value);

    private static FindingExtra ExtraOf(RaspContext ctx, string? route) => new(ctx.Framework, route, ctx.Method, ctx.Path, ctx);

    private static FindingExtra ExtraEarly(AgentEarlyRequest r) =>
        new(r.Framework, RaspScope.EventRouteOf(RaspAttackAgents.PathOnly(r.Url)), r.Method);

    /// <summary>
    /// The before-handler check, once the inputs are captured. Throws the deter exception (429)
    /// in block mode when the client is marked; otherwise reports and lets the request go on.
    /// <paramref name="ip"/> is the client address (deception's), <paramref name="headers"/> the
    /// request headers with lower-case names.
    /// </summary>
    public static void Before(RaspContext ctx, IReadOnlyDictionary<string, string> headers, string? ip)
    {
        if (ctx.AgentsChecked)
        {
            return;
        }

        ctx.AgentsChecked = true;
        try
        {
            var mode = RaspEngine.ModeFor(RaspAttackType.AiAttackAgent);
            if (mode == RaspMode.Off)
            {
                return;
            }

            var cfg = RaspEngine.AgentConfig();
            ctx.AgentHeaders = headers;
            ctx.AgentIp = ip;
            ctx.AgentLeftAlone = LeftAlone(ctx.Edge);
            var r = RaspAttackAgents.Tracker.Before(
                new AgentRequest { Ip = ip, User = ctx.User, Path = ctx.Path ?? "/", Headers = headers, Inputs = RequestValues(ctx), Verified = ctx.AgentLeftAlone },
                cfg,
                NowMs());
            if (r.Marked is null)
            {
                return;
            }

            var block = mode == RaspMode.Block;
            var rule = r.Mark is not null ? "attack_agent." + r.Mark.Reason : MarkedRule;
            var eventId = RaspEngine.ReportAttackAgent(rule, block, ExtraOf(ctx, ctx.ResolvedRoute()), r.Mark ?? r.Marked);
            if (!block)
            {
                return;
            }

            // The 429 is Shield360's own answer: never scored.
            ctx.ClaimAgentsScoring();
            RaspEngine.SendAgentVerdict(r.Marked.Kind, cfg.MarkTtlSeconds, ctx);
            throw new Shield360RaspBlockedException(rule, eventId, cfg.RetryAfterSeconds);
        }
        catch (Shield360RaspBlockedException)
        {
            throw;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>
    /// Scores the request once the app answered with <paramref name="status"/> (before the headers
    /// go out where the adapter can): marks, reports and, in block mode, tells Edge. Once per
    /// request; <paramref name="own"/>: the status is Shield360's own block. Never throws.
    /// </summary>
    public static void After(RaspContext ctx, int status, bool own = false)
    {
        if (!ctx.AgentsChecked || !ctx.ClaimAgentsScoring())
        {
            return;
        }

        try
        {
            var mode = RaspEngine.ModeFor(RaspAttackType.AiAttackAgent);
            if (mode == RaspMode.Off)
            {
                return;
            }

            var cfg = RaspEngine.AgentConfig();
            var route = ctx.ResolvedRoute();
            var m = RaspAttackAgents.Tracker.After(
                new AgentRequest { Ip = ctx.AgentIp, User = ctx.User, Path = ctx.Path ?? "/", Headers = ctx.AgentHeaders ?? s_noHeaders, Verified = ctx.AgentLeftAlone },
                new AgentResponse { Status = status, Route = string.IsNullOrEmpty(route) ? null : route, Finding = ctx.AgentFinding, Own = own || ctx.OwnBlock },
                cfg,
                NowMs());
            if (m is null)
            {
                return;
            }

            var block = mode == RaspMode.Block;
            RaspEngine.ReportAttackAgent(BehaviorRule, block, ExtraOf(ctx, route), m);
            if (block)
            {
                RaspEngine.SendAgentVerdict(m.Kind, cfg.MarkTtlSeconds, ctx);
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>
    /// Edge's context for an early request, verified without the replay cache: it only decides
    /// whether the request is left alone (no tripwire, no decoy scoring, no tripwire page), never
    /// what Edge is told.
    /// </summary>
    private static EdgeRequestContext? VerifiedEarly(AgentEarlyRequest r)
    {
        var value = r.Header(EdgeContext.ContextHeader);
        var keys = RaspEngine.EdgeKeys;
        if (string.IsNullOrEmpty(value) || keys.Count == 0)
        {
            return null;
        }

        var rid = r.Header(EdgeRequest.RequestIdHeader);
        return EdgeContext.Verify(keys, value, r.Method, RaspAttackAgents.PathOnly(r.Url), string.IsNullOrEmpty(rid) ? null : rid, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), null);
    }

    /// <summary>
    /// The tripwire URL (README "Decision" 1), answered before deception: true when the request is
    /// a tripwire hit, which marks the client; the adapter answers 404, or <paramref name="deter"/>
    /// (429) in block mode. The handler never runs. Never throws.
    /// </summary>
    public static bool CheckTripwire(AgentEarlyRequest r, out Shield360RaspBlockedException? deter)
    {
        deter = null;
        try
        {
            var mode = RaspEngine.ModeFor(RaspAttackType.AiAttackAgent);
            if (mode == RaspMode.Off)
            {
                return false;
            }

            var cfg = RaspEngine.AgentConfig();
            if (!cfg.Tripwire || !RaspAttackAgents.HitsTripwire(r.Url, cfg) || LeftAlone(VerifiedEarly(r)))
            {
                return false;
            }

            var res = RaspAttackAgents.Tracker.Before(new AgentRequest { Ip = r.Ip(), Path = r.Url, Headers = s_noHeaders }, cfg, NowMs());
            var mark = res.Mark ?? new AttackMark(RaspAttackAgents.KindAgent, RaspAttackAgents.ReasonTripwire);
            var block = mode == RaspMode.Block;
            var eventId = RaspEngine.ReportAttackAgent(TripwireRule, block, ExtraEarly(r), mark);
            if (block)
            {
                deter = new Shield360RaspBlockedException(TripwireRule, eventId, cfg.RetryAfterSeconds);
            }

            return true;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            deter = null;
            return false;
        }
    }

    /// <summary>
    /// A decoy hit (README "Deception"): scores it (10 points), reports a behavior mark, and returns
    /// the tripwire page the 404 carries when the tripwire is on (null: the adapter's own 404).
    /// Never throws.
    /// </summary>
    public static string? Decoy(AgentEarlyRequest r)
    {
        try
        {
            var mode = RaspEngine.ModeFor(RaspAttackType.AiAttackAgent);
            if (mode == RaspMode.Off)
            {
                return null;
            }

            var cfg = RaspEngine.AgentConfig();
            var left = LeftAlone(VerifiedEarly(r));
            var ip = r.Ip();
            var m = RaspAttackAgents.Tracker.After(
                new AgentRequest { Ip = ip, Path = r.Url, Headers = s_noHeaders, Verified = left },
                new AgentResponse { Status = 404, Decoy = true },
                cfg,
                NowMs());
            if (m is not null)
            {
                RaspEngine.ReportAttackAgent(BehaviorRule, mode == RaspMode.Block, ExtraEarly(r), m);
            }

            return RaspAttackAgents.TripwirePageFor(ip, cfg, left);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }
}
