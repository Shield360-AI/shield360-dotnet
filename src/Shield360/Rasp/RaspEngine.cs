using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;

namespace Shield360.Rasp;

/// <summary>The parts of a verified signed config the engine uses (<see cref="RaspConfigClient"/> verifies it).</summary>
internal sealed class RemoteConfig
{
    public string Version { get; init; } = string.Empty;

    public double Exp { get; init; }

    public bool KillSwitch { get; init; }

    public bool Snippets { get; init; }

    /// <summary>Allow-list events carry <c>shield360.rasp.target</c> (signed config only; no local option).</summary>
    public bool ReportTargets { get; init; }

    public RaspMode? Mode { get; init; }

    public IReadOnlyDictionary<RaspAttackType, RaspMode> Attacks { get; init; } = new Dictionary<RaspAttackType, RaspMode>();

    /// <summary>Each list is null when the config does not set it (the local list stays).</summary>
    public IReadOnlyList<string>? AllowCommands { get; init; }

    public IReadOnlyList<string>? AllowOutboundHosts { get; init; }

    public IReadOnlyList<string>? AllowFileRoots { get; init; }

    /// <summary>Null keeps the built-in virtual patches; a list replaces them.</summary>
    public IReadOnlyList<VirtualPatch>? Rules { get; init; }

    /// <summary>
    /// Custom rules as sent, the JSON text of the list (<see cref="RaspCustomRules"/> validates
    /// them); null = none. Text, not a <c>JsonElement</c>: this type is loaded on every check, and
    /// a System.Text.Json field would make loading it need the System.Text.Json version the SDK was
    /// built against, which the zero-code hook alone on .NET 8 and 9 does not have (it must fail open).
    /// </summary>
    public string? CustomRulesJson { get; init; }

    /// <summary>The decoy paths (README "Deception"); null = deception off.</summary>
    public DeceptionConfig? Deception { get; init; }

    /// <summary>SHIELD: protection triangle — the keys of Edge's context header and the app's verdicts (empty without Edge).</summary>
    public IReadOnlyList<EdgeKey> EdgeKeys { get; init; } = Array.Empty<EdgeKey>();

    /// <summary>SHIELD: uploads — the signed config's uploads block, read (null when absent).</summary>
    public UploadPolicy? Uploads { get; init; }

    /// <summary>SHIELD: AI attack agents — the signed attackAgents block, read; null when absent or not an object (the local option).</summary>
    public AttackAgentConfig? AttackAgents { get; init; }
}

/// <summary>One reported record: <c>{ name, time, attrs }</c>.</summary>
internal sealed record RaspEvent(string Name, string Time, IReadOnlyDictionary<string, string> Attrs);

/// <summary>Where the engine sends events (the reporter, or a test).</summary>
internal interface IRaspEventSink
{
    void Add(RaspEvent e, string foldKey);
}

internal enum RaspDecision
{
    Monitored,
    Blocked,
}

/// <summary>Request details an event carries, when the caller knows them better than the context.</summary>
/// <remarks>
/// <see cref="Context"/> is the request's context when the caller holds it before it is current
/// (request capture runs before the middleware enters it), so custom finding rules still see the
/// request and share its work budget.
/// </remarks>
internal sealed record FindingExtra(string? Framework = null, string? Route = null, string? Method = null, string? Path = null, RaspContext? Context = null)
{
    /// <summary>SHIELD: AI attack agents — the client kind and reason an ai_attack_agent event carries.</summary>
    public AttackMark? Agent { get; init; }
}

/// <summary>The engine's local settings.</summary>
internal sealed record EngineSettings(
    bool Enabled,
    string ApplicationName,
    RaspMode? Mode = null,
    IDictionary<RaspAttackType, RaspMode>? Attacks = null,
    RaspAllowOptions? Allow = null,
    bool ModelOutput = true,
    bool MonitorOnly = false,
    Func<string, string?>? Env = null,
    AttackAgentConfig? AttackAgents = null);

/// <summary>
/// The RASP engine: the effective mode of each attack type (local options, the
/// verified signed config, the kill switch), the decision for a finding, the
/// event and the block exception. Detectors (<see cref="RaspDetect"/>) are pure;
/// this is where a finding becomes an event or a block. Port of the TypeScript
/// <c>engine.ts</c>.
/// </summary>
internal static class RaspEngine
{
    public const string Language = "dotnet";

    private sealed class Local
    {
        public bool Enabled;
        public bool EnvOff;
        public string ApplicationName = "default";
        public RaspMode Mode = RaspMode.Monitor;
        public Dictionary<RaspAttackType, RaspMode> Attacks = new();
        public RaspAllow Allow = RaspAllow.Empty;
        public AttackAgentConfig AttackAgents = AttackAgentConfig.Default; // SHIELD: AI attack agents
    }

    private static Local s_local = new();
    private static RemoteConfig? s_remote;
    private static IRaspEventSink? s_sink;
    private static int s_runtimeDisabled;
    private static int s_monitorOnly;
    private static IReadOnlyList<string> s_alwaysAllowedHosts = Array.Empty<string>();
    private static IReadOnlyList<CustomRule> s_customRules = Array.Empty<CustomRule>();

    /// <summary><c>SHIELD360_RASP</c>: monitor, block or off (anything else is ignored).</summary>
    public static RaspMode? EnvSetting(Func<string, string?> env) =>
        RaspNames.Mode(JsText.Lower(JsText.Trim(env("SHIELD360_RASP") ?? string.Empty)));

    private static string[] Strings(IEnumerable<string>? values) =>
        values is null ? Array.Empty<string>() : values.Where(x => !string.IsNullOrEmpty(x)).Take(256).ToArray();

    public static void Configure(EngineSettings s)
    {
        var env = EnvSetting(s.Env ?? Environment.GetEnvironmentVariable);
        var local = new Local
        {
            EnvOff = env == RaspMode.Off,
            ApplicationName = string.IsNullOrEmpty(s.ApplicationName) ? "default" : s.ApplicationName,
            Mode = s.Mode ?? (env is RaspMode.Block or RaspMode.Monitor ? env.Value : RaspMode.Monitor),
            Attacks = s.Attacks is null ? new Dictionary<RaspAttackType, RaspMode>() : new Dictionary<RaspAttackType, RaspMode>(s.Attacks),
            Allow = new RaspAllow(Strings(s.Allow?.Commands), Strings(s.Allow?.OutboundHosts), Strings(s.Allow?.FileRoots)),
            AttackAgents = s.AttackAgents ?? AttackAgentConfig.Default,
        };
        local.Enabled = s.Enabled && !local.EnvOff;
        Volatile.Write(ref s_runtimeDisabled, 0);
        Volatile.Write(ref s_monitorOnly, s.MonitorOnly ? 1 : 0);
        Volatile.Write(ref s_remote, null);
        Volatile.Write(ref s_customRules, Array.Empty<CustomRule>());
        Volatile.Write(ref s_local, local);
        RaspModelOutput.SetRecording(local.Enabled && s.ModelOutput);
    }

    public static void SetEventSink(IRaspEventSink? sink) => Volatile.Write(ref s_sink, sink);

    public static void SetMonitorOnly(bool on) => Volatile.Write(ref s_monitorOnly, on ? 1 : 0);

    /// <summary>Applies a verified signed config (null drops it: local options again), compiling its custom rules.</summary>
    public static void SetRemoteConfig(RemoteConfig? c)
    {
        var rules = c?.CustomRulesJson is { } json ? ParseCustomRules(json) : Array.Empty<CustomRule>();
        Volatile.Write(ref s_remote, c);
        Volatile.Write(ref s_customRules, rules);
    }

    // Kept out of SetRemoteConfig's body so System.Text.Json loads only when there are rules.
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static IReadOnlyList<CustomRule> ParseCustomRules(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return RaspCustomRules.Parse(doc.RootElement.Clone(), ApplicationName);
        }
        catch (JsonException)
        {
            return Array.Empty<CustomRule>();
        }
    }

    /// <summary>The custom rules in force (README "Custom rules").</summary>
    public static IReadOnlyList<CustomRule> CustomRules => Volatile.Read(ref s_customRules);

    public static RemoteConfig? Remote => Volatile.Read(ref s_remote);

    /// <summary>The runtime switch (third in the kill-switch order).</summary>
    public static void SetRuntimeDisabled(bool off) => Volatile.Write(ref s_runtimeDisabled, off ? 1 : 0);

    /// <summary>The Shield360 URL's and OTLP endpoint's hosts: always allowed outbound (for the HTTP hooks).</summary>
    public static IReadOnlyList<string> AlwaysAllowedHosts
    {
        get => Volatile.Read(ref s_alwaysAllowedHosts);
        set => Volatile.Write(ref s_alwaysAllowedHosts, value ?? Array.Empty<string>());
    }

    /// <summary>Kill-switch order: env <c>SHIELD360_RASP=off</c>, the signed <c>killSwitch</c>, the runtime call.</summary>
    public static bool IsActive
    {
        get
        {
            var l = Volatile.Read(ref s_local);
            return l.Enabled && !l.EnvOff && Remote?.KillSwitch != true && Volatile.Read(ref s_runtimeDisabled) == 0;
        }
    }

    public static bool IsEnabled => Volatile.Read(ref s_local).Enabled;

    public static string ApplicationName => Volatile.Read(ref s_local).ApplicationName;

    /// <summary>The effective mode of an attack type: off when RASP is not active.</summary>
    public static RaspMode ModeFor(RaspAttackType attack)
    {
        if (!IsActive)
        {
            return RaspMode.Off;
        }

        var l = Volatile.Read(ref s_local);
        if (l.Attacks.TryGetValue(attack, out var localMode) && localMode == RaspMode.Off)
        {
            return RaspMode.Off;
        }

        var r = Remote;
        RaspMode m;
        if (attack == RaspAttackType.Deception)
        {
            // Only the explicit value: unset leaves the decision to the config's action, never the default mode.
            m = r is not null && r.Attacks.TryGetValue(attack, out var dm) ? dm
                : r is null && l.Attacks.TryGetValue(attack, out var ldm) ? ldm
                : RaspMode.Block;
        }
        else if (r is not null)
        {
            m = r.Attacks.TryGetValue(attack, out var rm) ? rm : r.Mode ?? RaspMode.Monitor;
        }
        else
        {
            m = l.Attacks.TryGetValue(attack, out var lm) ? lm : l.Mode;
        }

        if (m == RaspMode.Block && (RaspNames.MonitorOnly(attack) || Volatile.Read(ref s_monitorOnly) == 1))
        {
            m = RaspMode.Monitor;
        }

        return m;
    }

    public static RaspAllow AllowLists()
    {
        var l = Volatile.Read(ref s_local).Allow;
        var r = Remote;
        if (r is null)
        {
            return l;
        }

        return new RaspAllow(r.AllowCommands ?? l.Commands, r.AllowOutboundHosts ?? l.OutboundHosts, r.AllowFileRoots ?? l.FileRoots);
    }

    public static IReadOnlyList<VirtualPatch> VirtualPatches() => Remote?.Rules ?? RaspVirtualPatches.BuiltIn;

    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);

    private static readonly Regex s_unsafeKeyChar = new("[^A-Za-z0-9_.\\-\\[\\]]", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_badKeyStart = new("^[^A-Za-z0-9_]", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_unsafeRouteChar = new("[^\\x21\\x23-\\x26\\x28-\\x3b\\x3d\\x3f-\\x5b\\x5d-\\x7e]", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_method = new("^[A-Za-z]{3,10}\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_cve = new("^CVE-[0-9]{4}-[0-9]{4,7}\\z", RegexOptions.CultureInvariant, s_timeout);

    /// <summary>A snippet: masked by the shared contract (sdk/rasp/README.md, Masking), at most 64 characters.</summary>
    public static string MaskSnippet(string v) => Internal.Masking.MaskSnippet(v);

    /// <summary>The masking rules without the length cap (sdk/rasp/README.md, Masking). Application logs use them too.</summary>
    internal static string MaskCredentials(string v) => Internal.Masking.MaskSecrets(v);

    private static readonly HashSet<string> s_targetRules = new(StringComparer.Ordinal) { "shell_spawn.shell", "outbound.not_allowed", "path.outside_root" };
    private static readonly HashSet<string> s_dialects = new(StringComparer.Ordinal) { "mysql", "postgres", "sqlite", "mssql", "oracle", "db2", "generic" };

    /// <summary>
    /// An allow-list target as sent (contract "Masking", "Allow-list targets"): the shared
    /// masking's target rules. Null when empty, holding a control character or longer than 256
    /// characters (never cut).
    /// </summary>
    public static string? MaskTarget(string? raw) => Internal.Masking.MaskTarget(raw);

    // Event attributes must pass the platform's shape checks (lib/security/rasp/events.ts).
    private static string SafeKey(string k)
    {
        var s = s_badKeyStart.Replace(s_unsafeKeyChar.Replace(k, "_"), "_");
        return s.Length > 128 ? s.Substring(0, 128) : s;
    }

    private static string SafeRoute(string r)
    {
        var s = s_unsafeRouteChar.Replace(r, "_");
        if (s.Length > 256)
        {
            s = s.Substring(0, 256);
        }

        return JsText.Starts(s, "/") ? s : string.Empty;
    }

    private static string SafeMethod(string? m) => m is not null && s_method.IsMatch(m) ? m.ToUpperInvariant() : string.Empty;

    private static string NewEventId()
    {
        var bytes = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }

        var sb = new StringBuilder(32);
        foreach (var b in bytes)
        {
            sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Of several findings for one call, the one whose decision is strongest (block over
    /// monitor; an attack type that is off never counts), so a finding for a type in monitor
    /// or off mode cannot hide another that blocks. Ties go to the earlier finding (the
    /// contract's order). Null when no finding counts.
    /// </summary>
    public static RaspFinding? Strongest(params RaspFinding?[] findings)
    {
        RaspFinding? best = null;
        var bestRank = 0;
        foreach (var f in findings)
        {
            if (f is null)
            {
                continue;
            }

            var mode = ModeFor(f.Attack);
            if (f.Action is RaspMode action && RaspNames.Rank(action) < RaspNames.Rank(mode))
            {
                mode = action;
            }

            var rank = RaspNames.Rank(mode);
            if (rank > bestRank)
            {
                best = f;
                bestRank = rank;
            }
        }

        return best;
    }

    /// <summary>
    /// Applies a finding: reports it and, when the decision is blocked, throws the
    /// block exception. Returns the decision, or null when the attack type is off.
    /// </summary>
    public static RaspDecision? HandleFinding(RaspFinding f, string sink, FindingExtra? extra = null)
    {
        var mode = UploadMode(f, ModeFor(f.Attack));

        // A rule's own action (virtual patches, custom rules) caps the mode.
        if (f.Action is RaspMode action && RaspNames.Rank(action) < RaspNames.Rank(mode))
        {
            mode = action;
        }

        if (mode == RaspMode.Off)
        {
            return null;
        }

        // SHIELD: protection triangle — a client Edge already marked (flagged, deep in a honeypot, high risk) is
        // blocked for injection-class attacks this app only monitors. A rule's own action still caps it.
        var edgeCtx = extra?.Context ?? RaspScope.Current;
        var tightened = mode == RaspMode.Monitor && f.Action is null && s_tighten.Contains(f.Attack)
            && EdgeContext.SaysSuspect(edgeCtx?.Edge) && Volatile.Read(ref s_monitorOnly) == 0;
        if (tightened)
        {
            mode = RaspMode.Block;
        }

        var decision = mode == RaspMode.Block && !RaspNames.MonitorOnly(f.Attack) ? RaspDecision.Blocked : RaspDecision.Monitored;

        // SHIELD: AI attack agents — a finding feeds the client's behavior score; a block's 403 is never an auth failure.
        if (edgeCtx is not null)
        {
            if (!s_agentExcluded.Contains(f.Attack))
            {
                edgeCtx.AgentFinding = true;
            }

            if (decision == RaspDecision.Blocked)
            {
                edgeCtx.OwnBlock = true;
            }
        }

        var eventId = NewEventId();
        Emit(f, sink, extra, decision, mode, eventId, tightened);

        SendVerdict(edgeCtx, f, decision);

        // Custom rules that look at built-in findings; the first blocking decision wins, the built-in one first.
        var custom = f.Attack == RaspAttackType.CustomRule ? null : RunFindingRules(f, sink, extra);
        if (decision == RaspDecision.Blocked)
        {
            throw new Shield360RaspBlockedException(f.Attack, f.Rule, eventId);
        }

        if (custom is not null)
        {
            throw custom;
        }

        return decision;
    }

    /// <summary>SHIELD: AI attack agents — findings of these types do not add to the behavior score.</summary>
    private static readonly HashSet<RaspAttackType> s_agentExcluded = new() { RaspAttackType.AiAttackAgent, RaspAttackType.Deception, RaspAttackType.Baseline };

    /// <summary>SHIELD: AI attack agents — the settings in force: the signed config's block, else the local option.</summary>
    public static AttackAgentConfig AgentConfig() => Remote?.AttackAgents ?? Volatile.Read(ref s_local).AttackAgents;

    /// <summary>
    /// SHIELD: AI attack agents — reports a mark or a marked client's request (attack
    /// <c>ai_attack_agent</c>, sink <c>http.attack_agent</c>, no input) with the client kind and
    /// reason, and returns its event id. Never throws.
    /// </summary>
    public static string ReportAttackAgent(string rule, bool block, FindingExtra extra, AttackMark mark)
    {
        var eventId = NewEventId();
        Emit(
            new RaspFinding(RaspAttackType.AiAttackAgent, rule),
            RaspAttackAgents.Sink,
            extra with { Agent = mark },
            block ? RaspDecision.Blocked : RaspDecision.Monitored,
            block ? RaspMode.Block : RaspMode.Monitor,
            eventId,
            tightened: false);
        return eventId;
    }

    /// <summary>
    /// SHIELD: AI attack agents — tells Edge to block a marked client: a signed verdict with the
    /// client kind as category and the mark's TTL. Needs a verified Edge context and an open
    /// response; replaces a flag verdict set earlier in the request. Never throws.
    /// </summary>
    public static void SendAgentVerdict(string kind, int ttlSeconds, RaspContext? ctx)
    {
        try
        {
            var keys = EdgeKeys;
            if (ctx?.Edge is null || ctx.SetHeader is null || keys.Count == 0)
            {
                return;
            }

            var v = EdgeContext.SignVerdict(keys, ctx.Edge.Rid, "block", kind, "rasp", ttlSeconds, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if (v is null)
            {
                return;
            }

            ctx.SetHeader(EdgeContext.VerdictHeader, v);
            ctx.VerdictSent = true;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // reporting to Edge never breaks the call
        }
    }

    /// <summary>Builds and queues one event. Never throws.</summary>
    private static void Emit(RaspFinding f, string sink, FindingExtra? extra, RaspDecision decision, RaspMode mode, string eventId, bool tightened)
    {
        try
        {
            var x = extra ?? new FindingExtra();
            var ctx = x.Context ?? RaspScope.Current;
            var remote = Remote;
            var path = x.Path ?? ctx?.Path;
            var route = SafeRoute(x.Route ?? ctx?.ResolvedRoute() ?? (path is null ? string.Empty : RaspScope.EventRouteOf(path)));
            var decisionName = decision == RaspDecision.Blocked ? "blocked" : "monitored";
            var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["shield360.rasp.event_id"] = eventId,
                ["shield360.rasp.app"] = ApplicationName,
                ["shield360.rasp.attack"] = RaspNames.Of(f.Attack),
                ["shield360.rasp.rule"] = f.Rule,
                ["shield360.rasp.decision"] = decisionName,
                ["shield360.rasp.mode"] = RaspNames.Of(mode),
                ["shield360.rasp.sink"] = sink,
                ["shield360.rasp.config_version"] = remote?.Version ?? "local",
                ["shield360.rasp.language"] = Language,
            };
            void Opt(string k, string? v)
            {
                if (!string.IsNullOrEmpty(v))
                {
                    attrs[k] = v!;
                }
            }

            Opt("shield360.rasp.source", f.Input is null ? null : RaspNames.Of(f.Input.Source));
            Opt("shield360.rasp.input_key", f.Input is null ? null : SafeKey(f.Input.Key));
            Opt("shield360.rasp.route", route);
            Opt("shield360.rasp.method", SafeMethod(x.Method ?? ctx?.Method));
            Opt("shield360.rasp.framework", x.Framework ?? ctx?.Framework);
            Opt("shield360.rasp.cve", f.Cve is not null && s_cve.IsMatch(f.Cve) ? f.Cve : null);

            // SHIELD: protection triangle — the Edge request this happened in (one correlated event in Shield360), and a tightening.
            Opt("shield360.edge.request_id", ctx?.Edge?.Rid);
            if (tightened)
            {
                attrs["shield360.rasp.tightened_by_edge"] = "true";
            }
            if (remote?.Snippets == true && f.Input is not null)
            {
                attrs["shield360.rasp.snippet"] = MaskSnippet(f.Input.Value);
            }

            if (remote?.ReportTargets == true && s_targetRules.Contains(f.Rule))
            {
                Opt("shield360.rasp.target", MaskTarget(f.Target));
            }

            if (f.Attack == RaspAttackType.SqlInjection && f.Dialect is not null && s_dialects.Contains(f.Dialect))
            {
                attrs["shield360.rasp.sql.dialect"] = f.Dialect;
            }

            RaspUploads.AddAttrs(attrs, f); // SHIELD: uploads — README "Upload event attributes"

            // SHIELD: AI attack agents — the client kind and the reason it was marked.
            if (x.Agent is { } agent && f.Attack == RaspAttackType.AiAttackAgent)
            {
                attrs["shield360.rasp.client_kind"] = agent.Kind;
                attrs["shield360.rasp.reason"] = agent.Reason;
            }

            var time = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            var foldKey = string.Join("\u0000", RaspNames.Of(f.Attack), f.Rule, sink, route, decisionName);
            Volatile.Read(ref s_sink)?.Add(new RaspEvent("shield360.rasp.event", time, attrs), foldKey);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // reporting never breaks the call
        }
    }

    /// <summary>
    /// SHIELD: uploads — an upload route's own mode decides instead, capped by a local off, the
    /// kill switch (inactive) and no pinned key, like attack modes.
    /// </summary>
    private static RaspMode UploadMode(RaspFinding f, RaspMode mode)
    {
        if (f.Mode is not { } own || !IsActive)
        {
            return mode;
        }

        var l = Volatile.Read(ref s_local);
        if (l.Attacks.TryGetValue(f.Attack, out var localMode) && localMode == RaspMode.Off)
        {
            return mode;
        }

        return own == RaspMode.Block && Volatile.Read(ref s_monitorOnly) == 1 ? RaspMode.Monitor : own;
    }

    /// <summary>SHIELD: uploads — the mode that decides an upload finding (its own mode and action, capped as HandleFinding does).</summary>
    internal static RaspMode EffectiveUploadMode(RaspFinding f)
    {
        var m = UploadMode(f, ModeFor(f.Attack));
        return f.Action is RaspMode action && RaspNames.Rank(action) < RaspNames.Rank(m) ? action : m;
    }

    /// <summary>SHIELD: uploads — the event sink, for the scanner status record.</summary>
    internal static void AddEvent(string name, IReadOnlyDictionary<string, string> attrs)
    {
        var time = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        Volatile.Read(ref s_sink)?.Add(new RaspEvent(name, time, attrs), name + "\u0000" + Guid.NewGuid().ToString("N")); // never folded
    }

    /// <summary>SHIELD: protection triangle — attacks Edge's view of the client may tighten from monitor to block.</summary>
    private static readonly HashSet<RaspAttackType> s_tighten = new()
    {
        RaspAttackType.SqlInjection, RaspAttackType.NoSqlInjection, RaspAttackType.CommandInjection, RaspAttackType.ShellSpawn,
        RaspAttackType.CodeInjection, RaspAttackType.PathTraversal, RaspAttackType.Ssrf, RaspAttackType.Deserialization, RaspAttackType.Xxe,
    };

    /// <summary>SHIELD: protection triangle — the keys for Edge's context header and the app's verdicts (empty without Edge).</summary>
    public static IReadOnlyList<EdgeKey> EdgeKeys => Remote?.EdgeKeys ?? Array.Empty<EdgeKey>();

    /// <summary>
    /// SHIELD: protection triangle — for a request that came through Edge (a verified context), tells
    /// Edge about the detection in a signed response header: block for a blocked attack, flag for a
    /// monitored one. Once per request, never throws.
    /// </summary>
    private static void SendVerdict(RaspContext? ctx, RaspFinding f, RaspDecision decision)
    {
        try
        {
            var keys = EdgeKeys;
            if (ctx?.Edge is null || ctx.SetHeader is null || ctx.VerdictSent || keys.Count == 0)
            {
                return;
            }

            if (f.Attack == RaspAttackType.CustomRule && decision != RaspDecision.Blocked)
            {
                return;
            }

            var blocked = decision == RaspDecision.Blocked;
            var v = EdgeContext.SignVerdict(keys, ctx.Edge.Rid, blocked ? "block" : "flag", RaspNames.Of(f.Attack), "rasp", blocked ? 3600 : 900, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if (v is null)
            {
                return;
            }

            ctx.SetHeader(EdgeContext.VerdictHeader, v);
            ctx.VerdictSent = true;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // reporting to Edge never breaks the call
        }
    }

    /// <summary>Reports each custom finding rule the finding matches; returns the block exception of the first that blocks. Never throws.</summary>
    private static Shield360RaspBlockedException? RunFindingRules(RaspFinding f, string sink, FindingExtra? extra)
    {
        try
        {
            // Mode off skips custom rules entirely: nothing is evaluated and no budget is spent.
            var rules = CustomRules;
            if (rules.Count == 0 || ModeFor(RaspAttackType.CustomRule) == RaspMode.Off)
            {
                return null;
            }

            var ctx = extra?.Context ?? RaspScope.Current;
            var subject = RaspCustomRules.Subject(ctx, ApplicationName);
            subject.Sink = sink;
            subject.AttackType = RaspNames.Of(f.Attack);
            subject.AttackRule = f.Rule;
            var budget = ctx is null ? new RuleBudget() : RaspCustomRules.StateOf(ctx).Budget;
            foreach (var m in RaspCustomRules.MatchFindingRules(rules, subject, budget))
            {
                try
                {
                    HandleFinding(RaspCustomRules.Finding(m.Rule, RaspCustomRules.InputOf(m.Input) ?? f.Input), sink, extra);
                }
                catch (Shield360RaspBlockedException e)
                {
                    return e;
                }
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }

        return null;
    }

    /// <summary>
    /// Runs a check at a sink and applies what it finds. Fail open: any exception
    /// other than the block exception is swallowed. The entry point the sink hooks use.
    /// </summary>
    public static RaspDecision? Check(string sink, Func<RaspFinding?> run, FindingExtra? extra = null)
    {
        // Passive IAST (RaspIast): armed for sampled checks while it is on; reports only when no attack was found.
        var iast = IsActive ? RaspIast.Begin() : null;
        try
        {
            var f = run();
            if (iast is not null)
            {
                RaspIast.End(iast, f is null ? sink : null, extra);
            }

            return f is null ? null : HandleFinding(f, sink, extra);
        }
        catch (Shield360RaspBlockedException)
        {
            throw;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
        finally
        {
            if (iast is not null)
            {
                RaspIast.End(iast, null, null);
            }
        }
    }
}
