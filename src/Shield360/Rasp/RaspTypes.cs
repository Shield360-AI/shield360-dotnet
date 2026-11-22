using System;
using System.Collections.Generic;

namespace Shield360.Rasp;

/// <summary>
/// What a runtime protection (RASP) check does for one attack type
/// (sdk/rasp/README.md, "Attack types and modes").
/// </summary>
public enum RaspMode
{
    /// <summary>The check is skipped.</summary>
    Off,

    /// <summary>A detection is reported and the call goes through. The default.</summary>
    Monitor,

    /// <summary>A detection is reported and the call is refused with <see cref="Shield360RaspBlockedException"/>.</summary>
    Block,
}

/// <summary>The attack types RASP detects. Events carry their snake_case names (<c>sql_injection</c>).</summary>
public enum RaspAttackType
{
    /// <summary><c>sql_injection</c>.</summary>
    SqlInjection,

    /// <summary><c>nosql_injection</c>.</summary>
    NoSqlInjection,

    /// <summary><c>command_injection</c>.</summary>
    CommandInjection,

    /// <summary><c>shell_spawn</c>.</summary>
    ShellSpawn,

    /// <summary><c>path_traversal</c>.</summary>
    PathTraversal,

    /// <summary><c>file_write</c>.</summary>
    FileWrite,

    /// <summary><c>ssrf</c>.</summary>
    Ssrf,

    /// <summary><c>outbound</c>: only when an outbound allow-list is set.</summary>
    Outbound,

    /// <summary><c>deserialization</c>.</summary>
    Deserialization,

    /// <summary><c>code_injection</c>.</summary>
    CodeInjection,

    /// <summary><c>xxe</c>.</summary>
    Xxe,

    /// <summary><c>xss</c>: never blocks; <see cref="RaspMode.Block"/> is treated as <see cref="RaspMode.Monitor"/>.</summary>
    Xss,

    /// <summary><c>virtual_patch</c>: a rule may carry its own action, capped by this mode.</summary>
    VirtualPatch,

    /// <summary>
    /// <c>baseline</c>: start-up configuration findings (sdk/rasp/README.md, "Security baseline").
    /// Never blocks; <see cref="RaspMode.Block"/> is treated as <see cref="RaspMode.Monitor"/>.
    /// </summary>
    Baseline,

    /// <summary>
    /// <c>custom_rule</c>: the organization's own rules from the signed config (sdk/rasp/README.md,
    /// "Custom rules"). A rule's action is capped by this mode.
    /// </summary>
    CustomRule,

    /// <summary>
    /// <c>deception</c>: decoy paths from the signed config (sdk/rasp/README.md, "Deception"). The
    /// config's <c>action</c> decides, capped by this mode; unset leaves it to the action.
    /// </summary>
    Deception,

    /// <summary><c>malicious_upload</c>: what an uploaded file is (README "Uploads").</summary>
    MaliciousUpload,

    /// <summary><c>upload_backdoor</c>: an uploaded file saved where it runs, loaded, run or made executable (README "Backdoor checks").</summary>
    UploadBackdoor,

    /// <summary>
    /// <c>ai_attack_agent</c>: autonomous pentest agents and attack tools (README "AI attack agents"): a
    /// fingerprint, an OAST callback domain, the in-app behavior score, the opt-in LLM tripwire. Block
    /// answers a marked client with a 429 and Retry-After.
    /// </summary>
    AiAttackAgent,
}

/// <summary>Where a piece of untrusted input came from.</summary>
public enum RaspInputSource
{
    /// <summary>The request being served (<c>request</c>).</summary>
    Request,

    /// <summary>Text a model returned (<c>model_output</c>).</summary>
    ModelOutput,
}

/// <summary>
/// One piece of untrusted input. <see cref="Key"/> is a location name
/// (<c>query.id</c>, <c>body.user.name</c>); the value never leaves the process.
/// </summary>
public sealed class RaspInput
{
    /// <summary>Creates an input.</summary>
    public RaspInput(string value, string key, RaspInputSource source = RaspInputSource.Request)
    {
        Value = value ?? throw new ArgumentNullException(nameof(value));
        Key = key ?? throw new ArgumentNullException(nameof(key));
        Source = source;
    }

    /// <summary>The input as received.</summary>
    public string Value { get; }

    /// <summary>Where it was found, for example <c>query.id</c>. Never a value.</summary>
    public string Key { get; }

    /// <summary>Request input or model output.</summary>
    public RaspInputSource Source { get; }
}

/// <summary>What a detector found. The engine decides what it does.</summary>
/// <remarks>
/// <see cref="Target"/> is the raw destination an allow-list rule compared (contract: "Allow-list targets"),
/// masked before it is sent; <see cref="Dialect"/> is the SQL dialect the lexer used.
/// </remarks>
internal sealed record RaspFinding(RaspAttackType Attack, string Rule, RaspInput? Input = null, string? Cve = null, RaspMode? Action = null, string? Target = null, string? Dialect = null)
{
    /// <summary>SHIELD: uploads — when set, decides instead of the attack type's mode (an upload route's policy), capped like attack modes.</summary>
    public RaspMode? Mode { get; init; }

    /// <summary>SHIELD: uploads — README "Upload event attributes"; never a file name or content.</summary>
    public UploadAttrs? Upload { get; init; }
}

/// <summary>The contract's wire names for modes, attack types and sources.</summary>
internal static class RaspNames
{
    private static readonly string[] s_attacks =
    {
        "sql_injection", "nosql_injection", "command_injection", "shell_spawn", "path_traversal", "file_write",
        "ssrf", "outbound", "deserialization", "code_injection", "xxe", "xss", "virtual_patch", "baseline", "custom_rule",
        "deception", "malicious_upload", "upload_backdoor", "ai_attack_agent",
    };

    private static readonly Dictionary<string, RaspAttackType> s_byName = Build();

    public static IReadOnlyList<RaspAttackType> AttackTypes { get; } = (RaspAttackType[])Enum.GetValues(typeof(RaspAttackType));

    /// <summary>Attack types that never block (<c>xss</c>, <c>baseline</c>): block is treated as monitor.</summary>
    public static bool MonitorOnly(RaspAttackType attack) => attack is RaspAttackType.Xss or RaspAttackType.Baseline;

    public static string Of(RaspAttackType attack) => s_attacks[(int)attack];

    public static string Of(RaspMode mode) => mode switch
    {
        RaspMode.Off => "off",
        RaspMode.Block => "block",
        _ => "monitor",
    };

    public static string Of(RaspInputSource source) => source == RaspInputSource.ModelOutput ? "model_output" : "request";

    public static bool TryAttack(string? name, out RaspAttackType attack) => s_byName.TryGetValue(name ?? string.Empty, out attack);

    /// <summary>A mode from its wire name (exact, lower-case), or null.</summary>
    public static RaspMode? Mode(string? name) => name switch
    {
        "off" => RaspMode.Off,
        "monitor" => RaspMode.Monitor,
        "block" => RaspMode.Block,
        _ => null,
    };

    public static int Rank(RaspMode mode) => mode switch
    {
        RaspMode.Off => 0,
        RaspMode.Monitor => 1,
        _ => 2,
    };

    private static Dictionary<string, RaspAttackType> Build()
    {
        var map = new Dictionary<string, RaspAttackType>(StringComparer.Ordinal);
        for (var i = 0; i < s_attacks.Length; i++)
        {
            map[s_attacks[i]] = (RaspAttackType)i;
        }

        return map;
    }
}
