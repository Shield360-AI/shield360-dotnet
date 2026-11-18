using System;
using System.Collections.Generic;

namespace Shield360.Rasp;

/// <summary>
/// Runtime application self-protection (RASP) settings, set on
/// <see cref="Shield360Options.Rasp"/> or with <c>services.AddShield360Rasp(...)</c>.
/// RASP is off until the app sets these (or <c>SHIELD360_RASP=monitor|block</c>);
/// <c>SHIELD360_RASP=off</c> always wins. sdk/rasp/README.md is the contract.
/// </summary>
public sealed class RaspOptions
{
    /// <summary>
    /// Turns RASP on. Setting <see cref="Shield360Options.Rasp"/> turns it on unless this is
    /// <c>false</c>. <c>SHIELD360_RASP=monitor|block</c> turns it on too; <c>off</c> always wins.
    /// </summary>
    public bool? Enabled { get; set; }

    /// <summary>
    /// The mode of every attack type without its own. Default: <see cref="RaspMode.Monitor"/>,
    /// or <c>SHIELD360_RASP</c> when it says <c>block</c>.
    /// </summary>
    public RaspMode? Mode { get; set; }

    /// <summary>A mode per attack type. A local <see cref="RaspMode.Off"/> wins over the signed config.</summary>
    public IDictionary<RaspAttackType, RaspMode> Attacks { get; set; } = new Dictionary<RaspAttackType, RaspMode>();

    /// <summary>Allow-lists for commands, outbound hosts and file roots.</summary>
    public RaspAllowOptions Allow { get; set; } = new();

    /// <summary>
    /// Treat model output seen by the SDK's LLM instrumentation (<c>UseShield360()</c>)
    /// as untrusted input. Default: <c>true</c>.
    /// </summary>
    public bool ModelOutput { get; set; } = true;

    /// <summary>Poll the signed config from Shield360 when a URL and API key are set. Default: <c>true</c>.</summary>
    public bool Remote { get; set; } = true;

    /// <summary>
    /// Required to use the signed config: the environment's public key, as a JWK
    /// (<c>{"kty":"OKP","crv":"Ed25519","x":"…","kid":"…"}</c>), a JWKS
    /// (<c>{"keys":[…]}</c>, so a rotation can list the old and new key) or the bare
    /// base64url <c>x</c>. Environment: <c>SHIELD360_CONFIG_PUBLIC_KEY</c>. Copy it
    /// from the app's Runtime protection settings in Shield360. Without it the signed
    /// config is not fetched and RASP runs its built-in defaults in monitor mode.
    /// </summary>
    public string? ConfigPublicKey { get; set; }

    /// <summary>
    /// Development only: trust on first use (pin the first key the server names).
    /// Environment: <c>SHIELD360_CONFIG_TOFU=dev</c>. Ignored when <c>ASPNETCORE_ENVIRONMENT</c>,
    /// <c>DOTNET_ENVIRONMENT</c>, <c>ENVIRONMENT</c> or <c>NODE_ENV</c> is <c>production</c>.
    /// Never set it in production.
    /// </summary>
    public bool AllowUnpinnedConfig { get; set; }

    /// <summary>Where the last verified config is cached. Default: the OS temp directory + <c>shield360-rasp</c>.</summary>
    public string? CacheDir { get; set; }

    /// <summary>
    /// Check every <c>HttpClient</c> request and every SqlClient command (Microsoft.Data.SqlClient,
    /// System.Data.SqlClient) through the diagnostic events those libraries raise before the
    /// call. Default: <c>true</c>.
    /// </summary>
    public bool Hooks { get; set; } = true;

    /// <summary>Report the app's loaded assemblies and their versions at start and every 24 hours. Default: <c>true</c>.</summary>
    public bool Components { get; set; } = true;

    /// <summary>
    /// Passive IAST: also report where request input reaches a sink verbatim and unparameterized
    /// during normal traffic, even when nothing attacked it (sdk/rasp/README.md, "Passive IAST").
    /// Never blocks. Default: off. <c>SHIELD360_IAST=on</c> turns it on too; <c>SHIELD360_IAST=off</c>
    /// always wins, then the signed config's switch, then this option.
    /// </summary>
    public bool? Iast { get; set; }

    /// <summary>
    /// The share of checks passive IAST looks at, 0 to 1. Default: 1, or 0.1 in production.
    /// <c>SHIELD360_IAST_SAMPLE_RATE</c> and the signed config's rate win over it.
    /// </summary>
    public double? IastSampleRate { get; set; }
}

/// <summary>RASP allow-lists. The signed config's lists replace these when it sets them.</summary>
public sealed class RaspAllowOptions
{
    /// <summary>Executables (basename) allowed to run during requests without a <c>shell_spawn</c> event.</summary>
    public IList<string> Commands { get; set; } = new List<string>();

    /// <summary>
    /// The outbound allow-list. Empty means no outbound check. <c>*.example.com</c>
    /// matches subdomains. The Shield360 URL and the OTLP endpoint are always allowed.
    /// </summary>
    public IList<string> OutboundHosts { get; set; } = new List<string>();

    /// <summary>Directories file access may use; outside them, a path holding input is <c>path_traversal</c>.</summary>
    public IList<string> FileRoots { get; set; } = new List<string>();
}

/// <summary>The allow-lists the engine applies (local options or the signed config).</summary>
internal sealed record RaspAllow(IReadOnlyList<string> Commands, IReadOnlyList<string> OutboundHosts, IReadOnlyList<string> FileRoots)
{
    public static RaspAllow Empty { get; } = new(Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>());
}
