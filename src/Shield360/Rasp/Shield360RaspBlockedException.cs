using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Shield360.Rasp;

/// <summary>
/// Thrown by a runtime protection check in block mode: the one exception RASP
/// raises on purpose. The ASP.NET Core middleware (<c>UseShield360Rasp()</c>)
/// turns it into the contract's 403; code outside a request gets the exception
/// itself. Let it propagate: catching it lets the blocked call's caller go on.
/// </summary>
public sealed class Shield360RaspBlockedException : Exception
{
    /// <summary>The message every block carries.</summary>
    public const string BlockMessage = "Request blocked by Shield360 runtime protection";

    internal Shield360RaspBlockedException(RaspAttackType attack, string rule, string eventId)
        : base($"{BlockMessage} ({RaspNames.Of(attack)}, {rule})")
    {
        AttackType = attack;
        Attack = RaspNames.Of(attack);
        Rule = rule;
        EventId = eventId;
    }

    /// <summary>
    /// SHIELD: AI attack agents — the deter answer (sdk/rasp/README.md "AI attack agents"): a marked
    /// client in block mode gets 429 with Retry-After instead of the 403, so agents that honor rate
    /// limits give up. The middleware maps it like a block.
    /// </summary>
    internal Shield360RaspBlockedException(string rule, string eventId, int retryAfterSeconds)
        : this(RaspAttackType.AiAttackAgent, rule, eventId)
    {
        StatusCode = 429;
        RetryAfterSeconds = retryAfterSeconds;
    }

    /// <summary>The body message of the deter answer (429).</summary>
    public const string DeterMessage = "Too Many Requests";

    /// <summary>The attack type.</summary>
    public RaspAttackType AttackType { get; }

    /// <summary>The attack type's contract name, for example <c>sql_injection</c>.</summary>
    public string Attack { get; }

    /// <summary>The rule that fired, for example <c>sqli.userinput</c>.</summary>
    public string Rule { get; }

    /// <summary>The reported event's id (32 hex characters).</summary>
    public string EventId { get; }

    /// <summary>The HTTP status a block maps to: 403, or 429 for the deter answer to an AI attack agent.</summary>
    public int StatusCode { get; } = 403;

    /// <summary>The deter answer's <c>Retry-After</c> in seconds (status 429); null for a block (403).</summary>
    public int? RetryAfterSeconds { get; }

    /// <summary>
    /// The JSON body of the 403 (sdk/rasp/README.md, "The block response"):
    /// <c>{"error":"…","attack":"…","rule":"…","event":"…"}</c>; for the deter answer (429),
    /// <c>{"error":"Too Many Requests"}</c>.
    /// </summary>
    public string ToResponseJson()
    {
        if (StatusCode == 429)
        {
            return "{\"error\":\"" + DeterMessage + "\"}";
        }

        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteString("error", BlockMessage);
            w.WriteString("attack", Attack);
            w.WriteString("rule", Rule);
            w.WriteString("event", EventId);
            w.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }
}
