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

    /// <summary>The attack type.</summary>
    public RaspAttackType AttackType { get; }

    /// <summary>The attack type's contract name, for example <c>sql_injection</c>.</summary>
    public string Attack { get; }

    /// <summary>The rule that fired, for example <c>sqli.userinput</c>.</summary>
    public string Rule { get; }

    /// <summary>The reported event's id (32 hex characters).</summary>
    public string EventId { get; }

    /// <summary>The HTTP status a block maps to: 403.</summary>
    public int StatusCode { get; } = 403;

    /// <summary>
    /// The JSON body of the 403 (sdk/rasp/README.md, "The block response"):
    /// <c>{"error":"…","attack":"…","rule":"…","event":"…"}</c>.
    /// </summary>
    public string ToResponseJson()
    {
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
