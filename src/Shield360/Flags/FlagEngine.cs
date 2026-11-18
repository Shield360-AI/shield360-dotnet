using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Shield360.Flags;

/// <summary>
/// Why a flag served what it did. <see cref="Kind"/> is one of the
/// <see cref="FlagReasonKinds"/>; the other properties are set only for the
/// kinds they belong to, as in the other Shield360 SDKs.
/// </summary>
public sealed class FlagReason
{
    /// <summary>Creates a reason of one kind.</summary>
    public FlagReason(string kind)
    {
        Kind = kind;
    }

    /// <summary>OFF, ARCHIVED, RULE_MATCH, FALLTHROUGH or ERROR from the engine; NOT_READY, FLAG_NOT_FOUND or WRONG_TYPE from the client.</summary>
    public string Kind { get; }

    /// <summary>The index of the matching rule (RULE_MATCH).</summary>
    public int? RuleIndex { get; init; }

    /// <summary>The ID of the matching rule (RULE_MATCH).</summary>
    public string? RuleId { get; init; }

    /// <summary>True when a percentage rollout picked the variation.</summary>
    public bool? InRollout { get; init; }

    /// <summary>The rollout bucket (0..99,999) the context fell in.</summary>
    public int? Bucket { get; init; }

    /// <summary>MALFORMED_FLAG when the flag did not validate (ERROR).</summary>
    public string? ErrorKind { get; init; }

    /// <summary>The reason as JSON, leaving out the properties that are not set.</summary>
    public JsonObject ToJson()
    {
        var o = new JsonObject { ["kind"] = Kind };
        if (RuleIndex is { } i)
        {
            o["ruleIndex"] = i;
        }

        if (RuleId is not null)
        {
            o["ruleId"] = RuleId;
        }

        if (InRollout is { } r)
        {
            o["inRollout"] = r;
        }

        if (Bucket is { } b)
        {
            o["bucket"] = b;
        }

        if (ErrorKind is not null)
        {
            o["errorKind"] = ErrorKind;
        }

        return o;
    }

    internal FlagReason WithRollout(int bucket) => new(Kind)
    {
        RuleIndex = RuleIndex,
        RuleId = RuleId,
        InRollout = true,
        Bucket = bucket,
        ErrorKind = ErrorKind,
    };
}

/// <summary>The values of <see cref="FlagReason.Kind"/>.</summary>
public static class FlagReasonKinds
{
    /// <summary>The flag is off: its off variation was served.</summary>
    public const string Off = "OFF";

    /// <summary>The flag is archived: its off variation was served.</summary>
    public const string Archived = "ARCHIVED";

    /// <summary>A rule matched.</summary>
    public const string RuleMatch = "RULE_MATCH";

    /// <summary>No rule matched: the fallthrough was served.</summary>
    public const string Fallthrough = "FALLTHROUGH";

    /// <summary>Nothing was served (a malformed flag, or an error in the client); the caller's default applies.</summary>
    public const string Error = "ERROR";

    /// <summary>The client has not fetched the rules yet; the caller's default applies.</summary>
    public const string NotReady = "NOT_READY";

    /// <summary>The flag does not exist, or is for another application; the caller's default applies.</summary>
    public const string FlagNotFound = "FLAG_NOT_FOUND";

    /// <summary>The served value is not of the default's kind; the caller's default applies.</summary>
    public const string WrongType = "WRONG_TYPE";

    /// <summary>The <see cref="FlagReason.ErrorKind"/> of a flag that did not validate.</summary>
    public const string MalformedFlag = "MALFORMED_FLAG";
}

/// <summary>What the engine served a context.</summary>
public sealed class FlagEvaluation
{
    internal FlagEvaluation(string? variation, JsonNode? value, FlagReason reason)
    {
        Variation = variation;
        Value = value;
        Reason = reason;
    }

    /// <summary>The served variation's key; null only when the flag is malformed.</summary>
    public string? Variation { get; }

    /// <summary>The served variation's value (a copy); null when nothing was served.</summary>
    public JsonNode? Value { get; }

    /// <summary>Why it was served.</summary>
    public FlagReason Reason { get; }

    /// <summary><c>{variation, value, reason}</c>, as the other SDKs return it.</summary>
    public JsonObject ToJson() => new()
    {
        ["variation"] = Variation,
        ["value"] = Value?.DeepClone(),
        ["reason"] = Reason.ToJson(),
    };
}

/// <summary>One problem with a flag or segment definition.</summary>
/// <param name="Path">Where it is, such as <c>rules.0.conditions.1.operator</c>; empty for the whole definition.</param>
/// <param name="Code">What it is, such as <c>operator_invalid</c>.</param>
public sealed record FlagValidationError(string Path, string Code);

/// <summary>
/// The Shield360 feature-flag evaluation engine: a port of
/// <c>sdk/flags-core/src/engine.ts</c>, held to the same test vectors as the
/// TypeScript, server and Python implementations. Definitions and contexts are
/// JSON; nothing here reads the clock, randomness or the network, and
/// <see cref="Evaluate(JsonNode?, JsonNode?, JsonNode?)"/> never throws.
/// </summary>
public static class FlagEngine
{
    /// <summary>Buckets run 0..99,999: a rollout weight of 1 is a thousandth of a percent.</summary>
    public const int Buckets = 100000;

    /// <summary>The context attribute a rollout buckets by when it names none.</summary>
    public const string DefaultBucketBy = "key";

    /// <summary>The attribute a segment condition names.</summary>
    public const string SegmentAttribute = "segment";

    internal const int MaxVariations = 20;
    internal const int MaxRules = 50;
    internal const int MaxConditions = 20;
    internal const int MaxConditionValues = 100;
    internal const int MaxSegmentsPerCondition = 20;

    private static readonly string[] s_flagTypes = { "boolean", "string", "number", "json" };

    private static readonly string[] s_operators =
    {
        "equals", "not_equals", "in", "not_in", "contains", "starts_with",
        "lt", "lte", "gt", "gte",
        "semver_eq", "semver_lt", "semver_lte", "semver_gt", "semver_gte",
        "in_segment", "not_in_segment",
    };

    // JavaScript's $ (without the m flag) matches only at the end; .NET's also
    // matches before a final newline, so these use \z.
    private const RegexOptions Options = RegexOptions.CultureInvariant;
    private static readonly Regex s_flagKey = new(@"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?\z", Options);
    private static readonly Regex s_variationKey = new(@"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}\z", Options);
    private static readonly Regex s_ruleId = new(@"^[A-Za-z0-9_-]{1,64}\z", Options);
    private static readonly Regex s_attribute = new(@"^[A-Za-z_][A-Za-z0-9_.-]{0,63}\z", Options);
    private static readonly Regex s_salt = new(@"^[A-Za-z0-9_-]{1,64}\z", Options);
    private static readonly Regex s_numberText = new(@"^-?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?\z", Options);
    private static readonly Regex s_numericId = new(@"^[0-9]+\z", Options);
    private static readonly Regex s_semver = new(
        @"^v?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z",
        Options);

    // ------------------------------------------------------------ JSON kinds

    internal enum Kind
    {
        Null,
        Bool,
        Number,
        String,
        Array,
        Object,
        Other,
    }

    internal static Kind KindOf(JsonNode? node)
    {
        switch (node)
        {
            case null:
                return Kind.Null;
            case JsonObject:
                return Kind.Object;
            case JsonArray:
                return Kind.Array;
            case JsonValue v:
                switch (v.GetValueKind())
                {
                    case JsonValueKind.String:
                        return Kind.String;
                    case JsonValueKind.Number:
                        return Kind.Number;
                    case JsonValueKind.True:
                    case JsonValueKind.False:
                        return Kind.Bool;
                    case JsonValueKind.Null:
                        return Kind.Null;
                    default:
                        return Kind.Other;
                }

            default:
                return Kind.Other;
        }
    }

    internal static bool TryString(JsonNode? node, out string value)
    {
        value = string.Empty;
        if (node is not JsonValue v || v.GetValueKind() != JsonValueKind.String)
        {
            return false;
        }

        if (v.TryGetValue<string>(out var s) && s is not null)
        {
            value = s;
            return true;
        }

        // A value made from a char, Guid, DateTime and so on: read its JSON text.
        var text = JsonSerializer.Deserialize<string>(v.ToJsonString());
        if (text is null)
        {
            return false;
        }

        value = text;
        return true;
    }

    internal static bool TryBool(JsonNode? node, out bool value)
    {
        value = false;
        if (node is not JsonValue v)
        {
            return false;
        }

        switch (v.GetValueKind())
        {
            case JsonValueKind.True:
                value = true;
                return true;
            case JsonValueKind.False:
                return true;
            default:
                return false;
        }
    }

    /// <summary>Whether the node is a JSON number (JavaScript's <c>typeof v === 'number'</c>); the value may not be finite.</summary>
    internal static bool TryNumber(JsonNode? node, out double value)
    {
        value = 0;
        if (node is not JsonValue v || v.GetValueKind() != JsonValueKind.Number)
        {
            return false;
        }

        if (v.TryGetValue<double>(out value))
        {
            return true;
        }

        // Out of double range (1e400), or a value made from another numeric type.
        value = ParseDouble(v.ToJsonString()) ?? double.NaN;
        return true;
    }

    private static double? ParseDouble(string text)
    {
        try
        {
            return double.Parse(text, NumberStyles.Float, CultureInfo.InvariantCulture);
        }
        catch (OverflowException)
        {
            // .NET Framework throws where .NET Core returns infinity.
            return text.TrimStart().StartsWith("-", StringComparison.Ordinal) ? double.NegativeInfinity : double.PositiveInfinity;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static bool IsFinite(double d) => !double.IsNaN(d) && !double.IsInfinity(d);

    private static bool Has(JsonObject o, string name, out JsonNode? value) => o.TryGetPropertyValue(name, out value);

    private static JsonNode? Get(JsonObject o, string name) => o.TryGetPropertyValue(name, out var v) ? v : null;

    private static bool IsFlagKey(JsonNode? n) => TryString(n, out var s) && s_flagKey.IsMatch(s);

    private static bool IsVariationKey(JsonNode? n) => TryString(n, out var s) && s_variationKey.IsMatch(s);

    private static bool IsAttributeName(JsonNode? n) => TryString(n, out var s) && s_attribute.IsMatch(s);

    private static bool IsOperator(JsonNode? n) => TryString(n, out var s) && Array.IndexOf(s_operators, s) >= 0;

    private static bool IsSegmentOperator(JsonNode? n) =>
        TryString(n, out var s) && (s == "in_segment" || s == "not_in_segment");

    // --------------------------------------------------------------- hashing

    /// <summary>
    /// The UTF-8 bytes of a string, with each lone surrogate written as U+FFFD
    /// (as JavaScript's TextEncoder writes it).
    /// </summary>
    public static byte[] Utf8(string text)
    {
        if (text is null)
        {
            throw new ArgumentNullException(nameof(text));
        }

        var output = new List<byte>(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            int c = text[i];
            if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.Length)
            {
                int d = text[i + 1];
                if (d >= 0xdc00 && d <= 0xdfff)
                {
                    c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
                    i++;
                }
            }

            if (c >= 0xd800 && c <= 0xdfff)
            {
                c = 0xfffd;
            }

            if (c < 0x80)
            {
                output.Add((byte)c);
            }
            else if (c < 0x800)
            {
                output.Add((byte)(0xc0 | (c >> 6)));
                output.Add((byte)(0x80 | (c & 63)));
            }
            else if (c < 0x10000)
            {
                output.Add((byte)(0xe0 | (c >> 12)));
                output.Add((byte)(0x80 | ((c >> 6) & 63)));
                output.Add((byte)(0x80 | (c & 63)));
            }
            else
            {
                output.Add((byte)(0xf0 | (c >> 18)));
                output.Add((byte)(0x80 | ((c >> 12) & 63)));
                output.Add((byte)(0x80 | ((c >> 6) & 63)));
                output.Add((byte)(0x80 | (c & 63)));
            }
        }

        return output.ToArray();
    }

    /// <summary>MurmurHash3 (x86, 32-bit, seed 0) of the UTF-8 bytes of <paramref name="text"/>.</summary>
    public static uint Murmur3(string text)
    {
        var bytes = Utf8(text);
        const uint c1 = 0xcc9e2d51;
        const uint c2 = 0x1b873593;
        uint h = 0;
        var blocks = bytes.Length - (bytes.Length % 4);
        for (var i = 0; i < blocks; i += 4)
        {
            var k = bytes[i] | ((uint)bytes[i + 1] << 8) | ((uint)bytes[i + 2] << 16) | ((uint)bytes[i + 3] << 24);
            k *= c1;
            k = (k << 15) | (k >> 17);
            k *= c2;
            h ^= k;
            h = (h << 13) | (h >> 19);
            h = (h * 5) + 0xe6546b64;
        }

        uint t = 0;
        var tail = bytes.Length % 4;
        if (tail == 3)
        {
            t ^= (uint)bytes[blocks + 2] << 16;
        }

        if (tail >= 2)
        {
            t ^= (uint)bytes[blocks + 1] << 8;
        }

        if (tail >= 1)
        {
            t ^= bytes[blocks];
            t *= c1;
            t = (t << 15) | (t >> 17);
            t *= c2;
            h ^= t;
        }

        h ^= (uint)bytes.Length;
        h ^= h >> 16;
        h *= 0x85ebca6b;
        h ^= h >> 13;
        h *= 0xc2b2ae35;
        h ^= h >> 16;
        return h;
    }

    /// <summary>The bucket (0..99,999) a value falls in for a flag: stable across runs, processes and SDKs.</summary>
    public static int BucketOf(string flagKey, string salt, string value) =>
        (int)(Murmur3(flagKey + "." + salt + "." + value) % Buckets);

    // -------------------------------------------------------- attribute text

    /// <summary>
    /// The text of a scalar, the same in every SDK: strings as they are,
    /// booleans as true/false, numbers as JavaScript prints them (<c>10</c>,
    /// <c>0.5</c>, <c>1e-7</c>, <c>1e+21</c>). Null for anything else.
    /// </summary>
    public static string? TextOf(JsonNode? value)
    {
        if (TryString(value, out var s))
        {
            return s;
        }

        if (TryBool(value, out var b))
        {
            return b ? "true" : "false";
        }

        if (TryNumber(value, out var d))
        {
            return IsFinite(d) ? JsNumber(d) : null;
        }

        return null;
    }

    /// <summary>A number as JavaScript's <c>Number.prototype.toString()</c> prints it.</summary>
    public static string JsNumber(double value)
    {
        if (double.IsNaN(value))
        {
            return "NaN";
        }

        if (double.IsInfinity(value))
        {
            return value > 0 ? "Infinity" : "-Infinity";
        }

        if (value == 0)
        {
            return "0"; // -0 included
        }

        var negative = value < 0;
        var round = Shortest(Math.Abs(value));

        // Split the round-trip text into its significant digits and the
        // position of the decimal point within them (JavaScript's n).
        var exponent = 0;
        var mantissa = round;
        var e = round.IndexOf('E');
        if (e >= 0)
        {
            var sign = 1;
            for (var i = e + 1; i < round.Length; i++)
            {
                var ch = round[i];
                if (ch == '-')
                {
                    sign = -1;
                }
                else if (ch >= '0' && ch <= '9')
                {
                    exponent = (exponent * 10) + (ch - '0');
                }
            }

            exponent *= sign;
            mantissa = round.Substring(0, e);
        }

        var dot = mantissa.IndexOf('.');
        var whole = dot < 0 ? mantissa : mantissa.Substring(0, dot);
        var fraction = dot < 0 ? string.Empty : mantissa.Substring(dot + 1);
        var digits = whole + fraction;
        var n = whole.Length + exponent;
        var lead = 0;
        while (lead < digits.Length - 1 && digits[lead] == '0')
        {
            lead++;
        }

        digits = digits.Substring(lead);
        n -= lead;
        digits = digits.TrimEnd('0');
        if (digits.Length == 0)
        {
            return "0";
        }

        var k = digits.Length;
        var sb = new StringBuilder();
        if (negative)
        {
            sb.Append('-');
        }

        if (k <= n && n <= 21)
        {
            sb.Append(digits).Append('0', n - k);
        }
        else if (0 < n && n <= 21)
        {
            sb.Append(digits, 0, n).Append('.').Append(digits, n, k - n);
        }
        else if (-6 < n && n <= 0)
        {
            sb.Append("0.").Append('0', -n).Append(digits);
        }
        else
        {
            var exp = n - 1;
            sb.Append(digits[0]);
            if (k > 1)
            {
                sb.Append('.').Append(digits, 1, k - 1);
            }

            sb.Append('e').Append(exp < 0 ? '-' : '+').Append(Math.Abs(exp).ToString(CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }

    private static string Shortest(double value)
    {
#if NETCOREAPP3_0_OR_GREATER
        // .NET Core 3.0 and later print the shortest text that round-trips.
        return value.ToString("R", CultureInfo.InvariantCulture);
#else
        for (var precision = 15; precision < 17; precision++)
        {
            var text = value.ToString("G" + precision.ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);
            if (double.Parse(text, NumberStyles.Float, CultureInfo.InvariantCulture) == value)
            {
                return text;
            }
        }

        return value.ToString("G17", CultureInfo.InvariantCulture);
#endif
    }

    /// <summary>A finite number, or the text of one (no spaces); null otherwise.</summary>
    public static double? NumberOf(JsonNode? value)
    {
        if (TryNumber(value, out var d))
        {
            return IsFinite(d) ? d : null;
        }

        if (TryString(value, out var s) && s_numberText.IsMatch(s))
        {
            var n = ParseDouble(s);
            return n is { } x && IsFinite(x) ? x : null;
        }

        return null;
    }

    /// <summary>JavaScript's <c>String(v)</c>, for the one place the engine uses it.</summary>
    private static string JsString(JsonNode? node, bool present)
    {
        if (!present)
        {
            return "undefined";
        }

        switch (KindOf(node))
        {
            case Kind.Null:
                return "null";
            case Kind.String:
            case Kind.Bool:
            case Kind.Number:
                if (TryNumber(node, out var d))
                {
                    return JsNumber(d);
                }

                return TextOf(node) ?? string.Empty;
            case Kind.Array:
                var parts = new List<string>();
                foreach (var item in (JsonArray)node!)
                {
                    parts.Add(item is null ? string.Empty : JsString(item, true));
                }

                return string.Join(",", parts);
            default:
                return "[object Object]";
        }
    }

    // ---------------------------------------------------------------- semver

    internal sealed class SemVer
    {
        public double Major;
        public double Minor;
        public double Patch;
        public string[] Pre = Array.Empty<string>();
    }

    internal static SemVer? ParseSemver(JsonNode? value)
    {
        if (!TryString(value, out var s))
        {
            return null;
        }

        var m = s_semver.Match(s);
        if (!m.Success)
        {
            return null;
        }

        return new SemVer
        {
            Major = ParseDouble(m.Groups[1].Value) ?? 0,
            Minor = m.Groups[2].Success ? ParseDouble(m.Groups[2].Value) ?? 0 : 0,
            Patch = m.Groups[3].Success ? ParseDouble(m.Groups[3].Value) ?? 0 : 0,
            Pre = m.Groups[4].Success ? m.Groups[4].Value.Split('.') : Array.Empty<string>(),
        };
    }

    /// <summary>-1, 0 or 1, by semver precedence.</summary>
    internal static int CompareSemver(SemVer a, SemVer b)
    {
        if (a.Major != b.Major)
        {
            return a.Major < b.Major ? -1 : 1;
        }

        if (a.Minor != b.Minor)
        {
            return a.Minor < b.Minor ? -1 : 1;
        }

        if (a.Patch != b.Patch)
        {
            return a.Patch < b.Patch ? -1 : 1;
        }

        if (a.Pre.Length == 0 || b.Pre.Length == 0)
        {
            if (a.Pre.Length == b.Pre.Length)
            {
                return 0;
            }

            return a.Pre.Length > 0 ? -1 : 1; // a pre-release comes before its release
        }

        var n = Math.Min(a.Pre.Length, b.Pre.Length);
        for (var i = 0; i < n; i++)
        {
            var x = a.Pre[i];
            var y = b.Pre[i];
            if (x == y)
            {
                continue;
            }

            var xn = s_numericId.IsMatch(x);
            var yn = s_numericId.IsMatch(y);
            if (xn && yn)
            {
                return (ParseDouble(x) ?? 0) < (ParseDouble(y) ?? 0) ? -1 : 1;
            }

            if (xn != yn)
            {
                return xn ? -1 : 1;
            }

            return string.CompareOrdinal(x, y) < 0 ? -1 : 1;
        }

        if (a.Pre.Length == b.Pre.Length)
        {
            return 0;
        }

        return a.Pre.Length < b.Pre.Length ? -1 : 1;
    }

    // -------------------------------------------------------------- matching

    private static bool AnyValue(JsonArray values, Func<JsonNode?, bool> test)
    {
        foreach (var v in values)
        {
            if (test(v))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ScalarMatches(string op, JsonNode? actual, JsonArray values)
    {
        switch (op)
        {
            case "equals":
            case "in":
            {
                var text = TextOf(actual);
                return text is not null && AnyValue(values, v => TextOf(v) == text);
            }

            case "contains":
            case "starts_with":
            {
                var text = TextOf(actual);
                if (text is null)
                {
                    return false;
                }

                return AnyValue(values, v =>
                {
                    var want = TextOf(v);
                    if (want is null)
                    {
                        return false;
                    }

#pragma warning disable CA2249 // string.Contains(string, StringComparison) is not in netstandard2.0.
                    return op == "contains"
                        ? text.IndexOf(want, StringComparison.Ordinal) >= 0
                        : text.StartsWith(want, StringComparison.Ordinal);
#pragma warning restore CA2249
                });
            }

            case "lt":
            case "lte":
            case "gt":
            case "gte":
            {
                if (NumberOf(actual) is not { } n)
                {
                    return false;
                }

                return AnyValue(values, v =>
                {
                    if (NumberOf(v) is not { } w)
                    {
                        return false;
                    }

                    return op switch
                    {
                        "lt" => n < w,
                        "lte" => n <= w,
                        "gt" => n > w,
                        _ => n >= w,
                    };
                });
            }

            case "semver_eq":
            case "semver_lt":
            case "semver_lte":
            case "semver_gt":
            case "semver_gte":
            {
                var a = ParseSemver(actual);
                if (a is null)
                {
                    return false;
                }

                return AnyValue(values, v =>
                {
                    var b = ParseSemver(v);
                    if (b is null)
                    {
                        return false;
                    }

                    var c = CompareSemver(a, b);
                    return op switch
                    {
                        "semver_eq" => c == 0,
                        "semver_lt" => c < 0,
                        "semver_lte" => c <= 0,
                        "semver_gt" => c > 0,
                        _ => c >= 0,
                    };
                });
            }

            default:
                return false;
        }
    }

    /// <summary>
    /// Whether the context satisfies one condition of a valid flag. A missing
    /// (or null) attribute never matches, negated operators included. An array
    /// attribute matches a positive operator when any element does, and a
    /// negated one when none does.
    /// </summary>
    private static bool ConditionMatches(JsonObject condition, JsonObject context, IList<JsonNode?>? segments)
    {
        var opNode = Get(condition, "operator");
        if (IsSegmentOperator(opNode))
        {
            return SegmentConditionMatches(condition, context, segments);
        }

        TryString(Get(condition, "attribute"), out var attribute);
        var actual = Get(context, attribute);
        if (actual is null || KindOf(actual) == Kind.Null)
        {
            return false;
        }

        var items = actual is JsonArray array ? (IList<JsonNode?>)array : new[] { actual };
        if (items.Count == 0)
        {
            return false;
        }

        TryString(opNode, out var op);
        var values = (JsonArray)Get(condition, "values")!;
        var positive = op == "not_equals" ? "equals" : op == "not_in" ? "in" : null;
        if (positive is not null)
        {
            foreach (var item in items)
            {
                if (ScalarMatches(positive, item, values))
                {
                    return false;
                }
            }

            return true;
        }

        foreach (var item in items)
        {
            if (ScalarMatches(op, item, values))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The valid segment of this key among <paramref name="segments"/>, or null.</summary>
    private static JsonObject? FindSegment(IList<JsonNode?>? segments, JsonNode? key)
    {
        if (segments is null || !TryString(key, out var k))
        {
            return null;
        }

        foreach (var s in segments)
        {
            if (s is JsonObject o && TryString(Get(o, "key"), out var sk) && sk == k)
            {
                return ValidateSegment(o).Count > 0 ? null : o;
            }
        }

        return null;
    }

    private static bool SegmentMatches(JsonObject segment, JsonObject context)
    {
        var conditions = (JsonArray)Get(segment, "conditions")!;
        if (conditions.Count == 0)
        {
            return false;
        }

        foreach (var c in conditions)
        {
            var condition = (JsonObject)c!;
            if (IsSegmentOperator(Get(condition, "operator")) || !ConditionMatches(condition, context, null))
            {
                return false;
            }
        }

        return true;
    }

    private static bool SegmentConditionMatches(JsonObject condition, JsonObject context, IList<JsonNode?>? segments)
    {
        var inAny = false;
        foreach (var key in (JsonArray)Get(condition, "values")!)
        {
            var segment = FindSegment(segments, key);
            if (segment is null)
            {
                return false; // an unknown segment never matches, either way
            }

            if (SegmentMatches(segment, context))
            {
                inAny = true;
            }
        }

        TryString(Get(condition, "operator"), out var op);
        return op == "in_segment" ? inAny : !inAny;
    }

    private static bool RuleMatches(JsonObject rule, JsonObject context, IList<JsonNode?>? segments)
    {
        var conditions = (JsonArray)Get(rule, "conditions")!;
        if (conditions.Count == 0)
        {
            return false;
        }

        foreach (var c in conditions)
        {
            if (!ConditionMatches((JsonObject)c!, context, segments))
            {
                return false;
            }
        }

        return true;
    }

    private static (string Variation, int Bucket) RolloutVariation(string flagKey, string salt, JsonObject rollout, JsonObject context)
    {
        var by = TryString(Get(rollout, "bucketBy"), out var b) && b.Length > 0 ? b : DefaultBucketBy;
        var text = TextOf(Get(context, by));
        // Without the attribute everyone is bucket 0: the first variation with weight.
        var bucket = text is null ? 0 : BucketOf(flagKey, salt, text);
        double upper = 0;
        var weights = (JsonArray)Get(rollout, "weights")!;
        string last = string.Empty;
        foreach (var w in weights)
        {
            var weight = (JsonObject)w!;
            TryNumber(Get(weight, "weight"), out var amount);
            TryString(Get(weight, "variation"), out last);
            upper += amount;
            if (bucket < upper)
            {
                return (last, bucket);
            }
        }

        // Weights are validated to sum to Buckets; this is unreachable for a valid flag.
        return (last, bucket);
    }

    // ------------------------------------------------------------ validation

    /// <summary>Whether <paramref name="value"/> is of the flag's type. <paramref name="present"/> is false for a missing value.</summary>
    private static bool ValueMatchesType(string type, JsonNode? value, bool present)
    {
        switch (type)
        {
            case "boolean":
                return TryBool(value, out _);
            case "string":
                return TryString(value, out _);
            case "number":
                return TryNumber(value, out var d) && IsFinite(d);
            case "json":
                return present && PlainJson(value, 0);
            default:
                return false;
        }
    }

    /// <summary>Null, a string, a boolean, a finite number, or arrays and objects of them, at most 20 deep.</summary>
    internal static bool PlainJson(JsonNode? value, int depth)
    {
        if (depth > 20)
        {
            return false;
        }

        switch (KindOf(value))
        {
            case Kind.Null:
            case Kind.String:
            case Kind.Bool:
                return true;
            case Kind.Number:
                return TryNumber(value, out var d) && IsFinite(d);
            case Kind.Array:
                foreach (var item in (JsonArray)value!)
                {
                    if (!PlainJson(item, depth + 1))
                    {
                        return false;
                    }
                }

                return true;
            case Kind.Object:
                foreach (var kv in (JsonObject)value!)
                {
                    if (!PlainJson(kv.Value, depth + 1))
                    {
                        return false;
                    }
                }

                return true;
            default:
                return false;
        }
    }

    private static void ValidateServe(JsonNode? serve, string path, List<string> variationKeys, List<FlagValidationError> errors)
    {
        if (serve is not JsonObject s)
        {
            errors.Add(new FlagValidationError(path, "serve_invalid"));
            return;
        }

        var hasVariation = Has(s, "variation", out var variation);
        var hasRollout = Has(s, "rollout", out var rolloutNode);
        if (hasVariation == hasRollout)
        {
            errors.Add(new FlagValidationError(path, "serve_invalid"));
            return;
        }

        if (hasVariation)
        {
            if (!TryString(variation, out var v) || !variationKeys.Contains(v))
            {
                errors.Add(new FlagValidationError(path + ".variation", "variation_unknown"));
            }

            return;
        }

        if (rolloutNode is not JsonObject rollout || Get(rollout, "weights") is not JsonArray weights || weights.Count == 0)
        {
            errors.Add(new FlagValidationError(path + ".rollout", "rollout_invalid"));
            return;
        }

        if (Has(rollout, "bucketBy", out var bucketBy) && !IsAttributeName(bucketBy))
        {
            errors.Add(new FlagValidationError(path + ".rollout.bucketBy", "attribute_invalid"));
        }

        if (weights.Count > MaxVariations)
        {
            errors.Add(new FlagValidationError(path + ".rollout.weights", "too_many"));
        }

        double total = 0;
        var seen = new List<string>();
        for (var i = 0; i < weights.Count; i++)
        {
            var at = path + ".rollout.weights." + i.ToString(CultureInfo.InvariantCulture);
            if (weights[i] is not JsonObject w)
            {
                errors.Add(new FlagValidationError(at, "rollout_invalid"));
                continue;
            }

            if (!TryString(Get(w, "variation"), out var wv) || !variationKeys.Contains(wv))
            {
                errors.Add(new FlagValidationError(at + ".variation", "variation_unknown"));
            }
            else if (seen.Contains(wv))
            {
                errors.Add(new FlagValidationError(at + ".variation", "duplicate"));
            }
            else
            {
                seen.Add(wv);
            }

            if (!TryNumber(Get(w, "weight"), out var weight) || !IsFinite(weight) || Math.Floor(weight) != weight || weight < 0 || weight > Buckets)
            {
                errors.Add(new FlagValidationError(at + ".weight", "weight_invalid"));
            }
            else
            {
                total += weight;
            }
        }

        if (total != Buckets)
        {
            errors.Add(new FlagValidationError(path + ".rollout.weights", "weights_sum"));
        }
    }

    private static void ValidateCondition(JsonNode? node, string path, List<FlagValidationError> errors, bool inSegment)
    {
        if (node is not JsonObject c)
        {
            errors.Add(new FlagValidationError(path, "condition_invalid"));
            return;
        }

        var hasOperator = Has(c, "operator", out var opNode);
        if (IsSegmentOperator(opNode))
        {
            if (inSegment)
            {
                errors.Add(new FlagValidationError(path + ".operator", "segment_nested"));
                return;
            }

            if (!TryString(Get(c, "attribute"), out var a) || a != SegmentAttribute)
            {
                errors.Add(new FlagValidationError(path + ".attribute", "attribute_invalid"));
            }

            if (Get(c, "values") is not JsonArray keys || keys.Count == 0 || keys.Count > MaxSegmentsPerCondition)
            {
                errors.Add(new FlagValidationError(path + ".values", "values_invalid"));
                return;
            }

            var seen = new List<string>();
            for (var i = 0; i < keys.Count; i++)
            {
                var at = path + ".values." + i.ToString(CultureInfo.InvariantCulture);
                if (!IsFlagKey(keys[i]))
                {
                    errors.Add(new FlagValidationError(at, "value_not_segment"));
                }
                else
                {
                    TryString(keys[i], out var k);
                    if (seen.Contains(k))
                    {
                        errors.Add(new FlagValidationError(at, "duplicate"));
                    }
                    else
                    {
                        seen.Add(k);
                    }
                }
            }

            return;
        }

        if (!IsAttributeName(Get(c, "attribute")))
        {
            errors.Add(new FlagValidationError(path + ".attribute", "attribute_invalid"));
        }

        if (!IsOperator(opNode))
        {
            errors.Add(new FlagValidationError(path + ".operator", "operator_invalid"));
        }

        if (Get(c, "values") is not JsonArray values || values.Count == 0 || values.Count > MaxConditionValues)
        {
            errors.Add(new FlagValidationError(path + ".values", "values_invalid"));
            return;
        }

        var isString = TryString(opNode, out var opText);
        var single = isString && (opText == "equals" || opText == "not_equals");
        if (single && values.Count != 1)
        {
            errors.Add(new FlagValidationError(path + ".values", "values_invalid"));
        }

        var op = JsString(opNode, hasOperator);
        for (var i = 0; i < values.Count; i++)
        {
            var at = path + ".values." + i.ToString(CultureInfo.InvariantCulture);
            var v = values[i];
            var scalar = TryString(v, out _) || TryBool(v, out _) || (TryNumber(v, out var d) && IsFinite(d));
            if (!scalar)
            {
                errors.Add(new FlagValidationError(at, "value_invalid"));
                continue;
            }

            if ((op == "lt" || op == "lte" || op == "gt" || op == "gte") && NumberOf(v) is null)
            {
                errors.Add(new FlagValidationError(at, "value_not_number"));
            }

            if (op.StartsWith("semver_", StringComparison.Ordinal) && ParseSemver(v) is null)
            {
                errors.Add(new FlagValidationError(at, "value_not_semver"));
            }
        }
    }

    /// <summary>
    /// Everything wrong with a flag definition, by path; empty when it is valid.
    /// The server refuses to save an invalid flag; the SDKs treat one as
    /// malformed and serve the caller's default.
    /// </summary>
    public static IReadOnlyList<FlagValidationError> ValidateFlag(JsonNode? flag)
    {
        var errors = new List<FlagValidationError>();
        if (flag is not JsonObject f)
        {
            errors.Add(new FlagValidationError(string.Empty, "flag_invalid"));
            return errors;
        }

        if (!IsFlagKey(Get(f, "key")))
        {
            errors.Add(new FlagValidationError("key", "key_invalid"));
        }

        var knownType = TryString(Get(f, "type"), out var type) && Array.IndexOf(s_flagTypes, type) >= 0;
        if (!knownType)
        {
            errors.Add(new FlagValidationError("type", "type_invalid"));
        }

        if (!TryBool(Get(f, "on"), out _))
        {
            errors.Add(new FlagValidationError("on", "on_invalid"));
        }

        if (!TryString(Get(f, "salt"), out var salt) || !s_salt.IsMatch(salt))
        {
            errors.Add(new FlagValidationError("salt", "salt_invalid"));
        }

        if (Has(f, "archived", out var archived) && !TryBool(archived, out _))
        {
            errors.Add(new FlagValidationError("archived", "archived_invalid"));
        }

        var keys = new List<string>();
        if (Get(f, "variations") is not JsonArray variations || variations.Count < 2 || variations.Count > MaxVariations)
        {
            errors.Add(new FlagValidationError("variations", "variations_count"));
        }
        else
        {
            for (var i = 0; i < variations.Count; i++)
            {
                var at = "variations." + i.ToString(CultureInfo.InvariantCulture);
                if (variations[i] is not JsonObject v)
                {
                    errors.Add(new FlagValidationError(at, "variation_invalid"));
                    continue;
                }

                var keyNode = Get(v, "key");
                if (!IsVariationKey(keyNode))
                {
                    errors.Add(new FlagValidationError(at + ".key", "variation_key_invalid"));
                }
                else
                {
                    TryString(keyNode, out var key);
                    if (keys.Contains(key))
                    {
                        errors.Add(new FlagValidationError(at + ".key", "duplicate"));
                    }
                    else
                    {
                        keys.Add(key);
                    }
                }

                if (Has(v, "name", out var name) && !TryString(name, out _))
                {
                    errors.Add(new FlagValidationError(at + ".name", "name_invalid"));
                }

                var hasValue = Has(v, "value", out var value);
                if (knownType && !ValueMatchesType(type, value, hasValue))
                {
                    errors.Add(new FlagValidationError(at + ".value", "value_type"));
                }
            }

            var variationErrors = errors.Exists(e => e.Path.StartsWith("variations", StringComparison.Ordinal));
            if (type == "boolean" && knownType && !variationErrors)
            {
                TryBool(Get((JsonObject)variations[0]!, "value"), out var first);
                TryBool(Get((JsonObject)variations[1]!, "value"), out var second);
                if (variations.Count != 2 || first == second)
                {
                    errors.Add(new FlagValidationError("variations", "boolean_variations"));
                }
            }
        }

        if (!TryString(Get(f, "offVariation"), out var off) || !keys.Contains(off))
        {
            errors.Add(new FlagValidationError("offVariation", "variation_unknown"));
        }

        if (Get(f, "rules") is not JsonArray rules || rules.Count > MaxRules)
        {
            errors.Add(new FlagValidationError("rules", "rules_invalid"));
        }
        else
        {
            var ids = new List<string>();
            for (var i = 0; i < rules.Count; i++)
            {
                var at = "rules." + i.ToString(CultureInfo.InvariantCulture);
                if (rules[i] is not JsonObject r)
                {
                    errors.Add(new FlagValidationError(at, "rule_invalid"));
                    continue;
                }

                if (!TryString(Get(r, "id"), out var id) || !s_ruleId.IsMatch(id))
                {
                    errors.Add(new FlagValidationError(at + ".id", "rule_id_invalid"));
                }
                else if (ids.Contains(id))
                {
                    errors.Add(new FlagValidationError(at + ".id", "duplicate"));
                }
                else
                {
                    ids.Add(id);
                }

                if (Has(r, "description", out var description) && !TryString(description, out _))
                {
                    errors.Add(new FlagValidationError(at + ".description", "description_invalid"));
                }

                if (Get(r, "conditions") is not JsonArray conditions || conditions.Count == 0 || conditions.Count > MaxConditions)
                {
                    errors.Add(new FlagValidationError(at + ".conditions", "conditions_count"));
                }
                else
                {
                    for (var j = 0; j < conditions.Count; j++)
                    {
                        ValidateCondition(conditions[j], at + ".conditions." + j.ToString(CultureInfo.InvariantCulture), errors, false);
                    }
                }

                ValidateServe(Get(r, "serve"), at + ".serve", keys, errors);
            }
        }

        ValidateServe(Get(f, "fallthrough"), "fallthrough", keys, errors);
        return errors;
    }

    /// <summary>
    /// Everything wrong with a segment, by path; empty when it is valid. A
    /// segment has a key (the flag key pattern) and 1..20 conditions with the
    /// same operators as a rule's, except the segment operators: segments do not nest.
    /// </summary>
    public static IReadOnlyList<FlagValidationError> ValidateSegment(JsonNode? segment)
    {
        var errors = new List<FlagValidationError>();
        if (segment is not JsonObject s)
        {
            errors.Add(new FlagValidationError(string.Empty, "segment_invalid"));
            return errors;
        }

        if (!IsFlagKey(Get(s, "key")))
        {
            errors.Add(new FlagValidationError("key", "key_invalid"));
        }

        if (Get(s, "conditions") is not JsonArray conditions || conditions.Count == 0 || conditions.Count > MaxConditions)
        {
            errors.Add(new FlagValidationError("conditions", "conditions_count"));
        }
        else
        {
            for (var j = 0; j < conditions.Count; j++)
            {
                ValidateCondition(conditions[j], "conditions." + j.ToString(CultureInfo.InvariantCulture), errors, true);
            }
        }

        return errors;
    }

    // ------------------------------------------------------------ evaluation

    private static JsonObject? VariationOf(JsonObject flag, string key)
    {
        foreach (var v in (JsonArray)Get(flag, "variations")!)
        {
            if (v is JsonObject o && TryString(Get(o, "key"), out var k) && k == key)
            {
                return o;
            }
        }

        return null;
    }

    private static FlagEvaluation Malformed() =>
        new(null, null, new FlagReason(FlagReasonKinds.Error) { ErrorKind = FlagReasonKinds.MalformedFlag });

    private static FlagEvaluation Served(JsonObject flag, string key, FlagReason reason)
    {
        var v = VariationOf(flag, key)!;
        return new FlagEvaluation(key, Get(v, "value")?.DeepClone(), reason);
    }

    /// <summary>
    /// The variation a flag serves a context (<paramref name="segments"/> are
    /// the environment's segments, a JSON array, for rules that name them):
    /// archived or off, the off variation; on, the first rule in order whose
    /// conditions all hold, else the fallthrough. A rollout picks by bucket. A
    /// malformed flag serves nothing (ERROR) so the caller's default applies.
    /// Never throws.
    /// </summary>
    public static FlagEvaluation Evaluate(JsonNode? flag, JsonNode? context = null, JsonNode? segments = null) =>
        EvaluateWith(flag, context, segments as JsonArray);

    internal static FlagEvaluation EvaluateWith(JsonNode? flag, JsonNode? context, IList<JsonNode?>? segments)
    {
        try
        {
            if (ValidateFlag(flag).Count > 0)
            {
                return Malformed();
            }

            var f = (JsonObject)flag!;
            var ctx = context as JsonObject ?? new JsonObject();
            TryString(Get(f, "offVariation"), out var off);
            TryBool(Get(f, "archived"), out var archived);
            if (archived)
            {
                return Served(f, off, new FlagReason(FlagReasonKinds.Archived));
            }

            TryBool(Get(f, "on"), out var on);
            if (!on)
            {
                return Served(f, off, new FlagReason(FlagReasonKinds.Off));
            }

            TryString(Get(f, "key"), out var key);
            TryString(Get(f, "salt"), out var salt);
            FlagEvaluation Serve(JsonObject serve, FlagReason reason)
            {
                if (Has(serve, "variation", out var fixedNode))
                {
                    TryString(fixedNode, out var fixedKey);
                    return Served(f, fixedKey, reason);
                }

                var picked = RolloutVariation(key, salt, (JsonObject)Get(serve, "rollout")!, ctx);
                return Served(f, picked.Variation, reason.WithRollout(picked.Bucket));
            }

            var rules = (JsonArray)Get(f, "rules")!;
            for (var i = 0; i < rules.Count; i++)
            {
                var rule = (JsonObject)rules[i]!;
                if (RuleMatches(rule, ctx, segments))
                {
                    TryString(Get(rule, "id"), out var id);
                    return Serve((JsonObject)Get(rule, "serve")!, new FlagReason(FlagReasonKinds.RuleMatch) { RuleIndex = i, RuleId = id });
                }
            }

            return Serve((JsonObject)Get(f, "fallthrough")!, new FlagReason(FlagReasonKinds.Fallthrough));
        }
#pragma warning disable CA1031 // Evaluate never throws: anything unexpected is a malformed flag.
        catch (Exception)
#pragma warning restore CA1031
        {
            return Malformed();
        }
    }

    /// <summary>
    /// An evaluation context as JSON: strings, booleans, numbers (as JavaScript
    /// doubles), null, <see cref="JsonNode"/>/<see cref="JsonElement"/> values
    /// and lists of them. Other values are written as their invariant text.
    /// </summary>
    public static JsonObject ContextOf(IEnumerable<KeyValuePair<string, object?>>? context)
    {
        var o = new JsonObject();
        if (context is null)
        {
            return o;
        }

        foreach (var kv in context)
        {
            if (kv.Key is not null)
            {
                o[kv.Key] = ToNode(kv.Value, 0);
            }
        }

        return o;
    }

    internal static JsonNode? ToNode(object? value, int depth)
    {
        switch (value)
        {
            case null:
                return null;
            case JsonNode node:
                return node.DeepClone();
            case JsonElement element:
                return element.ValueKind == JsonValueKind.Undefined ? null : JsonNode.Parse(element.GetRawText());
            case string s:
                return JsonValue.Create(s);
            case bool b:
                return JsonValue.Create(b);
            case char ch:
                return JsonValue.Create(ch.ToString());
            case byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal:
                // Every number is a double, as in JavaScript.
                return JsonValue.Create(Convert.ToDouble(value, CultureInfo.InvariantCulture));
            case Enum e:
                return JsonValue.Create(e.ToString());
            case IEnumerable<KeyValuePair<string, object?>> map when depth < 32:
            {
                var o = new JsonObject();
                foreach (var kv in map)
                {
                    o[kv.Key] = ToNode(kv.Value, depth + 1);
                }

                return o;
            }

            case System.Collections.IEnumerable items when depth < 32:
            {
                var a = new JsonArray();
                foreach (var item in items)
                {
                    a.Add(ToNode(item, depth + 1));
                }

                return a;
            }

            default:
                return JsonValue.Create(Convert.ToString(value, CultureInfo.InvariantCulture));
        }
    }
}
