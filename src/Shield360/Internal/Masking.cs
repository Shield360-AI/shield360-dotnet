using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace Shield360.Internal;

/// <summary>
/// The masking contract every Shield360 SDK shares (sdk/rasp/README.md,
/// "Masking"; cases in sdk/rasp/testdata/masking.json), for RASP snippets and
/// application logs: credential pairs and bearer credentials lose their value,
/// opaque runs (keys, hashes, base64, JWTs, UUIDs) become <c>***</c>, and
/// readable identifiers (class names, package and file paths) survive.
/// Masking runs before the cut, over 1,024 characters of look-ahead.
/// </summary>
internal static class Masking
{
    public const string Mask = "***";
    public const int Lookahead = 1024;

    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);

    private const string Key =
        "(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
        + "|client[_-]?secret|auth(?:orization)?|bearer|cookie|session(?:[_-]?id)?|credentials?)";

    private static readonly Regex s_pair = new(
        "(" + Key + "[\"']?[ \\t]*[=:][ \\t]*)"
        + "(\"(?:[^\"\\\\]|\\\\.)*\"?|'(?:[^'\\\\]|\\\\.)*'?"
        + "|(?:(?:bearer|basic|digest|negotiate|token)[ \\t]+)?[^ \\t\\r\\n\\f\\x0B&;,'\"]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        s_timeout);

    private static readonly Regex s_bearer = new(
        "(bearer[ \\t]+)[A-Za-z0-9._~+/=-]+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        s_timeout);

    private static readonly HashSet<string> s_sensitiveWords = new(StringComparer.Ordinal)
    {
        "password", "passwd", "passphrase", "pwd", "secret", "token", "apikey",
        "authorization", "cookie", "credential", "credentials", "bearer", "otp",
        "signature", "privatekey", "sessionid", "jwt", "accesskey", "secretkey",
    };

    private static readonly HashSet<string> s_sensitivePairs = new(StringComparer.Ordinal)
    {
        "api key", "private key", "access key", "secret key", "session id",
    };

    /// <summary><paramref name="value"/> with credentials and opaque tokens masked; nothing is cut.</summary>
    public static string MaskSecrets(string value)
    {
        try
        {
            return MaskRuns(MaskCredentialRules(value));
        }
        catch (RegexMatchTimeoutException)
        {
            // Nothing unmasked leaves the process.
            return Mask;
        }
    }

    /// <summary>The contract's credential rules only: pairs (quotes kept), then bearer credentials.</summary>
    private static string MaskCredentialRules(string value)
    {
        var s = s_pair.Replace(value, m =>
        {
            var v = m.Groups[2].Value;
            var masked = v.StartsWith("\"", StringComparison.Ordinal) ? "\"***\""
                : v.StartsWith("'", StringComparison.Ordinal) ? "'***'"
                : Mask;
            return m.Groups[1].Value + masked;
        });
        return s_bearer.Replace(s, m => m.Groups[1].Value + Mask);
    }

    // Targets keep the strict long-token rule: hosts and directories are short labels.
    private static readonly Regex s_targetLongToken = new("[A-Za-z0-9_\\-+/]{20,}={0,2}", RegexOptions.CultureInvariant, s_timeout);

    /// <summary>
    /// An allow-list target as sent (sdk/rasp/README.md, "Masking", "Allow-list targets";
    /// cases in sdk/rasp/testdata/targets.json): the credential rules on the whole string, a
    /// <c>/</c> segment holding <c>@</c> masked whole, then every run of 20 or more token
    /// characters masked in each piece between <c>/</c> and <c>.</c>. Null when empty, holding a
    /// control character or longer than 256 characters (never cut).
    /// </summary>
    public static string? MaskTarget(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        string s;
        try
        {
            s = MaskCredentialRules(raw!);
            s = MapPieces(s, "/", p => p.IndexOf('@') >= 0 ? Mask : p);
            s = MapPieces(s, "/.", p => s_targetLongToken.Replace(p, Mask));
        }
        catch (RegexMatchTimeoutException)
        {
            return null;
        }

        if (s.Length == 0 || s.Length > 256)
        {
            return null;
        }

        foreach (var c in s)
        {
            if (c < 0x20 || c == 0x7f)
            {
                return null;
            }
        }

        return s;
    }

    /// <summary>Applies <paramref name="f"/> to each piece between separators, the separators kept.</summary>
    private static string MapPieces(string s, string separators, Func<string, string> f)
    {
        var sb = new StringBuilder(s.Length);
        var start = 0;
        for (var i = 0; i <= s.Length; i++)
        {
            if (i == s.Length || separators.IndexOf(s[i]) >= 0)
            {
                if (i > start)
                {
                    sb.Append(f(s.Substring(start, i - start)));
                }

                if (i < s.Length)
                {
                    sb.Append(s[i]);
                }

                start = i + 1;
            }
        }

        return sb.ToString();
    }

    /// <summary>At most <paramref name="limit"/> characters of <paramref name="value"/>, masked before it is cut.</summary>
    public static string MaskText(string value, int limit)
    {
        var scan = Cut(value, limit + Lookahead);
        return Cut(MaskSecrets(scan), limit);
    }

    /// <summary>A RASP snippet: masked, at most 64 characters.</summary>
    public static string MaskSnippet(string value) => MaskText(value, 64);

    /// <summary>Whether an attribute name names a credential (<c>password</c>, <c>x-api-key</c>, <c>sessionId</c>).</summary>
    public static bool IsSensitiveKey(string key)
    {
        var words = Words(key);
        for (var i = 0; i < words.Count; i++)
        {
            if (s_sensitiveWords.Contains(words[i]))
            {
                return true;
            }

            if (i + 1 < words.Count && s_sensitivePairs.Contains(words[i] + " " + words[i + 1]))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// A value as it may leave the process: null kept, anything under a
    /// credential name masked whole, strings masked and cut, lists item by
    /// item, maps entry by entry under their own names, other values kept.
    /// </summary>
    public static object? MaskValue(string key, object? value, int limit)
    {
        if (value is null)
        {
            return null;
        }

        if (IsSensitiveKey(key))
        {
            return Mask;
        }

        switch (value)
        {
            case string s:
                return MaskText(s, limit);
            case IDictionary map:
                var maskedMap = new Dictionary<string, object?>(StringComparer.Ordinal);
                foreach (DictionaryEntry e in map)
                {
                    var k = Convert.ToString(e.Key, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
                    maskedMap[k] = MaskValue(k, e.Value, limit);
                }

                return maskedMap;
            case IEnumerable<KeyValuePair<string, object?>> pairs:
                var maskedPairs = new Dictionary<string, object?>(StringComparer.Ordinal);
                foreach (var kv in pairs)
                {
                    maskedPairs[kv.Key] = MaskValue(kv.Key, kv.Value, limit);
                }

                return maskedPairs;
            case IEnumerable list:
                var maskedList = new List<object?>();
                foreach (var item in list)
                {
                    maskedList.Add(MaskValue(key, item, limit));
                }

                return maskedList;
            default:
                return value;
        }
    }

    internal static bool IsOpaque(string run)
    {
        if (run.IndexOf('+') >= 0 || run.EndsWith("=", StringComparison.Ordinal))
        {
            return true;
        }

        var start = 0;
        for (var i = 0; i <= run.Length; i++)
        {
            if (i == run.Length || run[i] is '.' or '/' or '-' or '_' or '=')
            {
                if (i - start >= 8 && !Readable(run, start, i - start))
                {
                    return true;
                }

                start = i + 1;
            }
        }

        return false;
    }

    private static string MaskRuns(string s)
    {
        StringBuilder? sb = null;
        var last = 0;
        var i = 0;
        while (i < s.Length)
        {
            if (!IsRunChar(s[i]))
            {
                i++;
                continue;
            }

            var start = i;
            while (i < s.Length && IsRunChar(s[i]))
            {
                i++;
            }

            if (i - start >= 20 && IsOpaque(s.Substring(start, i - start)))
            {
                sb ??= new StringBuilder(s.Length);
                sb.Append(s, last, start - last).Append(Mask);
                last = i;
            }
        }

        if (sb is null)
        {
            return s;
        }

        return sb.Append(s, last, s.Length - last).ToString();
    }

    private static bool IsRunChar(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '-' or '+' or '/' or '=' or '.';

    private static bool IsLetter(char c) => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z');

    private static bool IsUpper(char c) => c is >= 'A' and <= 'Z';

    private static bool IsLower(char c) => c is >= 'a' and <= 'z';

    private static bool IsDigit(char c) => c is >= '0' and <= '9';

    // ^[A-Za-z]+[0-9]{0,4}$, a fifth vowels, at most 6 uppercase in a row,
    // lower-to-upper transitions times 3 no more than the letters.
    private static bool Readable(string s, int start, int length)
    {
        var end = start + length;
        var letterEnd = start;
        while (letterEnd < end && IsLetter(s[letterEnd]))
        {
            letterEnd++;
        }

        var letters = letterEnd - start;
        if (letters == 0 || end - letterEnd > 4)
        {
            return false;
        }

        for (var i = letterEnd; i < end; i++)
        {
            if (!IsDigit(s[i]))
            {
                return false;
            }
        }

        int vowels = 0, upperRun = 0, longest = 0, transitions = 0;
        for (var i = start; i < letterEnd; i++)
        {
            var c = s[i];
            if ("aeiouyAEIOUY".IndexOf(c) >= 0)
            {
                vowels++;
            }

            if (IsUpper(c))
            {
                upperRun++;
                longest = Math.Max(longest, upperRun);
                if (i > start && IsLower(s[i - 1]))
                {
                    transitions++;
                }
            }
            else
            {
                upperRun = 0;
            }
        }

        return vowels * 5 >= letters && longest <= 6 && transitions * 3 <= letters;
    }

    private static List<string> Words(string key)
    {
        var words = new List<string>();
        var i = 0;
        while (i < key.Length)
        {
            if (!IsAlnum(key[i]))
            {
                i++;
                continue;
            }

            var chunkStart = i;
            while (i < key.Length && IsAlnum(key[i]))
            {
                i++;
            }

            var chunkEnd = i;
            var start = chunkStart;
            for (var j = chunkStart + 1; j < chunkEnd; j++)
            {
                char a = key[j - 1], b = key[j];
                var next = j + 1 < chunkEnd ? key[j + 1] : '\0';
                var lowerToUpper = (IsLower(a) || IsDigit(a)) && IsUpper(b);
                var acronymEnd = IsUpper(a) && IsUpper(b) && IsLower(next);
                if (lowerToUpper || acronymEnd)
                {
                    words.Add(key.Substring(start, j - start).ToLowerInvariant());
                    start = j;
                }
            }

            words.Add(key.Substring(start, chunkEnd - start).ToLowerInvariant());
        }

        return words;
    }

    private static bool IsAlnum(char c) => IsLetter(c) || IsDigit(c);

    private static string Cut(string s, int limit) => s.Length > limit ? s.Substring(0, limit) : s;
}
