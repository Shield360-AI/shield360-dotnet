using System;

namespace Shield360.Rasp;

/// <summary>
/// String helpers with the TypeScript reference's semantics (ordinal, UTF-16
/// code units), so the ports of the lexers and detectors read like the original
/// and agree with it case by case.
/// </summary>
internal static class JsText
{
    /// <summary>The character at <paramref name="i"/>, or NUL when out of range (JS <c>undefined</c>).</summary>
    public static char At(string s, int i) => i >= 0 && i < s.Length ? s[i] : '\0';

    /// <summary>JS <c>String.prototype.slice</c>: negative indexes count from the end; never throws.</summary>
    public static string Slice(string s, int start, int? end = null)
    {
        var n = s.Length;
        var from = start < 0 ? Math.Max(n + start, 0) : Math.Min(start, n);
        var e = end ?? n;
        var to = e < 0 ? Math.Max(n + e, 0) : Math.Min(e, n);
        return to > from ? s.Substring(from, to - from) : string.Empty;
    }

    /// <summary>JS <c>trim()</c>: white space and the BOM.</summary>
    public static string Trim(string s) => s.Trim().Trim('﻿').Trim();

    public static bool Has(string hay, string needle) => hay.IndexOf(needle, StringComparison.Ordinal) >= 0;

    public static bool Has(string hay, char c) => hay.IndexOf(c) >= 0;

    public static int IndexOf(string hay, string needle, int from = 0) =>
        from > hay.Length ? -1 : hay.IndexOf(needle, Math.Max(from, 0), StringComparison.Ordinal);

    public static int IndexOf(string hay, char c, int from = 0) => from >= hay.Length ? -1 : hay.IndexOf(c, Math.Max(from, 0));

    /// <summary>JS <c>s.startsWith(prefix, at)</c>.</summary>
    public static bool StartsAt(string s, string prefix, int at) =>
        at >= 0 && at + prefix.Length <= s.Length && string.CompareOrdinal(s, at, prefix, 0, prefix.Length) == 0;

    public static bool Starts(string s, string prefix) => s.StartsWith(prefix, StringComparison.Ordinal);

    public static bool Ends(string s, string suffix) => s.EndsWith(suffix, StringComparison.Ordinal);

    /// <summary>JS <c>s.replace(a, b)</c> with a string pattern: the first occurrence only.</summary>
    public static string ReplaceFirst(string s, string a, string b)
    {
        var i = s.IndexOf(a, StringComparison.Ordinal);
        return i < 0 ? s : s.Substring(0, i) + b + s.Substring(i + a.Length);
    }

    public static string Lower(string s) => s.ToLowerInvariant();
}
