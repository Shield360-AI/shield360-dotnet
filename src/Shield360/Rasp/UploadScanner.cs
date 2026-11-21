#pragma warning disable CA1861 // small literal arrays on cold paths
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Shield360.Rasp;

/// <summary>
/// Upload inspection (sdk/rasp/README.md "Uploads"): what an uploaded file really is,
/// from its bytes. A port of the Go SDK's uploadscan.go, held to the same answers by
/// testdata/uploads.json. Feed the bytes with <see cref="Push(byte[], int, int)"/> as
/// they arrive and call <see cref="Finish"/> once. Memory stays bounded whatever the
/// file's size: the first 64 KiB, the last 1 MiB, one piece of at most 1 MiB with a
/// 2 KiB overlap, and a running hash.
/// </summary>
public sealed class UploadScanner : IDisposable
{
    /// <summary>How many bytes the signatures read by default.</summary>
    public const long DefaultScanBytes = 8L << 20;

    /// <summary>The most bytes the signatures read.</summary>
    public const long MaxScanBytes = 64L << 20;

    private const int Head = 64 << 10;
    private const int Tail = 1 << 20;
    private const long Mib = 1L << 20;
    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);

    /// <summary>README "Inspection rules": the first finding is reported.</summary>
    public static readonly IReadOnlyList<string> RuleOrder = new[]
    {
        "upload.eicar", "upload.malware", "upload.reputation", "upload.webshell", "upload.signature",
        "upload.executable", "upload.script", "upload.polyglot", "upload.active_content", "upload.server_config",
        "upload.double_extension", "upload.archive_traversal", "upload.archive_symlink", "upload.archive_bomb",
        "upload.archive_encrypted", "upload.office_macro", "upload.office_ole", "upload.archive_script",
        "upload.type_mismatch", "upload.type_not_allowed", "upload.too_large", "upload.scan_unavailable",
    };

    internal static readonly HashSet<string> Capped = new(StringComparer.Ordinal) { "upload.office_ole", "upload.archive_script", "upload.type_mismatch" };

    internal static int Rank(string rule)
    {
        for (var i = 0; i < RuleOrder.Count; i++)
        {
            if (RuleOrder[i] == rule)
            {
                return i;
            }
        }

        return RuleOrder.Count;
    }

    internal static List<UploadFileFinding> Sorted(IEnumerable<UploadFileFinding> fs) => fs.OrderBy(f => Rank(f.Rule)).ToList();

    private static readonly Dictionary<string, string> s_kindOf = BuildKinds();

    private static Dictionary<string, string> BuildKinds()
    {
        var m = new Dictionary<string, string>(StringComparer.Ordinal) { ["svg"] = "svg", ["html"] = "html", ["text"] = "text", ["unknown"] = "other" };
        void Put(string kind, params string[] types)
        {
            foreach (var t in types)
            {
                m[t] = kind;
            }
        }

        Put("executable", "elf", "pe", "macho", "java_class", "wasm", "jar", "war");
        Put("image", "jpeg", "png", "gif", "webp", "bmp", "ico", "tiff");
        Put("document", "pdf", "ole2", "docx", "xlsx", "pptx");
        Put("archive", "zip", "gzip", "bzip2", "xz", "7z", "rar", "tar");
        Put("media", "mp4", "webm", "mp3", "wav", "ogg");
        Put("script", "php", "jsp_asp", "shebang");
        return m;
    }

    /// <summary>The kind of a real type.</summary>
    public static string KindOf(string type) => s_kindOf.TryGetValue(type, out var k) ? k : "other";

    internal static bool KnownType(string type) => s_kindOf.ContainsKey(type);

    // ---- real type -------------------------------------------------------

    private static bool HasAt(byte[] b, int at, params int[] sig)
    {
        if (at < 0 || b.Length < at + sig.Length)
        {
            return false;
        }

        for (var i = 0; i < sig.Length; i++)
        {
            if (b[at + i] != sig[i])
            {
                return false;
            }
        }

        return true;
    }

    private static string StrAt(byte[] b, int at, int n) => at >= b.Length ? string.Empty : Latin1(b, at, Math.Min(n, b.Length - at));

    internal static string Latin1(byte[] b, int at, int n)
    {
        var c = new char[n];
        for (var i = 0; i < n; i++)
        {
            c[i] = (char)b[at + i];
        }

        return new string(c);
    }

    internal static byte[] Latin1Bytes(string s)
    {
        var b = new byte[s.Length];
        for (var i = 0; i < s.Length; i++)
        {
            b[i] = (byte)s[i];
        }

        return b;
    }

    private static int I32Le(byte[] b, int at) => b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24);

    /// <summary>The real type from the first bytes (README "Real type").</summary>
    public static string Sniff(byte[] h)
    {
        if (HasAt(h, 0, 0x7f, 'E', 'L', 'F'))
        {
            return "elf";
        }

        if (HasAt(h, 0, 'M', 'Z') && h.Length >= 0x40 && I32Le(h, 0x3c) is var off && off >= 0 && HasAt(h, off, 'P', 'E', 0, 0))
        {
            return "pe";
        }

        if (HasAt(h, 0, 0xfe, 0xed, 0xfa, 0xce) || HasAt(h, 0, 0xfe, 0xed, 0xfa, 0xcf) || HasAt(h, 0, 0xce, 0xfa, 0xed, 0xfe) || HasAt(h, 0, 0xcf, 0xfa, 0xed, 0xfe))
        {
            return "macho";
        }

        if (HasAt(h, 0, 0xca, 0xfe, 0xba, 0xbe))
        {
            return h.Length >= 8 && (uint)((h[4] << 24) | (h[5] << 16) | (h[6] << 8) | h[7]) < 30 ? "macho" : "java_class";
        }

        if (HasAt(h, 0, 0xff, 0xd8, 0xff))
        {
            return "jpeg";
        }

        if (HasAt(h, 0, 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a))
        {
            return "png";
        }

        var s6 = StrAt(h, 0, 6);
        if (s6 == "GIF87a" || s6 == "GIF89a")
        {
            return "gif";
        }

        if (StrAt(h, 0, 4) == "RIFF" && StrAt(h, 8, 4) == "WEBP")
        {
            return "webp";
        }

        if (StrAt(h, 0, 2) == "BM" && h.Length >= 26)
        {
            return "bmp";
        }

        if (HasAt(h, 0, 0, 0, 1, 0))
        {
            return "ico";
        }

        if (HasAt(h, 0, 'I', 'I', '*', 0) || HasAt(h, 0, 'M', 'M', 0, '*'))
        {
            return "tiff";
        }

        if (UploadSignatures.IndexOf(h, 0, Math.Min(h.Length, 1024), Latin1Bytes("%PDF-")) >= 0)
        {
            return "pdf";
        }

        if (HasAt(h, 0, 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1))
        {
            return "ole2";
        }

        if (HasAt(h, 0, 'P', 'K', 3, 4) || HasAt(h, 0, 'P', 'K', 5, 6))
        {
            return "zip";
        }

        if (HasAt(h, 0, 0x1f, 0x8b))
        {
            return "gzip";
        }

        if (StrAt(h, 0, 3) == "BZh")
        {
            return "bzip2";
        }

        if (HasAt(h, 0, 0xfd, '7', 'z', 'X', 'Z', 0))
        {
            return "xz";
        }

        if (HasAt(h, 0, '7', 'z', 0xbc, 0xaf, 0x27, 0x1c))
        {
            return "7z";
        }

        if (HasAt(h, 0, 'R', 'a', 'r', '!', 0x1a, 0x07))
        {
            return "rar";
        }

        if (StrAt(h, 257, 5) == "ustar")
        {
            return "tar";
        }

        if (StrAt(h, 4, 4) == "ftyp")
        {
            return "mp4";
        }

        if (HasAt(h, 0, 0x1a, 0x45, 0xdf, 0xa3))
        {
            return "webm";
        }

        if (StrAt(h, 0, 3) == "ID3" || HasAt(h, 0, 0xff, 0xfb) || HasAt(h, 0, 0xff, 0xf3) || HasAt(h, 0, 0xff, 0xf2))
        {
            return "mp3";
        }

        if (StrAt(h, 0, 4) == "RIFF" && StrAt(h, 8, 4) == "WAVE")
        {
            return "wav";
        }

        if (StrAt(h, 0, 4) == "OggS")
        {
            return "ogg";
        }

        if (HasAt(h, 0, 0, 'a', 's', 'm'))
        {
            return "wasm";
        }

        var i = HasAt(h, 0, 0xef, 0xbb, 0xbf) ? 3 : 0;
        while (i < h.Length && (h[i] == ' ' || (h[i] >= 0x09 && h[i] <= 0x0d)))
        {
            i++;
        }

        var start = Math.Min(i, h.Length);
        var lead = Latin1(UploadSignatures.Fold(h, start, Math.Min(h.Length, i + 1024)), 0, Math.Min(h.Length, i + 1024) - start);
        if (lead.StartsWith("<?php", StringComparison.Ordinal) || lead.StartsWith("<?=", StringComparison.Ordinal))
        {
            return "php";
        }

        if (lead.StartsWith("<%", StringComparison.Ordinal) || lead.StartsWith("<jsp:", StringComparison.Ordinal))
        {
            return "jsp_asp";
        }

        if (lead.StartsWith("#!/", StringComparison.Ordinal))
        {
            return "shebang";
        }

        foreach (var t in new[] { "<!doctype html", "<html", "<head", "<body", "<script", "<iframe" })
        {
            if (lead.StartsWith(t, StringComparison.Ordinal))
            {
                return "html";
            }
        }

        if (lead.IndexOf("<svg", StringComparison.Ordinal) >= 0)
        {
            return "svg";
        }

        var n = Math.Min(h.Length, 8192);
        for (var k = 0; k < n; k++)
        {
            if (h[k] == 0)
            {
                return "unknown";
            }
        }

        return "text";
    }

    // ---- names ------------------------------------------------------------

    private static readonly HashSet<string> s_serverConfig = new(StringComparer.Ordinal) { ".htaccess", ".htpasswd", ".user.ini", "web.config" };
    private static readonly Regex s_scriptExt = new("^(aspx?|jspx?|php[3-7]?|phar|phtml|sh|bash|py|pyc|pl|rb|so|dll|dylib|exe|cgi|js|mjs|cjs)\\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_aspSemicolon = new("\\.(aspx?|jspx?|php[3-7]?|phtml|cgi|pl)[\\t\\n\\v\\f\\r ]*;", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_trailing = new("\\.[^.]+[. ]+\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_archiveExt = new("\\.(aspx?|jspx?|php[3-7]?|phar|phtml|cgi|pl|sh)\\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, s_timeout);
    internal static readonly Regex ExtShape = new("^[a-z0-9]{1,10}\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_oleEntry = new("(^|/)embeddings/oleObject|(^|/)activeX/", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_drive = new("^[A-Za-z]:", RegexOptions.CultureInvariant, s_timeout);

    internal static string Base(string name)
    {
        var i = Math.Max(name.LastIndexOf('/'), name.LastIndexOf('\\'));
        return i >= 0 ? name.Substring(i + 1) : name;
    }

    /// <summary>A name's last extension, lower case ([a-z0-9]{1,10}); "" otherwise.</summary>
    public static string Ext(string? name)
    {
        if (name is null)
        {
            return string.Empty;
        }

        var b = Base(name).TrimEnd('.', ' ');
        var dot = b.LastIndexOf('.');
        if (dot <= 0 && !b.StartsWith(".", StringComparison.Ordinal))
        {
            return string.Empty;
        }

        var e = b.Substring(dot + 1).ToLowerInvariant();
        return ExtShape.IsMatch(e) ? e : string.Empty;
    }

    /// <summary>upload.server_config.</summary>
    public static bool IsServerConfigName(string? name) => name is not null && s_serverConfig.Contains(Base(name).ToLowerInvariant());

    /// <summary>upload.double_extension.</summary>
    public static bool HasDoubleExtension(string? name)
    {
        if (name is null)
        {
            return false;
        }

        var b = Base(name);
        if (b.IndexOf('\0') >= 0 || b.IndexOf("%00", StringComparison.Ordinal) >= 0 || s_trailing.IsMatch(b))
        {
            return true;
        }

        var parts = b.Split('.');
        if (parts.Length < 3 && b.IndexOf(';') < 0)
        {
            return false;
        }

        for (var i = 1; i < parts.Length - 1; i++)
        {
            var seg = parts[i];
            var semi = seg.IndexOf(';');
            if (s_scriptExt.IsMatch(semi >= 0 ? seg.Substring(0, semi) : seg))
            {
                return true;
            }
        }

        return s_aspSemicolon.IsMatch(b);
    }

    private static readonly Dictionary<string, string[]> s_extTypes = new(StringComparer.Ordinal)
    {
        ["jpg"] = new[] { "jpeg" }, ["jpeg"] = new[] { "jpeg" }, ["jpe"] = new[] { "jpeg" }, ["png"] = new[] { "png" }, ["gif"] = new[] { "gif" },
        ["webp"] = new[] { "webp" }, ["bmp"] = new[] { "bmp" }, ["ico"] = new[] { "ico" }, ["tif"] = new[] { "tiff" }, ["tiff"] = new[] { "tiff" },
        ["pdf"] = new[] { "pdf" }, ["docx"] = new[] { "docx", "zip" }, ["xlsx"] = new[] { "xlsx", "zip" }, ["pptx"] = new[] { "pptx", "zip" },
        ["doc"] = new[] { "ole2" }, ["xls"] = new[] { "ole2" }, ["ppt"] = new[] { "ole2" }, ["zip"] = new[] { "zip", "docx", "xlsx", "pptx", "jar", "war" },
        ["gz"] = new[] { "gzip" }, ["tgz"] = new[] { "gzip" }, ["mp4"] = new[] { "mp4" }, ["m4a"] = new[] { "mp4" }, ["mov"] = new[] { "mp4" },
        ["mp3"] = new[] { "mp3" }, ["csv"] = new[] { "text" }, ["txt"] = new[] { "text" }, ["json"] = new[] { "text" }, ["md"] = new[] { "text" },
    };

    private static readonly Dictionary<string, string[]> s_ctTypes = new(StringComparer.Ordinal)
    {
        ["image/jpeg"] = new[] { "jpeg" }, ["image/png"] = new[] { "png" }, ["image/gif"] = new[] { "gif" }, ["image/webp"] = new[] { "webp" },
        ["image/bmp"] = new[] { "bmp" }, ["image/x-icon"] = new[] { "ico" }, ["image/vnd.microsoft.icon"] = new[] { "ico" }, ["image/tiff"] = new[] { "tiff" },
        ["application/pdf"] = new[] { "pdf" },
        ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = new[] { "docx", "zip" },
        ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = new[] { "xlsx", "zip" },
        ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = new[] { "pptx", "zip" },
        ["application/msword"] = new[] { "ole2" }, ["application/vnd.ms-excel"] = new[] { "ole2" }, ["application/vnd.ms-powerpoint"] = new[] { "ole2" },
        ["application/zip"] = new[] { "zip", "docx", "xlsx", "pptx", "jar", "war" }, ["application/gzip"] = new[] { "gzip" },
        ["video/mp4"] = new[] { "mp4" }, ["audio/mp4"] = new[] { "mp4" }, ["video/quicktime"] = new[] { "mp4" }, ["audio/mpeg"] = new[] { "mp3" },
        ["text/csv"] = new[] { "text" }, ["text/plain"] = new[] { "text" }, ["application/json"] = new[] { "text" },
    };

    /// <summary>upload.type_mismatch.</summary>
    public static bool TypeMismatch(string type, string? name, string? contentType)
    {
        if (type == "unknown")
        {
            return false;
        }

        var c = contentType ?? string.Empty;
        var semi = c.IndexOf(';');
        var ct = (semi >= 0 ? c.Substring(0, semi) : c).Trim().ToLowerInvariant();
        foreach (var expected in new[] { s_extTypes.TryGetValue(Ext(name), out var e) ? e : null, s_ctTypes.TryGetValue(ct, out var t) ? t : null })
        {
            if (expected is { Length: > 0 } && !expected.Contains(type) && KindOf(expected[0]) != KindOf(type))
            {
                return true;
            }
        }

        return false;
    }

    // ---- archives -----------------------------------------------------------

    internal sealed record Entry(string Name, bool Symlink, bool Encrypted, ulong Compressed, ulong Size);

    private static int U16(byte[] b, int at) => b[at] | (b[at + 1] << 8);

    private static ulong U32(byte[] b, int at) => (uint)(U16(b, at) | (U16(b, at + 2) << 16));

    private static ulong U64(byte[] b, int at) => U32(b, at) | (U32(b, at + 4) << 32);

    /// <summary>The central directory's entries from the tail; null when no end record is there.</summary>
    internal static (List<Entry> Entries, ulong Total)? ZipEntries(byte[] tail)
    {
        var eocd = -1;
        for (var i = tail.Length - 22; i >= 0 && i >= tail.Length - 22 - 65535; i--)
        {
            if (HasAt(tail, i, 'P', 'K', 5, 6))
            {
                eocd = i;
                break;
            }
        }

        if (eocd < 0)
        {
            return null;
        }

        var entries = new List<Entry>();
        ulong total = (ulong)U16(tail, eocd + 10);
        var cdSize = U32(tail, eocd + 12);
        var cdEnd = eocd;
        if (total == 0xffff || cdSize == 0xffffffff)
        {
            var loc = eocd - 20;
            if (loc < 0 || !HasAt(tail, loc, 'P', 'K', 6, 7))
            {
                return (entries, total);
            }

            var z = loc - 56;
            if (z < 0 || !HasAt(tail, z, 'P', 'K', 6, 6))
            {
                return (entries, total);
            }

            total = U64(tail, z + 32);
            cdSize = U64(tail, z + 40);
            cdEnd = z;
        }

        if (cdSize > (ulong)cdEnd)
        {
            return (entries, total);
        }

        var p = cdEnd - (int)cdSize;
        while (p + 46 <= cdEnd && HasAt(tail, p, 'P', 'K', 1, 2) && entries.Count < 10001)
        {
            var madeBy = U16(tail, p + 4) >> 8;
            var flags = U16(tail, p + 8);
            var compressed = U32(tail, p + 20);
            var size = U32(tail, p + 24);
            var nameLen = U16(tail, p + 28);
            var extraLen = U16(tail, p + 30);
            var commentLen = U16(tail, p + 32);
            var attr = U32(tail, p + 38);
            if (p + 46 + nameLen + extraLen > tail.Length)
            {
                break;
            }

            var name = Encoding.UTF8.GetString(tail, p + 46, nameLen);
            var e = p + 46 + nameLen;
            var extraEnd = e + extraLen;
            while (e + 4 <= extraEnd)
            {
                var id = U16(tail, e);
                var ln = U16(tail, e + 2);
                if (id == 1)
                {
                    var q = e + 4;
                    if (size == 0xffffffff && q + 8 <= e + 4 + ln && q + 8 <= tail.Length)
                    {
                        size = U64(tail, q);
                        q += 8;
                    }

                    if (compressed == 0xffffffff && q + 8 <= e + 4 + ln && q + 8 <= tail.Length)
                    {
                        compressed = U64(tail, q);
                    }
                }

                e += 4 + ln;
            }

            var mode = (attr >> 16) & 0xF000; // 0o170000
            entries.Add(new Entry(name, madeBy == 3 && mode == 0xA000, (flags & 1) == 1, compressed, size));
            p = extraEnd + commentLen;
        }

        return (entries, total);
    }

    /// <summary>upload.archive_traversal for one entry name.</summary>
    public static bool EntryEscapes(string name)
    {
        var n = name.Replace('\\', '/');
        return n.StartsWith("/", StringComparison.Ordinal) || s_drive.IsMatch(n) || n.Split('/').Any(seg => seg == "..");
    }

    private static readonly Regex s_paxPath = new("(?:^|\n)[0-9]+ path=([^\n]*)\n", RegexOptions.CultureInvariant, s_timeout);

    /// <summary>Reads tar headers as the bytes pass (ustar name and prefix, GNU L, pax path).</summary>
    internal sealed class TarReader
    {
        private long _next;
        private byte[] _header = Array.Empty<byte>();
        private int _wantKind;
        private long _wantLeft;
        private long _wantSkip;
        private List<byte> _wantBytes = new();
        private string? _pendingName;
        private bool _done;

        public List<Entry> Entries { get; } = new();

        private static string Field(byte[] h, int o, int l)
        {
            var s = Encoding.UTF8.GetString(h, o, l);
            var z = s.IndexOf('\0');
            return z >= 0 ? s.Substring(0, z) : s;
        }

        public void Feed(byte[] chunk, int from, int to, long offset)
        {
            var i = from;
            while (i < to && !_done && Entries.Count <= 10000)
            {
                var pos = offset + (i - from);
                if (_wantKind != 0)
                {
                    var take = Math.Min(to - i, _wantLeft);
                    var room = (_wantKind == 'x' ? 4096 : 512) - _wantBytes.Count;
                    var keep = Math.Min(take, Math.Max(room, 0));
                    _wantBytes.AddRange(new ArraySegment<byte>(chunk, i, (int)keep));
                    _wantLeft -= take;
                    i += (int)take;
                    if (_wantLeft == 0)
                    {
                        var text = Encoding.UTF8.GetString(_wantBytes.ToArray());
                        if (_wantKind == 'L')
                        {
                            var z = text.IndexOf('\0');
                            _pendingName = z >= 0 ? text.Substring(0, z) : text;
                        }
                        else if (s_paxPath.Match(text) is { Success: true } m)
                        {
                            _pendingName = m.Groups[1].Value;
                        }

                        _next = offset + (i - from) + _wantSkip;
                        _wantKind = 0;
                        _wantBytes = new List<byte>();
                    }

                    continue;
                }

                if (pos < _next)
                {
                    i += (int)Math.Min(_next - pos, to - i);
                    continue;
                }

                var takeH = Math.Min(512 - _header.Length, to - i);
                var h2 = new byte[_header.Length + takeH];
                Buffer.BlockCopy(_header, 0, h2, 0, _header.Length);
                Buffer.BlockCopy(chunk, i, h2, _header.Length, takeH);
                _header = h2;
                i += takeH;
                if (_header.Length < 512)
                {
                    continue;
                }

                var h = _header;
                _header = Array.Empty<byte>();
                if (h.All(c => c == 0))
                {
                    _done = true;
                    break;
                }

                long size;
                try
                {
                    var f = Field(h, 124, 12).Trim();
                    size = f.Length == 0 ? 0 : Convert.ToInt64(f, 8);
                }
                catch (Exception e) when (e is FormatException or ArgumentException or OverflowException)
                {
                    size = 0;
                }

                size = Math.Max(size, 0);
                int typ = h[156];
                if (typ == 0)
                {
                    typ = '0';
                }

                var padded = (size + 511) / 512 * 512;
                _next = offset + (i - from) + padded;
                if (typ == 'L' || typ == 'x')
                {
                    long cap = typ == 'x' ? 4096 : 512;
                    if (size > 0)
                    {
                        var left = Math.Min(size, cap);
                        _wantKind = typ;
                        _wantLeft = left;
                        _wantSkip = padded - left;
                    }

                    continue;
                }

                if (typ == 'g')
                {
                    continue;
                }

                var name = Field(h, 0, 100);
                var prefix = Field(h, 345, 155);
                if (prefix.Length > 0 && Latin1(h, 257, 5) == "ustar")
                {
                    name = prefix + "/" + name;
                }

                if (_pendingName is not null)
                {
                    name = _pendingName;
                    _pendingName = null;
                }

                Entries.Add(new Entry(name, typ == '1' || typ == '2', false, (ulong)size, (ulong)size));
            }
        }
    }

    // ---- scanner ------------------------------------------------------------

    private static readonly string[] s_polyglot = { "<?php", "<script", "<jsp:", "runat=\"server\"" };
    private static readonly string[] s_active = { "<script", "javascript:", "<foreignobject", "<iframe", "<embed", "<object" };
    private static readonly Regex s_eventHandler = new("[\\t\\n\\f\\r /]on[a-z]{3,20}[\\t\\n\\v\\f\\r ]*=", RegexOptions.CultureInvariant, s_timeout);
    private static readonly byte[] s_oleVba = Utf16Le("_VBA_PROJECT");
    private static readonly byte[] s_oleEncrypted = Utf16Le("EncryptedPackage");
    private static readonly byte[] s_oleNative = Utf16Le("\u0001Ole10Native");

    // The EICAR test string, in two halves so this source file is not itself the test file.
    private static readonly byte[] s_eicar = Latin1Bytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    private static byte[] Utf16Le(string s)
    {
        var out_ = new byte[2 * s.Length];
        for (var i = 0; i < s.Length; i++)
        {
            out_[2 * i] = (byte)s[i];
        }

        return out_;
    }

    private readonly string _name;
    private readonly string _contentType;
    private readonly long _scanBytes;
    private readonly IReadOnlyCollection<string> _trusted;
    private readonly MemoryStream _head = new();
    private readonly MemoryStream _pending = new();
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly UploadSignatures.Matcher _builtin;
    private readonly UploadSignatures.Matcher? _custom;
    private readonly HashSet<string> _markers = new(StringComparer.Ordinal);
    private long _size;
    private long _scanned;
    private byte[] _tail = Array.Empty<byte>();
    private int _tailLen;
    private byte[] _carry = Array.Empty<byte>();
    private byte[] _carryFold = Array.Empty<byte>();
    private TarReader? _tar;
    private bool _tarChecked;

    /// <summary>
    /// Starts an inspection. scanBytes 0 is the default (8 MiB); custom are the
    /// organization's own signatures (deep scan on), trusted the SHA-256 hashes marked safe.
    /// </summary>
    public UploadScanner(string? name, string? contentType, long scanBytes = 0, IReadOnlyList<UploadSignature>? custom = null, IReadOnlyCollection<string>? trusted = null)
    {
        _name = name ?? string.Empty;
        _contentType = contentType ?? string.Empty;
        _scanBytes = Math.Min(scanBytes <= 0 ? DefaultScanBytes : scanBytes, MaxScanBytes);
        _trusted = trusted ?? Array.Empty<string>();
        _builtin = new UploadSignatures.Matcher(UploadSignatures.BuiltIn);
        _custom = custom is { Count: > 0 } ? new UploadSignatures.Matcher(custom) : null;
    }

    /// <summary>Feeds the next bytes.</summary>
    public void Push(byte[] data) => Push(data, 0, data?.Length ?? 0);

    /// <summary>Feeds data[offset, offset + count).</summary>
    public void Push(byte[] data, int offset, int count)
    {
        if (data is null || count <= 0)
        {
            return;
        }

        var start = _size;
        _size += count;
        _hash.AppendData(data, offset, count);
        if (_head.Length < Head)
        {
            _head.Write(data, offset, (int)Math.Min(count, Head - _head.Length));
        }

        AppendTail(data, offset, count);
        if (!_tarChecked && _head.Length >= 262)
        {
            _tarChecked = true;
            var h = _head.ToArray();
            if (Sniff(h) == "tar")
            {
                _tar = new TarReader();
                var fed = (int)Math.Min(h.Length, start + count);
                _tar.Feed(h, 0, fed, 0);
                if (start + count > fed)
                {
                    var skip = (int)(fed - start);
                    _tar.Feed(data, offset + skip, offset + count, fed);
                }
            }
        }
        else if (_tar is not null)
        {
            _tar.Feed(data, offset, offset + count, start);
        }

        if (_scanned < _scanBytes)
        {
            var part = (int)Math.Min(count, _scanBytes - _scanned);
            _scanned += part;
            _pending.Write(data, offset, part);
            if (_pending.Length >= UploadSignatures.Piece)
            {
                Flush(false);
            }
        }
    }

    private void AppendTail(byte[] data, int offset, int count)
    {
        if (_tailLen + count > _tail.Length)
        {
            var keep = Math.Min(_tailLen, Tail);
            var grown = new byte[Math.Max(2 * Tail, keep + count)];
            Buffer.BlockCopy(_tail, _tailLen - keep, grown, 0, keep);
            _tail = grown;
            _tailLen = keep;
        }

        Buffer.BlockCopy(data, offset, _tail, _tailLen, count);
        _tailLen += count;
    }

    private void Scan(byte[] text, byte[] folded, bool last)
    {
        _builtin.Feed(text, folded, last);
        _custom?.Feed(text, folded, last);
        foreach (var m in s_polyglot.Concat(s_active))
        {
            if (UploadSignatures.Contains(folded, Latin1Bytes(m)))
            {
                _markers.Add(m);
            }
        }

        try
        {
            if (s_eventHandler.IsMatch(Latin1(folded, 0, folded.Length)))
            {
                _markers.Add("on*=");
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // too slow: no marker
        }

        foreach (var m in new[] { s_oleVba, s_oleEncrypted, s_oleNative })
        {
            if (UploadSignatures.Contains(text, m))
            {
                _markers.Add(Latin1(m, 0, m.Length));
            }
        }
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var out_ = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, out_, 0, a.Length);
        Buffer.BlockCopy(b, 0, out_, a.Length, b.Length);
        return out_;
    }

    private static byte[] Last(byte[] b, int n)
    {
        var k = Math.Min(n, b.Length);
        var out_ = new byte[k];
        Buffer.BlockCopy(b, b.Length - k, out_, 0, k);
        return out_;
    }

    private void Flush(bool last)
    {
        if (_pending.Length == 0 && !last)
        {
            return;
        }

        var p = _pending.ToArray();
        _pending.SetLength(0);
        var text = Concat(_carry, p);
        var folded = Concat(_carryFold, UploadSignatures.Fold(p));
        Scan(text, folded, last);
        _carry = Last(text, UploadSignatures.Overlap);
        _carryFold = Last(folded, UploadSignatures.Overlap);
    }

    private bool Marker(IEnumerable<string> ms) => ms.Any(_markers.Contains);

    private static bool Has(List<Entry> entries, Func<string, bool> p) => entries.Any(e => p(e.Name.Replace('\\', '/')));

    /// <summary>The verdict. complete: the scanner saw every byte (only then is the hash reported).</summary>
    public UploadVerdict Finish(bool complete = true)
    {
        Flush(true);
        var t = new byte[Math.Min(_tailLen, Tail)];
        Buffer.BlockCopy(_tail, _tailLen - t.Length, t, 0, t.Length);
        if (_size > _scanned)
        {
            var extra = Last(t, (int)Math.Min(_size - _scanned, t.Length));
            Scan(extra, UploadSignatures.Fold(extra), true);
        }

        var digest = _hash.GetHashAndReset();
        var sha = complete ? string.Concat(digest.Select(b => b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture))) : string.Empty;
        var h = _head.ToArray();
        var type = Sniff(h);
        var entries = new List<Entry>();
        ulong total = 0;
        if (type == "zip")
        {
            if (ZipEntries(t) is { } z)
            {
                (entries, total) = z;
                if (Has(entries, n => n == "[Content_Types].xml"))
                {
                    if (Has(entries, n => n.StartsWith("word/", StringComparison.Ordinal)))
                    {
                        type = "docx";
                    }
                    else if (Has(entries, n => n.StartsWith("xl/", StringComparison.Ordinal)))
                    {
                        type = "xlsx";
                    }
                    else if (Has(entries, n => n.StartsWith("ppt/", StringComparison.Ordinal)))
                    {
                        type = "pptx";
                    }
                }

                if (type == "zip" && Has(entries, n => n.StartsWith("WEB-INF/", StringComparison.Ordinal)))
                {
                    type = "war";
                }
                else if (type == "zip" && Has(entries, n => n == "META-INF/MANIFEST.MF"))
                {
                    type = "jar";
                }
            }
        }
        else if (_tar is not null)
        {
            entries = _tar.Entries;
            total = (ulong)_tar.Entries.Count;
        }

        var kind = KindOf(type);
        var fs = new List<UploadFileFinding>();
        if (sha.Length == 0 || !_trusted.Contains(sha))
        {
            if (_size <= 256)
            {
                var e = h.Length;
                while (e > 0 && (h[e - 1] == ' ' || h[e - 1] == '\t' || h[e - 1] == '\r' || h[e - 1] == '\n' || h[e - 1] == '\f' || h[e - 1] == 0x0b))
                {
                    e--;
                }

                if (e <= 128 && e >= s_eicar.Length && UploadSignatures.IndexOf(h, 0, s_eicar.Length, s_eicar) == 0)
                {
                    fs.Add(new UploadFileFinding("upload.eicar", "builtin"));
                }
            }

            if (_builtin.Matched() is { Count: > 0 } m)
            {
                fs.Add(new UploadFileFinding("upload.webshell", "builtin", m[0].Id));
            }

            if (_custom?.Matched() is { Count: > 0 } c)
            {
                fs.Add(new UploadFileFinding("upload.signature", "custom", c[0].Id));
            }

            switch (kind)
            {
                case "executable":
                    fs.Add(new UploadFileFinding("upload.executable", "builtin"));
                    break;
                case "script":
                    fs.Add(new UploadFileFinding("upload.script", "builtin"));
                    break;
                case "image" or "document" or "media" or "archive" when Marker(s_polyglot):
                    fs.Add(new UploadFileFinding("upload.polyglot", "builtin"));
                    break;
                case "html" or "svg" when Marker(s_active) || _markers.Contains("on*="):
                    fs.Add(new UploadFileFinding("upload.active_content", "builtin"));
                    break;
            }

            if (_name.Length > 0 && IsServerConfigName(_name))
            {
                fs.Add(new UploadFileFinding("upload.server_config", "builtin"));
            }

            if (_name.Length > 0 && HasDoubleExtension(_name))
            {
                fs.Add(new UploadFileFinding("upload.double_extension", "builtin"));
            }

            ulong declared = 0;
            bool traversal = false, link = false, encrypted = false, macro = false, ole = false, script = false, entryBomb = false;
            foreach (var e in entries)
            {
                declared += e.Size;
                var n = e.Name.Replace('\\', '/');
                var stripped = ("/" + n).TrimEnd('/');
                var lastSeg = stripped.Length == 0 ? "/" : Base(stripped);
                traversal |= EntryEscapes(e.Name);
                link |= e.Symlink;
                encrypted |= e.Encrypted;
                macro |= string.Equals(lastSeg, "vbaProject.bin", StringComparison.OrdinalIgnoreCase);
                ole |= s_oleEntry.IsMatch(n);
                script |= s_archiveExt.IsMatch(lastSeg);
                var compressed = Math.Max(e.Compressed, 1UL);
                entryBomb |= e.Size > 10 * Mib && e.Size > unchecked(1000 * compressed);
            }

            if (traversal)
            {
                fs.Add(new UploadFileFinding("upload.archive_traversal", "builtin"));
            }

            if (link)
            {
                fs.Add(new UploadFileFinding("upload.archive_symlink", "builtin"));
            }

            var bomb = total > 10000 || entries.Count > 10000 || declared > 1024 * Mib || entryBomb;
            if (type == "gzip" && t.Length >= 4 && _size > 18)
            {
                var isize = U32(t, t.Length - 4);
                bomb |= isize > 10 * Mib && isize > 1000 * (ulong)_size;
            }

            if (bomb)
            {
                fs.Add(new UploadFileFinding("upload.archive_bomb", "builtin"));
            }

            var ole2 = type == "ole2";
            if (encrypted || (ole2 && _markers.Contains(Latin1(s_oleEncrypted, 0, s_oleEncrypted.Length))))
            {
                fs.Add(new UploadFileFinding("upload.archive_encrypted", "builtin"));
            }

            if (macro || (ole2 && _markers.Contains(Latin1(s_oleVba, 0, s_oleVba.Length))))
            {
                fs.Add(new UploadFileFinding("upload.office_macro", "builtin"));
            }

            if (ole || (ole2 && _markers.Contains(Latin1(s_oleNative, 0, s_oleNative.Length))))
            {
                fs.Add(new UploadFileFinding("upload.office_ole", "builtin"));
            }

            if (script)
            {
                fs.Add(new UploadFileFinding("upload.archive_script", "builtin"));
            }

            if (TypeMismatch(type, _name, _contentType))
            {
                fs.Add(new UploadFileFinding("upload.type_mismatch", "builtin"));
            }
        }

        return new UploadVerdict(type, kind, _size, sha, Ext(_name), Sorted(fs));
    }

    /// <summary>Inspects bytes in memory.</summary>
    public static UploadVerdict InspectBytes(byte[] data, string? name, string? contentType)
    {
        using var s = new UploadScanner(name, contentType);
        s.Push(data);
        return s.Finish(true);
    }

    /// <summary>Releases the hash.</summary>
    public void Dispose()
    {
        _hash.Dispose();
        _head.Dispose();
        _pending.Dispose();
    }
}
