using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Shield360.Rasp;

/// <summary>A clamd address: unix (an absolute path) or tcp (host and port).</summary>
public sealed class ClamAddress
{
    internal ClamAddress(string network, string? host, int port, string? path)
    {
        Network = network;
        Host = host;
        Port = port;
        Path = path;
    }

    /// <summary>unix or tcp.</summary>
    public string Network { get; }

    /// <summary>The host (tcp).</summary>
    public string? Host { get; }

    /// <summary>The port (tcp).</summary>
    public int Port { get; }

    /// <summary>The socket path (unix).</summary>
    public string? Path { get; }

    /// <inheritdoc/>
    public override string ToString() => Network == "unix" ? "unix:" + Path : "tcp:" + Host + ":" + Port.ToString(CultureInfo.InvariantCulture);
}

/// <summary>The deep scan engines and how they run (the mode is <see cref="UploadOptions.DeepScanMode"/>).</summary>
public sealed class DeepScanOptions
{
    /// <summary>Scan after the app saved the file (<see cref="RaspUploads.Saved"/>); sync (the default) holds the upload until the engines answer.</summary>
    public bool Async { get; set; }

    /// <summary>One scan, all engines: 100 ms to 60 s, default 5 s.</summary>
    public long TimeoutMs { get; set; } = RaspDeepScan.DefaultTimeoutMs;

    /// <summary>Raise upload.scan_unavailable when an engine cannot answer (default: the file goes through and the status is reported).</summary>
    public bool FailClosed { get; set; }

    /// <summary>The customer's clamd.</summary>
    public ClamAddress? ClamAv { get; set; }

    /// <summary>The hash-only reputation lookup.</summary>
    public bool Reputation { get; set; }

    /// <summary>A new value tests the engines once and reports the result.</summary>
    public string TestId { get; set; } = string.Empty;

    internal long Timeout => TimeoutMs <= 0 ? RaspDeepScan.DefaultTimeoutMs : Math.Min(Math.Max(TimeoutMs, 100), 60000);

    internal string FailMode => FailClosed ? "closed" : "open";

    internal DeepScanOptions Copy() => new() { Async = Async, TimeoutMs = TimeoutMs, FailClosed = FailClosed, ClamAv = ClamAv, Reputation = Reputation, TestId = TestId };

    /// <summary>The signed config's deepScan block (decoded JSON).</summary>
    internal static DeepScanOptions Parse(JsonElement d)
    {
        var o = new DeepScanOptions();
        if (d.ValueKind != JsonValueKind.Object)
        {
            return o;
        }

        o.ClamAv = d.TryGetProperty("clamav", out var c) ? RaspDeepScan.ParseClamAddress(c) : null;
        o.Async = d.TryGetProperty("scan", out var s) && s.ValueKind == JsonValueKind.String && s.GetString() == "async";
        var t = UploadPolicy.TimeoutMs(d, "timeoutMs");
        if (t > 0)
        {
            o.TimeoutMs = t;
        }

        o.FailClosed = d.TryGetProperty("failMode", out var fm) && fm.ValueKind == JsonValueKind.String && fm.GetString() == "closed";
        o.Reputation = d.TryGetProperty("reputation", out var r) && r.ValueKind == JsonValueKind.True;
        if (d.TryGetProperty("testId", out var tid) && tid.ValueKind == JsonValueKind.String && tid.GetString()!.Length <= 128)
        {
            o.TestId = tid.GetString()!;
        }

        return o;
    }
}

/// <summary>Why a deep scan engine could not answer: unreachable, timeout or error.</summary>
public sealed class DeepScanEngineException : Exception
{
    /// <summary>Creates the error.</summary>
    public DeepScanEngineException()
        : this("error")
    {
    }

    /// <summary>Creates the error with its status.</summary>
    public DeepScanEngineException(string status)
        : base("deep scan engine: " + status)
    {
        Status = status;
    }

    /// <summary>Creates the error.</summary>
    public DeepScanEngineException(string status, Exception innerException)
        : base("deep scan engine: " + status, innerException)
    {
        Status = status;
    }

    /// <summary>unreachable, timeout or error.</summary>
    public string Status { get; }
}

/// <summary>
/// Deep scan (sdk/rasp/README.md "Upload policy and deep scan", "Scanner status"): the
/// customer's own ClamAV (clamd zINSTREAM over TCP or a Unix socket) and the hash-only
/// reputation lookup (POST /api/rasp/upload-reputation, only the SHA-256 leaves the
/// app), sync or async, with the fail mode and the quarantine. A port of the Go SDK's
/// upload_deepscan.go. File contents are streamed in bounded pieces, never stored or
/// sent anywhere but the customer's own clamd.
/// </summary>
public static class RaspDeepScan
{
    /// <summary>The scanner status record.</summary>
    public const string ScannerEvent = "shield360.rasp.scanner";

    /// <summary>The deep scan's sink.</summary>
    public const string Sink = "upload.deep_scan";

    internal const long DefaultTimeoutMs = 5000;
    internal const string ReputationPath = "/api/rasp/upload-reputation";
    internal const string EmptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const int ClamChunk = 64 * 1024;
    private static readonly TimeSpan s_scannerRepeat = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan s_reputationTtl = TimeSpan.FromHours(1);
    private const int ReputationMax = 1000;
    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);
    private static readonly Regex s_clamName = new("^[A-Za-z0-9._:/-]{1,128}\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_clamTcp = new("^tcp:([A-Za-z0-9.-]{1,253}|\\[[0-9a-fA-F:.]{2,45}\\]):([0-9]{1,5})\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_clamOk = new(":[\\t\\n\\v\\f\\r ]*OK\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_clamFound = new(":[\\t\\n\\v\\f\\r ]*(.+?)[\\t\\n\\v\\f\\r ]+FOUND\\z", RegexOptions.CultureInvariant, s_timeout);

    /// <summary>Reads unix:&lt;absolute path&gt; or tcp:&lt;host&gt;:&lt;port&gt; (a string, or {"address": ...}); null otherwise.</summary>
    public static ClamAddress? ParseClamAddress(string? s)
    {
        if (s is null)
        {
            return null;
        }

        if (s.StartsWith("unix:", StringComparison.Ordinal))
        {
            var p = s.Substring(5);
            return p.Length > 0 && RaspUploads.IsAbsPath(p) ? new ClamAddress("unix", null, 0, p) : null;
        }

        var m = s_clamTcp.Match(s);
        if (!m.Success)
        {
            return null;
        }

        var port = int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
        if (port < 1 || port > 65535)
        {
            return null;
        }

        return new ClamAddress("tcp", m.Groups[1].Value.Trim('[', ']'), port, null);
    }

    internal static ClamAddress? ParseClamAddress(JsonElement v)
    {
        if (v.ValueKind == JsonValueKind.Object && v.TryGetProperty("address", out var a))
        {
            v = a;
        }

        return v.ValueKind == JsonValueKind.String ? ParseClamAddress(v.GetString()) : null;
    }

    // ---- clamd -----------------------------------------------------------------

    /// <summary>One clamd connection with a deadline; every I/O is bounded by it.</summary>
    internal sealed class ClamStream : IDisposable
    {
        private readonly Socket _socket;
        private readonly DateTime _deadline;
        private DeepScanEngineException? _err;

        private ClamStream(Socket socket, DateTime deadline)
        {
            _socket = socket;
            _deadline = deadline;
        }

        private int LeftMs => (int)Math.Max(1, Math.Min(int.MaxValue, (_deadline - DateTime.UtcNow).TotalMilliseconds));

        public static ClamStream Dial(ClamAddress a, DateTime deadline)
        {
            Socket? s = null;
            try
            {
                EndPoint ep;
                if (a.Network == "unix")
                {
#if NET8_0_OR_GREATER
                    s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                    ep = new UnixDomainSocketEndPoint(a.Path!);
#else
                    throw new DeepScanEngineException("unreachable");
#endif
                }
                else
                {
                    var host = IPAddress.TryParse(a.Host, out var ip) ? ip : Dns.GetHostAddresses(a.Host!).First();
                    s = new Socket(host.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    ep = new IPEndPoint(host, a.Port);
                }

                var left = (int)Math.Max(1, (deadline - DateTime.UtcNow).TotalMilliseconds);
                var connect = s.BeginConnect(ep, null, null);
                if (!connect.AsyncWaitHandle.WaitOne(left))
                {
                    s.Dispose();
                    throw new DeepScanEngineException("timeout");
                }

                s.EndConnect(connect);
                var c = new ClamStream(s, deadline);
                s.SendTimeout = c.LeftMs;
                s.ReceiveTimeout = c.LeftMs;
                return c;
            }
            catch (DeepScanEngineException)
            {
                s?.Dispose();
                throw;
            }
            catch (Exception e) when (e is SocketException or IOException or ArgumentException or InvalidOperationException or ObjectDisposedException)
            {
                s?.Dispose();
                throw new DeepScanEngineException("unreachable", e);
            }
        }

        private DeepScanEngineException Failure(Exception e) =>
            new(e is SocketException { SocketErrorCode: SocketError.TimedOut } || DateTime.UtcNow >= _deadline ? "timeout" : "error", e);

        public void Send(byte[] b, int off, int len)
        {
            if (_err is not null)
            {
                return;
            }

            try
            {
                _socket.SendTimeout = LeftMs;
                var sent = 0;
                while (sent < len)
                {
                    sent += _socket.Send(b, off + sent, len - sent, SocketFlags.None);
                }
            }
            catch (Exception e) when (e is SocketException or IOException or ObjectDisposedException)
            {
                _err = Failure(e);
            }
        }

        /// <summary>Frames a piece (4-byte big-endian length, at most 64 KiB a frame); an error is kept for the reply.</summary>
        public void Write(byte[] p, int off, int len)
        {
            for (var o = 0; o < len && _err is null; o += ClamChunk)
            {
                var n = Math.Min(ClamChunk, len - o);
                var frame = new byte[4 + n];
                frame[0] = (byte)(n >> 24);
                frame[1] = (byte)(n >> 16);
                frame[2] = (byte)(n >> 8);
                frame[3] = (byte)n;
                Buffer.BlockCopy(p, off + o, frame, 4, n);
                Send(frame, 0, frame.Length);
            }
        }

        public string Reply()
        {
            if (_err is not null)
            {
                throw _err;
            }

            try
            {
                using var buf = new MemoryStream();
                var tmp = new byte[4096];
                while (buf.Length < 4096)
                {
                    _socket.ReceiveTimeout = LeftMs;
                    var n = _socket.Receive(tmp);
                    if (n <= 0)
                    {
                        break;
                    }

                    buf.Write(tmp, 0, n);
                    if (Array.IndexOf(tmp, (byte)0, 0, n) >= 0)
                    {
                        break;
                    }
                }

                var s = Encoding.UTF8.GetString(buf.ToArray());
                var z = s.IndexOf('\0');
                return (z >= 0 ? s.Substring(0, z) : s).Trim();
            }
            catch (Exception e) when (e is SocketException or IOException or ObjectDisposedException)
            {
                throw Failure(e);
            }
        }

        public static ClamStream Start(ClamAddress a, DateTime deadline)
        {
            var s = Dial(a, deadline);
            var cmd = Encoding.ASCII.GetBytes("zINSTREAM\0");
            s.Send(cmd, 0, cmd.Length);
            return s;
        }

        /// <summary>Ends the stream and reads the answer: null for clean, ClamAV's name for a find.</summary>
        public string? Finish()
        {
            try
            {
                Send(new byte[4], 0, 4);
                var r = Reply();
                if (s_clamOk.IsMatch(r))
                {
                    return null;
                }

                var m = s_clamFound.Match(r);
                if (m.Success)
                {
                    return s_clamName.IsMatch(m.Groups[1].Value) ? m.Groups[1].Value : "unnamed";
                }

                throw new DeepScanEngineException("error");
            }
            finally
            {
                Dispose();
            }
        }

        public void Dispose() => _socket.Dispose();
    }

    /// <summary>Streams src to clamd (zINSTREAM): ClamAV's name for a find, null for clean.</summary>
    public static string? ClamScan(ClamAddress address, Stream src, long timeoutMs)
    {
        var s = ClamStream.Start(address, DateTime.UtcNow.AddMilliseconds(timeoutMs));
        var buf = new byte[ClamChunk];
        try
        {
            int n;
            while ((n = src.Read(buf, 0, buf.Length)) > 0)
            {
                s.Write(buf, 0, n);
            }
        }
        catch (IOException e)
        {
            s.Dispose();
            throw new DeepScanEngineException("error", e);
        }

        return s.Finish();
    }

    /// <summary>Asks clamd zPING and expects PONG.</summary>
    public static bool ClamPing(ClamAddress address, long timeoutMs)
    {
        using var s = ClamStream.Dial(address, DateTime.UtcNow.AddMilliseconds(timeoutMs));
        var cmd = Encoding.ASCII.GetBytes("zPING\0");
        s.Send(cmd, 0, cmd.Length);
        return s.Reply() == "PONG";
    }

    // ---- reputation ---------------------------------------------------------------

    private sealed record Env(string Url, string ApiKey, HttpMessageHandler? Handler);

    private static Env s_env = new(string.Empty, string.Empty, null);
    private static readonly object s_repLock = new();
    private static readonly Dictionary<string, (string Verdict, DateTime Until)> s_repCache = new(StringComparer.Ordinal);
    private static readonly LinkedList<string> s_repOrder = new();

    internal static void SetEnv(string? url, string? apiKey, HttpMessageHandler? handler) =>
        Volatile.Write(ref s_env, new Env((url ?? string.Empty).TrimEnd('/'), apiKey ?? string.Empty, handler));

    /// <summary>
    /// Asks Shield360 about a file's SHA-256 (only the hash leaves the app): malicious,
    /// suspicious, clean or unknown. Answers are cached an hour, at most 1000 hashes.
    /// </summary>
    public static string Reputation(string sha256, long timeoutMs)
    {
        lock (s_repLock)
        {
            if (s_repCache.TryGetValue(sha256, out var e) && e.Until > DateTime.UtcNow)
            {
                return e.Verdict;
            }
        }

        var env = Volatile.Read(ref s_env);
        if (env.Url.Length == 0 || env.ApiKey.Length == 0)
        {
            throw new DeepScanEngineException("unreachable");
        }

        string body;
        try
        {
            using var http = env.Handler is null ? new HttpClient() : new HttpClient(env.Handler, disposeHandler: false);
            http.Timeout = System.Threading.Timeout.InfiniteTimeSpan;
            using var req = new HttpRequestMessage(HttpMethod.Post, env.Url + ReputationPath)
            {
                Content = new StringContent("{\"sha256\":" + JsonSerializer.Serialize(sha256) + "}", Encoding.UTF8, "application/json"),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", env.ApiKey);
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(Math.Max(1, timeoutMs)));
            using var res = http.SendAsync(req, cts.Token).GetAwaiter().GetResult();
            if (!res.IsSuccessStatusCode)
            {
                throw new DeepScanEngineException("error");
            }

            body = res.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        }
        catch (OperationCanceledException e)
        {
            throw new DeepScanEngineException("timeout", e);
        }
        catch (HttpRequestException e)
        {
            throw new DeepScanEngineException("unreachable", e);
        }

        var verdict = "unknown";
        var text = body.Length > 65536 ? body.Substring(0, 65536) : body;
        if (text.Trim().Length > 0)
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("verdict", out var v) && v.ValueKind == JsonValueKind.String
                    && v.GetString() is "malicious" or "suspicious" or "clean")
                {
                    verdict = v.GetString()!;
                }
            }
            catch (JsonException e)
            {
                throw new DeepScanEngineException("error", e);
            }
        }

        lock (s_repLock)
        {
            if (!s_repCache.ContainsKey(sha256))
            {
                if (s_repOrder.Count >= ReputationMax && s_repOrder.First is { } first)
                {
                    s_repCache.Remove(first.Value);
                    s_repOrder.RemoveFirst();
                }

                s_repOrder.AddLast(sha256);
            }

            s_repCache[sha256] = (verdict, DateTime.UtcNow + s_reputationTtl);
        }

        return verdict;
    }

    // ---- scanner status ------------------------------------------------------------

    private sealed class Status
    {
        public Status(string status, DateTime since)
        {
            Value = status;
            Since = since;
        }

        public string Value { get; }

        public DateTime Since { get; }

        public int Failures { get; set; }

        public DateTime LastSent { get; set; } = DateTime.MinValue;
    }

    private static readonly object s_scannerLock = new();
    private static readonly Dictionary<string, Status> s_statuses = new(StringComparer.Ordinal);
    private static string s_lastTest = string.Empty;

    /// <summary>Tests only.</summary>
    internal static void Reset()
    {
        lock (s_scannerLock)
        {
            s_statuses.Clear();
            s_lastTest = string.Empty;
        }

        lock (s_repLock)
        {
            s_repCache.Clear();
            s_repOrder.Clear();
        }
    }

    /// <summary>Records an engine's status and reports it when it changes, every 5 minutes while it is not ok, and for each test.</summary>
    internal static void NoteEngine(string engine, string status, string failMode, string testId)
    {
        var now = DateTime.UtcNow;
        var attrs = new Dictionary<string, string>(StringComparer.Ordinal);
        bool send;
        lock (s_scannerLock)
        {
            if (!s_statuses.TryGetValue(engine, out var s) || s.Value != status)
            {
                s = new Status(status, now) { Failures = status == "ok" ? 0 : 1 };
                s_statuses[engine] = s;
                send = true;
            }
            else
            {
                if (status != "ok")
                {
                    s.Failures++;
                }

                send = testId.Length > 0 || (status != "ok" && now - s.LastSent >= s_scannerRepeat);
            }

            if (send)
            {
                s.LastSent = now;
            }

            attrs["shield360.rasp.app"] = RaspEngine.ApplicationName;
            attrs["shield360.rasp.scanner.engine"] = engine;
            attrs["shield360.rasp.scanner.status"] = status;
            attrs["shield360.rasp.scanner.fail_mode"] = failMode;
            attrs["shield360.rasp.scanner.since"] = s.Since.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            attrs["shield360.rasp.scanner.failures"] = s.Failures.ToString(CultureInfo.InvariantCulture);
        }

        if (!send)
        {
            return;
        }

        if (testId.Length > 0)
        {
            attrs["shield360.rasp.scanner.test_id"] = testId;
        }

        RaspEngine.AddEvent(ScannerEvent, attrs);
    }

    /// <summary>Answers a new deepScan.testId once (in the background): clamd zPING and a reputation lookup of the empty file's hash.</summary>
    internal static void TestEngines(DeepScanOptions? d)
    {
        if (d is null || d.TestId.Length == 0)
        {
            return;
        }

        lock (s_scannerLock)
        {
            if (s_lastTest == d.TestId)
            {
                return;
            }

            s_lastTest = d.TestId;
        }

        _ = Task.Run(() => RunTest(d));
    }

    private static void RunTest(DeepScanOptions d)
    {
        try
        {
            var timeout = Math.Min(d.Timeout, 5000);
            if (d.ClamAv is not null)
            {
                string status;
                try
                {
                    status = ClamPing(d.ClamAv, timeout) ? "ok" : "error";
                }
                catch (DeepScanEngineException e)
                {
                    status = e.Status;
                }

                NoteEngine("clamav", status, d.FailMode, d.TestId);
            }

            if (d.Reputation)
            {
                string status;
                try
                {
                    Reputation(EmptySha256, timeout);
                    status = "ok";
                }
                catch (DeepScanEngineException e)
                {
                    status = e.Status;
                }

                NoteEngine("reputation", status, d.FailMode, d.TestId);
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // never
        }
    }

    // ---- the scan -------------------------------------------------------------------

    internal static bool On(UploadOptions o) => o.DeepScanMode is RaspMode m && m != RaspMode.Off && (o.DeepScan.ClamAv is not null || o.DeepScan.Reputation);

    /// <summary>One scan in progress: ClamAV fed as the bytes arrive, the reputation lookup once the hash is known.</summary>
    internal sealed class Run
    {
        private readonly UploadOptions _o;
        private readonly DateTime _deadline;
        private readonly List<string> _failed = new();

        public Run(UploadOptions o)
        {
            _o = o;
            _deadline = DateTime.UtcNow.AddMilliseconds(o.DeepScan.Timeout);
            if (o.DeepScan.ClamAv is { } a)
            {
                try
                {
                    Clam = ClamStream.Start(a, _deadline);
                }
                catch (DeepScanEngineException e)
                {
                    NoteEngine("clamav", e.Status, o.DeepScan.FailMode, string.Empty);
                    _failed.Add("clamav");
                }
            }
        }

        public ClamStream? Clam { get; set; }

        /// <summary>Feeds ClamAV (never fails).</summary>
        public void Write(byte[] p, int off, int len) => Clam?.Write(p, off, len);

        /// <summary>
        /// Reads the engines' answers for a file with this hash ("" when not hashed):
        /// upload.malware, upload.reputation or (fail closed) upload.scan_unavailable; null for none.
        /// </summary>
        public UploadFileFinding? Finish(string sha, bool complete)
        {
            var fm = _o.DeepScan.FailMode;
            if (Clam is { } c)
            {
                Clam = null;
                string? name = null;
                DeepScanEngineException? err = null;
                if (complete)
                {
                    try
                    {
                        name = c.Finish();
                    }
                    catch (DeepScanEngineException e)
                    {
                        err = e;
                    }
                }
                else
                {
                    c.Dispose();
                    err = new DeepScanEngineException("error");
                }

                if (err is not null)
                {
                    NoteEngine("clamav", err.Status, fm, string.Empty);
                    _failed.Add("clamav");
                }
                else
                {
                    NoteEngine("clamav", "ok", fm, string.Empty);
                    if (name is not null)
                    {
                        return new UploadFileFinding("upload.malware", "clamav", name);
                    }
                }
            }

            if (_o.DeepScan.Reputation && !string.IsNullOrEmpty(sha))
            {
                var left = (long)Math.Max(1, (_deadline - DateTime.UtcNow).TotalMilliseconds);
                try
                {
                    var v = Reputation(sha, left);
                    NoteEngine("reputation", "ok", fm, string.Empty);
                    if (v == "malicious")
                    {
                        return new UploadFileFinding("upload.reputation", "reputation");
                    }
                }
                catch (DeepScanEngineException e)
                {
                    NoteEngine("reputation", e.Status, fm, string.Empty);
                    _failed.Add("reputation");
                }
            }

            return _failed.Count > 0 && _o.DeepScan.FailClosed ? new UploadFileFinding("upload.scan_unavailable", _failed[0]) : null;
        }
    }

    internal static Run? Start(UploadOptions o)
    {
        TestEngines(o.DeepScan);
        return On(o) ? new Run(o) : null;
    }

    /// <summary>Drops the scan (the file was refused or is trusted).</summary>
    internal static void Abort(Run? r)
    {
        r?.Clam?.Dispose();
        if (r is not null)
        {
            r.Clam = null;
        }
    }

    /// <summary>The finding the deep scan's mode decides.</summary>
    internal static RaspFinding Finding(UploadFileFinding f, UploadVerdict v, UploadOptions o) =>
        new(RaspAttackType.MaliciousUpload, f.Rule, RaspUploads.Input(o)) { Mode = o.DeepScanMode, Upload = new UploadAttrs(v, f.Signature, f.Engine, null) };

    /// <summary>Runs the deep scan engines on a saved file now: the finding, or null for none. It does not report.</summary>
    public static UploadFileFinding? ScanFile(string path, string? sha, UploadOptions options)
    {
        if (options is null || !On(options) || options.IsTrusted(sha ?? string.Empty))
        {
            return null;
        }

        var r = Start(options)!;
        var complete = true;
        if (r.Clam is not null)
        {
            try
            {
                using var f = File.OpenRead(path);
                var buf = new byte[ClamChunk];
                int n;
                while ((n = f.Read(buf, 0, buf.Length)) > 0)
                {
                    r.Write(buf, 0, n);
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                complete = false;
            }
        }

        return r.Finish(sha ?? string.Empty, complete);
    }

    /// <summary>Scans a saved file in the background: a find the mode blocks moves every known location of the file to quarantine.</summary>
    internal static void Async(string path, UploadVerdict v, UploadOptions o)
    {
        var ctx = RaspScope.Current;
        _ = Task.Run(() =>
        {
            try
            {
                AsyncScan(path, v, o, ctx);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // never
            }
        });
    }

    internal static void AsyncScan(string path, UploadVerdict v, UploadOptions o, RaspContext? ctx)
    {
        if (ScanFile(path, v.Sha256, o) is not { } f)
        {
            return;
        }

        var fd = Finding(f, v, o);
        if (RaspEngine.EffectiveUploadMode(fd) == RaspMode.Block)
        {
            var moved = false;
            foreach (var p in new[] { path }.Concat(RaspUploadBackdoor.LocationsOf(v)).Distinct(StringComparer.Ordinal).ToList())
            {
                var keys = RaspUploadBackdoor.KeysOf(p);
                if (File.Exists(p) && !File.GetAttributes(p).HasFlag(FileAttributes.ReparsePoint) && Quarantine(p, v.Sha256))
                {
                    RaspUploadBackdoor.Forget(keys);
                    moved = true;
                }
            }

            if (moved)
            {
                fd.Upload!.Action = "quarantined";
            }
        }

        try
        {
            RaspEngine.HandleFinding(fd, Sink, ctx is null ? null : new FindingExtra(ctx.Framework, ctx.ResolvedRoute(), ctx.Method, ctx.Path, ctx));
        }
        catch (Shield360RaspBlockedException)
        {
            // after the response: the event says what happened
        }
    }

    // ---- quarantine -----------------------------------------------------------------

    private static string s_quarantineDir = string.Empty;

    /// <summary>Where blocked uploads are moved (the local options, else the temp directory + shield360-quarantine).</summary>
    public static string QuarantineDir
    {
        get
        {
            var d = Volatile.Read(ref s_quarantineDir);
            return d.Length == 0 ? System.IO.Path.Combine(System.IO.Path.GetTempPath(), "shield360-quarantine") : d;
        }
    }

    internal static void SetQuarantineDir(string? d) => Volatile.Write(ref s_quarantineDir, RaspUploads.IsAbsPath(d) ? d! : string.Empty);

    /// <summary>Moves a file into the quarantine directory (created 0700), renamed to its SHA-256 with mode 0600.</summary>
    public static bool Quarantine(string path, string? sha)
    {
        try
        {
            var dir = QuarantineDir;
            Directory.CreateDirectory(dir);
#if NET8_0_OR_GREATER
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
#endif
            var name = sha is not null && RaspUploads.ShaShape.IsMatch(sha) ? sha : "upload-" + DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture);
            var target = System.IO.Path.Combine(dir, name + ".quarantined");
            if (File.Exists(target))
            {
                File.Delete(target);
            }

            try
            {
                File.Move(path, target);
            }
            catch (IOException)
            {
                File.Copy(path, target, true);
                File.Delete(path);
            }

#if NET8_0_OR_GREATER
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
#endif
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }
}
