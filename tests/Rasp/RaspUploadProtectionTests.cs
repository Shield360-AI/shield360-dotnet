using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Upload protection, all four layers: the shared corpus (sdk/rasp/testdata/uploads.json)
/// and fixture files built here (never real malware), the policy, the deep scan (a fake
/// clamd over TCP and a Unix socket, a fake reputation service), quarantine, the
/// backdoor checks and the ASP.NET Core middleware.
/// </summary>
public class RaspUploadProtectionTests : RaspStateTest
{
    private static readonly byte[] s_png = Convert.FromHexString("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a9b10000000049454e44ae426082");
    private static readonly byte[] s_jpeg = Convert.FromHexString("ffd8ffe000104a46494600010100000100010000ffd9");
    private static readonly byte[] s_shell = Encoding.ASCII.GetBytes("<?php @eval($_POST[\"x\"]); ?>");
    private readonly string _tmp = Path.Combine(Path.GetTempPath(), "s360-up-" + Guid.NewGuid().ToString("N"));

    public RaspUploadProtectionTests()
    {
        Directory.CreateDirectory(_tmp);
        RaspDeepScan.Reset();
        RaspUploadBackdoor.Reset();
        RaspUploads.SetLocal(null, 0, null);
    }

    protected override void Dispose(bool disposing)
    {
        RaspDeepScan.SetEnv(null, null, null);
        RaspDeepScan.Reset();
        RaspUploadBackdoor.Reset();
        RaspUploads.SetLocal(null, 0, null);
        try
        {
            Directory.Delete(_tmp, true);
        }
        catch (IOException)
        {
        }

        base.Dispose(disposing);
    }

    private static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    private static JsonObject Corpus() => RaspCorpus.Load("testdata/uploads.json");

    private static ListSink On(RaspMode mode = RaspMode.Monitor, Dictionary<RaspAttackType, RaspMode>? attacks = null) =>
        Configure(new EngineSettings(true, "orders-api", mode, attacks));

    private static T InRequest<T>(Func<T> fn) => RaspScope.Run(new RaspContext(null, inRequest: true), fn);

    private static List<IReadOnlyDictionary<string, string>> Events(ListSink s, string name = "shield360.rasp.event")
    {
        lock (s.Events)
        {
            return s.Events.Where(e => e.Name == name).Select(e => e.Attrs).ToList();
        }
    }

    [Fact]
    public void BuiltInSignaturesAreByteIdenticalAndAllCompile()
    {
        var contract = File.ReadAllBytes(Path.Combine(RaspCorpus.RaspDir, "rules", "upload-signatures.json"));
        Assert.Equal(contract, UploadSignatures.BuiltInJson());
        using var doc = JsonDocument.Parse(contract);
        var rules = doc.RootElement.GetProperty("rules");
        var (sigs, errs) = UploadSignatures.CompileAll(rules);
        Assert.Empty(errs);
        Assert.Equal(rules.GetArrayLength(), UploadSignatures.BuiltIn.Count);
        Assert.Equal(sigs.Count, UploadSignatures.BuiltIn.Count);
    }

    [Fact]
    public void PassesTheSharedCorpus()
    {
        var c = Corpus();
        var errors = new List<string>();
        foreach (var t in c["types"]!.AsArray())
        {
            var got = UploadScanner.Sniff(Convert.FromHexString(t!["hex"]!.GetValue<string>()));
            if (got != t["type"]!.GetValue<string>())
            {
                errors.Add($"sniff {t["type"]}: {got}");
            }
        }

        foreach (var t in c["names"]!.AsArray())
        {
            var name = t!["name"]!.GetValue<string>();
            var got = new List<string>();
            if (UploadScanner.IsServerConfigName(name))
            {
                got.Add("upload.server_config");
            }

            if (UploadScanner.HasDoubleExtension(name))
            {
                got.Add("upload.double_extension");
            }

            if (!got.SequenceEqual(RaspCorpus.Strings(t["rules"])))
            {
                errors.Add($"name {name}: {string.Join(",", got)}");
            }
        }

        foreach (var t in c["mismatch"]!.AsArray())
        {
            var got = UploadScanner.TypeMismatch(t!["type"]!.GetValue<string>(), t["name"]?.GetValue<string>(), t["contentType"]?.GetValue<string>());
            if (got != t["mismatch"]!.GetValue<bool>())
            {
                errors.Add($"mismatch {t.ToJsonString()}");
            }
        }

        foreach (var t in c["signatures"]!.AsArray())
        {
            using var doc = JsonDocument.Parse(t!["rule"]!.ToJsonString());
            UploadSignature sig;
            try
            {
                sig = UploadSignatures.Compile(doc.RootElement);
            }
            catch (UploadSignatureException e)
            {
                errors.Add($"signature {t["rule"]!["id"]}: {e.Code}");
                continue;
            }

            var sampleText = t["sample"]!.GetValue<string>();
            var sample = sampleText == "@@ACROSS@@"
                ? Encoding.ASCII.GetBytes(new string('x', 1048570) + "MARKERTEXT" + new string('x', 100))
                : Encoding.UTF8.GetBytes(sampleText);
            var got = UploadSignatures.MatchSample(new[] { sig }, sample).Count > 0;
            if (got != t["match"]!.GetValue<bool>())
            {
                errors.Add($"signature {t["rule"]!["id"]}: match {got}");
            }
        }

        foreach (var t in c["invalid"]!.AsArray())
        {
            using var doc = JsonDocument.Parse(t!["rule"]!.ToJsonString());
            try
            {
                UploadSignatures.Compile(doc.RootElement);
                errors.Add($"invalid {t["rule"]!.ToJsonString()}: compiled");
            }
            catch (UploadSignatureException e) when (e.Code != t["code"]!.GetValue<string>())
            {
                errors.Add($"invalid {t["rule"]!.ToJsonString()}: {e.Code} want {t["code"]}");
            }
            catch (UploadSignatureException)
            {
                // the expected code
            }
        }

        Assert.True(errors.Count == 0, string.Join("\n", errors));
    }

    [Fact]
    public void SignatureWorkIsBounded()
    {
        using var doc = JsonDocument.Parse("""{"id":"r","title":"t","strings":[{"id":"a","regex":"(a|aa)*b","anchor":"aaa"}],"condition":"any"}""");
        var sig = UploadSignatures.Compile(doc.RootElement);
        var started = DateTime.UtcNow;
        Assert.Empty(UploadSignatures.MatchSample(new[] { sig }, Enumerable.Repeat((byte)'a', 4 << 20).ToArray()));
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(10), "regex work is not bounded");
    }

    // ---- fixtures -------------------------------------------------------------

    private sealed record ZipFixture(string Name, string Data, bool Symlink = false, bool Encrypted = false, uint Declared = 0);

    private static byte[] Zip(params ZipFixture[] entries)
    {
        using var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
        {
            foreach (var e in entries)
            {
                using var w = new StreamWriter(z.CreateEntry(e.Name, CompressionLevel.NoCompression).Open());
                w.Write(e.Data);
            }
        }

        var out_ = ms.ToArray();
        for (var p = 0; p + 46 <= out_.Length; p++)
        {
            if (out_[p] != 'P' || out_[p + 1] != 'K' || out_[p + 2] != 1 || out_[p + 3] != 2)
            {
                continue;
            }

            var n = BitConverter.ToUInt16(out_, p + 28);
            var name = Encoding.UTF8.GetString(out_, p + 46, n);
            foreach (var e in entries.Where(e => e.Name == name))
            {
                if (e.Declared > 0)
                {
                    BitConverter.GetBytes(e.Declared).CopyTo(out_, p + 24);
                }

                if (e.Encrypted)
                {
                    out_[p + 8] |= 1;
                }

                if (e.Symlink)
                {
                    out_[p + 5] = 3;
                    BitConverter.GetBytes(0xA1FFu << 16).CopyTo(out_, p + 38);
                }
            }
        }

        return out_;
    }

    private static byte[] Tar(string name, char typ)
    {
        var h = new byte[512];
        Encoding.UTF8.GetBytes(name).CopyTo(h, 0);
        Encoding.ASCII.GetBytes("00000000000\0").CopyTo(h, 124);
        h[156] = (byte)typ;
        Encoding.ASCII.GetBytes("ustar\0").CopyTo(h, 257);
        return Cat(h, new byte[1024]);
    }

    private static string FirstRule(byte[] data, string name)
    {
        var v = UploadScanner.InspectBytes(data, name, string.Empty);
        return v.Findings.Count == 0 ? string.Empty : v.Findings[0].Rule;
    }

    [Fact]
    public void FixturesRaiseTheirRules()
    {
        var v = UploadScanner.InspectBytes(Cat(s_jpeg, s_shell), "avatar.jpg", "image/jpeg");
        Assert.Equal("jpeg", v.Type);
        Assert.Equal("upload.webshell", v.Findings[0].Rule);
        Assert.Equal("php.eval_request", v.Findings[0].Signature);
        Assert.Equal(64, v.Sha256.Length);
        Assert.Equal("upload.script", FirstRule(Encoding.ASCII.GetBytes("<?php echo \"hi\"; ?>"), "a.jpg"));
        Assert.Equal("upload.active_content", FirstRule(Encoding.ASCII.GetBytes("<svg xmlns=\"http://www.w3.org/2000/svg\"><script>x()</script></svg>"), "logo.svg"));
        Assert.Equal("upload.active_content", FirstRule(Encoding.ASCII.GetBytes("<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"x()\"></svg>"), "logo.svg"));
        Assert.Empty(UploadScanner.InspectBytes(s_png, "a.png", "image/png").Findings);
        Assert.Equal("upload.archive_traversal", FirstRule(Zip(new ZipFixture("../../var/www/html/x.php", "a")), "a.zip"));
        Assert.Equal("upload.archive_symlink", FirstRule(Zip(new ZipFixture("link", "/etc/passwd", Symlink: true)), "a.zip"));
        Assert.Equal("upload.archive_bomb", FirstRule(Zip(new ZipFixture("big.bin", new string('x', 1000), Declared: 4000u << 20)), "a.zip"));
        Assert.Equal("upload.archive_encrypted", FirstRule(Zip(new ZipFixture("secret.txt", "xxxx", Encrypted: true)), "a.zip"));
        Assert.Equal("upload.archive_traversal", FirstRule(Tar("../etc/cron.d/x", '0'), "a.tar"));
        Assert.Equal("upload.archive_symlink", FirstRule(Tar("link", '2'), "a.tar"));
        Assert.Equal("upload.eicar", FirstRule(Encoding.ASCII.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), "test.txt"));
        Assert.Equal("upload.executable", FirstRule(new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0, 0, 0 }, "cat.png"));
        Assert.Equal("upload.server_config", FirstRule(Encoding.ASCII.GetBytes("AddType application/x-httpd-php .jpg\n"), ".htaccess"));
        Assert.Equal("upload.double_extension", FirstRule(s_png, "shell.php.png"));
        var docm = UploadScanner.InspectBytes(Zip(new ZipFixture("[Content_Types].xml", "<Types/>"), new ZipFixture("word/document.xml", "<w/>"), new ZipFixture("word/vbaProject.bin", "vba")), "report.docx", string.Empty);
        Assert.Equal("docx", docm.Type);
        Assert.Equal("upload.office_macro", docm.Findings[0].Rule);
        Assert.Equal("upload.office_macro", FirstRule(Cat(Convert.FromHexString("d0cf11e0a1b11ae1"), new byte[504], Encoding.Unicode.GetBytes("_VBA_PROJECT")), "old.doc"));
        var big = Cat(Encoding.ASCII.GetBytes(new string('x', 3 << 20)), s_shell);
        using var s = new UploadScanner("a.txt", "text/plain");
        for (var i = 0; i < big.Length; i += 7777)
        {
            s.Push(big, i, Math.Min(7777, big.Length - i));
        }

        var streamed = s.Finish();
        Assert.Equal("upload.webshell", streamed.Findings[0].Rule);
        using var trusted = new UploadScanner("a.txt", "text/plain", trusted: new[] { streamed.Sha256 });
        trusted.Push(big);
        Assert.Empty(trusted.Finish().Findings);
    }

    // ---- policy and events --------------------------------------------------------

    [Fact]
    public void InspectionReportsOneEventAFileWithTheUploadAttributes()
    {
        var sink = On();
        var v = InRequest(() => RaspUploads.Inspect(Cat(s_jpeg, s_shell), "avatar.jpg", "image/jpeg", new UploadOptions { Field = "avatar" }));
        Assert.Equal("jpeg", v.Type);
        var a = Assert.Single(Events(sink));
        Assert.Equal("malicious_upload", a["shield360.rasp.attack"]);
        Assert.Equal("upload.webshell", a["shield360.rasp.rule"]);
        Assert.Equal("request.upload", a["shield360.rasp.sink"]);
        Assert.Equal("body.avatar.filename", a["shield360.rasp.input_key"]);
        Assert.Equal("jpeg", a["shield360.rasp.upload.type"]);
        Assert.Equal("image", a["shield360.rasp.upload.kind"]);
        Assert.Equal("jpg", a["shield360.rasp.upload.ext"]);
        Assert.Equal("php.eval_request", a["shield360.rasp.upload.signature"]);
        Assert.Equal("builtin", a["shield360.rasp.upload.engine"]);
        Assert.Equal(64, a["shield360.rasp.upload.sha256"].Length);
        Assert.DoesNotContain("avatar.jpg", a.Values);
    }

    [Fact]
    public void RouteModeBlocksCappedRulesNeverDoAndListedTypesPassTheTypeChecks()
    {
        On();
        var e = Assert.Throws<Shield360RaspBlockedException>(() =>
            RaspUploads.Inspect(Encoding.ASCII.GetBytes("%PDF-1.4\n"), "a.pdf", "application/pdf", new UploadOptions { Mode = RaspMode.Block, Allow = new[] { "image" } }));
        Assert.Equal("upload.type_not_allowed", e.Rule);
        var capped = RaspUploads.Inspect(Encoding.ASCII.GetBytes("%PDF-1.4\n"), "a.jpg", "image/jpeg", new UploadOptions { Mode = RaspMode.Block });
        Assert.Equal("upload.type_mismatch", capped.Findings[0].Rule);
        RaspUploads.Inspect(new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0 }, "tool", string.Empty, new UploadOptions { Mode = RaspMode.Block, Allow = new[] { "elf" } });
        using var rules = JsonDocument.Parse("""[{"id":"r","title":"t","strings":[{"id":"a","text":"abc"}],"condition":"any"}]""");
        var custom = new UploadOptions { Signatures = UploadSignatures.CompileAll(rules.RootElement).Signatures, DeepScanMode = RaspMode.Block };
        Assert.Equal("upload.signature", Assert.Throws<Shield360RaspBlockedException>(() => RaspUploads.Inspect(Encoding.ASCII.GetBytes("xx abc yy"), "a.txt", "text/plain", custom)).Rule);
        On(RaspMode.Monitor, new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.MaliciousUpload] = RaspMode.Off });
        RaspUploads.Inspect(Cat(s_jpeg, s_shell), "a.jpg", "image/jpeg", new UploadOptions { Mode = RaspMode.Block });
    }

    [Fact]
    public void PolicyFromTheSignedConfigAndRoutes()
    {
        On();
        var p = UploadPolicy.Parse("""
            {"allow":["image","bogus"],"maxBytes":1000,"trusted":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","x"],
             "rules":[{"id":"r","title":"t","strings":[{"id":"a","text":"abc"}],"condition":"any"}],"servedDirs":["/srv/www","rel"],
             "deepScan":{"mode":"monitor","clamav":"tcp:127.0.0.1:3310","reputation":true,"timeoutMs":5,"failMode":"closed","scan":"async"},
             "routes":[{"route":"/avatars/*","allow":["png"],"maxBytes":10,"mode":"block","deepScan":"block","scan":"sync","timeoutMs":2000,"failMode":"open"},{"route":"nope"}]}
            """)!;
        Assert.Equal(new[] { "image" }, p.Allow);
        Assert.Equal(1000, p.MaxBytes);
        Assert.Single(p.Trusted);
        Assert.Single(p.Signatures);
        Assert.Equal(new[] { "/srv/www" }, p.ServedDirs);
        Assert.Equal(RaspMode.Monitor, p.DeepScanMode);
        Assert.Equal("tcp:127.0.0.1:3310", p.DeepScan.ClamAv!.ToString());
        Assert.True(p.DeepScan.Reputation && p.DeepScan.Async && p.DeepScan.FailClosed);
        Assert.Equal(100, p.DeepScan.TimeoutMs);
        Assert.Single(p.Routes);
        RaspEngine.SetRemoteConfig(new RemoteConfig { Version = "v1", Uploads = p });
        var app = RaspUploads.OptionsFor("/other");
        Assert.Equal(new[] { "image" }, app.Allow);
        Assert.Null(app.Mode);
        var route = RaspUploads.OptionsFor("/avatars/1");
        Assert.Equal(new[] { "png" }, route.Allow);
        Assert.Equal(10, route.MaxBytes);
        Assert.Equal(RaspMode.Block, route.Mode);
        Assert.Equal(RaspMode.Block, route.DeepScanMode);
        Assert.False(route.DeepScan.Async);
        Assert.False(route.DeepScan.FailClosed);
        Assert.Equal(2000, route.DeepScan.TimeoutMs);
        Assert.True(app.DeepScan.Async);
        Assert.Null(UploadPolicy.Parse("\"x\""));
        Assert.Null(RaspDeepScan.ParseClamAddress("unix:relative"));
        Assert.Null(RaspDeepScan.ParseClamAddress("tcp:host:70000"));
        Assert.Equal("tcp:::1:3310", RaspDeepScan.ParseClamAddress("tcp:[::1]:3310")!.ToString());
        RaspEngine.SetRemoteConfig(null);
        RaspUploads.SetLocal("""{"maxBytes":5,"servedDirs":["/srv/public"]}""", 1024, _tmp);
        Assert.Equal(5, RaspUploads.OptionsFor("/x").MaxBytes);
        Assert.Equal(1024, RaspUploads.OptionsFor("/x").ScanBytes);
        Assert.Equal(new[] { "/srv/public" }, RaspUploads.ServedDirs());
        Assert.Equal(_tmp, RaspDeepScan.QuarantineDir);
    }

    // ---- fake clamd ---------------------------------------------------------------

    private static void ServeClamd(Stream s)
    {
        var cmd = new List<byte>();
        int c;
        while ((c = s.ReadByte()) > 0)
        {
            cmd.Add((byte)c);
        }

        if (Encoding.ASCII.GetString(cmd.ToArray()) == "zPING")
        {
            s.Write(Encoding.ASCII.GetBytes("PONG\0"));
            return;
        }

        var data = new MemoryStream();
        var len = new byte[4];
        while (true)
        {
            s.ReadExactly(len);
            var n = (len[0] << 24) | (len[1] << 16) | (len[2] << 8) | len[3];
            if (n == 0)
            {
                break;
            }

            var chunk = new byte[n];
            s.ReadExactly(chunk);
            data.Write(chunk);
        }

        var bad = Encoding.Latin1.GetString(data.ToArray()).Contains("MALWARE", StringComparison.Ordinal);
        s.Write(Encoding.ASCII.GetBytes(bad ? "stream: Test.Malware FOUND\0" : "stream: OK\0"));
    }

    private static TcpListener TcpClamd()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        _ = Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    using var client = await l.AcceptTcpClientAsync();
                    ServeClamd(client.GetStream());
                }
                catch (Exception e) when (e is SocketException or ObjectDisposedException or IOException or InvalidOperationException)
                {
                    return;
                }
            }
        });
        return l;
    }

    private static string Addr(TcpListener l) => "tcp:127.0.0.1:" + ((IPEndPoint)l.LocalEndpoint).Port;

    [Fact]
    public async Task ClamScanOverTcpAndAUnixSocket()
    {
        var l = TcpClamd();
        try
        {
            var a = RaspDeepScan.ParseClamAddress(Addr(l))!;
            Assert.Equal("Test.Malware", RaspDeepScan.ClamScan(a, new MemoryStream(Encoding.ASCII.GetBytes("xx MALWARE")), 2000));
            Assert.Null(RaspDeepScan.ClamScan(a, new MemoryStream(new byte[200_000]), 2000));
            Assert.True(RaspDeepScan.ClamPing(a, 2000));
        }
        finally
        {
            l.Stop();
        }

        var sock = Path.Combine(Path.GetTempPath(), "c" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".sock");
        using (var server = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
        {
            server.Bind(new UnixDomainSocketEndPoint(sock));
            server.Listen(1);
            var t = Task.Run(() =>
            {
                using var c = server.Accept();
                using var ns = new NetworkStream(c);
                ServeClamd(ns);
            });
            Assert.Equal("Test.Malware", RaspDeepScan.ClamScan(RaspDeepScan.ParseClamAddress("unix:" + sock)!, new MemoryStream(Encoding.ASCII.GetBytes("MALWARE")), 2000));
            await t.WaitAsync(TimeSpan.FromSeconds(2));
        }

        File.Delete(sock);
        Assert.Equal("unreachable", Assert.Throws<DeepScanEngineException>(() => RaspDeepScan.ClamPing(RaspDeepScan.ParseClamAddress("unix:" + Path.Combine(_tmp, "missing.sock"))!, 500)).Status);
    }

    [Fact]
    public void ClamdThatNeverAnswersTimesOut()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        try
        {
            var e = Assert.Throws<DeepScanEngineException>(() => RaspDeepScan.ClamPing(RaspDeepScan.ParseClamAddress(Addr(l))!, 300));
            Assert.Equal("timeout", e.Status);
        }
        finally
        {
            l.Stop();
        }
    }

    [Fact]
    public void ReputationSendsOnlyTheHashAndCaches()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, "{\"verdict\":\"malicious\"}");
        var sha = new string('a', 64);
        Assert.Equal("unreachable", Assert.Throws<DeepScanEngineException>(() => RaspDeepScan.Reputation(sha, 1000)).Status);
        RaspDeepScan.SetEnv("https://shield.example/", "test-key", handler);
        Assert.Equal("malicious", RaspDeepScan.Reputation(sha, 2000));
        Assert.Equal("malicious", RaspDeepScan.Reputation(sha, 2000));
        var r = Assert.Single(handler.Requests);
        Assert.Equal("https://shield.example/api/rasp/upload-reputation", r.Request.RequestUri!.ToString());
        Assert.Equal("{\"sha256\":\"" + sha + "\"}", r.Body);
        Assert.Equal("Bearer test-key", r.Request.Headers.Authorization!.ToString());
    }

    [Fact]
    public void SyncDeepScanBlocksMalwareAndFailsClosedWhenAsked()
    {
        var sink = On();
        var l = TcpClamd();
        try
        {
            var o = new UploadOptions { DeepScanMode = RaspMode.Block, DeepScan = new DeepScanOptions { ClamAv = RaspDeepScan.ParseClamAddress(Addr(l)) } };
            var e = Assert.Throws<Shield360RaspBlockedException>(() => RaspUploads.Inspect(Encoding.ASCII.GetBytes("harmless text MALWARE"), "a.txt", "text/plain", o));
            Assert.Equal("upload.malware", e.Rule);
            var a = Events(sink).Last();
            Assert.Equal("upload.deep_scan", a["shield360.rasp.sink"]);
            Assert.Equal("clamav", a["shield360.rasp.upload.engine"]);
            Assert.Equal("Test.Malware", a["shield360.rasp.upload.signature"]);
            RaspUploads.Inspect(Encoding.ASCII.GetBytes("clean"), "a.txt", "text/plain", o);
            var status = Events(sink, RaspDeepScan.ScannerEvent)[0];
            Assert.Equal("clamav", status["shield360.rasp.scanner.engine"]);
            Assert.Equal("ok", status["shield360.rasp.scanner.status"]);
        }
        finally
        {
            l.Stop();
        }

        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        var port = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();
        var down = new UploadOptions { DeepScanMode = RaspMode.Block, DeepScan = new DeepScanOptions { ClamAv = RaspDeepScan.ParseClamAddress("tcp:127.0.0.1:" + port) } };
        RaspUploads.Inspect(Encoding.ASCII.GetBytes("clean"), "a.txt", "text/plain", down);
        var st = Events(sink, RaspDeepScan.ScannerEvent).Last();
        Assert.Equal("unreachable", st["shield360.rasp.scanner.status"]);
        Assert.Equal("open", st["shield360.rasp.scanner.fail_mode"]);
        down.DeepScan.FailClosed = true;
        Assert.Equal("upload.scan_unavailable", Assert.Throws<Shield360RaspBlockedException>(() => RaspUploads.Inspect(Encoding.ASCII.GetBytes("clean"), "a.txt", "text/plain", down)).Rule);
    }

    [Fact]
    public void ConnectionTestAnswersEachTestIdOnce()
    {
        var sink = On();
        var l = TcpClamd();
        try
        {
            var d = new DeepScanOptions { ClamAv = RaspDeepScan.ParseClamAddress(Addr(l)), TestId = "t1" };
            RaspDeepScan.TestEngines(d);
            RaspDeepScan.TestEngines(d);
            SpinWait.SpinUntil(() => Events(sink, RaspDeepScan.ScannerEvent).Count > 0, 10_000);
            Thread.Sleep(200);
            var st = Assert.Single(Events(sink, RaspDeepScan.ScannerEvent));
            Assert.Equal("t1", st["shield360.rasp.scanner.test_id"]);
            Assert.Equal("ok", st["shield360.rasp.scanner.status"]);
        }
        finally
        {
            l.Stop();
        }
    }

    [Fact]
    public void AsyncDeepScanQuarantinesASavedFileTheModeBlocks()
    {
        var sink = On();
        var q = Path.Combine(_tmp, "quarantine");
        RaspUploads.SetLocal(null, 0, q);
        var l = TcpClamd();
        try
        {
            var o = new UploadOptions { DeepScanMode = RaspMode.Block, DeepScan = new DeepScanOptions { Async = true, ClamAv = RaspDeepScan.ParseClamAddress(Addr(l)) } };
            var data = Encoding.ASCII.GetBytes("report MALWARE");
            var v = RaspUploads.Inspect(data, "report.txt", "text/plain", o);
            var saved = Path.Combine(_tmp, "files", "report.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(saved)!);
            File.WriteAllBytes(saved, data);
            RaspUploads.Saved(saved, v, o);
            Assert.True(SpinWait.SpinUntil(() => Events(sink).Any(a => a["shield360.rasp.rule"] == "upload.malware"), 10_000));
            var a = Events(sink).Last(x => x["shield360.rasp.rule"] == "upload.malware");
            Assert.Equal("quarantined", a["shield360.rasp.upload.action"]);
            Assert.Equal("blocked", a["shield360.rasp.decision"]);
            Assert.False(File.Exists(saved));
            Assert.True(File.Exists(Path.Combine(q, v.Sha256 + ".quarantined")));
        }
        finally
        {
            l.Stop();
        }
    }

    // ---- backdoor checks ------------------------------------------------------------

    [Fact]
    public void BackdoorChecksThroughTheSinks()
    {
        // file_write.script and shell_spawn would answer first (a script under the temp directory, sh -c).
        var sink = On(RaspMode.Block, new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.FileWrite] = RaspMode.Off, [RaspAttackType.ShellSpawn] = RaspMode.Off });
        var monitor = new UploadOptions { Mode = RaspMode.Monitor };
        var dir = Path.Combine(_tmp, "srv", "public");
        Directory.CreateDirectory(dir);
        InRequest(() =>
        {
            Assert.NotEmpty(RaspUploads.Inspect(s_shell, "shell.php", string.Empty, monitor).Findings);
            var saved = Path.Combine(dir, "shell.php");
            var e = Assert.Throws<Shield360RaspBlockedException>(() => RaspFile.WriteAllBytes(saved, s_shell));
            Assert.Equal("backdoor.write_executable", e.Rule);
            var a = Events(sink).Last();
            Assert.Equal("upload_backdoor", a["shield360.rasp.attack"]);
            Assert.DoesNotContain("shell.php", a["shield360.rasp.upload.dest"], StringComparison.Ordinal);
            Assert.Equal("backdoor.exec", Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckProcess(new System.Diagnostics.ProcessStartInfo("php", "-f " + saved))).Rule);
            Assert.Equal("backdoor.exec", Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckCommand("cd /tmp && php '" + saved + "'")).Rule);
            Assert.Equal("backdoor.chmod", Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckChmod(saved, true)).Rule);
            Shield360Rasp.CheckChmod(saved, false);
            Assert.Equal("backdoor.include", Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckLoad(saved)).Rule);
            var svg = RaspUploads.Inspect(Encoding.ASCII.GetBytes("<svg><script>x()</script></svg>"), "logo.svg", string.Empty, monitor);
            var upload = Path.Combine(_tmp, "up", "tmp123");
            RaspUploads.Saved(upload, svg, monitor);
            Assert.Equal("backdoor.write_served", Assert.Throws<Shield360RaspBlockedException>(() => RaspFile.Copy(upload, Path.Combine(dir, "x.bin"))).Rule);
            var html = Encoding.ASCII.GetBytes("<html><script>1</script></html>");
            RaspUploads.Inspect(html, "a.html", string.Empty, monitor);
            Assert.Equal("backdoor.write_served", Assert.Throws<Shield360RaspBlockedException>(() => RaspFile.WriteAllBytes(Path.Combine(dir, "other.dat"), html)).Rule);
            var zip = RaspUploads.Inspect(Zip(new ZipFixture("../x.php", "a")), "a.zip", string.Empty, monitor);
            var archive = Path.Combine(_tmp, "up", "a.zip");
            RaspUploads.Saved(archive, zip, monitor);
            Assert.Equal("backdoor.extract", Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckExtract(archive)).Rule);
            RaspFile.WriteAllText(Path.Combine(_tmp, "notes.txt"), "ok");
            Shield360Rasp.CheckProcess(new System.Diagnostics.ProcessStartInfo("ls", "-l"));
            return 0;
        });
    }

    [Fact]
    public void SavingInABlockedPlaceQuarantinesTheFile()
    {
        On(RaspMode.Block);
        RaspUploads.SetLocal(null, 0, Path.Combine(_tmp, "q"));
        var v = RaspUploads.Inspect(s_shell, "x.php", string.Empty, new UploadOptions { Mode = RaspMode.Monitor });
        var saved = Path.Combine(_tmp, "www", "x.php");
        Directory.CreateDirectory(Path.GetDirectoryName(saved)!);
        File.WriteAllBytes(saved, s_shell);
        Assert.Equal("backdoor.write_executable", Assert.Throws<Shield360RaspBlockedException>(() => RaspUploads.Saved(saved, v, new UploadOptions())).Rule);
        Assert.False(File.Exists(saved));
        Assert.True(File.Exists(Path.Combine(_tmp, "q", v.Sha256 + ".quarantined")));
    }

    [Fact]
    public void UploadLocationsAreBoundedAndExpire()
    {
        On();
        var v = UploadScanner.InspectBytes(Encoding.ASCII.GetBytes("a"), "a.txt", string.Empty);
        for (var i = 0; i < RaspUploadBackdoor.MaxLocations + 50; i++)
        {
            RaspUploadBackdoor.Remember("/srv/up/" + i, v);
        }

        Assert.Equal(RaspUploadBackdoor.MaxLocations, RaspUploadBackdoor.Count);
        Assert.Null(RaspUploadBackdoor.At("/srv/up/0"));
        Assert.NotNull(RaspUploadBackdoor.At("/srv/up/" + (RaspUploadBackdoor.MaxLocations + 49)));
        var later = DateTime.UtcNow.AddHours(25);
        RaspUploadBackdoor.Now = () => later;
        Assert.Null(RaspUploadBackdoor.At("/srv/up/" + (RaspUploadBackdoor.MaxLocations + 49)));
        Assert.Equal(
            new[] { new[] { "a", "b c" }, new[] { "d" }, new[] { "e\"f" } },
            RaspUploadBackdoor.CommandSegments("a 'b c'; d | \"e\\\"f\"").Select(x => x.ToArray()).ToArray());
    }

    // ---- the middleware ---------------------------------------------------------------

    [Fact]
    public async Task MiddlewareInspectsMultipartFilesBeforeTheApp()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddShield360Rasp(o => o.Attacks[RaspAttackType.MaliciousUpload] = RaspMode.Block, Env.Empty);
        await using var app = builder.Build();
        app.UseShield360Rasp();
        var served = 0;
        app.MapPost("/avatars", async (HttpContext c) =>
        {
            served++;
            var form = await c.Request.ReadFormAsync();
            return form.Files.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        });
        await app.StartAsync();
        var client = app.GetTestClient();
        using var bad = new MultipartFormDataContent { { new ByteArrayContent(Cat(s_jpeg, s_shell)), "avatar", "me.jpg" } };
        var denied = await client.PostAsync(new Uri("/avatars", UriKind.Relative), bad);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Contains("upload.webshell", await denied.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(0, served);
        using var ok = new MultipartFormDataContent { { new ByteArrayContent(s_png), "avatar", "me.png" } };
        var res = await client.PostAsync(new Uri("/avatars", UriKind.Relative), ok);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("1", await res.Content.ReadAsStringAsync());
        await app.StopAsync();
    }
}
