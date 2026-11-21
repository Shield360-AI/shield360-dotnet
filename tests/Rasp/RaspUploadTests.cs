using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Shield360.AspNetCore;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// Upload file names: read from multipart part headers (or a form already read),
/// recorded as request input, checked by <c>file_write.upload</c>, and then seen by
/// <c>file_write.script</c> when the app writes a file named after them. Port of upload.test.ts.
/// </summary>
public class RaspUploadTests : RaspStateTest
{
    private const string Boundary = "----shield360test";
    private const string MultipartType = "multipart/form-data; boundary=" + Boundary;

    private static byte[] Multipart(params (string Disposition, string Body)[] parts)
    {
        var sb = new StringBuilder();
        foreach (var (disposition, body) in parts)
        {
            sb.Append("--").Append(Boundary).Append("\r\nContent-Disposition: ").Append(disposition).Append("\r\n\r\n").Append(body).Append("\r\n");
        }

        sb.Append("--").Append(Boundary).Append("--\r\n");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static Task<IReadOnlyList<RaspUpload>> Names(byte[] body, string contentType = MultipartType) =>
        RaspUploadNames.FromMultipartAsync(body, contentType, CancellationToken.None);

    private static RaspContext Ctx() => RaspCapture.CaptureRequest(new RequestShape { Framework = "test", Method = "POST", Url = "/upload" });

    private static ListSink Monitor(RaspMode fileWrite = RaspMode.Monitor) =>
        Configure(new EngineSettings(true, "a", Attacks: new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.FileWrite] = fileWrite }));

    [Fact]
    public async Task Reads_file_names_from_part_headers_not_plain_fields()
    {
        var body = Multipart(
            ("form-data; name=\"title\"", "Quarterly report"),
            ("form-data; name=\"attachment\"; filename=\"report.pdf\"", "fixture"));
        Assert.Equal(new[] { new RaspUpload("attachment", "report.pdf") }, await Names(body));
    }

    [Fact]
    public async Task Reads_unquoted_parameters_in_any_order_and_filename_star()
    {
        var body = Multipart(
            ("form-data; filename=report.pdf; name=attachment", "fixture"),
            ("form-data; name=\"doc\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf", "fixture"));
        Assert.Equal(new[] { new RaspUpload("attachment", "report.pdf"), new RaspUpload("doc", "résumé.pdf") }, await Names(body));
    }

    [Fact]
    public async Task Never_reads_header_like_text_inside_a_files_content()
    {
        var body = Multipart(("form-data; name=\"attachment\"; filename=\"report.pdf\"", "Content-Disposition: form-data; name=\"x\"; filename=\"page.php\""));
        Assert.Equal(new[] { "report.pdf" }, (await Names(body)).Select(u => u.Name));
    }

    [Fact]
    public async Task Caps_the_number_of_names_and_keeps_those_before_a_cut()
    {
        var many = Multipart(Enumerable.Range(0, 40).Select(i => ($"form-data; name=\"f{i}\"; filename=\"x{i}.txt\"", "1")).ToArray());
        Assert.Equal(RaspCapture.MaxUploads, (await Names(many)).Count);

        var whole = Multipart(("form-data; name=\"a\"; filename=\"report.pdf\"", "fixture"), ("form-data; name=\"b\"; filename=\"notes.txt\"", new string('x', 4096)));
        var cut = whole.AsSpan(0, whole.Length - 2048).ToArray();
        Assert.Equal(new[] { "report.pdf", "notes.txt" }, (await Names(cut)).Select(u => u.Name));
    }

    [Fact]
    public async Task Reads_parts_with_more_headers_than_the_form_readers_defaults()
    {
        // An app may raise FormOptions.MultipartHeadersCountLimit / MultipartHeadersLengthLimit; the names must still be read.
        var manyHeaders = string.Concat(Enumerable.Range(0, 20).Select(i => $"\r\nX-Extra-{i}: {i}"));
        var longHeader = "\r\nX-Long: " + new string('x', 20 * 1024);
        var body = Multipart(
            ("form-data; name=\"a\"; filename=\"page.php\"" + manyHeaders, "fixture"),
            ("form-data; name=\"b\"; filename=\"report.pdf\"" + longHeader, "fixture"));
        Assert.Equal(new[] { "page.php", "report.pdf" }, (await Names(body)).Select(u => u.Name));
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData("multipart/form-data")]
    [InlineData(null)]
    public async Task Reads_nothing_without_a_multipart_boundary(string? contentType)
    {
        var body = Multipart(("form-data; name=\"attachment\"; filename=\"report.pdf\"", "fixture"));
        Assert.Empty(await Names(body, contentType!));
    }

    [Theory]
    [InlineData("page.php")]
    [InlineData("uploads\\page.php")]
    public void Upload_flags_a_script_name(string name)
    {
        Assert.Equal("file_write.upload", RaspDetect.Upload(new RaspInput(name, "body.file.filename"))?.Rule);
    }

    [Theory]
    [InlineData("report.pdf")]
    [InlineData("php.txt")]
    public void Upload_passes_an_ordinary_name(string name)
    {
        Assert.Null(RaspDetect.Upload(new RaspInput(name, "body.file.filename")));
    }

    [Fact]
    public void Records_the_name_as_input_and_reports_a_script_upload_in_monitor()
    {
        var sink = Monitor();
        var ctx = Ctx();
        RaspCapture.CaptureBody(ctx, new BodyShape(null, MultipartType, new[] { new RaspUpload("attachment", "page.php") }));
        Assert.Contains(RaspScope.InputsOf(ctx), i => i.Key == "body.attachment.filename" && i.Value == "page.php");
        var e = Assert.Single(sink.Events);
        Assert.Equal("file_write.upload", e.Attrs["shield360.rasp.rule"]);
        Assert.Equal("request.upload", e.Attrs["shield360.rasp.sink"]);
        Assert.Equal("body.attachment.filename", e.Attrs["shield360.rasp.input_key"]);
        Assert.Equal("POST", e.Attrs["shield360.rasp.method"]);
    }

    [Fact]
    public void Checks_the_full_name_even_when_the_input_entry_is_cut()
    {
        var sink = Monitor();
        var ctx = Ctx();
        var name = new string('a', RaspNormalize.MaxValue + 10) + ".php";
        RaspCapture.CaptureBody(ctx, new BodyShape(null, MultipartType, new[] { new RaspUpload("f", name) }));
        Assert.Equal(RaspNormalize.MaxValue, RaspScope.InputsOf(ctx).Single(i => i.Key == "body.f.filename").Value.Length);
        Assert.Equal("file_write.upload", Assert.Single(sink.Events).Attrs["shield360.rasp.rule"]);
    }

    [Fact]
    public void Blocks_a_script_upload_when_file_write_blocks_and_lets_an_ordinary_one_through()
    {
        var sink = Monitor(RaspMode.Block);
        Assert.Throws<Shield360RaspBlockedException>(() =>
            RaspCapture.CaptureBody(Ctx(), new BodyShape(null, MultipartType, new[] { new RaspUpload("f", "page.php") })));
        sink.Events.Clear();
        RaspCapture.CaptureBody(Ctx(), new BodyShape(null, MultipartType, new[] { new RaspUpload("f", "report.pdf") }));
        Assert.Empty(sink.Events);
    }

    [Fact]
    public void A_later_write_named_after_the_upload_is_caught_by_file_write_script()
    {
        Monitor();
        var ctx = Ctx();
        RaspCapture.CaptureBody(ctx, new BodyShape(null, MultipartType, new[] { new RaspUpload("f", "page.php") }));
        Assert.Equal("file_write.script", RaspDetect.FilePath("/srv/app/public/page.php", FileOp.Write, RaspScope.InputsOf(ctx), null, true)?.Rule);
    }

    // ---- In the ASP.NET Core middleware ----------------------------------------

    private static async Task<WebApplication> Serve(bool readFormFirst = false)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        if (readFormFirst)
        {
            app.Use(async (context, next) =>
            {
                await context.Request.ReadFormAsync();
                await next(context);
            });
        }

        app.UseShield360Rasp();
        app.MapPost("/upload", async (HttpRequest request) =>
        {
            var form = await request.ReadFormAsync();
            var file = form.Files["attachment"]!;
            using var reader = new System.IO.StreamReader(file.OpenReadStream());
            var keys = RaspScope.InputsOf(RaspScope.Current!).Where(i => i.Key.EndsWith(".filename", StringComparison.Ordinal)).Select(i => i.Key + "=" + i.Value);
            return Results.Json(new { name = file.FileName, content = await reader.ReadToEndAsync(), title = form["title"].ToString(), inputs = keys });
        }).DisableAntiforgery();
        await app.StartAsync();
        return app;
    }

    private static MultipartFormDataContent Form(string fileName, string content = "fixture content")
    {
        var form = new MultipartFormDataContent(Boundary)
        {
            { new StringContent("Quarterly report"), "title" },
        };
        form.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(content)), "attachment", fileName);
        return form;
    }

    [Fact]
    public async Task The_middleware_reads_the_names_and_the_app_still_reads_the_whole_form()
    {
        var sink = Monitor();
        await using var app = await Serve();
        var res = await app.GetTestClient().PostAsync(new Uri("/upload", UriKind.Relative), Form("page.php"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var got = JsonNode.Parse(await res.Content.ReadAsStringAsync())!;
        Assert.Equal("page.php", (string?)got["name"]);
        Assert.Equal("fixture content", (string?)got["content"]);
        Assert.Equal("Quarterly report", (string?)got["title"]);
        Assert.Contains("body.attachment.filename=page.php", got["inputs"]!.AsArray().Select(n => (string?)n));
        var e = Assert.Single(sink.Events);
        Assert.Equal("file_write.upload", e.Attrs["shield360.rasp.rule"]);
        Assert.Equal("aspnetcore", e.Attrs["shield360.rasp.framework"]);
    }

    [Fact]
    public async Task The_middleware_blocks_a_script_upload_and_passes_an_ordinary_one()
    {
        var sink = Monitor(RaspMode.Block);
        await using var app = await Serve();
        var client = app.GetTestClient();
        var blocked = await client.PostAsync(new Uri("/upload", UriKind.Relative), Form("page.php"));
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Equal("file_write.upload", (string?)JsonNode.Parse(await blocked.Content.ReadAsStringAsync())!["rule"]);
        sink.Events.Clear();
        // A real PDF: a text file named .pdf is reported as upload.type_mismatch (monitor only).
        var ok = await client.PostAsync(new Uri("/upload", UriKind.Relative), Form("report.pdf", "%PDF-1.4\n%%EOF\n"));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Empty(sink.Events);
    }

    [Fact]
    public async Task The_middleware_reads_a_form_that_was_already_read()
    {
        Monitor(RaspMode.Block);
        await using var app = await Serve(readFormFirst: true);
        var res = await app.GetTestClient().PostAsync(new Uri("/upload", UriKind.Relative), Form("page.php"));
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }
}
