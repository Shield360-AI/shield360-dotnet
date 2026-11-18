using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Shield360.Rasp;

namespace Shield360.AspNetCore;

/// <summary>
/// The names of a request's uploaded files (sdk/rasp/README.md, "Path",
/// <c>file_write.upload</c>): from <c>Request.Form.Files</c> when the form has already been
/// read, otherwise from the part headers of the multipart body the middleware buffered
/// (at most <see cref="RaspCapture.MaxUploads"/> names from the first
/// <see cref="RaspCapture.MaxUploadScan"/> bytes). Parsed with <see cref="MultipartReader"/>,
/// so header-like text inside a file's content is never read as a part header. Never throws.
/// </summary>
internal static class RaspUploadNames
{
    private static readonly IReadOnlyList<RaspUpload> s_none = Array.Empty<RaspUpload>();

    /// <summary>The names of the files a form already read holds, or null when the form has not been read.</summary>
    public static IReadOnlyList<RaspUpload>? FromReadForm(HttpContext context)
    {
        try
        {
            // IFormFeature.Form is the parsed form, or null: it never reads the body.
            var form = context.Features.Get<IFormFeature>()?.Form;
            if (form is null)
            {
                return null;
            }

            var out_ = new List<RaspUpload>();
            foreach (var f in form.Files)
            {
                if (out_.Count >= RaspCapture.MaxUploads)
                {
                    break;
                }

                if (!string.IsNullOrEmpty(f.FileName))
                {
                    out_.Add(new RaspUpload(f.Name, f.FileName));
                }
            }

            return out_;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    /// <summary>
    /// The file names in the part headers of a <c>multipart/form-data</c> body (the bytes the
    /// middleware read and put back; the app's own stream is not touched). A body cut at the
    /// read limit yields the names before the cut.
    /// </summary>
    public static async Task<IReadOnlyList<RaspUpload>> FromMultipartAsync(byte[]? body, string? contentType, CancellationToken cancellationToken)
    {
        if (body is null || body.Length == 0 || !MediaTypeHeaderValue.TryParse(contentType, out var media) ||
            !media.MediaType.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase))
        {
            return s_none;
        }

        var boundary = HeaderUtilities.RemoveQuotes(media.Boundary);
        if (StringSegment.IsNullOrEmpty(boundary) || boundary.Length > 200)
        {
            return s_none;
        }

        var out_ = new List<RaspUpload>();
        try
        {
            using var stream = new MemoryStream(body, 0, Math.Min(body.Length, RaspCapture.MaxUploadScan), writable: false);
            // No header limits of its own: the app's form options may allow more than the reader's
            // defaults (16 headers, 16 KiB), and a part RASP gave up on would reach the app unchecked.
            // The buffer is already capped at 1 MiB, so that bounds the work.
            var reader = new MultipartReader(boundary.Value!, stream)
            {
                HeadersCountLimit = int.MaxValue,
                HeadersLengthLimit = RaspCapture.MaxUploadScan,
            };
            while (out_.Count < RaspCapture.MaxUploads)
            {
                var section = await reader.ReadNextSectionAsync(cancellationToken).ConfigureAwait(false);
                if (section is null)
                {
                    break;
                }

                if (!ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var cd) ||
                    !cd.DispositionType.Equals("form-data", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // filename* (RFC 5987) is already decoded; filename is the quoted value.
                var name = !StringSegment.IsNullOrEmpty(cd.FileNameStar) ? cd.FileNameStar : HeaderUtilities.RemoveQuotes(cd.FileName);
                if (StringSegment.IsNullOrEmpty(name))
                {
                    continue;
                }

                var field = HeaderUtilities.RemoveQuotes(cd.Name);
                out_.Add(new RaspUpload(StringSegment.IsNullOrEmpty(field) ? "file" : field.Value!, name.Value!));
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException)
        {
            // a cut or malformed body: keep the names read so far
        }

        return out_;
    }
}
