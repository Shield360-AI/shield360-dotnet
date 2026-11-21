using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using Shield360.Rasp;

namespace Shield360.AspNetCore;

/// <summary>
/// SHIELD: uploads (sdk/rasp/README.md "Uploads") — inspects each multipart file part
/// with the route's policy before the app runs. The whole body is read once more from
/// the request's buffer (spooled to disk past 30 KiB by ASP.NET Core) and rewound, so
/// the app reads it as if RASP were not there; a form the app already read is
/// inspected from its files. A refused file throws the block error (403).
/// </summary>
internal static class RaspUploadInspection
{
    public static async Task InspectAsync(HttpContext context, RaspContext ctx, CancellationToken cancellationToken)
    {
        if (!RaspEngine.IsActive)
        {
            return;
        }

        var route = ctx.ResolvedRoute();
        if (string.IsNullOrEmpty(route))
        {
            route = ctx.Path;
        }

        var form = context.Features.Get<IFormFeature>()?.Form;
        if (form is not null)
        {
            foreach (var f in form.Files)
            {
                if (string.IsNullOrEmpty(f.FileName))
                {
                    continue;
                }

                var o = RaspUploads.OptionsFor(route);
                o.Field = f.Name ?? string.Empty;
                using var s = f.OpenReadStream();
                var (_, blocked) = await RaspUploads.InspectCoreAsync(s, f.FileName, f.ContentType, o, ctx, cancellationToken).ConfigureAwait(false);
                if (blocked is not null)
                {
                    throw blocked;
                }
            }

            return;
        }

        var request = context.Request;
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var media) || !media.MediaType.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var boundary = HeaderUtilities.RemoveQuotes(media.Boundary);
        if (boundary.Length == 0 || boundary.Length > 200 || !request.Body.CanSeek)
        {
            return;
        }

        var start = request.Body.Position;
        try
        {
            var reader = new MultipartReader(boundary.Value!, request.Body) { HeadersCountLimit = int.MaxValue, HeadersLengthLimit = 1 << 20 };
            var files = 0;
            while (files < RaspUploads.MaxRequestUploads)
            {
                var section = await reader.ReadNextSectionAsync(cancellationToken).ConfigureAwait(false);
                if (section is null)
                {
                    break;
                }

                if (!ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var cd) || !cd.DispositionType.Equals("form-data", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var name = HeaderUtilities.RemoveQuotes(cd.FileNameStar.HasValue ? cd.FileNameStar : cd.FileName).Value;
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                files++;
                var o = RaspUploads.OptionsFor(route);
                o.Field = HeaderUtilities.RemoveQuotes(cd.Name).Value ?? string.Empty;
                var (_, blocked) = await RaspUploads.InspectCoreAsync(section.Body, name, section.ContentType, o, ctx, cancellationToken).ConfigureAwait(false);
                if (blocked is not null)
                {
                    throw blocked;
                }
            }
        }
        catch (Exception e) when (e is IOException or InvalidDataException or BadHttpRequestException)
        {
            // a malformed body: the app's own reader reports it
        }
        finally
        {
            request.Body.Position = start;
        }
    }
}
