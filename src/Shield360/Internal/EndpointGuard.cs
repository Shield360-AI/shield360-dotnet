using System;
using System.Net;

namespace Shield360.Internal;

/// <summary>URL checks shared by the exporter set-up and the rule engine client.</summary>
internal static class EndpointGuard
{
    /// <summary>
    /// Throws unless <paramref name="url"/> is an absolute HTTPS URL, or an HTTP
    /// URL on the local machine. An API key is never sent over plain HTTP to
    /// another host. The message names the setting, never the key.
    /// </summary>
    public static Uri RequireSecure(string url, string setting)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new Shield360Exception($"{setting} must be an absolute http or https URL.");
        }

        if (uri.Scheme == Uri.UriSchemeHttp && !IsLoopback(uri))
        {
            throw new Shield360Exception($"{setting} must use https unless it points at localhost.");
        }

        return uri;
    }

    public static bool IsLoopback(Uri uri)
    {
        if (uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip);
    }

    /// <summary>
    /// The URL for one OTLP signal (<c>traces</c>, <c>metrics</c>, <c>logs</c>)
    /// under a base endpoint. Any trailing <c>/v1/&lt;signal&gt;</c> is replaced,
    /// and a base path (an OTLP route behind a gateway) is kept, matching the Go SDK.
    /// </summary>
    public static Uri SignalEndpoint(string endpoint, string signal)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        {
            throw new Shield360Exception("OtlpEndpoint must be an absolute URL.");
        }

        var path = uri.AbsolutePath.TrimEnd('/');
        foreach (var s in new[] { "traces", "metrics", "logs" })
        {
            var suffix = "/v1/" + s;
            if (path.EndsWith(suffix, StringComparison.Ordinal))
            {
                path = path.Substring(0, path.Length - suffix.Length);
                break;
            }
        }

        var builder = new UriBuilder(uri) { Path = path + "/v1/" + signal };
        return builder.Uri;
    }
}
