using System;
using System.Collections.Generic;

namespace Shield360.Internal;

/// <summary>
/// SHIELD: request tracing without the noise. Health probes (Kubernetes, load
/// balancers, uptime checks) arrive every few seconds and say nothing about the
/// app, and the SDK's own calls to Shield360 (guard reports, heartbeats, config)
/// are not the app's work. Neither is traced.
/// Must stay in sync with: sdk/typescript/src/instrumentation/http-noise.ts
/// </summary>
internal static class RequestNoise
{
    private static readonly HashSet<string> HealthPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/health", "/healthz", "/healthcheck", "/ready", "/readyz", "/live", "/livez", "/ping", "/status", "/metrics", "/api/health",
    };

    private static readonly string[] ProbeAgents =
    {
        "kube-probe", "ELB-HealthChecker", "GoogleHC", "Consul Health Check", "Amazon-Route53-Health-Check-Service", "UptimeRobot",
    };

    /// <summary>Whether an incoming request is a health probe: a probe's user agent, or a well-known health path.</summary>
    public static bool IsHealthProbe(string? path, string? userAgent)
    {
        if (!string.IsNullOrEmpty(userAgent))
        {
            foreach (var agent in ProbeAgents)
            {
                if (userAgent!.StartsWith(agent, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        var p = (path ?? string.Empty).Split('?')[0].TrimEnd('/');
        return HealthPaths.Contains(p.Length == 0 ? "/" : p);
    }

    /// <summary>The host:port the SDK reports to, from the Shield360 URL, or null.</summary>
    public static string? Shield360Authority(string? shield360Url) =>
        Uri.TryCreate(shield360Url, UriKind.Absolute, out var uri) ? uri.Authority : null;

    /// <summary>Whether an outgoing request goes to Shield360 itself.</summary>
    public static bool IsOwnCall(Uri? requestUri, string? shield360Authority) =>
        requestUri is not null && shield360Authority is not null &&
        string.Equals(requestUri.Authority, shield360Authority, StringComparison.OrdinalIgnoreCase);
}
