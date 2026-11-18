using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shield360.Rasp;

namespace Shield360.AspNetCore;

/// <summary>
/// The client address custom rules read (<c>request.ip</c>), as ASP.NET Core reports it when
/// the rule is judged. <c>AddShield360Rasp</c> puts the RASP middleware first, before the app's
/// <c>UseForwardedHeaders</c>, so the address can still change after capture:
/// <list type="bullet">
/// <item>the connection feature is wrapped, and when the app (forwarded headers) sets the address,
/// the rules that read <c>request.ip</c> are judged again with it, blocking from there;</item>
/// <item>when the app configures <see cref="ForwardedHeadersOptions"/> in services (or
/// <c>ASPNETCORE_FORWARDEDHEADERS_ENABLED</c>) and the request comes from a proxy those options
/// trust with an <c>X-Forwarded-For</c>, those rules wait for that address instead of judging the
/// proxy's (until forwarded headers apply, a later RASP middleware, or the first checked sink).</item>
/// </list>
/// Without forwarded headers an <c>X-Forwarded-For</c> changes nothing: the socket address is used.
/// </summary>
internal static class RaspClientAddress
{
    /// <summary>Wires the context to the request's address. Never throws.</summary>
    public static void Attach(RaspContext ctx, HttpContext context)
    {
        try
        {
            ctx.IpSource = () => context.Connection.RemoteIpAddress?.ToString();
            if (!RaspEngine.CustomRules.Any(r => r.Expr.UsesIp))
            {
                return;
            }

            ctx.IpPending = AwaitsForwardedAddress(context);
            if (context.Features.Get<IHttpConnectionFeature>() is { } inner)
            {
                context.Features.Set<IHttpConnectionFeature>(new Watched(inner, ctx));
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open: the address as captured
        }
    }

    /// <summary>
    /// The address <c>request.ip</c> ends up with, known now: <c>Connection.RemoteIpAddress</c>, or,
    /// when forwarded headers configured in services will rewrite it later in the pipeline (the case
    /// where rules wait), the address they will set, worked out by those same options on a copy of
    /// the request. Null when unknown. Deception uses it to mark and look up clients.
    /// </summary>
    public static string? Settled(HttpContext context)
    {
        var remote = context.Connection.RemoteIpAddress;
        if (AwaitsForwardedAddress(context) && context.RequestServices?.GetService<IOptions<ForwardedHeadersOptions>>()?.Value is { } o)
        {
            var probe = new DefaultHttpContext();
            probe.Connection.RemoteIpAddress = remote;
            probe.Connection.RemotePort = context.Connection.RemotePort;
            foreach (var h in context.Request.Headers)
            {
                probe.Request.Headers[h.Key] = h.Value;
            }

            new ForwardedHeadersMiddleware(_ => Task.CompletedTask, NullLoggerFactory.Instance, Options.Create(o)).ApplyForwarders(probe);
            remote = probe.Connection.RemoteIpAddress;
        }

        return remote?.ToString();
    }

    /// <summary>Whether forwarded headers configured in services will rewrite this request's address.</summary>
    private static bool AwaitsForwardedAddress(HttpContext context)
    {
        var headers = context.Request.Headers;
        if (!headers.ContainsKey("X-Forwarded-For"))
        {
            return false;
        }

        var services = context.RequestServices;
        var configured = services?.GetService<IEnumerable<IConfigureOptions<ForwardedHeadersOptions>>>()?.Any() == true
            || string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_FORWARDEDHEADERS_ENABLED"), "true", StringComparison.OrdinalIgnoreCase);
        if (!configured || services?.GetService<IOptions<ForwardedHeadersOptions>>()?.Value is not { } o ||
            (o.ForwardedHeaders & ForwardedHeaders.XForwardedFor) == 0)
        {
            return false;
        }

        // The middleware trusts only these senders (both empty: every sender).
        var remote = context.Connection.RemoteIpAddress;
        if (o.KnownProxies.Count == 0 && o.KnownNetworks.Count == 0)
        {
            return true;
        }

        if (remote is null)
        {
            return false;
        }

        var forms = remote.IsIPv4MappedToIPv6 ? new[] { remote, remote.MapToIPv4() } : new[] { remote };
        return forms.Any(a => o.KnownProxies.Contains(a) || o.KnownNetworks.Any(n => n.Contains(a)));
    }

    /// <summary>The connection feature, telling RASP when the app sets the client address.</summary>
    private sealed class Watched : IHttpConnectionFeature
    {
        private readonly IHttpConnectionFeature _inner;
        private readonly RaspContext _ctx;

        public Watched(IHttpConnectionFeature inner, RaspContext ctx)
        {
            _inner = inner;
            _ctx = ctx;
        }

        public string ConnectionId
        {
            get => _inner.ConnectionId;
            set => _inner.ConnectionId = value;
        }

        public IPAddress? RemoteIpAddress
        {
            get => _inner.RemoteIpAddress;
            set
            {
                var changed = !Equals(_inner.RemoteIpAddress, value);
                _inner.RemoteIpAddress = value;
                if (changed || _ctx.IpPending)
                {
                    // A block surfaces through the pipeline to the RASP middleware, which answers 403.
                    RaspCapture.RunIpRules(_ctx);
                }
            }
        }

        public IPAddress? LocalIpAddress
        {
            get => _inner.LocalIpAddress;
            set => _inner.LocalIpAddress = value;
        }

        public int RemotePort
        {
            get => _inner.RemotePort;
            set => _inner.RemotePort = value;
        }

        public int LocalPort
        {
            get => _inner.LocalPort;
            set => _inner.LocalPort = value;
        }
    }
}
