using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Shield360.AspNetCore;
using Shield360.Defend;

namespace Shield360.AspNetCore
{
    /// <summary>
    /// ASP.NET Core middleware for Shield360 Defend. Each request is decided before the
    /// rest of the pipeline: a denied one gets Defend's 403 (401 for require_sign_in), a
    /// honeypot decoy gets its fake file, and an allowed one goes on with the result in
    /// <c>HttpContext.Items[Shield360DefendMiddleware.ResultKey]</c> and, with honeypots
    /// on, the crumb header (<c>X-Debug-Trace</c>) on its response. The client address is
    /// the connection's (<c>Connection.RemoteIpAddress</c>, after any forwarded-headers
    /// middleware); X-Forwarded-For is read only with <c>DefendFactsOptions.TrustProxy</c>.
    /// </summary>
    public sealed class Shield360DefendMiddleware
    {
        /// <summary>The <c>HttpContext.Items</c> key of the <see cref="DefendResult"/>.</summary>
        public const string ResultKey = "Shield360.Defend.Result";

        private readonly RequestDelegate _next;
        private readonly Shield360Defend _defend;
        private readonly Func<HttpContext, IReadOnlyList<string>?>? _content;

        /// <summary>Creates the middleware.</summary>
        public Shield360DefendMiddleware(RequestDelegate next, Shield360Defend defend, Func<HttpContext, IReadOnlyList<string>?>? content = null)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _defend = defend ?? throw new ArgumentNullException(nameof(defend));
            _content = content;
        }

        internal static DefendRequest RequestOf(HttpContext context)
        {
            var r = context.Request;
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in r.Headers)
            {
                headers[h.Key] = string.Join(", ", (IEnumerable<string?>)h.Value);
            }

            var target = r.PathBase.Add(r.Path).ToUriComponent() + r.QueryString.ToUriComponent();
            var remote = context.Connection.RemoteIpAddress;
            return new DefendRequest
            {
                Method = r.Method,
                Target = string.IsNullOrEmpty(target) ? "/" : target,
                Headers = headers,
                RemoteAddr = remote?.IsIPv4MappedToIPv6 == true ? remote.MapToIPv4().ToString() : remote?.ToString(),
            };
        }

        /// <summary>Decides the request, then answers or goes on.</summary>
        public async Task InvokeAsync(HttpContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var call = new DefendCall();
            if (_content is not null)
            {
                try
                {
                    call.Content = _content(context) ?? Array.Empty<string>();
                }
#pragma warning disable CA1031 // the decision goes on without content
                catch (Exception)
#pragma warning restore CA1031
                {
                    call.Content = Array.Empty<string>();
                }
            }

            var result = _defend.Decide(RequestOf(context), call);
            var answer = Shield360Defend.ResponseFor(result);
            if (answer is not null)
            {
                var res = context.Response;
                res.StatusCode = answer.Status;
                foreach (var h in answer.Headers)
                {
                    res.Headers[h.Key] = h.Value;
                }

                if (!HttpMethods.IsHead(context.Request.Method))
                {
                    var body = Encoding.UTF8.GetBytes(answer.Body);
                    res.ContentLength = body.Length;
                    await res.Body.WriteAsync(body, context.RequestAborted).ConfigureAwait(false);
                }

                return;
            }

            if (result.CrumbHeader is not null)
            {
                context.Response.Headers[ClientCrumbs.HeaderName] = result.CrumbHeader;
            }

            context.Items[ResultKey] = result;
            await _next(context).ConfigureAwait(false);
        }
    }
}

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>Registers Shield360 Defend in the request pipeline.</summary>
    public static class Shield360DefendApplicationBuilderExtensions
    {
        /// <summary>
        /// Decides every request with Defend before the rest of the pipeline; content
        /// reads text to check from the request (a header or query value; read bodies in
        /// the handler and call <see cref="Shield360Defend.Decide"/> there).
        /// </summary>
        public static IApplicationBuilder UseShield360Defend(this IApplicationBuilder app, Shield360Defend defend, Func<HttpContext, IReadOnlyList<string>?>? content = null)
        {
            if (app is null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (defend is null)
            {
                throw new ArgumentNullException(nameof(defend));
            }

            return content is null ? app.UseMiddleware<Shield360DefendMiddleware>(defend) : app.UseMiddleware<Shield360DefendMiddleware>(defend, content);
        }
    }
}
