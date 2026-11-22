using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Shield360.Rasp;

namespace Shield360.AspNetCore;

/// <summary>
/// ASP.NET Core middleware for Shield360 runtime protection (RASP). Records the
/// request's untrusted input (query, route values, form and JSON body leaves,
/// uploaded file names, cookies, the contract's input headers) in the request's RASP context, runs the
/// virtual patches before the endpoint, turns
/// <see cref="Shield360RaspBlockedException"/> into the contract's 403, and checks HTML
/// responses for reflected input (monitor only; the response is never changed). While
/// RASP is not active it passes the request straight through.
/// </summary>
/// <remarks>
/// Add it with <c>app.UseShield360Rasp()</c>, after <c>UseExceptionHandler</c> or
/// <c>UseDeveloperExceptionPage</c> so a block from an endpoint reaches it first.
/// <c>services.AddShield360Rasp()</c> also adds it at the start of the pipeline;
/// a request is captured once however many times the middleware appears.
/// </remarks>
public sealed class Shield360RaspMiddleware
{
    /// <summary>The <c>shield360.rasp.framework</c> value.</summary>
    public const string Framework = "aspnetcore";

    /// <summary>The <c>shield360.rasp.sink</c> of the reflected-XSS check.</summary>
    public const string XssSink = "http.response";

    /// <summary>At most this much of a request body is read (and buffered for the app to read again).</summary>
    public const int MaxBodyBytes = 1024 * 1024;

    private static readonly object s_captured = new();
    private static readonly object s_ownBlock = new(); // SHIELD: AI attack agents — the response is Shield360's own block
    private readonly RequestDelegate _next;
    private readonly bool _deferDecoys;

    /// <summary>Creates the middleware.</summary>
    public Shield360RaspMiddleware(RequestDelegate next)
        : this(next, deferDecoys: false)
    {
    }

    /// <summary>
    /// <paramref name="deferDecoys"/>: this instance runs ahead of the app's own middleware (the
    /// startup filter), with <see cref="RaspDecoyMatcherPolicy"/> registered, so a decoy goes on to
    /// the app's not-found handling instead of being answered here.
    /// </summary>
    internal Shield360RaspMiddleware(RequestDelegate next, bool deferDecoys)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _deferDecoys = deferDecoys;
    }

    /// <summary>Handles one request.</summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        if (context.Items.ContainsKey(s_captured))
        {
            // An outer instance captured this request. Placed after UseForwardedHeaders, this one
            // ends a wait for the forwarded client address; then it only maps a block from inside.
            try
            {
                if (RaspScope.Current is { IpPending: true } outer)
                {
                    RaspCapture.RunIpRules(outer);
                }
            }
            catch (Shield360RaspBlockedException e)
            {
                await WriteBlockedAsync(context, e).ConfigureAwait(false);
                return;
            }

            await PassAsync(context).ConfigureAwait(false);
            return;
        }

        if (!Shield360Rasp.IsActive)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // SHIELD: AI attack agents — the tripwire URL is answered first, then deception (README "AI attack agents").
        var verdict = DeceptionVerdict.Pass;
        Shield360RaspBlockedException? deceptionBlock = null;
        string? tripwirePage = null;
        if (RaspEngine.AgentConfig().Tripwire && RaspAgents.CheckTripwire(Early(context), out var deter))
        {
            verdict = deter is null ? DeceptionVerdict.NotFound : DeceptionVerdict.Block;
            deceptionBlock = deter;
        }
        else if (RaspEngine.Remote?.Deception is not null)
        {
            // Deception runs first, before capture, virtual patches and body buffering (README "Deception").
            verdict = Deceive(context, out deceptionBlock);

            // SHIELD: AI attack agents — a decoy hit adds to the behavior score; the 404 may carry the tripwire page.
            if (verdict == DeceptionVerdict.NotFound)
            {
                tripwirePage = RaspAgents.Decoy(Early(context));
            }
        }

        if (verdict != DeceptionVerdict.Pass)
        {
            switch (verdict)
            {
                case DeceptionVerdict.NotFound when tripwirePage is not null:
                    context.Items[s_captured] = true;
                    await WriteTripwirePageAsync(context, tripwirePage).ConfigureAwait(false);
                    return;
                case DeceptionVerdict.NotFound when _deferDecoys:
                    // Ahead of the app's middleware: routing matches no endpoint for the decoy, so
                    // the app answers it as it answers an unknown path (its status code pages too).
                    // Later RASP instances, and a re-executed request, only pass it on.
                    context.Items[s_captured] = true;
                    context.Features.Set(new RaspDecoyFeature(context.Request.PathBase, context.Request.Path));
                    await PassAsync(context).ConfigureAwait(false);
                    return;
                case DeceptionVerdict.NotFound:
                    // ASP.NET Core's own answer to an unknown path: an empty 404, which status code
                    // pages registered before this middleware render as they render any other.
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                case DeceptionVerdict.Block when deceptionBlock is not null:
                    await WriteBlockedAsync(context, deceptionBlock).ConfigureAwait(false);
                    return;
            }
        }

        context.Items[s_captured] = true;
        RaspContext? ctx;
        try
        {
            var shape = Shape(context);
            ctx = RaspCapture.CaptureRequest(shape);

            // SHIELD: protection triangle — a verdict for Edge goes out as a response header while the headers are not sent.
            var response = context.Response;
            ctx.SetHeader = (name, value) =>
            {
                if (!response.HasStarted)
                {
                    response.Headers[name] = value;
                }
            };

            // SHIELD: AI attack agents — the request is scored when its status goes out, while a mark can still set the verdict header.
            var agents = RaspEngine.ModeFor(RaspAttackType.AiAttackAgent) != RaspMode.Off;
            if (agents)
            {
                var scored = ctx;
                response.OnStarting(() =>
                {
                    RaspAgents.After(scored, response.StatusCode, context.Items.ContainsKey(s_ownBlock));
                    return Task.CompletedTask;
                });
            }
            ctx.RouteSource = () => RouteTemplate(context);
            RaspClientAddress.Attach(ctx, context);
            ctx.Late = () =>
            {
                CaptureRouteValues(ctx, context);

                // The first checked sink ends a wait for the forwarded client address.
                if (ctx.IpPending)
                {
                    RaspCapture.RunIpRules(ctx);
                }

                return true;
            };
            RaspCapture.RunVirtualPatches(ctx);
            var body = await ReadBodyAsync(context, context.RequestAborted).ConfigureAwait(false);
            var contentType = context.Request.ContentType;

            // Upload file names: from a form already read, else from the part headers of the buffered body.
            var uploads = RaspUploadNames.FromReadForm(context)
                ?? await RaspUploadNames.FromMultipartAsync(body, contentType, context.RequestAborted).ConfigureAwait(false);
            if (body is not null || uploads.Count > 0)
            {
                RaspCapture.CaptureBody(ctx, new BodyShape(body, contentType, uploads));
            }

            // SHIELD: uploads — each file part's bytes, with the route's policy, before the app.
            if (uploads.Count > 0)
            {
                await RaspUploadInspection.InspectAsync(context, ctx, context.RequestAborted).ConfigureAwait(false);
            }
            else if (HasNoBody(context))
            {
                // No body, or an empty one: a known, empty body. A body that reads empty although the
                // request framed one (a length, chunks, HTTP/2 data) was consumed earlier and stays unknown.
                RaspCapture.CaptureEmptyBody(ctx);
            }

            // SHIELD: AI attack agents — once the inputs are known, before the body patches: a marked client is deterred here.
            if (agents)
            {
                RaspAgents.Before(ctx, shape.Headers, RaspClientAddress.Settled(context));
            }

            RaspCapture.RunVirtualPatches(ctx);
        }
        catch (Shield360RaspBlockedException e)
        {
            await WriteBlockedAsync(context, e).ConfigureAwait(false);
            return;
        }
        catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException)
        {
            // fail open: the request goes on without RASP
            ctx = null;
        }

        if (ctx is null)
        {
            await PassAsync(context).ConfigureAwait(false);
            return;
        }

        // Async-local: the endpoint and everything it awaits see this request's context.
        RaspScope.Enter(ctx);
        try
        {
            if (WantsXssCheck())
            {
                await PassCheckingXssAsync(context).ConfigureAwait(false);
            }
            else
            {
                await PassAsync(context).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // SHIELD: AI attack agents — an exception nothing inside answered is a server error (no
            // status goes out for it here when no exception handler wraps the pipeline).
            RaspAgents.After(ctx, StatusCodes.Status500InternalServerError, context.Items.ContainsKey(s_ownBlock));
            throw;
        }

        // SHIELD: AI attack agents — a response with no body yet is scored here (a no-op when it already was).
        RaspAgents.After(ctx, context.Response.StatusCode, context.Items.ContainsKey(s_ownBlock));
    }

    /// <summary>SHIELD: AI attack agents — what the tripwire and the decoy scoring need of a request, before capture.</summary>
    private static AgentEarlyRequest Early(HttpContext context)
    {
        var request = context.Request;
        var raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        var url = !string.IsNullOrEmpty(raw) && raw![0] == '/'
            ? raw
            : request.PathBase.ToUriComponent() + request.Path.ToUriComponent() + request.QueryString.ToUriComponent();
        return new AgentEarlyRequest
        {
            Framework = Framework,
            Method = request.Method,
            Url = url,
            Ip = () => RaspClientAddress.Settled(context),
            Header = name => request.Headers.TryGetValue(name, out var v) ? v.ToString() : null,
        };
    }

    /// <summary>SHIELD: AI attack agents — the decoy's 404 with the LLM tripwire page (README "AI attack agents").</summary>
    private static async Task WriteTripwirePageAsync(HttpContext context, string page)
    {
        var response = context.Response;
        if (response.HasStarted)
        {
            return;
        }

        var bytes = System.Text.Encoding.UTF8.GetBytes(page);
        response.Clear();
        response.StatusCode = StatusCodes.Status404NotFound;
        response.ContentType = "text/html; charset=utf-8";
        response.Headers.CacheControl = "no-store";
        response.ContentLength = bytes.Length;
        if (!HttpMethods.IsHead(context.Request.Method))
        {
            await response.Body.WriteAsync(bytes, context.RequestAborted).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Deception's verdict for the request. The path is the raw request target
    /// (<c>IHttpRequestFeature.RawTarget</c>) decoded once; without one, <c>PathBase + Path</c> as the
    /// server decoded it, never decoded again (so an encoded slash the server leaves as <c>%2F</c>
    /// stays those three characters there). Never throws.
    /// </summary>
    private static DeceptionVerdict Deceive(HttpContext context, out Shield360RaspBlockedException? block)
    {
        block = null;
        try
        {
            var request = context.Request;
            var raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
            Func<byte[]?> path;
            string eventPath;
            if (!string.IsNullOrEmpty(raw) && raw![0] == '/')
            {
                path = () => RaspDeception.RawPathBytes(raw);
                eventPath = raw;
            }
            else
            {
                var decoded = request.PathBase.Value + request.Path.Value;
                path = () => RaspDeception.DecodedPathBytes(decoded);
                eventPath = request.PathBase.ToUriComponent() + request.Path.ToUriComponent();
            }

            return RaspDeception.Evaluate(path, eventPath, () => RaspClientAddress.Settled(context), request.Method, Framework, out block);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open: as if deception were off
            block = null;
            return DeceptionVerdict.Pass;
        }
    }

    /// <summary>
    /// The reflected-XSS check listens unless it is off. Which inputs to compare is decided
    /// only after the response, so route values (known after routing) and model output the
    /// endpoint records count too. Non-HTML responses are written straight to the server.
    /// </summary>
    private static bool WantsXssCheck()
    {
        try
        {
            return RaspEngine.ModeFor(RaspAttackType.Xss) != RaspMode.Off;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open: no XSS check
            return false;
        }
    }

    /// <summary>
    /// Runs the rest of the pipeline with the response body copied (HTML only, at most
    /// 1 MiB), then checks it for reflected input (<c>xss.reflected</c>). Monitor only:
    /// the response is written exactly as the app wrote it, and the check runs after it.
    /// </summary>
    private async Task PassCheckingXssAsync(HttpContext context)
    {
        var prior = context.Features.Get<IHttpResponseBodyFeature>();
        if (prior is null)
        {
            await PassAsync(context).ConfigureAwait(false);
            return;
        }

        var feature = new RaspXssBodyFeature(prior, new RaspXssCapture(prior.Stream, context.Response));
        context.Features.Set<IHttpResponseBodyFeature>(feature);
        try
        {
            await PassAsync(context).ConfigureAwait(false);
            await feature.FlushWriterAsync(context.RequestAborted).ConfigureAwait(false);
        }
        finally
        {
            context.Features.Set(prior);
        }

        try
        {
            var body = feature.Capture.Text();
            if (body is not null)
            {
                var type = feature.Capture.ContentType;
                RaspHooks.Run(XssSink, (_, inputs) => RaspDetect.Xss(type, body, inputs));
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // monitoring never changes or fails a response
        }
    }

    private async Task PassAsync(HttpContext context)
    {
        try
        {
            await _next(context).ConfigureAwait(false);
        }
        catch (Exception e) when (Blocked(e) is { } block && !context.Response.HasStarted)
        {
            await WriteBlockedAsync(context, block).ConfigureAwait(false);
        }
    }

    /// <summary>The block exception in <paramref name="e"/> or its inner exceptions, if any.</summary>
    internal static Shield360RaspBlockedException? Blocked(Exception? e)
    {
        for (var depth = 0; e is not null && depth < 8; depth++)
        {
            switch (e)
            {
                case Shield360RaspBlockedException b:
                    return b;
                case AggregateException { InnerExceptions.Count: 1 } a:
                    e = a.InnerExceptions[0];
                    break;
                default:
                    e = e.InnerException;
                    break;
            }
        }

        return null;
    }

    /// <summary>
    /// Writes the contract's 403, or the deter answer's 429 with <c>Retry-After</c> for an AI attack
    /// agent (no-op once the response has started). A verdict for Edge set earlier in the request stays.
    /// </summary>
    internal static async Task WriteBlockedAsync(HttpContext context, Shield360RaspBlockedException e)
    {
        var response = context.Response;
        if (response.HasStarted)
        {
            return;
        }

        // SHIELD: AI attack agents — Shield360's own answer is never scored as the app's.
        context.Items[s_ownBlock] = true;

        // SHIELD: protection triangle — the signed verdict survives the reset of the response.
        var verdict = response.Headers[EdgeContext.VerdictHeader];
        response.Clear();
        if (!Microsoft.Extensions.Primitives.StringValues.IsNullOrEmpty(verdict))
        {
            response.Headers[EdgeContext.VerdictHeader] = verdict;
        }

        response.StatusCode = e.StatusCode;
        if (e.RetryAfterSeconds is { } retryAfter)
        {
            response.Headers.RetryAfter = retryAfter.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        response.ContentType = "application/json";
        response.Headers.CacheControl = "no-store";
        await response.WriteAsync(e.ToResponseJson(), context.RequestAborted).ConfigureAwait(false);
    }

    private static RequestShape Shape(HttpContext context)
    {
        var request = context.Request;
        var headers = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var h in request.Headers)
        {
            headers[h.Key.ToLowerInvariant()] = string.Join(", ", (IEnumerable<string?>)h.Value);
        }

        var raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        var url = !string.IsNullOrEmpty(raw) && raw![0] == '/'
            ? raw
            : request.PathBase.ToUriComponent() + request.Path.ToUriComponent() + request.QueryString.ToUriComponent();
        return new RequestShape
        {
            Framework = Framework,
            Method = request.Method,
            Url = url,
            Headers = headers,

            // As the framework reports it: UseForwardedHeaders, when the app trusts a proxy, has already applied X-Forwarded-For.
            Ip = context.Connection.RemoteIpAddress?.ToString(),
        };
    }

    /// <summary>The endpoint's route template once routing has chosen one.</summary>
    private static string? RouteTemplate(HttpContext context)
    {
        var text = (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText;
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        return text![0] == '/' ? text : "/" + text;
    }

    /// <summary>Route values are known after routing; they join the inputs when a sink first reads them.</summary>
    private static void CaptureRouteValues(RaspContext ctx, HttpContext context)
    {
        try
        {
            var values = context.Request.RouteValues;
            if (values.Count == 0)
            {
                return;
            }

            ctx.Mutate((inputs, _) =>
            {
                foreach (var kv in values)
                {
                    if (kv.Value is string s)
                    {
                        RaspNormalize.AddInput(inputs, s, "params." + kv.Key);
                    }
                }
            });
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>
    /// Reads up to <see cref="MaxBodyBytes"/> of the body from where the stream is now and
    /// puts it back there, so the endpoint reads exactly what it would have read without
    /// RASP. Middleware earlier in the pipeline may already have buffered and consumed part
    /// of the body; that part is neither captured nor replayed.
    /// </summary>
    /// <summary>
    /// True when the request has no body: <c>Content-Length: 0</c>, or the server reports it cannot
    /// have one (HTTP/1.x without a length or chunks, HTTP/2 headers that end the stream). Without
    /// that report, only HTTP/1.x with neither header counts (README "When rules run").
    /// </summary>
    internal static bool HasNoBody(HttpContext context)
    {
        var request = context.Request;
        if (request.ContentLength is { } length)
        {
            return length == 0;
        }

        var detection = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestBodyDetectionFeature>();
        if (detection is not null)
        {
            return !detection.CanHaveBody;
        }

        return request.Protocol.StartsWith("HTTP/1.", StringComparison.OrdinalIgnoreCase)
            && !request.Headers.ContainsKey("Transfer-Encoding");
    }

    private static async Task<byte[]?> ReadBodyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var request = context.Request;
        if (context.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody == false || request.ContentLength == 0)
        {
            return null;
        }

        request.EnableBuffering();
        var start = request.Body.Position;
        var buffer = new byte[Math.Min(MaxBodyBytes, (int)Math.Min(request.ContentLength ?? MaxBodyBytes, MaxBodyBytes))];
        var total = 0;
        try
        {
            while (total < buffer.Length)
            {
                var n = await request.Body.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }

                total += n;
            }
        }
        finally
        {
            request.Body.Position = start;
        }

        if (total == 0)
        {
            return null;
        }

        if (total == buffer.Length)
        {
            return buffer;
        }

        var exact = new byte[total];
        Array.Copy(buffer, exact, total);
        return exact;
    }
}
