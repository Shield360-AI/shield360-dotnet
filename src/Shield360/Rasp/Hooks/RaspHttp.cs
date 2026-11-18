using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Shield360.Rasp;

/// <summary>What the outbound check knows about one request: the inputs in scope when it was sent, and the last URL checked.</summary>
internal sealed class RaspHttpState
{
    public RaspHttpState(IReadOnlyList<RaspInput> inputs)
    {
        Inputs = inputs;
    }

    public IReadOnlyList<RaspInput> Inputs { get; }

    /// <summary>The URL last checked (a redirect changes the request's URL).</summary>
    public string? CheckedUrl { get; set; }

    /// <summary>An SSRF finding was already reported for <see cref="CheckedUrl"/>.</summary>
    public bool Reported { get; set; }
}

/// <summary>
/// The outbound HTTP check (sdk/rasp/README.md, "SSRF"): the URL before anything is
/// sent (outbound allow-list, then SSRF), and the addresses the connection actually
/// uses (DNS rebinding) when the handler's <c>ConnectCallback</c> is RASP's. Each
/// request is checked once before sending, whichever hook sees it first (the
/// <see cref="Shield360RaspHttpHandler"/> or the <c>HttpClient</c> diagnostic event).
/// </summary>
internal static class RaspHttpCheck
{
    public const string Sink = "HttpClient.SendAsync";

#if NET
    private static readonly HttpRequestOptionsKey<RaspHttpState> s_key = new("Shield360.Rasp");
#else
    private const string PropertyKey = "Shield360.Rasp";
#endif

    /// <summary>The resolver the connect check uses (tests replace it).</summary>
    internal static Func<string, CancellationToken, Task<IPAddress[]>> Resolve { get; set; } = DefaultResolve;

    private static Task<IPAddress[]> DefaultResolve(string host, CancellationToken cancellationToken) =>
#if NET
        Dns.GetHostAddressesAsync(host, cancellationToken);
#else
        Dns.GetHostAddressesAsync(host);
#endif

    internal static RaspHttpState? StateOf(HttpRequestMessage request)
    {
#if NET
        return request.Options.TryGetValue(s_key, out var state) ? state : null;
#else
        return request.Properties.TryGetValue(PropertyKey, out var state) ? state as RaspHttpState : null;
#endif
    }

    private static void SetState(HttpRequestMessage request, RaspHttpState state)
    {
#if NET
        request.Options.Set(s_key, state);
#else
        request.Properties[PropertyKey] = state;
#endif
    }

    private static string? UrlOf(HttpRequestMessage request) =>
        request.RequestUri is { IsAbsoluteUri: true } uri ? uri.OriginalString : null;

    /// <summary>
    /// Checks a request before it is sent: the outbound allow-list, SSRF on the URL and,
    /// when an input names the host, SSRF on the addresses the host resolves to. Once per
    /// URL: a redirect to another URL is checked again. Throws only the block exception.
    /// </summary>
    /// <remarks>
    /// The address check here is a lookup of its own, so it holds for every way the
    /// request may travel (a pooled connection, HTTP/3, a proxy). RASP's
    /// <c>ConnectCallback</c> then checks the addresses a direct TCP connection really
    /// uses, which a rebinding DNS server cannot answer differently.
    /// </remarks>
    public static void BeforeSend(HttpRequestMessage? request)
    {
        if (request is null || !RaspEngine.IsActive)
        {
            return;
        }

        var url = UrlOf(request);
        if (url is null)
        {
            return;
        }

        var state = StateOf(request);
        if (state?.CheckedUrl == url)
        {
            return;
        }

        if (state is null)
        {
            state = new RaspHttpState(RaspHooks.CurrentInputs());
            SetState(request, state);
        }

        var inputs = state.Inputs;
        state.CheckedUrl = url;
        state.Reported = false;
        var always = RaspEngine.AlwaysAllowedHosts;
        RaspFinding? winner = null;
        var decision = RaspHooks.RunWith(
            Sink,
            inputs,
            inp => winner = RaspEngine.Strongest(RaspDetect.Outbound(url, RaspEngine.AllowLists().OutboundHosts, always), RaspDetect.Ssrf(url, inp)),
            requireInputs: false);

        // An SSRF finding settles this URL. An outbound one that let the call on
        // (monitor) does not: the address checks still run, here and at connect.
        var ssrfReported = decision is not null && winner?.Attack == RaspAttackType.Ssrf;
        state.Reported = ssrfReported || ResolvedCheck(url, inputs) is not null;
    }

    /// <summary>
    /// SSRF on the addresses a tainted host resolves to (<c>ssrf.internal</c>,
    /// <c>ssrf.metadata</c>). Only when an input names the host and it is not an IP
    /// literal, so an ordinary request costs no lookup. A failed lookup checks nothing.
    /// </summary>
    private static RaspDecision? ResolvedCheck(string url, IReadOnlyList<RaspInput> inputs)
    {
        if (inputs.Count == 0)
        {
            return null;
        }

        string host;
        IPAddress[] addresses;
        try
        {
            var raw = RaspDetect.RawUrl(url);
            host = raw?.Host ?? string.Empty;
            if (host.Length == 0 || RaspDetect.IsIpLiteral(host) || RaspDetect.TaintOf(url, host, inputs) is null)
            {
                return null;
            }

            addresses = Resolve(host, CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }

        var resolved = addresses.Select(a => a.ToString()).ToArray();
        return RaspHooks.RunWith(Sink, inputs, inp => RaspDetect.Ssrf(url, inp, resolved));
    }

    /// <summary>
    /// Checks the addresses a connection to <paramref name="host"/> is about to use, and,
    /// for a URL not yet checked (a redirect), the whole check. Skipped through a proxy
    /// (the connection goes to the proxy, not the request's host) and when this URL was
    /// already reported before sending.
    /// </summary>
    public static void BeforeConnect(HttpRequestMessage? request, string host, IReadOnlyList<IPAddress> addresses)
    {
        if (request?.RequestUri is not { IsAbsoluteUri: true } uri || !RaspEngine.IsActive)
        {
            return;
        }

        if (!string.Equals(uri.IdnHost.Trim('[', ']'), host.Trim('[', ']'), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var url = uri.OriginalString;
        var state = StateOf(request);
        var same = state is not null && state.CheckedUrl == url;
        if (same && state!.Reported)
        {
            return;
        }

        var resolved = addresses.Select(a => a.ToString()).ToArray();
        if (same)
        {
            RaspHooks.RunWith(Sink, state!.Inputs, inp => RaspDetect.Ssrf(url, inp, resolved));
            return;
        }

        // No hook saw this URL before sending (no hook at all, or a redirect): the whole check runs here.
        var inputs = state?.Inputs ?? RaspHooks.CurrentInputs();
        var always = RaspEngine.AlwaysAllowedHosts;
        var decision = RaspHooks.RunWith(
            Sink,
            inputs,
            inp => RaspEngine.Strongest(RaspDetect.Outbound(url, RaspEngine.AllowLists().OutboundHosts, always), RaspDetect.Ssrf(url, inp, resolved)),
            requireInputs: false);
        if (state is not null)
        {
            state.CheckedUrl = url;
            state.Reported = decision is not null;
        }
    }

#if NET
    /// <summary>
    /// A <see cref="SocketsHttpHandler.ConnectCallback"/> that resolves the host once,
    /// checks those addresses, and connects to exactly them, so a rebinding DNS server
    /// cannot answer the check and the connection differently.
    /// </summary>
    public static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var endpoint = context.DnsEndPoint;
        var addresses = IPAddress.TryParse(endpoint.Host, out var literal)
            ? new[] { literal }
            : await Resolve(endpoint.Host, cancellationToken).ConfigureAwait(false);
        BeforeConnect(context.InitialRequestMessage, endpoint.Host, addresses);

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(addresses, endpoint.Port, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
#endif
}

/// <summary>
/// A <see cref="DelegatingHandler"/> that runs the RASP outbound check (SSRF and the
/// outbound allow-list) before each request is sent. In block mode a finding throws
/// <see cref="Shield360RaspBlockedException"/> and nothing is sent. Add it to an
/// <c>IHttpClientFactory</c> client with <c>AddShield360Rasp()</c>, or use
/// <see cref="Shield360RaspHttp.CreateHandler"/>, which also checks the addresses
/// actually connected to.
/// </summary>
public sealed class Shield360RaspHttpHandler : DelegatingHandler
{
    /// <summary>Creates the handler; the factory or the caller sets <see cref="DelegatingHandler.InnerHandler"/>.</summary>
    public Shield360RaspHttpHandler()
    {
    }

    /// <summary>Creates the handler around <paramref name="innerHandler"/>.</summary>
    public Shield360RaspHttpHandler(HttpMessageHandler innerHandler)
        : base(innerHandler)
    {
    }

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            RaspHttpCheck.BeforeSend(request);
        }
        catch (Shield360RaspBlockedException e)
        {
            return Task.FromException<HttpResponseMessage>(e);
        }

        return base.SendAsync(request, cancellationToken);
    }

#if NET
    /// <inheritdoc />
    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        RaspHttpCheck.BeforeSend(request);
        return base.Send(request, cancellationToken);
    }
#endif
}

/// <summary>Helpers that put the RASP outbound check on <see cref="HttpClient"/>s you create yourself.</summary>
public static class Shield360RaspHttp
{
    /// <summary>
    /// A handler chain with the outbound check before sending and, on .NET 8 and later,
    /// the check of the addresses actually connected to (a <c>SocketsHttpHandler</c>
    /// whose <c>ConnectCallback</c> is RASP's). Pass it to <c>new HttpClient(...)</c>.
    /// </summary>
    public static HttpMessageHandler CreateHandler()
    {
#if NET
        var primary = new SocketsHttpHandler();
        UseConnectCheck(primary);
        return new Shield360RaspHttpHandler(primary);
#else
        return new Shield360RaspHttpHandler(new HttpClientHandler());
#endif
    }

    /// <summary>An <see cref="HttpClient"/> over <see cref="CreateHandler"/>.</summary>
    public static HttpClient CreateClient() => new(CreateHandler(), disposeHandler: true);

#if NET
    /// <summary>
    /// Sets RASP's <c>ConnectCallback</c> on <paramref name="handler"/>: the host is
    /// resolved once, the addresses are checked for SSRF (DNS rebinding), and the
    /// socket connects to exactly those addresses. Returns false, and changes nothing,
    /// when the handler already has a <c>ConnectCallback</c> of its own.
    /// </summary>
    public static bool UseConnectCheck(SocketsHttpHandler handler)
    {
        if (handler is null)
        {
            throw new ArgumentNullException(nameof(handler));
        }

        if (handler.ConnectCallback is not null)
        {
            return false;
        }

        handler.ConnectCallback = RaspHttpCheck.ConnectAsync;
        return true;
    }
#endif
}
