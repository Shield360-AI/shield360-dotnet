using System;
using System.Net.Http;
using Shield360.Rasp;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Puts the Shield360 RASP outbound check on <c>IHttpClientFactory</c> clients.</summary>
public static class Shield360RaspHttpClientBuilderExtensions
{
    /// <summary>
    /// Adds <see cref="Shield360RaspHttpHandler"/> (the check before sending) to this
    /// client and, on .NET 8 and later, makes its primary handler a
    /// <c>SocketsHttpHandler</c> with RASP's <c>ConnectCallback</c> (the check of
    /// the addresses actually connected to). A primary handler you configure after this
    /// call replaces it, and keeps only the check before sending.
    /// </summary>
    public static IHttpClientBuilder AddShield360Rasp(this IHttpClientBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.AddHttpMessageHandler(() => new Shield360RaspHttpHandler());
#if NET
        builder.UseSocketsHttpHandler((handler, _) => Shield360RaspHttp.UseConnectCheck(handler));
#endif
        return builder;
    }

    /// <summary>
    /// <see cref="AddShield360Rasp(IHttpClientBuilder)"/> for every client the factory
    /// creates (<c>ConfigureHttpClientDefaults</c>).
    /// </summary>
    public static IServiceCollection AddShield360RaspHttpClients(this IServiceCollection services)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        return services.ConfigureHttpClientDefaults(b => b.AddShield360Rasp());
    }
}
