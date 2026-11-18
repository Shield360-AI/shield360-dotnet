using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Shield360.Internal;

internal static class Http
{
    public static Task<string> ReadBodyAsync(HttpContent content, CancellationToken cancellationToken)
    {
#if NET
        return content.ReadAsStringAsync(cancellationToken);
#else
        cancellationToken.ThrowIfCancellationRequested();
        return content.ReadAsStringAsync();
#endif
    }
}
