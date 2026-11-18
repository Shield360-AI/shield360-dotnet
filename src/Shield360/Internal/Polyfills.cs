#if NETSTANDARD2_0
namespace System.Runtime.CompilerServices
{
    // Lets init-only setters compile for netstandard2.0.
    internal static class IsExternalInit
    {
    }
}
#endif
