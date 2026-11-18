using System;
using System.Threading;

namespace Shield360;

/// <summary>
/// The zero-code start (the <c>Shield360.StartupHook</c> assembly named in
/// <c>DOTNET_STARTUP_HOOKS</c>): Shield360 starts from SHIELD360_* / OTEL_*
/// environment variables before <c>Main</c>, and a later
/// <see cref="Init(Shield360Options?)"/> or <c>AddShield360()</c> in the app's
/// code is a no-op.
/// </summary>
public static partial class Shield360Sdk
{
    private static Shield360Handle? s_zeroCodeHandle;
    private static int s_skippedWarned;

    /// <summary>Whether the zero-code startup hook initialized Shield360 and it is still running.</summary>
    internal static bool StartedByZeroCode
    {
        get
        {
            lock (s_lock)
            {
                return s_handle is not null && ReferenceEquals(s_handle, s_zeroCodeHandle);
            }
        }
    }

    /// <summary>Initializes from the environment for the startup hook. Throws what <see cref="Init(Shield360Options?)"/> throws.</summary>
    internal static Shield360Handle InitZeroCode(Func<string, string?> env)
    {
        lock (s_lock)
        {
            if (s_handle is not null)
            {
                return s_handle;
            }

            var handle = Init(null, env);
            s_zeroCodeHandle = handle;
            return handle;
        }
    }

    private static void NoteSkippedInit()
    {
        if (Interlocked.Exchange(ref s_skippedWarned, 1) == 0)
        {
            Console.Error.WriteLine("Shield360: already started by the startup hook from SHIELD360_* environment variables; this Shield360Sdk.Init() call is ignored.");
        }
    }
}
