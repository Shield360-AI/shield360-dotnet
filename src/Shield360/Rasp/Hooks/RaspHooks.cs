using System;
using System.Collections.Generic;

namespace Shield360.Rasp;

/// <summary>
/// What every sink hook shares: the active check, the context lookup and the
/// fail-open call into the engine. A hook passes its detector; this decides
/// whether it runs at all. Outside a request with no model output in scope a
/// sink that needs input costs one context lookup.
/// </summary>
internal static class RaspHooks
{
    private static readonly IReadOnlyList<RaspInput> s_none = Array.Empty<RaspInput>();

    /// <summary>
    /// Tests only: called with the sink name just before a hook's detector runs.
    /// Throwing from it makes the detector fail; counting calls shows whether it ran.
    /// </summary>
    internal static Action<string>? DetectorProbe { get; set; }

    /// <summary>
    /// Runs a check at <paramref name="sink"/> with the current context's inputs.
    /// With <paramref name="requireInputs"/> it is skipped when no untrusted input is
    /// in scope; checks that apply without input (outbound, shell spawns, NTFS
    /// streams) pass false. Throws only <see cref="Shield360RaspBlockedException"/>.
    /// </summary>
    public static RaspDecision? Run(string sink, Func<RaspContext?, IReadOnlyList<RaspInput>, RaspFinding?> detect, bool requireInputs = true)
    {
        if (!RaspEngine.IsActive)
        {
            return null;
        }

        RaspContext? ctx;
        IReadOnlyList<RaspInput> inputs;
        try
        {
            ctx = RaspScope.Current;
            if (ctx is null && requireInputs)
            {
                return null;
            }

            // A virtual patch matched by a late body throws the block exception from here.
            inputs = ctx is null ? s_none : RaspScope.InputsOf(ctx);
        }
        catch (Shield360RaspBlockedException)
        {
            throw;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }

        if (requireInputs && inputs.Count == 0)
        {
            return null;
        }

        return RaspEngine.Check(sink, () =>
        {
            DetectorProbe?.Invoke(sink);
            return detect(ctx, inputs);
        });
    }

    /// <summary>Runs a check against inputs the hook captured earlier (an HTTP connection opened after the request was checked).</summary>
    public static RaspDecision? RunWith(string sink, IReadOnlyList<RaspInput> inputs, Func<IReadOnlyList<RaspInput>, RaspFinding?> detect, bool requireInputs = true)
    {
        if (!RaspEngine.IsActive || (requireInputs && inputs.Count == 0))
        {
            return null;
        }

        return RaspEngine.Check(sink, () =>
        {
            DetectorProbe?.Invoke(sink);
            return detect(inputs);
        });
    }

    /// <summary>The current context's inputs (empty outside one). Never throws except for a block.</summary>
    public static IReadOnlyList<RaspInput> CurrentInputs()
    {
        try
        {
            var ctx = RaspScope.Current;
            return ctx is null ? s_none : RaspScope.InputsOf(ctx);
        }
        catch (Shield360RaspBlockedException)
        {
            throw;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return s_none;
        }
    }
}
