using System;
using System.Collections.Generic;

namespace Shield360.Rasp;

/// <summary>
/// Shield360 runtime application self-protection (RASP), opt-in. Turn it on with
/// <see cref="Shield360Options.Rasp"/>, <c>services.AddShield360Rasp()</c> (package
/// Shield360.AspNetCore) or <c>SHIELD360_RASP=monitor|block</c>;
/// <c>SHIELD360_RASP=off</c> always wins. Fail open everywhere: the only exception
/// RASP raises on purpose is <see cref="Shield360RaspBlockedException"/>.
/// </summary>
public static partial class Shield360Rasp
{
    /// <summary>
    /// The runtime kill switch: checks return immediately until <see cref="Enable"/>.
    /// Third in the kill-switch order, after <c>SHIELD360_RASP=off</c> and the signed
    /// config's <c>killSwitch</c>.
    /// </summary>
    public static void Disable() => RaspEngine.SetRuntimeDisabled(true);

    /// <summary>Undoes <see cref="Disable"/>. The environment switch and the signed config's kill switch still win.</summary>
    public static void Enable() => RaspEngine.SetRuntimeDisabled(false);

    /// <summary>Whether RASP checks run right now (on, and no kill switch).</summary>
    public static bool IsActive => RaspEngine.IsActive;

    /// <summary>
    /// Runs <paramref name="fn"/> in a fresh context that is not a request, for a
    /// worker that acts on a model's answer: model output recorded inside counts as
    /// untrusted input for the rest of the job, and only there.
    /// </summary>
    public static T RunInScope<T>(Func<T> fn)
    {
        if (fn is null)
        {
            throw new ArgumentNullException(nameof(fn));
        }

        return RaspScope.Run(new RaspContext(), fn);
    }

    /// <summary>Runs <paramref name="action"/> in a fresh context that is not a request.</summary>
    public static void RunInScope(Action action)
    {
        if (action is null)
        {
            throw new ArgumentNullException(nameof(action));
        }

        RaspScope.Run(new RaspContext(), () =>
        {
            action();
            return 0;
        });
    }

    /// <summary>
    /// Runs <paramref name="fn"/> with a context holding the given inputs (a message
    /// handler or a job with input of its own). For an async function, the inputs
    /// stay in scope for everything it awaits.
    /// </summary>
    public static T RunWithInputs<T>(IEnumerable<RaspInput> inputs, Func<T> fn)
    {
        if (fn is null)
        {
            throw new ArgumentNullException(nameof(fn));
        }

        return RaspScope.Run(new RaspContext(inputs), fn);
    }

    /// <summary>Runs <paramref name="action"/> with a context holding the given inputs.</summary>
    public static void RunWithInputs(IEnumerable<RaspInput> inputs, Action action)
    {
        if (action is null)
        {
            throw new ArgumentNullException(nameof(action));
        }

        RaspScope.Run(new RaspContext(inputs), () =>
        {
            action();
            return 0;
        });
    }

    /// <summary>
    /// Registers text a model returned as untrusted input, for calls the SDK's
    /// instrumentation does not see. Split into lines and fenced code blocks.
    /// A no-op unless RASP is on with <see cref="RaspOptions.ModelOutput"/>. Never throws.
    /// </summary>
    public static void RecordModelOutput(string? text) => RaspModelOutput.Record(text);

    /// <summary>
    /// Registers tool-call arguments a model returned (a JSON string, a dictionary or a
    /// <c>JsonNode</c>) as untrusted input, keyed <c>model.tool.&lt;toolName&gt;.&lt;path&gt;</c>. Never throws.
    /// </summary>
    public static void RecordToolArguments(object? arguments, string? toolName = null) => RaspModelOutput.RecordToolArguments(arguments, toolName);
}
