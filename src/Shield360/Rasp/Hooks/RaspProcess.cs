using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Shield360.Rasp;

/// <summary>
/// The process check (sdk/rasp/README.md, "Command"): an argv spawn is checked for an
/// executable taken from input, the script of <c>sh -c</c> / <c>cmd /c</c> /
/// <c>powershell -Command</c> for injection, and the executable for <c>shell_spawn</c>;
/// a shell command line for injection and <c>shell_spawn</c>. Port of the TypeScript
/// <c>hooks/process.ts</c> <c>detectProcess</c>.
/// </summary>
internal static class RaspProcess
{
    public const string Sink = "Process.Start";

    /// <summary>The argv a start info runs: the file name, then the argument list or the parsed argument string.</summary>
    public static List<string> ArgvOf(ProcessStartInfo info)
    {
        var argv = new List<string> { info.FileName ?? string.Empty };
#if NET
        if (info.ArgumentList.Count > 0)
        {
            argv.AddRange(info.ArgumentList);
            return argv;
        }
#endif
        argv.AddRange(SplitArguments(info.Arguments));
        return argv;
    }

    /// <summary>
    /// An argument string as the runtime splits it for the new process: whitespace
    /// separates, double quotes group, a backslash escapes a quote.
    /// </summary>
    public static List<string> SplitArguments(string? arguments)
    {
        var result = new List<string>();
        if (string.IsNullOrEmpty(arguments))
        {
            return result;
        }

        var s = arguments!;
        var current = new StringBuilder();
        var inWord = false;
        var quoted = false;
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c == '\\' && i + 1 < s.Length && s[i + 1] == '"')
            {
                current.Append('"');
                inWord = true;
                i++;
            }
            else if (c == '"')
            {
                quoted = !quoted;
                inWord = true;
            }
            else if (!quoted && char.IsWhiteSpace(c))
            {
                if (inWord)
                {
                    result.Add(current.ToString());
                    current.Clear();
                    inWord = false;
                }
            }
            else
            {
                current.Append(c);
                inWord = true;
            }
        }

        if (inWord)
        {
            result.Add(current.ToString());
        }

        return result;
    }

    /// <summary>
    /// The contract's command checks for an argv. The finding with the strongest decision
    /// wins, so one in monitor or off mode never hides one that blocks.
    /// </summary>
    public static RaspFinding? DetectArgv(IReadOnlyList<string> argv, IReadOnlyList<RaspInput> inputs, bool inRequest, IReadOnlyList<string> allow)
    {
        var script = RaspDetect.ShellScriptOf(argv);
        return RaspEngine.Strongest(
            RaspDetect.Argv(argv, inputs),
            script is null ? null : RaspDetect.Command(script, inputs),
            script is null ? null : RaspDetect.ShellSpawn(null, script, false, allow),
            RaspDetect.ShellSpawn(argv.Count > 0 ? argv[0] : null, null, inRequest, allow));
    }

    /// <summary>The contract's command checks for a shell command line; the strongest decision wins.</summary>
    public static RaspFinding? DetectCommand(string command, IReadOnlyList<RaspInput> inputs, bool inRequest, IReadOnlyList<string> allow) =>
        RaspEngine.Strongest(RaspDetect.Command(command, inputs), RaspDetect.ShellSpawn(null, command, inRequest, allow));

    public static void Check(ProcessStartInfo info, string sink)
    {
        if (!RaspEngine.IsActive)
        {
            return;
        }

        RaspHooks.Run(
            sink,
            (ctx, inputs) => DetectArgv(ArgvOf(info), inputs, ctx?.InRequest == true, RaspEngine.AllowLists().Commands),
            requireInputs: false);
    }

    public static void CheckCommandLine(string command, string sink)
    {
        if (string.IsNullOrEmpty(command))
        {
            return;
        }

        RaspHooks.Run(
            sink,
            (ctx, inputs) => DetectCommand(command, inputs, ctx?.InRequest == true, RaspEngine.AllowLists().Commands),
            requireInputs: false);
    }
}
