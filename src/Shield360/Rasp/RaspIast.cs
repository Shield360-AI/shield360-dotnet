using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;

namespace Shield360.Rasp;

/// <summary>What passive IAST reads at start: the local options, the app, its environment and the environment variables.</summary>
internal sealed record IastSettings(
    bool? Option,
    double? SampleRate,
    string ApplicationName,
    string? Environment = null,
    Func<string, string?>? Env = null,
    Func<long>? NowMs = null,
    Func<double>? Random = null);

/// <summary>The signed config's passive IAST switch and rate.</summary>
internal sealed record IastRemote(string? Iast, double? SampleRate, string? Version);

/// <summary>One frame of a stack, as the code location reads it.</summary>
internal readonly record struct IastFrame(string? Assembly, string? File, int Line);

/// <summary>
/// Passive IAST (sdk/rasp/README.md, "Passive IAST"): while RASP checks its sinks during
/// normal traffic, report the places where a request input reaches a sink verbatim and
/// unparameterized, even when the value is harmless and no attack happened. Off by default;
/// never blocks; does not depend on the attack modes. Each vulnerability has a fingerprint
/// (route, sink, input key, rule) and is reported at most once per process per hour, with
/// the count seen since the last report. Events name locations, never values, and carry no
/// snippet. Port of the TypeScript <c>iast.ts</c>.
/// </summary>
internal static class RaspIast
{
    public const string EventName = "shield360.rasp.vulnerability";

    /// <summary>A fingerprint is reported at most once per this period per process.</summary>
    public const long ReportEveryMs = 60 * 60 * 1000;

    /// <summary>Fingerprints remembered per process; the oldest is forgotten past this.</summary>
    public const int MaxFingerprints = 10_000;

    public const double DefaultRate = 1;
    public const double DefaultRateProduction = 0.1;

    private sealed class Seen
    {
        /// <summary>When it was last sent (milliseconds), or null when never.</summary>
        public long? LastSent { get; set; }

        public int Pending { get; set; }

        public string Location { get; set; } = string.Empty;
    }

    private sealed class State
    {
        public string? Env;
        public double? EnvRate;
        public bool? Local;
        public double? LocalRate;
        public string? Remote;
        public double? RemoteRate;
        public string ConfigVersion = "local";
        public bool Production;
        public string App = "default";
        public Func<RaspEvent, string, bool>? Sink;
        public Func<long> NowMs = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public Func<double> Random = SharedRandom;
        public readonly Dictionary<string, Seen> Seen = new(StringComparer.Ordinal);
        public readonly Queue<string> Order = new();
    }

    private static readonly object s_lock = new();
    private static readonly object s_randomLock = new();
    private static readonly Random s_random = new();
    private static State s_state = new();

    private static double SharedRandom()
    {
        lock (s_randomLock)
        {
            return s_random.NextDouble();
        }
    }

    private static string? AsSetting(string? v)
    {
        var s = JsText.Lower(JsText.Trim(v ?? string.Empty));
        return s is "on" or "off" ? s : null;
    }

    private static double? AsRate(double? n) => n is { } d && !double.IsNaN(d) && !double.IsInfinity(d) && d >= 0 && d <= 1 ? d : null;

    private static double? AsRate(string? v)
    {
        var s = JsText.Trim(v ?? string.Empty);
        return s.Length > 0 && double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? AsRate(d) : null;
    }

    /// <summary>Reads the local option and the environment (<c>SHIELD360_IAST</c>, <c>SHIELD360_IAST_SAMPLE_RATE</c>). Forgets what was seen.</summary>
    public static void Configure(IastSettings s)
    {
        var env = s.Env ?? System.Environment.GetEnvironmentVariable;
        var state = new State
        {
            Env = AsSetting(env("SHIELD360_IAST")),
            EnvRate = AsRate(env("SHIELD360_IAST_SAMPLE_RATE")),

            // Setting only the rate means on, as the TypeScript option object does.
            Local = s.Option ?? (s.SampleRate is not null ? true : null),
            LocalRate = AsRate(s.SampleRate),
            Production = RaspBaseline.ProductionEnv(s.Environment, env),
            App = string.IsNullOrEmpty(s.ApplicationName) ? "default" : s.ApplicationName,
        };
        if (s.NowMs is not null)
        {
            state.NowMs = s.NowMs;
        }

        if (s.Random is not null)
        {
            state.Random = s.Random;
        }

        lock (s_lock)
        {
            state.Sink = s_state.Sink;
            s_state = state;
        }
    }

    /// <summary>The signed config's switch and rate, from verified claims.</summary>
    public static IastRemote RemoteOf(RaspClaims c)
    {
        var j = c.Json;
        var iast = j.TryGetProperty("iast", out var i) && i.ValueKind == JsonValueKind.String ? i.GetString() : null;
        double? rate = j.TryGetProperty("iastSampleRate", out var r) && r.ValueKind == JsonValueKind.Number && r.TryGetDouble(out var d) ? d : null;
        return new IastRemote(iast, rate, c.Version);
    }

    /// <summary>The verified signed config's switch and rate (null drops them).</summary>
    public static void SetRemote(IastRemote? c)
    {
        lock (s_lock)
        {
            s_state.Remote = AsSetting(c?.Iast);
            s_state.RemoteRate = AsRate(c?.SampleRate);
            s_state.ConfigVersion = string.IsNullOrEmpty(c?.Version) ? "local" : c!.Version!;
        }
    }

    /// <summary>Where reports go: the RASP reporter, unfolded; false means it refused the event (rate limit, full queue).</summary>
    public static void SetSink(Func<RaspEvent, string, bool>? sink)
    {
        lock (s_lock)
        {
            s_state.Sink = sink;
        }
    }

    /// <summary>Whether passive IAST is on: <c>SHIELD360_IAST=off</c> wins; then the signed config; then the option or <c>SHIELD360_IAST=on</c>.</summary>
    public static bool Enabled
    {
        get
        {
            var s = Volatile.Read(ref s_state);
            if (s.Env == "off")
            {
                return false;
            }

            if (s.Remote is not null)
            {
                return s.Remote == "on";
            }

            return s.Local == true || s.Env == "on";
        }
    }

    /// <summary>The share of checks that run the rules: env, then the signed config, then the option, then 1 (0.1 in production).</summary>
    public static double SampleRate
    {
        get
        {
            var s = Volatile.Read(ref s_state);
            return s.EnvRate ?? s.RemoteRate ?? s.LocalRate ?? (s.Production ? DefaultRateProduction : DefaultRate);
        }
    }

    /// <summary>
    /// Arms the slot for one check, or returns null: off, not sampled, or no request input in
    /// scope. <see cref="RaspEngine.Check"/> calls it only while RASP is active.
    /// </summary>
    public static RaspIastScope.Slot? Begin()
    {
        try
        {
            if (!Enabled)
            {
                return null;
            }

            var ctx = RaspScope.Current;
            if (ctx is null || (!ctx.HasInputs && ctx.Late is null))
            {
                return null;
            }

            var rate = SampleRate;
            if (rate <= 0 || (rate < 1 && Volatile.Read(ref s_state).Random() >= rate))
            {
                return null;
            }

            return RaspIastScope.Arm();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }

    /// <summary>Disarms the slot. With a sink (the check found no attack), reports the vulnerability noted, if any. Never throws.</summary>
    public static void End(RaspIastScope.Slot slot, string? sink, FindingExtra? extra)
    {
        var vuln = RaspIastScope.Close(slot);
        if (vuln is null || sink is null)
        {
            return;
        }

        try
        {
            Report(vuln, sink, extra ?? new FindingExtra());
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // reporting never breaks the call
        }
    }

    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);
    private static readonly Regex s_unsafeKeyChar = new("[^A-Za-z0-9_.\\-\\[\\]]", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_badKeyStart = new("^[^A-Za-z0-9_]", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_unsafeRouteChar = new("[^\\x21\\x23-\\x26\\x28-\\x3b\\x3d\\x3f-\\x5b\\x5d-\\x7e]", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_method = new("^[A-Za-z]{3,10}\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_sink = new("^[A-Za-z_][A-Za-z0-9_]*(?:[.:/][A-Za-z0-9_]+)*\\z", RegexOptions.CultureInvariant, s_timeout);
    private static readonly Regex s_locationChar = new("[^A-Za-z0-9_./@+~-]", RegexOptions.CultureInvariant, s_timeout);

    private static string SafeKey(string k)
    {
        var s = s_badKeyStart.Replace(s_unsafeKeyChar.Replace(k, "_"), "_");
        return s.Length > 128 ? s.Substring(0, 128) : s;
    }

    private static string SafeRoute(string r)
    {
        var s = s_unsafeRouteChar.Replace(r, "_");
        if (s.Length > 256)
        {
            s = s.Substring(0, 256);
        }

        return JsText.Starts(s, "/") ? s : string.Empty;
    }

    private static string SafeMethod(string? m) => m is not null && s_method.IsMatch(m) ? m.ToUpperInvariant() : string.Empty;

    private static string Hex(byte[] bytes, int count)
    {
        var sb = new StringBuilder(count * 2);
        for (var i = 0; i < count; i++)
        {
            sb.Append(bytes[i].ToString("x2", CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }

    /// <summary>The fingerprint: SHA-256 of route, sink, input key and rule (NUL-separated), first 32 hex.</summary>
    public static string Fingerprint(string route, string sink, string inputKey, string rule)
    {
        var data = Encoding.UTF8.GetBytes(string.Join("\u0000", route, sink, inputKey, rule));
#if NET
        var hash = SHA256.HashData(data);
#else
        byte[] hash;
        using (var sha = SHA256.Create())
        {
            hash = sha.ComputeHash(data);
        }
#endif
        return Hex(hash, 16);
    }

    private static string NewEventId()
    {
        var bytes = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }

        return Hex(bytes, 16);
    }

    private static bool Recent(Seen seen, long now) => seen.LastSent is { } last && now - last < ReportEveryMs;

    private static void Report(RaspVuln v, string sink, FindingExtra extra)
    {
        if (sink.Length > 64 || !s_sink.IsMatch(sink))
        {
            return;
        }

        var ctx = RaspScope.Current;
        var path = extra.Path ?? ctx?.Path;
        var template = extra.Route ?? ctx?.ResolvedRoute();
        var route = SafeRoute(template ?? (string.IsNullOrEmpty(path) ? string.Empty : RouteOf(path!)));
        var inputKey = SafeKey(v.Input.Key);
        if (inputKey.Length == 0)
        {
            return;
        }

        var fp = Fingerprint(route, sink, inputKey, v.Rule);
        State state;
        Seen? seen;
        long now;
        lock (s_lock)
        {
            state = s_state;
            now = state.NowMs();
            if (state.Seen.TryGetValue(fp, out seen) && Recent(seen, now))
            {
                seen.Pending++;
                return;
            }
        }

        if (seen is null)
        {
            // First sight in this process: the one time the stack is read (outside the lock).
            var location = CodeLocation();
            lock (s_lock)
            {
                if (!state.Seen.TryGetValue(fp, out seen))
                {
                    seen = new Seen { Location = location };
                    if (state.Seen.Count >= MaxFingerprints && state.Order.Count > 0)
                    {
                        state.Seen.Remove(state.Order.Dequeue());
                    }

                    state.Seen[fp] = seen;
                    state.Order.Enqueue(fp);
                }
                else if (Recent(seen, now))
                {
                    seen.Pending++;
                    return;
                }
            }
        }

        Dictionary<string, string> attrs;
        int counted;
        long? previous;
        lock (s_lock)
        {
            attrs = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["shield360.rasp.kind"] = "vulnerability",
                ["shield360.rasp.event_id"] = NewEventId(),
                ["shield360.rasp.app"] = state.App,
                ["shield360.rasp.rule"] = v.Rule,
                ["shield360.rasp.sink"] = sink,
                ["shield360.rasp.source"] = "request",
                ["shield360.rasp.input_key"] = inputKey,
                ["shield360.rasp.config_version"] = state.ConfigVersion,
                ["shield360.rasp.language"] = RaspEngine.Language,
                ["shield360.rasp.vuln.fingerprint"] = fp,
                ["shield360.rasp.vuln.position"] = v.Position,
                ["shield360.rasp.count"] = (seen.Pending + 1).ToString(CultureInfo.InvariantCulture),
            };

            // Claimed before sending, so a concurrent sighting counts instead of sending twice.
            counted = seen.Pending;
            previous = seen.LastSent;
            seen.LastSent = now;
        }

        void Opt(string k, string? value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                attrs[k] = value!;
            }
        }

        Opt("shield360.rasp.route", route);
        Opt("shield360.rasp.method", SafeMethod(extra.Method ?? ctx?.Method));
        Opt("shield360.rasp.framework", extra.Framework ?? ctx?.Framework);
        Opt("shield360.rasp.vuln.location", seen.Location);
        var time = DateTimeOffset.FromUnixTimeMilliseconds(now).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        bool sent;
        try
        {
            // No fold key: the reporter queues or refuses it outright; IAST keeps the count.
            sent = state.Sink?.Invoke(new RaspEvent(EventName, time, attrs), string.Empty) == true;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            sent = false;
        }

        lock (s_lock)
        {
            if (sent)
            {
                seen.Pending -= counted;
            }
            else
            {
                // Refused (rate limit, full queue) or nowhere to send: count it, and try again at the next sighting.
                seen.LastSent = previous;
                seen.Pending++;
            }
        }
    }

    /// <summary>
    /// The route of a finding whose framework gave no template: the event route (README
    /// "Event route"), shared with attack events.
    /// </summary>
    public static string RouteOf(string path) => RaspScope.EventRouteOf(path);

    private static readonly HashSet<string> s_sdkAssemblies = new(
        new[] { "Shield360", "Shield360.AspNetCore", "Shield360.EntityFrameworkCore", "Shield360.StartupHook" },
        StringComparer.Ordinal);

    /// <summary>Whether a frame is in the app's own code: not the SDK, not the runtime or framework (System.*, Microsoft.*), with a source file.</summary>
    public static bool IsAppFrame(IastFrame f)
    {
        if (string.IsNullOrEmpty(f.File) || f.Line <= 0)
        {
            return false;
        }

        var a = f.Assembly ?? string.Empty;
        if (a.Length == 0 || s_sdkAssemblies.Contains(a) || a is "System" or "mscorlib" or "netstandard" ||
            a.StartsWith("System.", StringComparison.Ordinal) || a.StartsWith("Microsoft.", StringComparison.Ordinal))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// The top stack frame in the app's own code, as <c>path:line</c> relative to the working
    /// directory (only the last three segments when outside it), or empty when there is none.
    /// </summary>
    public static string CodeLocation(IEnumerable<IastFrame>? frames = null, string? cwd = null)
    {
        try
        {
            var dir = (cwd ?? Directory.GetCurrentDirectory()).Replace('\\', '/').TrimEnd('/');
            foreach (var f in frames ?? CurrentFrames())
            {
                if (!IsAppFrame(f))
                {
                    continue;
                }

                var file = f.File!.Replace('\\', '/');
                var shown = dir.Length > 0 && file.StartsWith(dir + "/", StringComparison.Ordinal)
                    ? file.Substring(dir.Length + 1)
                    : string.Join("/", file.Split('/').Where(p => p.Length > 0).Reverse().Take(3).Reverse());
                shown = s_locationChar.Replace(shown, "_");
                if (shown.Length > 240)
                {
                    shown = shown.Substring(0, 240);
                }

                return shown + ":" + f.Line.ToString(CultureInfo.InvariantCulture);
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // no location
        }

        return string.Empty;
    }

    private static IEnumerable<IastFrame> CurrentFrames()
    {
        var trace = new StackTrace(1, true);
        var count = Math.Min(trace.FrameCount, 64);
        for (var i = 0; i < count; i++)
        {
            var frame = trace.GetFrame(i);
            var method = frame?.GetMethod();
            yield return new IastFrame(method?.DeclaringType?.Assembly.GetName().Name, frame?.GetFileName(), frame?.GetFileLineNumber() ?? 0);
        }
    }

    /// <summary>Forgets every fingerprint seen and the configuration (tests, re-init).</summary>
    internal static void Reset()
    {
        lock (s_lock)
        {
            s_state = new State();
        }
    }
}
