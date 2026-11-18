using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Shield360.Internal;

namespace Shield360.Rasp;

/// <summary>Settings for <see cref="RaspReporter"/>.</summary>
internal sealed class RaspReporterOptions
{
    public string Url { get; init; } = string.Empty;

    public string ApiKey { get; init; } = string.Empty;

    public string ApplicationName { get; init; } = "default";

    public string? Environment { get; init; }

    public string? SdkVersion { get; init; }

    public HttpMessageHandler? Handler { get; init; }

    /// <summary>Milliseconds since the epoch.</summary>
    public Func<long> NowMs { get; init; } = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromMilliseconds(500);
}

/// <summary>A component the app runs: names and versions only.</summary>
internal sealed record RaspComponent(string Ecosystem, string Name, string Version);

/// <summary>
/// RASP event reporter (sdk/rasp/README.md, "Events"). Batches
/// <c>shield360.rasp.event</c> and <c>shield360.rasp.component</c> records to
/// <c>POST /api/guard/events</c> through <see cref="GuardEventsTransport"/>, off
/// the call path. At most 100 events a minute per process; repeats of the same
/// (attack, rule, sink, route, decision) within 10 s fold into one more event
/// carrying <c>shield360.rasp.count</c>. Events name locations, never values.
/// Port of the TypeScript <c>reporter.ts</c>.
/// </summary>
internal sealed class RaspReporter : IRaspEventSink, IDisposable
{
    public const string EventName = "shield360.rasp.event";
    public const string ComponentName = "shield360.rasp.component";
    public const int PerMinute = 100;
    public const long FoldMs = 10_000;
    public const int MaxComponents = 500;
    private const long WindowMs = 60_000;
    private static readonly TimeSpan s_flushEvery = TimeSpan.FromSeconds(2);
    private const int MaxQueued = 1000;
    private const int Batch = 100;

    private sealed class Fold
    {
        public Fold(RaspEvent e, long until)
        {
            Event = e;
            Until = until;
        }

        public RaspEvent Event { get; }

        public long Until { get; }

        public int Extra { get; set; }
    }

    private readonly RaspReporterOptions _o;
    private readonly object _lock = new();
    private readonly List<RaspEvent> _queue = new();
    private readonly Dictionary<string, Fold> _folds = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _sending = new(1, 1);
    private readonly HttpClient _http;
    private readonly string _endpoint;
    private long _windowStart = long.MinValue;
    private int _sentInWindow;
    private Timer? _timer;

    public RaspReporter(RaspReporterOptions options)
    {
        _o = options;
        _endpoint = GuardEventsTransport.Endpoint(options.Url);
        _http = options.Handler is null
            ? new HttpClient { Timeout = Timeout.InfiniteTimeSpan }
            : new HttpClient(options.Handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
        var resource = new Dictionary<string, string>(StringComparer.Ordinal) { ["service.name"] = options.ApplicationName };
        var host = SafeHost();
        if (host.Length > 0)
        {
            resource["host.name"] = host;
        }

        if (!string.IsNullOrEmpty(options.Environment))
        {
            resource["deployment.environment"] = options.Environment!;
        }

        if (!string.IsNullOrEmpty(options.SdkVersion))
        {
            resource["service.version"] = options.SdkVersion!;
        }

        Resource = resource;
    }

    public IReadOnlyDictionary<string, string> Resource { get; }

    public void Start()
    {
        lock (_lock)
        {
            _timer ??= new Timer(_ => _ = FlushAsync(), null, s_flushEvery, s_flushEvery);
        }
    }

    /// <summary>Queues an event, folding repeats of the same key. Returns whether it was queued now.</summary>
    public bool Add(RaspEvent e, string foldKey)
    {
        lock (_lock)
        {
            var now = _o.NowMs();
            CloseFolds(now, now);
            if (_folds.TryGetValue(foldKey, out var f) && now < f.Until)
            {
                f.Extra++;
                return false;
            }

            _folds[foldKey] = new Fold(e, now + FoldMs);
            return Enqueue(e, now);
        }
    }

    void IRaspEventSink.Add(RaspEvent e, string foldKey) => Add(e, foldKey);

    /// <summary>
    /// Queues an event with no fold key: queued now, or refused (rate limit, full queue) and
    /// forgotten. For senders that dedupe and count themselves (passive IAST), so a refused event
    /// is never kept and sent later beside the sender's own retry.
    /// </summary>
    public bool AddUnfolded(RaspEvent e)
    {
        lock (_lock)
        {
            var now = _o.NowMs();
            CloseFolds(now, now);
            return Enqueue(e, now);
        }
    }

    private bool Enqueue(RaspEvent e, long now)
    {
        if (_windowStart == long.MinValue || now - _windowStart >= WindowMs)
        {
            _windowStart = now;
            _sentInWindow = 0;
        }

        if (_sentInWindow >= PerMinute || _queue.Count >= MaxQueued)
        {
            return false;
        }

        _sentInWindow++;
        _queue.Add(e);
        return true;
    }

    /// <summary>Closes the folds whose window ended by <paramref name="closeAt"/>; repeats become one more event.</summary>
    private void CloseFolds(long closeAt, long now)
    {
        foreach (var kv in _folds.ToList())
        {
            var f = kv.Value;
            if (closeAt < f.Until)
            {
                continue;
            }

            _folds.Remove(kv.Key);
            if (f.Extra > 0)
            {
                var attrs = new Dictionary<string, string>(f.Event.Attrs.ToDictionary(a => a.Key, a => a.Value), StringComparer.Ordinal)
                {
                    ["shield360.rasp.count"] = f.Extra.ToString(CultureInfo.InvariantCulture),
                };
                Enqueue(new RaspEvent(f.Event.Name, IsoTime(now), attrs), now);
            }
        }
    }

    private static string IsoTime(long ms) =>
        DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    /// <summary>Queued events (tests).</summary>
    public IReadOnlyList<RaspEvent> Pending()
    {
        lock (_lock)
        {
            return _queue.ToArray();
        }
    }

    /// <summary>Sends what is queued; <paramref name="force"/> also closes every open fold. Never throws.</summary>
    public async Task FlushAsync(bool force = false)
    {
        try
        {
            await _sending.WaitAsync().ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        try
        {
            lock (_lock)
            {
                var now = _o.NowMs();
                CloseFolds(force ? long.MaxValue : now, now);
            }

            while (true)
            {
                List<RaspEvent> batch;
                lock (_lock)
                {
                    if (_queue.Count == 0)
                    {
                        break;
                    }

                    batch = _queue.Take(Batch).ToList();
                    _queue.RemoveRange(0, batch.Count);
                }

                var payload = GuardEventsTransport.Payload(Resource, batch.Select(e => new GuardEvent(e.Name, e.Time, e.Attrs)));
                await GuardEventsTransport.PostAsync(_http, _endpoint, _o.ApiKey, payload, batch.Count, "runtime protection event", retryDelay: _o.RetryDelay)
                    .ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // reporting never breaks the app
        }
        finally
        {
            _sending.Release();
        }
    }

    /// <summary>Queues the components report: names and versions only, at most 500.</summary>
    public void ReportComponents(IEnumerable<RaspComponent> components)
    {
        lock (_lock)
        {
            var time = IsoTime(_o.NowMs());
            foreach (var c in components.Take(MaxComponents))
            {
                if (_queue.Count >= MaxQueued)
                {
                    break;
                }

                _queue.Add(new RaspEvent(ComponentName, time, new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["shield360.rasp.app"] = _o.ApplicationName,
                    ["shield360.rasp.component.ecosystem"] = c.Ecosystem,
                    ["shield360.rasp.component.name"] = c.Name,
                    ["shield360.rasp.component.version"] = c.Version,
                }));
            }
        }
    }

    public Task StopAsync()
    {
        lock (_lock)
        {
            _timer?.Dispose();
            _timer = null;
        }

        return FlushAsync(force: true);
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _timer?.Dispose();
            _timer = null;
        }

        _http.Dispose();
    }

    private static string SafeHost()
    {
        try
        {
            return System.Environment.MachineName;
        }
        catch (InvalidOperationException)
        {
            return string.Empty;
        }
    }
}

/// <summary>The components report: the runtime and the app's loaded assemblies.</summary>
internal static class RaspComponents
{
    private static readonly Regex s_name = new("^[A-Za-z0-9@_][A-Za-z0-9@/._+~-]{0,213}\\z", RegexOptions.CultureInvariant);
    private static readonly Regex s_version = new("^v?[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}\\z", RegexOptions.CultureInvariant);

    /// <summary>
    /// The runtime (<c>runtime</c>/<c>dotnet</c>) and every loaded assembly that is not
    /// part of the runtime itself (<c>nuget</c>), by assembly name and version (the
    /// informational version without its <c>+commit</c> suffix). Names and versions only;
    /// at most 500.
    /// </summary>
    public static List<RaspComponent> Collect(IEnumerable<Assembly>? assemblies = null)
    {
        var output = new List<RaspComponent> { new("runtime", "dotnet", Environment.Version.ToString()) };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var runtimeDir = RuntimeDirectory();
        foreach (var a in assemblies ?? AppDomain.CurrentDomain.GetAssemblies())
        {
            if (output.Count >= RaspReporter.MaxComponents)
            {
                break;
            }

            try
            {
                if (a.IsDynamic || (runtimeDir.Length > 0 && a.Location.StartsWith(runtimeDir, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                var name = a.GetName().Name;
                var version = VersionOf(a);
                if (name is null || version is null || !s_name.IsMatch(name) || !s_version.IsMatch(version) || !seen.Add(name + "@" + version))
                {
                    continue;
                }

                output.Add(new RaspComponent("nuget", name, version));
            }
            catch (Exception e) when (e is NotSupportedException or System.IO.FileNotFoundException or System.Security.SecurityException)
            {
                // an assembly we cannot read is left out
            }
        }

        return output;
    }

    private static string? VersionOf(Assembly a)
    {
        var informational = a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrEmpty(informational))
        {
            var plus = informational!.IndexOf('+');
            return plus < 0 ? informational : informational.Substring(0, plus);
        }

        return a.GetName().Version?.ToString();
    }

    private static string RuntimeDirectory()
    {
        try
        {
            return RuntimeEnvironment.GetRuntimeDirectory();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return string.Empty;
        }
    }
}
