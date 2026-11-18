using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;

namespace Shield360.Rasp;

/// <summary>
/// The hooks RASP installs for the whole process, through <see cref="DiagnosticListener"/>
/// events the libraries already raise, so no driver is referenced or patched:
/// <list type="bullet">
/// <item><c>HttpHandlerDiagnosticListener</c> / <c>System.Net.Http.Request</c>: every
/// <see cref="HttpClient"/> request, checked before it is sent (SSRF, outbound).</item>
/// <item><c>SqlClientDiagnosticListener</c> / <c>WriteCommandBefore</c>
/// (Microsoft.Data.SqlClient and System.Data.SqlClient): every command, checked before it
/// is executed.</item>
/// </list>
/// The libraries raise these events synchronously on the calling thread before the
/// work, so the block exception propagates to the caller and nothing is sent.
/// Installed by <see cref="RaspRuntime.Start"/>, removed by <see cref="RaspRuntime.Shutdown"/>.
/// </summary>
internal sealed class RaspDiagnosticHooks : IObserver<DiagnosticListener>, IDisposable
{
    public const string HttpListener = "HttpHandlerDiagnosticListener";
    public const string HttpRequestEvent = "System.Net.Http.Request";
    public const string HttpClientActivity = "System.Net.Http.HttpRequestOut";
    public const string SqlListener = "SqlClientDiagnosticListener";
    public const string MicrosoftSqlBefore = "Microsoft.Data.SqlClient.WriteCommandBefore";
    public const string SystemSqlBefore = "System.Data.SqlClient.WriteCommandBefore";

    private static readonly object s_lock = new();
    private static RaspDiagnosticHooks? s_installed;

    private readonly List<IDisposable> _subscriptions = new();
    private IDisposable? _all;
    private int _disposed;

    private RaspDiagnosticHooks()
    {
    }

    /// <summary>Whether the hooks are installed.</summary>
    public static bool Installed
    {
        get
        {
            lock (s_lock)
            {
                return s_installed is not null;
            }
        }
    }

    /// <summary>Subscribes to the listeners. Idempotent; never throws.</summary>
    public static bool Install()
    {
        lock (s_lock)
        {
            if (s_installed is not null)
            {
                return true;
            }

            var hooks = new RaspDiagnosticHooks();
            try
            {
                // AllListeners replays the listeners that already exist, then reports new ones.
                hooks._all = DiagnosticListener.AllListeners.Subscribe(hooks);
                s_installed = hooks;
                return true;
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                hooks.Dispose();
                return false;
            }
        }
    }

    /// <summary>Removes every subscription. Idempotent; never throws.</summary>
    public static void Uninstall()
    {
        RaspDiagnosticHooks? hooks;
        lock (s_lock)
        {
            hooks = s_installed;
            s_installed = null;
        }

        hooks?.Dispose();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        IDisposable[] subs;
        lock (_subscriptions)
        {
            subs = _subscriptions.ToArray();
            _subscriptions.Clear();
        }

        foreach (var s in subs)
        {
            try
            {
                s.Dispose();
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // never
            }
        }

        try
        {
            _all?.Dispose();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // never
        }
    }

    public void OnNext(DiagnosticListener value)
    {
        if (Volatile.Read(ref _disposed) == 1 || value is null)
        {
            return;
        }

        try
        {
            IDisposable? sub = value.Name switch
            {
                HttpListener => value.Subscribe(new EventObserver(this), name => name == HttpRequestEvent),
                SqlListener => value.Subscribe(new EventObserver(this), name => name is MicrosoftSqlBefore or SystemSqlBefore),
                _ => null,
            };
            if (sub is null)
            {
                return;
            }

            lock (_subscriptions)
            {
                if (Volatile.Read(ref _disposed) == 0)
                {
                    _subscriptions.Add(sub);
                    return;
                }
            }

            sub.Dispose();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open: that library goes unchecked
        }
    }

    public void OnError(Exception error)
    {
    }

    public void OnCompleted()
    {
    }

    private void OnEvent(string name, object? payload)
    {
        if (Volatile.Read(ref _disposed) == 1)
        {
            return;
        }

        try
        {
            switch (name)
            {
                case HttpRequestEvent:
                    RaspHttpCheck.BeforeSend(RaspReflect.Property(payload, "Request") as HttpRequestMessage);
                    break;
                case MicrosoftSqlBefore:
                case SystemSqlBefore:
                    RaspSql.OnSqlClientCommand(name, payload);
                    break;
            }
        }
        catch (Shield360RaspBlockedException e)
        {
            if (name == HttpRequestEvent)
            {
                StopClientActivity(e);
            }
            else
            {
                RaspSql.ResetParentOperation(RaspReflect.Property(payload, "Command"));
            }

            throw;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>
    /// The HttpClient activity started for this request ends here: the handler that would
    /// stop it never runs once the event throws. Marked as an error, so the span is exported.
    /// </summary>
    private static void StopClientActivity(Shield360RaspBlockedException e)
    {
        try
        {
            var activity = Activity.Current;
            if (activity is not null && activity.OperationName == HttpClientActivity && !activity.IsStopped)
            {
                activity.SetStatus(ActivityStatusCode.Error, Shield360RaspBlockedException.BlockMessage);
                activity.SetTag("shield360.rasp.rule", e.Rule);
                activity.Stop();
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // never
        }
    }

    private sealed class EventObserver : IObserver<KeyValuePair<string, object?>>
    {
        private readonly RaspDiagnosticHooks _owner;

        public EventObserver(RaspDiagnosticHooks owner)
        {
            _owner = owner;
        }

        public void OnNext(KeyValuePair<string, object?> value) => _owner.OnEvent(value.Key, value.Value);

        public void OnError(Exception error)
        {
        }

        public void OnCompleted()
        {
        }
    }
}
