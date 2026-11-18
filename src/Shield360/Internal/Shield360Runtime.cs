using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Shield360.Internal;

/// <summary>
/// The settled configuration and pricing for one initialisation. The active
/// runtime is what <c>UseShield360()</c> and the span processor read when they
/// are not given settings of their own.
/// </summary>
internal sealed class Shield360Runtime
{
    private static Shield360Runtime? s_current;
    private static readonly Lazy<Pricing> s_bundled = new(LoadBundled, LazyThreadSafetyMode.ExecutionAndPublication);

    private Pricing _pricing;

    internal Shield360Runtime(ResolvedOptions options, Pricing pricing)
    {
        Options = options;
        _pricing = pricing;
    }

    public static Shield360Runtime? Current => Volatile.Read(ref s_current);

    /// <summary>The bundled pricing, loaded once.</summary>
    public static Pricing BundledPricing => s_bundled.Value;

    public ResolvedOptions Options { get; }

    public Pricing Pricing => Volatile.Read(ref _pricing);

    /// <summary>Completes when pricing from a URL has loaded (or failed). Already complete otherwise.</summary>
    public Task PricingLoaded { get; private set; } = Task.CompletedTask;

    public IEnumerable<Shield360Instrumentations.Library> EnabledLibraries =>
        Shield360Instrumentations.All.Where(l => Options.IsInstrumentationEnabled(l.Name));

    public IEnumerable<string> ActivitySources =>
        new[] { Shield360Sdk.ActivitySourceName }.Concat(EnabledLibraries.SelectMany(l => l.ActivitySources));

    public IEnumerable<string> Meters =>
        new[] { Shield360Sdk.MeterName }.Concat(EnabledLibraries.SelectMany(l => l.Meters));

    /// <summary>Builds a runtime, turns on library telemetry and makes it the active one.</summary>
    public static Shield360Runtime Activate(ResolvedOptions options)
    {
        var runtime = Create(options);
        runtime.ApplySwitches();
        Volatile.Write(ref s_current, runtime);
        return runtime;
    }

    /// <summary>Builds a runtime without activating it.</summary>
    public static Shield360Runtime Create(ResolvedOptions options)
    {
        var runtime = new Shield360Runtime(options, BundledPricing.WithOverrides(options.PricingOverrides));
        runtime.StartPricingLoad();
        return runtime;
    }

    /// <summary>Clears the active runtime if it is this one.</summary>
    public void Deactivate() => Interlocked.CompareExchange(ref s_current, null, this);

    /// <summary>
    /// Sets each enabled library's AppContext switches. Libraries read these
    /// once, so this has to run before the first client is created.
    /// </summary>
    public void ApplySwitches()
    {
        foreach (var library in EnabledLibraries)
        {
            foreach (var name in library.EnableSwitches)
            {
                AppContext.SetSwitch(name, true);
            }

            foreach (var name in library.ContentSwitches)
            {
                AppContext.SetSwitch(name, Options.CaptureMessageContent);
            }
        }
    }

    private void StartPricingLoad()
    {
        var source = Options.PricingJson;
        if (source is null)
        {
            return;
        }

        if (source.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            source.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            // Keep the bundled prices until the download lands.
            PricingLoaded = Task.Run(async () =>
            {
                try
                {
                    var loaded = await Pricing.LoadAsync(source).ConfigureAwait(false);
                    Volatile.Write(ref _pricing, loaded.WithOverrides(Options.PricingOverrides));
                }
                catch (Exception e) when (e is Shield360Exception or System.Net.Http.HttpRequestException or TaskCanceledException)
                {
                    // The URL is not written out: it may carry a token.
                    Trace.TraceWarning("Shield360: could not load pricing data from the configured URL ({0}); using the bundled prices.", e.GetType().Name);
                }
            });
            return;
        }

        try
        {
            var loaded = Pricing.LoadAsync(source).GetAwaiter().GetResult();
            _pricing = loaded.WithOverrides(Options.PricingOverrides);
        }
        catch (Shield360Exception e)
        {
            Trace.TraceWarning("Shield360: {0} Using the bundled prices.", e.Message);
        }
    }

    private static Pricing LoadBundled()
    {
        try
        {
            return Pricing.Bundled();
        }
        catch (Shield360Exception)
        {
            return Pricing.Empty;
        }
    }
}
