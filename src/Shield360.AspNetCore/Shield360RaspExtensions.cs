using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Shield360.AspNetCore;
using Shield360.Internal;
using Shield360.Rasp;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>Registers Shield360 runtime protection (RASP) in an ASP.NET Core host.</summary>
    public static class Shield360RaspServiceCollectionExtensions
    {
        /// <summary>
        /// Turns RASP on with <paramref name="configure"/>'s settings (or keeps the settings
        /// <c>AddShield360</c> started it with), adds <see cref="Shield360RaspMiddleware"/> at the
        /// start of the pipeline, maps a block that reaches <c>UseExceptionHandler</c> to the 403,
        /// and flushes RASP events when the host stops. The Shield360 URL, API key and application
        /// name come from <c>AddShield360</c> when it ran first, else from the environment.
        /// </summary>
        /// <example>
        /// <code>
        /// builder.Services.AddShield360(o => o.ApplicationName = "orders-api");
        /// builder.Services.AddShield360Rasp(r =>
        /// {
        ///     r.ConfigPublicKey = builder.Configuration["Shield360:ConfigPublicKey"];
        ///     r.Attacks[RaspAttackType.SqlInjection] = RaspMode.Block;
        /// });
        /// </code>
        /// </example>
        public static IServiceCollection AddShield360Rasp(this IServiceCollection services, Action<RaspOptions>? configure = null) =>
            services.AddShield360Rasp(configure, Environment.GetEnvironmentVariable);

        internal static IServiceCollection AddShield360Rasp(this IServiceCollection services, Action<RaspOptions>? configure, Func<string, string?> env)
        {
            if (services is null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configure is not null || !RaspEngine.IsEnabled)
            {
                var options = new RaspOptions();
                configure?.Invoke(options);
                var resolved = Shield360Runtime.Current?.Options ?? ResolvedOptions.Resolve(null, env);
                RaspRuntime.Start(options, RaspStartContext.From(resolved, env, RaspStartContext.HostEnvironmentOf(services)));
            }

            services.TryAddEnumerable(ServiceDescriptor.Transient<IStartupFilter, Shield360RaspStartupFilter>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<MatcherPolicy, RaspDecoyMatcherPolicy>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IExceptionHandler, Shield360RaspExceptionHandler>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, Shield360RaspLifetime>());
            return services;
        }
    }
}

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>Adds the Shield360 runtime protection (RASP) middleware to a pipeline.</summary>
    public static class Shield360RaspApplicationBuilderExtensions
    {
        /// <summary>
        /// Adds <see cref="Shield360RaspMiddleware"/> here. Put it after <c>UseExceptionHandler</c>
        /// and <c>UseDeveloperExceptionPage</c> so a block from an endpoint becomes the 403 before
        /// they see it. RASP itself is turned on by <c>AddShield360Rasp</c>,
        /// <c>Shield360Options.Rasp</c> or <c>SHIELD360_RASP</c>.
        /// </summary>
        public static IApplicationBuilder UseShield360Rasp(this IApplicationBuilder app)
        {
            if (app is null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<Shield360RaspMiddleware>();
        }
    }
}

namespace Shield360.AspNetCore
{
    /// <summary>Adds the middleware at the start of the pipeline.</summary>
    internal sealed class Shield360RaspStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            // Decoys go on to the app's own not-found handling (RaspDecoyMatcherPolicy, registered with this filter).
            app.Use(inner => new Shield360RaspMiddleware(inner, deferDecoys: true).InvokeAsync);
            next(app);
        };
    }

    /// <summary>Maps a block that reached <c>UseExceptionHandler</c> to the contract's 403.</summary>
    internal sealed class Shield360RaspExceptionHandler : IExceptionHandler
    {
        public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
        {
            if (Shield360RaspMiddleware.Blocked(exception) is not { } block || httpContext.Response.HasStarted)
            {
                return false;
            }

            await Shield360RaspMiddleware.WriteBlockedAsync(httpContext, block).ConfigureAwait(false);
            return true;
        }
    }

    /// <summary>Flushes RASP events and stops polling when the host stops.</summary>
    internal sealed class Shield360RaspLifetime : IHostedService
    {
        public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken)
        {
            RaspRuntime.Shutdown(RaspRuntime.ShutdownFlushWait);
            return Task.CompletedTask;
        }
    }
}
