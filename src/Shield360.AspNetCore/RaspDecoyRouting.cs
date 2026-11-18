using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Matching;

namespace Shield360.AspNetCore;

/// <summary>
/// Set on a request that hit a decoy (sdk/rasp/README.md, "Deception") when the RASP middleware
/// runs ahead of the app's own middleware (<c>AddShield360Rasp</c>, zero-code setup). The request
/// goes on through the app's pipeline, but routing matches no endpoint for it, so the app answers
/// it exactly as it answers an unknown path (status code pages, re-execute and redirect handlers
/// included) and no endpoint ever runs.
/// </summary>
internal sealed class RaspDecoyFeature
{
    public RaspDecoyFeature(PathString pathBase, PathString path)
    {
        PathBase = pathBase;
        Path = path;
    }

    public PathString PathBase { get; }

    public PathString Path { get; }

    /// <summary>
    /// Whether routing must match nothing: the request still has the decoy's path. A status code
    /// page or exception handler that re-executes the pipeline on another path routes normally.
    /// </summary>
    public static bool Applies(HttpContext context) =>
        context.Features.Get<RaspDecoyFeature>() is { } d &&
        context.Features.Get<IStatusCodeReExecuteFeature>() is null &&
        context.Request.Path.Equals(d.Path) &&
        context.Request.PathBase.Equals(d.PathBase);
}

/// <summary>Endpoint routing's side of <see cref="RaspDecoyFeature"/>: every candidate is rejected for a decoy.</summary>
internal sealed class RaspDecoyMatcherPolicy : MatcherPolicy, IEndpointSelectorPolicy
{
    // After the built-in policies (HTTP method and others), so a decoy never gets a 405 either.
    public override int Order => int.MaxValue;

    public bool AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints) => endpoints.Count > 0;

    public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
    {
        if (RaspDecoyFeature.Applies(httpContext))
        {
            for (var i = 0; i < candidates.Count; i++)
            {
                candidates.SetValidity(i, false);
            }
        }

        return Task.CompletedTask;
    }
}
