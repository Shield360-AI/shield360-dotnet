using System;
using System.Diagnostics;
using OpenTelemetry;

namespace Shield360.Internal;

/// <summary>
/// SHIELD: Grpc.Net.Client emits its call span with its own tags
/// (<c>grpc.method</c> = <c>/orders.Orders/Get</c>, <c>grpc.status_code</c>).
/// This adds the OpenTelemetry RPC conventions (<c>rpc.system</c>,
/// <c>rpc.service</c>, <c>rpc.method</c>, <c>rpc.grpc.status_code</c>) and names
/// the span <c>orders.Orders/Get</c>. Messages are never recorded.
/// Must be added before the exporter.
/// </summary>
internal sealed class GrpcClientSpanProcessor : BaseProcessor<Activity>
{
    public const string SourceName = "Grpc.Net.Client";

    public override void OnEnd(Activity data)
    {
        if (data.Source.Name != SourceName)
        {
            return;
        }

        if (data.GetTagItem("grpc.method") is string fullMethod && TrySplit(fullMethod, out var service, out var method))
        {
            data.SetTag("rpc.system", "grpc");
            data.SetTag("rpc.service", service);
            data.SetTag("rpc.method", method);
            data.DisplayName = service + "/" + method;
        }

        var status = data.GetTagItem("grpc.status_code");
        if (status is not null && int.TryParse(Convert.ToString(status, System.Globalization.CultureInfo.InvariantCulture), out var code))
        {
            data.SetTag("rpc.grpc.status_code", code);
        }
    }

    /// <summary>Splits <c>/package.Service/Method</c> into its service and method.</summary>
    internal static bool TrySplit(string fullMethod, out string service, out string method)
    {
        service = method = string.Empty;
        var trimmed = fullMethod.TrimStart('/');
        var slash = trimmed.LastIndexOf('/');
        if (slash <= 0 || slash == trimmed.Length - 1)
        {
            return false;
        }

        service = trimmed.Substring(0, slash);
        method = trimmed.Substring(slash + 1);
        return true;
    }
}
