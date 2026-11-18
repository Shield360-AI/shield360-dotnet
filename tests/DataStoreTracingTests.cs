using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Net.Client;
using MongoDB.Bson;
using MongoDB.Driver;
using OpenTelemetry;
using OpenTelemetry.Trace;
using Shield360.Internal;
using Xunit;

namespace Shield360.Tests;

/// <summary>
/// SHIELD: MySqlConnector, MongoDB.Driver and Grpc.Net.Client trace themselves
/// through an ActivitySource; Shield360 listens to them. The real libraries run
/// against a closed port, so each call fails fast but still emits its span.
/// </summary>
public class DataStoreTracingTests
{
    [Fact]
    public async Task MongoDB_operations_are_traced_without_their_query()
    {
        var spans = await Collect(async () =>
        {
            var settings = MongoClientSettings.FromConnectionString("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=200");
            var users = new MongoClient(settings).GetDatabase("shop").GetCollection<BsonDocument>("users");
            await Assert.ThrowsAsync<TimeoutException>(() => users.Find(new BsonDocument("email", "ada@example.com")).FirstOrDefaultAsync());
        });

        var find = Assert.Single(spans, s => s.Source.Name == OpenTelemetrySetup.MongoDBSource && s.DisplayName == "find shop.users");
        Assert.Equal("mongodb", find.GetTagItem("db.system.name"));
        Assert.Equal("users", find.GetTagItem("db.collection.name"));
        Assert.Null(find.GetTagItem("db.query.text"));
        Assert.DoesNotContain(find.TagObjects, t => Convert.ToString(t.Value, System.Globalization.CultureInfo.InvariantCulture)!.Contains("ada@example.com", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Grpc_client_calls_carry_the_rpc_conventions()
    {
        var spans = await Collect(async () =>
        {
            using var channel = GrpcChannel.ForAddress("http://127.0.0.1:1");
            var get = new Method<byte[], byte[]>(MethodType.Unary, "orders.Orders", "Get", Marshallers.Create(b => b, b => b), Marshallers.Create(b => b, b => b));
            await Assert.ThrowsAsync<RpcException>(async () => await channel.CreateCallInvoker().AsyncUnaryCall(get, null, default, new byte[] { 1 }));
        });

        var call = Assert.Single(spans, s => s.Source.Name == GrpcClientSpanProcessor.SourceName);
        Assert.Equal("orders.Orders/Get", call.DisplayName);
        Assert.Equal("grpc", call.GetTagItem("rpc.system"));
        Assert.Equal("orders.Orders", call.GetTagItem("rpc.service"));
        Assert.Equal("Get", call.GetTagItem("rpc.method"));
        Assert.Equal((int)Grpc.Core.StatusCode.Unavailable, call.GetTagItem("rpc.grpc.status_code"));
    }

    [Fact]
    public async Task MySqlConnector_source_is_listened_to()
    {
        // MySqlConnector starts its command spans only once connected; its source name is what matters here.
        var spans = await Collect(() =>
        {
            using var source = new ActivitySource(OpenTelemetrySetup.MySqlConnectorSource);
            using (source.StartActivity("Execute", ActivityKind.Client))
            {
            }

            return Task.CompletedTask;
        });

        Assert.Contains(spans, s => s.Source.Name == OpenTelemetrySetup.MySqlConnectorSource);
    }

    [Fact]
    public async Task Each_can_be_turned_off()
    {
        var spans = await Collect(
            () =>
            {
                foreach (var name in new[] { OpenTelemetrySetup.MySqlConnectorSource, OpenTelemetrySetup.MongoDBSource, GrpcClientSpanProcessor.SourceName })
                {
                    using var source = new ActivitySource(name);
                    using (source.StartActivity("op", ActivityKind.Client))
                    {
                    }
                }

                return Task.CompletedTask;
            },
            "mysqlconnector", "mongodb", "grpc");

        Assert.DoesNotContain(spans, s => s.Source.Name is OpenTelemetrySetup.MySqlConnectorSource or OpenTelemetrySetup.MongoDBSource or GrpcClientSpanProcessor.SourceName);
    }

    [Theory]
    [InlineData("/orders.Orders/Get", "orders.Orders", "Get")]
    [InlineData("pkg.v1.Svc/Do", "pkg.v1.Svc", "Do")]
    public void Splits_the_full_method(string full, string service, string method)
    {
        Assert.True(GrpcClientSpanProcessor.TrySplit(full, out var s, out var m));
        Assert.Equal(service, s);
        Assert.Equal(method, m);
    }

    [Theory]
    [InlineData("")]
    [InlineData("/")]
    [InlineData("/NoMethod")]
    [InlineData("/svc/")]
    public void Ignores_a_malformed_method(string full) =>
        Assert.False(GrpcClientSpanProcessor.TrySplit(full, out _, out _));

    private static async Task<List<Activity>> Collect(Func<Task> run, params string[] disabled)
    {
        var spans = new List<Activity>();
        try
        {
            using (var provider = Sdk.CreateTracerProviderBuilder()
                .AddShield360Instrumentation(o =>
                {
                    o.ApplicationName = "orders-api";
                    o.DisabledInstrumentors = disabled;
                })
                .AddInMemoryExporter(spans)
                .Build()!)
            {
                await run();
                provider.ForceFlush();
            }
        }
        finally
        {
            Shield360Runtime.Current?.Deactivate();
        }

        lock (spans)
        {
            return spans.ToList();
        }
    }
}
