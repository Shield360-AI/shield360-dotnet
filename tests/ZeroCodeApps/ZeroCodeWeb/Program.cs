using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

// A plain minimal API with no Shield360 code: no AddShield360Rasp, no UseShield360Rasp.
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:0");
builder.Logging.ClearProviders();
var app = builder.Build();
app.MapGet("/", () => "ok");
app.MapGet("/orders/{id}", (string id) => id);
app.MapGet("/healthz", () => "ok");
await app.StartAsync();
var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
Console.WriteLine("LISTENING " + address);
await app.WaitForShutdownAsync();
