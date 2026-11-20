# Shield360 .NET SDK

OpenTelemetry-native AI observability for .NET. Shield360 collects GenAI traces, token usage and cost from the .NET AI libraries you already use, and sends them to Shield360 (or any OpenTelemetry backend) over OTLP.

- **Built on OpenTelemetry .NET** - one call sets up tracing and metrics, or add Shield360 to a pipeline you already have.
- **Microsoft.Extensions.AI middleware** - `UseShield360()` records every `IChatClient` call as a GenAI span with tokens, cost and latency, streaming included.
- **Library telemetry, collected** - turns on and listens to the GenAI telemetry built into the OpenAI .NET SDK, Azure AI Inference, Semantic Kernel and Microsoft.Extensions.AI.
- **Cost tracking** - `gen_ai.usage.cost` from the same pricing data as the Python and TypeScript SDKs.
- **Nothing sensitive by default** - prompts and responses are recorded only when you turn content capture on.
- **Rule engine client** - evaluate trace attributes against your Shield360 rules.
- **Feature flags** - evaluated locally with the same engine as the server and the other SDKs, with helpers for model choice, kill switches and Prompt Hub prompts.
- **Runtime protection (RASP)** - opt-in: request and model-output input tracking, the shared detectors, virtual patches, a signed remote config and sink hooks (HttpClient, SqlClient, processes, files, XML, deserializers), with ASP.NET Core middleware in `Shield360.AspNetCore` and an EF Core interceptor in `Shield360.EntityFrameworkCore`.

Full documentation: [.NET SDK overview](https://github.com/ThinkfleetAI/shield360-dotnet/blob/main/docs/dotnet-overview.mdx).

## Requirements

- .NET 8 or later (the package also targets .NET Standard 2.0, for .NET Framework 4.6.2 and later).

## Installation

```bash
dotnet add package Shield360
```

## Quick start

### Console app

Call `Shield360Sdk.Init` once at start-up, before you create any AI client, and dispose the handle before the app exits so buffered telemetry is sent.

```csharp
using Microsoft.Extensions.AI;
using OpenAI;
using Shield360;

using var shield360 = Shield360Sdk.Init(new Shield360Options
{
    OtlpEndpoint = "http://127.0.0.1:4318",
    ApplicationName = "my-ai-app",
    Environment = "production",
});

IChatClient client = new OpenAIClient(Environment.GetEnvironmentVariable("OPENAI_API_KEY"))
    .GetChatClient("gpt-4o-mini")
    .AsIChatClient()
    .AsBuilder()
    .UseShield360()
    .Build();

var response = await client.GetResponseAsync("What is OpenTelemetry?");
Console.WriteLine(response.Text);
```

### ASP.NET Core and other hosted apps

```csharp
using Microsoft.Extensions.AI;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddShield360(o =>
{
    o.ApplicationName = "orders-api";
    o.Environment = builder.Environment.EnvironmentName;
});

builder.Services.AddChatClient(services =>
        new OpenAI.OpenAIClient(builder.Configuration["OpenAI:ApiKey"])
            .GetChatClient("gpt-4o-mini")
            .AsIChatClient())
    .UseShield360();

var app = builder.Build();
app.MapGet("/ask", async (IChatClient chat, string q) => (await chat.GetResponseAsync(q)).Text);
app.Run();
```

`AddShield360` returns the OpenTelemetry builder, so you can add more instrumentation to the same pipeline:

```csharp
builder.Services.AddShield360()
    .WithTracing(t => t.AddAspNetCoreInstrumentation());
```

### Already using OpenTelemetry

Add Shield360's sources, meters and GenAI span processing to your own providers. Add it before your exporter.

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddShield360Instrumentation(o => o.ApplicationName = "orders-api").AddOtlpExporter())
    .WithMetrics(m => m.AddShield360Instrumentation().AddOtlpExporter());
```

### Microsoft.Extensions.AI (`IChatClient`)

`UseShield360()` is a chat client middleware. Each call becomes a `chat {model}` span with:

- request settings (`gen_ai.request.temperature`, `max_tokens`, `top_p`, `seed`, stop sequences, output type)
- the response ID, model and finish reasons
- `gen_ai.usage.input_tokens`, `output_tokens`, `total_tokens`, cached and reasoning tokens
- `gen_ai.usage.cost`, from the pricing data
- tool calls (`gen_ai.tool.name`, `gen_ai.tool.call.id`) and the tool definitions offered
- `service.name`, `deployment.environment`, `telemetry.sdk.name` and `gen_ai.sdk.version`

It also records the GenAI metrics: `gen_ai.client.token.usage`, `gen_ai.client.operation.duration`, `gen_ai.usage.cost`, and, for streaming calls, `gen_ai.server.time_to_first_token`, `gen_ai.server.time_per_output_token`, `gen_ai.client.operation.time_to_first_chunk`, `gen_ai.client.operation.time_per_output_chunk` and `gen_ai.server.request.duration`.

Settings come from `Init` or `AddShield360`. Override them for one client:

```csharp
var client = inner.AsBuilder()
    .UseShield360(o =>
    {
        o.ApplicationName = "support-bot";
        o.ProviderName = "ollama"; // when the inner client does not report one
    })
    .Build();
```

`UseShield360()` does the job of `UseOpenTelemetry()`. Use one of them in a pipeline, not both, or each call is traced twice.

### Semantic Kernel

Semantic Kernel's GenAI telemetry is turned on and collected for you; there is nothing to add to the kernel.

```csharp
using Microsoft.SemanticKernel;
using Shield360;

using var shield360 = Shield360Sdk.Init(new Shield360Options { ApplicationName = "planner" });

var kernel = Kernel.CreateBuilder()
    .AddOpenAIChatCompletion("gpt-4o-mini", Environment.GetEnvironmentVariable("OPENAI_API_KEY")!)
    .Build();

Console.WriteLine(await kernel.InvokePromptAsync("Plan a three-step rollout."));
```

## Zero-code setup

Turn on Shield360, telemetry and runtime protection (RASP), in an app that does not reference Shield360 and is not rebuilt. A .NET startup hook starts the SDK before `Main`; everything is configured with environment variables.

Build the hook directory once (it holds the hook, Shield360, Shield360.AspNetCore, their dependencies, and a `store/` of newer framework assemblies for .NET 8 and 9) and ship it next to the app, for example as a container layer:

```bash
dotnet publish src/Shield360.StartupHook/Shield360.StartupHook.csproj -c Release -o /opt/shield360
```

Then start the app with:

```bash
export DOTNET_STARTUP_HOOKS=/opt/shield360/Shield360.StartupHook.dll
# Needed on .NET 8 and 9, harmless on 10:
export DOTNET_ADDITIONAL_DEPS=/opt/shield360/Shield360.AdditionalDeps.deps.json
export DOTNET_SHARED_STORE=/opt/shield360/store
export OTEL_SERVICE_NAME=orders-api
export SHIELD360_URL=https://app.shield360.ai
export SHIELD360_API_KEY=...                      # from Settings > API keys
export SHIELD360_RASP=monitor                     # the default; block blocks attacks, off turns RASP off
export SHIELD360_CONFIG_PUBLIC_KEY='{"kty":"OKP",...}'  # Runtime protection settings

dotnet OrdersApi.dll
```

Why three variables: Shield360 builds against `Microsoft.Extensions.AI` 10, which needs version 10.0 of `System.Diagnostics.DiagnosticSource`, `System.Text.Json` and some `Microsoft.Extensions.*` assemblies. The .NET 8 and 9 shared frameworks carry older versions, and a startup hook runs too late to replace a framework assembly. The .NET host can do it before the app starts: `DOTNET_ADDITIONAL_DEPS` lists those packages and `DOTNET_SHARED_STORE` points at the copies in `store/`. Where two versions of an assembly meet, the host takes the higher, as it does for an app's own package references. On .NET 10 the framework already has them. With `DOTNET_STARTUP_HOOKS` alone on .NET 8 or 9, the hook fails open and its warning names the two variables.

What the hook does, before `Main`:

- Loads Shield360 and its dependencies from its own directory when the app does not carry them (the app's own copies win).
- Starts Shield360 as `Shield360Sdk.Init()` would, from `OTEL_SERVICE_NAME`, `OTEL_DEPLOYMENT_ENVIRONMENT`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `SHIELD360_URL`, `SHIELD360_API_KEY`, `SHIELD360_RASP` and the other variables in [Configuration](#configuration). RASP is on in monitor mode when `SHIELD360_RASP` is unset: attacks are reported, nothing is blocked.
- In an ASP.NET Core app with RASP on, adds `Shield360.AspNetCore` to `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`.

### ASP.NET Core: the middleware without code

A startup hook runs before the host exists, so it cannot add middleware by itself. ASP.NET Core's hosting startup assemblies can: `Shield360.AspNetCore` carries a hosting startup that registers what `AddShield360Rasp()` registers (the RASP middleware first in the pipeline through an `IStartupFilter`, the block mapped to the 403 behind `UseExceptionHandler`, events flushed at shutdown). The hook turns it on for you, so a minimal-API app with no Shield360 code answers a blocked request with the 403. This works for hosts built with `WebApplication.CreateBuilder` and `ConfigureWebHostDefaults`, which read `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`.

- To leave the middleware out, set `ASPNETCORE_HOSTINGSTARTUPEXCLUDEASSEMBLIES=Shield360.AspNetCore`.
- An app that references `Shield360.AspNetCore` but has no Shield360 code can turn on the same middleware without the hook: `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=Shield360.AspNetCore` with `SHIELD360_RASP=monitor|block`.
- Code that also calls `AddShield360Rasp()` or `UseShield360Rasp()` is fine: the services are registered once and a second middleware only maps blocks. `AddShield360Rasp(r => ...)` with options restarts RASP with those options, so the app's explicit RASP settings win.

Rules it keeps:

- **Fail open.** If Shield360 cannot start (invalid settings, an assembly that will not load), the hook prints one warning and the app starts without it.
- **No double start.** If the app also calls `Shield360Sdk.Init()`, the call returns the hook's handle and prints one line; `AddShield360()` adds nothing more. The environment settings stay in force.

Limits:

- Native AOT apps do not run startup hooks, and trimmed apps (`PublishTrimmed`) turn them off by default.
- On .NET 8 and 9 the additional deps move the app to the 10.0 versions of the assemblies listed in `Shield360.AdditionalDeps.deps.json` (`System.Diagnostics.DiagnosticSource`, `System.Text.Json` and some `Microsoft.Extensions.*`). These packages support .NET 8 and later, but test the app with them. Tested on the .NET 9 and .NET 10 runtimes, console and minimal-API apps.
- Other dependencies the app carries itself (OpenTelemetry, say) must be the same version as the hook's or newer, or the hook fails open with a warning.
- The `store/` covers x64 and arm64 apps targeting `net8.0`, `net9.0` and `net10.0`.
- Single-file apps were not tested.
- Child .NET processes inherit `DOTNET_STARTUP_HOOKS` and start Shield360 too.

No new environment variables: the hook uses the variables `Shield360Sdk.Init()` already reads, and the standard `DOTNET_STARTUP_HOOKS` and `ASPNETCORE_HOSTINGSTARTUP*` ones.

## Instrumented libraries

| Library | Name (for `DisabledInstrumentors`) | ActivitySource / Meter | Switch Shield360 turns on |
|---------|------------------------------------|------------------------|---------------------------|
| Shield360 `UseShield360()` | always on | `Shield360` | - |
| Microsoft.Extensions.AI `UseOpenTelemetry()` | `microsoft-extensions-ai` | `Experimental.Microsoft.Extensions.AI` | - |
| OpenAI .NET SDK, and Azure.AI.OpenAI | `openai` | `OpenAI.*` (`OpenAI.ChatClient`) | `OpenAI.Experimental.EnableOpenTelemetry` |
| Azure.AI.Inference | `azure-ai-inference` | `Azure.AI.Inference.*` (`Azure.AI.Inference.ChatCompletionsClient`) | `Azure.Experimental.EnableActivitySource` |
| Semantic Kernel | `semantic-kernel` | `Microsoft.SemanticKernel*` | `Microsoft.SemanticKernel.Experimental.GenAI.EnableOTelDiagnostics` |
| MySqlConnector (command text, never parameter values) | `mysqlconnector` | `MySqlConnector` | - |
| MongoDB.Driver 3.x (operation and collection; query text stays off) | `mongodb` | `MongoDB.Driver` | - |
| Grpc.Net.Client (`rpc.system`, `rpc.service`, `rpc.method`, `rpc.grpc.status_code` added; messages never recorded) | `grpc` | `Grpc.Net.Client` | - |

Checked against MySqlConnector 2.6.2, MongoDB.Driver 3.13.0, Grpc.Net.Client 2.85.0, OpenAI 2.14.0, Microsoft.Extensions.AI 10.11.0, Azure.AI.OpenAI 2.9.0-beta.1, Azure.AI.Inference 1.0.0-beta.5 and Semantic Kernel 1.81.0.

Things to know:

- **The switches are AppContext switches that each library reads once.** Call `Init` or `AddShield360` before creating any AI client. To set them yourself instead, use `AppContext.SetSwitch("OpenAI.Experimental.EnableOpenTelemetry", true)` or the `<RuntimeHostConfigurationOption>` item in your project file. The OpenAI SDK emits no spans or metrics without its switch.
- `Azure.Experimental.EnableActivitySource` applies to every Azure SDK client, not only Azure AI Inference. Shield360 only listens to the Azure AI Inference source.
- The content switches (`Azure.Experimental.TraceGenAIMessageContent`, `Microsoft.SemanticKernel.Experimental.GenAI.EnableOTelDiagnosticsSensitive`) are set to your content capture setting.
- Spans from these libraries get the same Shield360 treatment as `UseShield360()` spans: `service.name`, `deployment.environment` and `telemetry.sdk.name`, `gen_ai.usage.cost` computed from their token counts, both `gen_ai.provider.name` and `gen_ai.system`, and message content removed unless capture is on.
- When GenAI spans nest (Semantic Kernel over the OpenAI SDK, or `UseShield360()` over an OpenAI `IChatClient`), only the outermost span carries the cost, so it is not counted twice.

## Configuration

Every option falls back to its environment variable, then to its default. The names match the Python, TypeScript and Go SDKs.

| Option | Environment variable | Description | Default |
|--------|----------------------|-------------|---------|
| `OtlpEndpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP endpoint. `/v1/traces` and `/v1/metrics` are added for you. | `http://127.0.0.1:4318` |
| `OtlpHeaders` | `OTEL_EXPORTER_OTLP_HEADERS` | Headers for every export (`name=value,name2=value2`) | none |
| `ApiKey` | `SHIELD360_API_KEY` | Shield360 API key | none |
| `Shield360Url` | `SHIELD360_URL` | Shield360 URL. With an API key and no OTLP endpoint, telemetry goes to `{url}/api/ingest/otlp` with the key as a bearer token. HTTPS unless localhost. | none |
| `ApplicationName` | `OTEL_SERVICE_NAME` | Recorded as `service.name` | `default` |
| `Environment` | `OTEL_DEPLOYMENT_ENVIRONMENT` | Recorded as `deployment.environment` | `default` |
| `ServiceVersion` | `SHIELD360_SERVICE_VERSION`, `OTEL_SERVICE_VERSION` | Recorded as `service.version` | none |
| `CaptureMessageContent` | `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT` | Record prompts, responses and tool arguments. Stored only if your organization's Data retention setting allows it. | `false` |
| `PricingJson` | `SHIELD360_PRICING_JSON` | Pricing data: a URL, a file path or a JSON string | bundled pricing |
| `PricingOverrides` | - | Per-model chat prices (USD per 1,000 tokens) that win over the pricing data | none |
| `DisableTracing` | - | Do not export traces | `false` |
| `DisableMetrics` | `SHIELD360_DISABLE_METRICS` | Do not export metrics | `false` |
| `DisableBatch` | `SHIELD360_DISABLE_BATCH` | Export each span as it ends | `false` |
| `DisabledInstrumentors` | `SHIELD360_DISABLED_INSTRUMENTORS` | Libraries to leave off (see the table above) | none |
| `CustomSpanAttributes` | `SHIELD360_CUSTOM_SPAN_ATTRIBUTES` | Attributes added to every GenAI span (JSON object in the variable) | none |
| `ResourceAttributes` | `OTEL_RESOURCE_ATTRIBUTES` | Attributes added to the OpenTelemetry resource | none |
| `ExportTimeout` | - | Timeout for each export | 10 seconds |
| `MetricExportInterval` | `OTEL_EXPORTER_OTLP_METRICS_EXPORT_INTERVAL` | Metric export interval (milliseconds in the variable) | 30 seconds |
| `CaptureLogs` | `SHIELD360_CAPTURE_LOGS` | Send the application's own `ILogger` records (see [Application logs](#application-logs)) | `false` |
| `LogLevel` | `SHIELD360_LOG_LEVEL` | Lowest level sent when `CaptureLogs` is on | `info` |

### Send telemetry to Shield360

With a Shield360 URL and API key, nothing else is needed:

```bash
export SHIELD360_URL=https://app.shield360.ai
export SHIELD360_API_KEY=your-api-key
```

```csharp
using var shield360 = Shield360Sdk.Init(new Shield360Options { ApplicationName = "my-ai-app" });
```

## Application logs

Off by default. Set `SHIELD360_CAPTURE_LOGS=true` (or the init option, `CaptureLogs = true`) to send the application's own log records to Shield360, on the same endpoint and key as traces. `SHIELD360_LOG_LEVEL` sets the lowest level sent (`info` by default; `trace`, `debug`, `info`, `warn`, `error`, `fatal`). Records carry the active trace and span ids, `service.name` and `deployment.environment`; credentials and opaque tokens in messages and attributes are masked before they leave the process; at most 500 records a second per bridge are sent, in batches, and a failure to send never reaches the application.

The bridge is an `ILogger` provider (OpenTelemetry's, with Shield360's masking and limits in front of an OTLP/HTTP log exporter). Masking follows the contract every Shield360 SDK shares (`sdk/rasp/README.md`, "Masking"): credential pairs (`password=…`, `"api_key": "…"`, `Authorization: Bearer …`) and opaque tokens (keys, hashes, base64, JWTs, UUIDs) are masked, as is the whole value of any field named like a credential (`password`, `x-api-key`, `sessionId`); readable identifiers such as exception class names and file paths survive, so stack traces stay useful. Masking runs before values are cut to size.

```csharp
// Console apps: take loggers from Shield360Sdk.LoggerFactory (a no-op factory while logs are off).
using var shield360 = Shield360Sdk.Init(new Shield360Options { ApplicationName = "orders", CaptureLogs = true });
var log = Shield360Sdk.CreateLogger("Orders.Checkout");
log.LogWarning("Payment for {OrderId} retried", orderId);

// Hosted apps: AddShield360 adds Shield360 to the host's logging when CaptureLogs (or the variable) is on ...
builder.Services.AddShield360(o => o.CaptureLogs = true);
// ... or add it to the logging builder yourself (this turns it on).
builder.Logging.AddShield360Logs(o => o.LogLevel = "warn");
```

Each record's body is the formatted message, its scope the logger category, its severity the OpenTelemetry short name (`TRACE` … `FATAL`) and number; the message template's values become attributes, and an exception becomes `exception.type`, `exception.message` and `exception.stacktrace`. Records from the `Shield360` and `OpenTelemetry` categories, and anything logged while a record is being exported, are never sent. The host's own logging filters (for example `Logging:LogLevel:Default`) still apply before `LogLevel`. With the zero-code start, a hosted app's `ILogger` records are forwarded when `SHIELD360_CAPTURE_LOGS=true`.

## Rule engine

Evaluate trace attributes against your Shield360 rules and get back the matching rules and their contexts, prompts or evaluations. This is a plain HTTP call and does not need `Init`.

```csharp
using Shield360;
using Shield360.RuleEngine;

var result = await Shield360Sdk.EvaluateRuleAsync(new EvaluateRuleOptions
{
    EntityType = RuleEntityType.Context,
    Fields = new Dictionary<string, object?>
    {
        ["gen_ai.system"] = "openai",
        ["gen_ai.request.model"] = "gpt-4o",
        ["service.name"] = "my-app",
    },
    IncludeEntityData = true,
});

foreach (var entity in result.Entities)
{
    Console.WriteLine($"{entity.RuleId}: {entity.EntityType} {entity.EntityId}");
}
```

`Url` falls back to `SHIELD360_URL`, then `http://127.0.0.1:3000`; `ApiKey` falls back to `SHIELD360_API_KEY`. The URL must use HTTPS unless it points at localhost. For dependency injection, create a `RuleEngineClient` with an `HttpClient` from `IHttpClientFactory`. Errors are raised as `Shield360Exception`, whose message never contains the API key.

## Feature flags

`Shield360Sdk.Flags` polls your environment's flags (`GET /api/flags/rules`, every 30 seconds with jitter, sending the last ETag) and evaluates them in-process with the same engine as the server and the Python and TypeScript SDKs. It uses the Shield360 URL, API key and application name from `Init` (or `SHIELD360_URL`, `SHIELD360_API_KEY` and `OTEL_SERVICE_NAME`), and starts polling on first use.

Nothing throws into your app. Until rules arrive, for an unknown flag or a flag scoped to another application, for a value of the wrong kind, or on any error, you get your default back. Each served flag sets `shield360.flag.<key>` = the variation key on `Activity.Current`, so you can compare cost, latency and evals by variant.

```csharp
using Shield360;
using Shield360.Flags;

var flags = Shield360Sdk.Flags;
await flags.WaitUntilReadyAsync(TimeSpan.FromSeconds(5)); // optional

var user = new Dictionary<string, object?> { ["key"] = userId, ["plan"] = "pro", ["groups"] = new[] { "beta" } };

if (flags.IsEnabled("new-checkout", user)) { /* ... */ }
var maxTokens = flags.GetNumber("max-tokens", user, 1024);
var detail = flags.GetFlagDetail("model-choice", user, "openai/gpt-4o-mini"); // Value, Variation, Reason

// AI helpers
var model = flags.Model("model-choice", user, "openai/gpt-4o-mini");   // "provider/model"
if (flags.KillSwitch("chat-enabled", user)) { return; }                  // engaged when the flag is false
var prompt = await flags.PromptAsync("support-prompt", user, new PromptRef("support"),
    new PromptOptions { Variables = new Dictionary<string, object?> { ["name"] = "Ada" } });
// prompt.Prompt is the Prompt Hub answer, or null with prompt.Error set.
```

A Prompt Hub flag's value is `{"name": "...", "version": "..."}`, `"name"` or `"name@version"`. For your own client, use `new FlagsClient(new FlagsOptions { Url = ..., ApiKey = ..., ApplicationName = ..., PollInterval = ... })` and dispose it when you are done. `FlagEngine.Evaluate` evaluates a flag definition directly.

## Runtime packages

With a Shield360 URL and API key, the SDK reports the NuGet packages the process has loaded so Shield360 can match them against vulnerability data (Security → Code, as a "runtime" target): the .NET version and, for every loaded assembly that is not part of the runtime, the package the app's `.deps.json` says it came from (package id and version), or else its assembly name and version. Each is a name and a version; no path, file or other field leaves the process, and at most 500 are sent. The report goes to `/api/guard/events` with the app's API key, about 15 seconds after start and then once a day, off the call path; it never throws and a report that cannot be delivered is dropped. When runtime protection is on it uses this report instead of sending its own.

Turn it off with `RuntimePackages = false` in `Shield360Options`, or `SHIELD360_RUNTIME_PACKAGES=off`.

## Runtime protection (RASP)

Runtime application self-protection, opt-in. RASP keeps each request's untrusted input in memory (an `AsyncLocal` context that lives as long as the request), and, for AI apps, the model output `UseShield360()` sees. It checks that input where it reaches a dangerous sink. In monitor mode (the default) a detection is reported to Shield360. In block mode the call throws `Shield360RaspBlockedException`, which the ASP.NET Core middleware turns into a 403. Everything else fails open: RASP never breaks your app. Events name the attack, the rule and where the input came from (`query.id`), never the input itself. The contract all Shield360 SDKs follow is `sdk/rasp/README.md` in the Shield360 repository.

```csharp
// Program.cs (ASP.NET Core). The middleware is in the Shield360.AspNetCore package.
using Shield360.Rasp;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddShield360(o => o.ApplicationName = "orders-api");
builder.Services.AddShield360Rasp(r =>
{
    r.ConfigPublicKey = builder.Configuration["Shield360:ConfigPublicKey"]; // or SHIELD360_CONFIG_PUBLIC_KEY
    r.Attacks[RaspAttackType.SqlInjection] = RaspMode.Block;
});

var app = builder.Build();
app.UseExceptionHandler("/error");
app.UseShield360Rasp(); // optional: AddShield360Rasp already adds it first; here it sees blocks before the exception page
app.Run();
```

In a console app or worker, set `Shield360Options.Rasp = new RaspOptions { ... }` in `Shield360Sdk.Init`, and wrap each job that acts on a model's answer in `Shield360Rasp.RunInScope(...)`. You can also turn RASP on with `SHIELD360_RASP=monitor` or `block` ([Zero-code setup](#zero-code-setup) adds the middleware without code, too). `SHIELD360_RASP=off` always wins, then the signed config's kill switch, then `Shield360Rasp.Disable()`.

| Option | Default | Meaning |
|---|---|---|
| `Mode` | `Monitor` | The mode of every attack type without its own (`Off`, `Monitor`, `Block`). |
| `Attacks` | empty | A mode per `RaspAttackType`. `Xss` and `Baseline` never block. |
| `Allow.Commands`, `Allow.OutboundHosts`, `Allow.FileRoots` | empty | Allow-lists for the process, outbound and file checks. |
| `ModelOutput` | `true` | Treat model output seen by `UseShield360()` as untrusted input. |
| `Remote` | `true` | Poll the signed config when `Shield360Url` and `ApiKey` are set. |
| `ConfigPublicKey` | `SHIELD360_CONFIG_PUBLIC_KEY` | **Required for the signed config**: the environment's Ed25519 public key (JWK, JWKS or bare `x`) from the app's Runtime protection settings. Without it, RASP uses its built-in defaults and stays in monitor mode. |
| `AllowUnpinnedConfig` | `false` (`SHIELD360_CONFIG_TOFU=dev`) | Development only: trust on first use. Ignored when `ASPNETCORE_ENVIRONMENT`, `DOTNET_ENVIRONMENT`, `ENVIRONMENT` or `NODE_ENV` is production. |
| `CacheDir` | temp dir + `shield360-rasp` | Where the last verified config is cached (re-verified on load). |
| `Hooks` | `true` | Check every `HttpClient` request and SqlClient command through their diagnostic events. |
| `Components` | `true` | Report loaded assembly names and versions at start and every 24 hours. |
| `Iast` | off (`SHIELD360_IAST=on`) | Passive IAST: report where request input reaches a sink unparameterized during normal traffic (see below). Never blocks. `SHIELD360_IAST=off` always wins, then the signed config's switch. |
| `IastSampleRate` | 1, or 0.1 in production (`SHIELD360_IAST_SAMPLE_RATE`) | The share of checks passive IAST looks at, 0 to 1. The environment variable, then the signed config's rate, win over it. Setting it alone turns passive IAST on. |

The signed config (`GET /api/rasp/config`) is an Ed25519 JWS. It is verified against the pinned key, polled every 60 seconds with jitter (5 minutes after a failure), and never blocks start-up. Once verified, its modes, allow-lists, virtual patches and custom rules replace the local ones; a local `Off` still wins. Ed25519 verification uses the BouncyCastle.Cryptography package, because .NET 8 and .NET Standard 2.0 have no Ed25519 in the base library.

**Custom rules.** The rules your organization writes in Shield360 (an app's Runtime protection settings) arrive in the signed config and run in the SDK as data: each expression is parsed and type-checked when the config arrives, never compiled to code, and evaluated with the same grammar, limits and regex subset as the platform (a linear-time Pike VM on every target, with a budget of 4,000,000 steps per request). Request rules run with the virtual patches before the endpoint, in two phases: head rules before the middleware reads the body (their `input.*` is the query, cookies and input headers only), body rules once it has. A request with no body or an empty one (a `GET`, an empty `POST`) has a known, empty body, so body rules still run; "no body" means `Content-Length: 0` or the server reporting the request cannot have one (`IHttpRequestBodyDetectionFeature`: HTTP/1.x without a length or chunks, HTTP/2 headers that end the stream). A body that reads empty although the request framed one (a length, chunks, HTTP/2 data; an earlier middleware consumed it) stays unknown and its body rules do not run. Rules that read `sink.*` or `attack.*` run when a built-in check finds something. A match is a `custom_rule` event with rule `custom.<id>`; it blocks only when the rule's action is `block` and `Attacks[RaspAttackType.CustomRule]` (or the signed config) is `Block`. An invalid rule is skipped with one log line and the rest of the config applies. `request.ip` is ASP.NET Core's `Connection.RemoteIpAddress` when the rule is judged, so it honors `UseForwardedHeaders` even though `AddShield360Rasp` puts the RASP middleware first: rules that read it are judged again when forwarded headers set the client address, and, when `ForwardedHeadersOptions` are configured in services (or `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true`) and a trusted proxy sends `X-Forwarded-For`, they wait for that address instead of judging the proxy's. Configure the options in services, not only inline, so a rule that matches the proxy's own address never fires on it. Without forwarded headers, `X-Forwarded-For` changes nothing.

**Deception.** Decoy paths (honeypots) such as `/wp-admin` on an app that is not WordPress, set per app in its Runtime protection settings in Shield360 and sent in the signed config's `deception` block. Off unless the config names decoys; there is no local option that defines them. The middleware checks them first, before anything else it does. A request whose path (the raw request target, `IHttpRequestFeature.RawTarget`, percent-decoded once; without one, `PathBase + Path` as the server decoded it, where an encoded slash stays `%2F`) is a decoy or under one never reaches an endpoint and gets the same answer as an unknown path; it is reported as `deception.hit`. With `AddShield360Rasp` (and zero-code setup), where the middleware runs first, the decoy goes on through your pipeline but endpoint routing matches nothing for it (fallback endpoints included), so your status code pages, re-execute and redirect handlers answer it as they answer any unknown path. A middleware added only with `UseShield360Rasp()` answers it itself with ASP.NET Core's empty 404, which status code pages registered before it render as usual. Middleware that answers requests before routing (static files, a terminal `app.Run`) sees a decoy as it sees any other path. The client's address (the same one `request.ip` uses, forwarded headers included) is then suspicious for the config's `ttlSeconds`, and its later requests are reported as `deception.suspicious`: with the block's `action` `block` they get the 403, with `monitor` they go on to the app. `Attacks[RaspAttackType.Deception] = RaspMode.Off` (or `off` in the signed config) turns deception off, `monitor` caps it, and without a pinned key `block` is lowered to `monitor`. Suspicious addresses are kept in memory per process (at most 10,000; when full, expired marks are dropped first, then the mark closest to expiring), so replicas and instances do not share them. Any error in deception lets the request through.

**Passive IAST.** With `Iast = true` (or `SHIELD360_IAST=on`, or the app's "Report vulnerabilities" setting), the checks RASP already runs also report `shield360.rasp.vulnerability` events where a request input reaches SQL, a command, a file path, a URL, evaluated code, an assembly load, a deserializer or a resolving XML parser verbatim, even when the value is harmless. It never blocks, adds no hooks, and only looks at sampled checks that found no attack. Each finding (route, sink, input key, rule) is reported at most once an hour per process with a count, names the input's location and the top frame of your code (`Routes/Orders.cs:42`, read from the stack once; it needs PDBs), and never carries the value.

What this version covers: request capture (query, route values, form and JSON body leaves, cookies, `User-Agent`, `Referer`, `X-Forwarded-For`, percent-decoded forms) and model output as input. It also covers every detector in the contract (SQL, NoSQL, command, shell spawn, path, file write, SSRF and outbound, deserialization, code, XXE, XSS), virtual patches run before the endpoint, the signed config, the sink hooks below, and events and the components report sent to `/api/guard/events`.

### Sink hooks

.NET has no runtime patching, so RASP checks a sink in one of three ways: through a `DiagnosticListener` event the library already raises before the call, through a handler or interceptor you register, or through a helper you call. In block mode each one throws `Shield360RaspBlockedException` before the call is made. In monitor mode it reports once and lets the call through. With RASP off it does nothing, and any failure inside a check lets the call through.

| Sink | How | What is checked |
|---|---|---|
| `HttpClient` (every request) | Automatic: the `System.Net.Http.Request` diagnostic event | Outbound allow-list, then SSRF on the URL, before anything is sent; each redirect hop again. When an input names the host, its addresses too (one lookup), so pooled connections, proxies and HTTP/3 are covered. |
| `HttpClient` (the connection) | `Shield360RaspHttp.CreateHandler()` / `CreateClient()`, or `AddShield360Rasp()` on an `IHttpClientBuilder` (`services.AddShield360RaspHttpClients()` for every factory client) | Also resolves the host once, checks those addresses (`ssrf.internal`, `ssrf.metadata`), and connects to exactly them (`SocketsHttpHandler.ConnectCallback`), so DNS rebinding cannot pass the check and connect elsewhere. A redirect to a new host gets the whole check here. Through a proxy or over HTTP/3 the connection's own lookup is not RASP's, so only the check before sending applies there. |
| SqlClient | Automatic: the `WriteCommandBefore` diagnostic event of Microsoft.Data.SqlClient and System.Data.SqlClient | SQL injection in each text command, in the SQL Server dialect. The legacy `Begin*` (APM) methods raise no event and are not checked; call `CheckSql` before them. |
| Entity Framework Core | `optionsBuilder.AddShield360Rasp()` from the **Shield360.EntityFrameworkCore** package | SQL injection in every command, in the provider's dialect. A command checked here is not checked again by the SqlClient hook. |
| MongoDB | `Shield360Rasp.CheckMongo(filter, update)` | Operator objects from the request (`nosqli.operator`) and tainted `$where` code. Takes a `BsonDocument`, JSON, a `JsonNode` or a dictionary. |
| Oracle (Oracle.ManagedDataAccess) | Entity Framework Core: `AddShield360Rasp()` (provider `Oracle.EntityFrameworkCore`). Plain ADO.NET: `Shield360Rasp.CheckSql(command.CommandText, RaspSqlDialect.Oracle)` before executing | SQL injection, in the Oracle dialect. The driver raises no diagnostic event before a command (its OpenTelemetry package only traces), so plain ADO.NET calls are checked only through `CheckSql`. |
| IBM Db2 (IBM.Data.Db2) | Entity Framework Core: `AddShield360Rasp()` (provider `IBM.EntityFrameworkCore`). Plain ADO.NET: `Shield360Rasp.CheckSql(command.CommandText, RaspSqlDialect.Db2)` before executing | SQL injection, in the Db2 dialect. The driver raises no diagnostic event, so plain ADO.NET calls are checked only through `CheckSql`. |
| Other SQL | `Shield360Rasp.CheckSql(sql, RaspSqlDialect.Postgres)` | SQL injection. |
| Processes | `Shield360Rasp.StartProcess(...)` or `CheckProcess(startInfo)`; `CheckCommand(line)` for a line a shell interprets | An executable from input, injection in the script of `sh -c`, `cmd /c` or `powershell -Command`, shells and downloaders started during a request (`Allow.Commands` exempts them), and `curl … \| sh` at any time. |
| Files | `RaspFile` and `RaspDirectory` (the `File` / `Directory` methods, checked first), or `Shield360Rasp.CheckPath(path, op)` | Path traversal, absolute paths and NUL bytes from input, paths outside `Allow.FileRoots`, secret files, script writes during a request, NTFS streams. |
| XML | `RaspXml.CreateReader(xml, settings)`, `RaspXml.LoadXml(document, xml)`, or `Shield360Rasp.CheckXml(xml, settings)` | XXE. With `DtdProcessing.Parse` and an `XmlResolver`, an external entity is `xxe.external_entity`; without a resolver it is `xxe.doctype`. |
| Deserializers | `Shield360Rasp.CheckDeserialization(RaspDeserializer.BinaryFormatter, data)` (also `SoapFormatter`, `LosFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`); `Shield360Rasp.CheckJson(json, settings)` for Newtonsoft.Json | Tainted data for the formatters; `"$type"` in tainted JSON when `TypeNameHandling` is not `None`. |
| Code | `Shield360Rasp.CheckCode(code)` before a scripting engine runs it | Tainted input spanning code tokens. |
| Template source | `Shield360Rasp.CheckTemplate("scriban", source)` before Scriban `Template.Parse`; `"liquid"` before Fluid `FluidParser.Parse`; `"handlebars"` before Handlebars.Net `Handlebars.Compile` | Input that adds a template delimiter or spans two or more expression tokens (`code.template_injection`). Only the source is checked, never the model you render with. These engines raise no diagnostic events, and Razor is not compiled from strings at run time, so there is no automatic hook. |
| Assembly loading | `Shield360Rasp.CheckAssemblyLoad(nameOrPath)` before `Assembly.Load`, `LoadFrom`, `LoadFile` or `AssemblyLoadContext.LoadFromAssemblyPath` | A name equal to an input, or holding an input that is a path (`code.include`). The only way `code.include` is checked in .NET. |
| Uploads | Automatic in the ASP.NET Core middleware | Each uploaded file name (at most 32, from the first 1 MiB of the body) becomes input `body.<field>.filename`; a script name is `file_write.upload` (sink `request.upload`), and a later write named after it is `file_write.script`. Read from `Request.Form.Files` when the form was already read, otherwise from the multipart part headers of the body the middleware buffers; the endpoint still reads the whole form. |
| HTML responses | Automatic in the ASP.NET Core middleware | Reflected input (`xss.reflected`), monitor only: the response is never changed. HTML bodies up to 1 MiB that are not compressed, against every input known when the response ends (route values and model output the endpoint recorded included). Other responses are written straight to the server. |

```csharp
builder.Services.AddShield360RaspHttpClients(); // every IHttpClientFactory client: the connection check too
builder.Services.AddDbContext<OrdersDb>(o => o.UseSqlServer(connectionString).AddShield360Rasp());

using var p = Shield360Rasp.StartProcess("convert", input, "out.png"); // no shell; checked first
var text = RaspFile.ReadAllText(Path.Combine(uploads, name));          // checked first
```

A block raised while `HttpClient` connects reaches you as an `HttpRequestException` whose inner exception is `Shield360RaspBlockedException`; the ASP.NET Core middleware finds it there and still returns the 403. A request blocked at the diagnostic event has its client activity stopped as an error, tagged `shield360.rasp.rule`. Set `RaspOptions.Hooks = false` to leave out the two automatic diagnostic hooks. .NET does not apply the signed config's sink rules.

### Security baseline

Once per process, on the thread pool after RASP starts, the SDK looks at how the process is set up and reports each risky setting as a `baseline` event (sink `startup`). Baseline events never block, even in block mode, and name only the rule, never a setting's value. The rules: `baseline.tls_verify_off` (a `ServicePointManager.ServerCertificateValidationCallback` that accepts every certificate), `baseline.inspector_in_production` (a debugger attached in production), `baseline.development_mode_in_production` (the host environment is Development while `Shield360Options.Environment` or `ENVIRONMENT` says production; the host's own `IHostEnvironment` when `AddShield360` or `AddShield360Rasp` runs on a host builder, otherwise `DOTNET_ENVIRONMENT` or `ASPNETCORE_ENVIRONMENT`, and not judged when both are set and differ), `baseline.running_as_root` (root, or an elevated Windows administrator on .NET 8+), `baseline.config_key_unpinned` (in production, a signed config is expected but no `ConfigPublicKey` is set) and `baseline.runtime_end_of_life` (.NET 5 to 7 and every .NET Core line; .NET 8 and 9 after 2026-11-10). Multipart part headers are read without the form reader's header limits, so a part the app's raised `FormOptions` accept is still checked. Certificate callbacks on a single `HttpClientHandler`, a developer exception page and Swagger UI are not checked. Turn it off with `Attacks = { [RaspAttackType.Baseline] = RaspMode.Off }`.

## Security and data handling

- Message content is off by default. Turning it on records prompts, responses, system instructions and tool call arguments and results.
- The SDK does not log API keys or headers. Error messages name the setting, never its value.
- The API key is sent only over HTTPS, or HTTP to localhost.
- RASP keeps request input and model output in memory for the request only. Events carry locations, never values; a masked snippet of at most 64 characters is sent only when the signed config allows it. With the signed config's `reportTargets: true`, `shell_spawn.shell`, `outbound.not_allowed` and `path.outside_root` events also carry the masked destination the rule compared (`shield360.rasp.target`: the executable, host or directory, never arguments, paths or file names); SQL findings carry `shield360.rasp.sql.dialect`.

## Development

From the SDK directory (the repository root of the public mirror):

```bash
dotnet build -warnaserror
dotnet test
dotnet pack src/Shield360/Shield360.csproj -c Release -o artifacts
dotnet pack src/Shield360.AspNetCore/Shield360.AspNetCore.csproj -c Release -o artifacts
dotnet pack src/Shield360.EntityFrameworkCore/Shield360.EntityFrameworkCore.csproj -c Release -o artifacts
```

## License

Apache-2.0. See [LICENSE](LICENSE).
