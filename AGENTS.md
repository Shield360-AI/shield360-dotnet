# .NET SDK instructions

These instructions supplement the repository-root `AGENTS.md`.

- Read `../../agent-guides/js-sdk-genai-instrumentation.md` before changing
  span attributes, metrics or content capture: the attribute names and
  behavior must match the Python, TypeScript and Go SDKs. Put new attribute
  names in `SemanticConventions`.
- Keep the package free of AI provider dependencies. Library telemetry is
  collected by ActivitySource and Meter name (`Shield360Instrumentations`);
  provider packages belong in the test project only. When you change a pinned
  library version in the tests, re-check the source names and switches there.
- Content capture stays off by default. Anything that can carry prompt,
  response or tool data must be gated on it.
- Never log or put API keys, headers or tokens into exception messages.
- `src/Shield360/pricing.json` is a copy of `assets/pricing.json`; update both
  together (CI / Pricing Data checks they match).
- RASP (`src/Shield360/Rasp`) follows `../rasp/README.md`, the contract all SDKs
  share; port behavior from the TypeScript reference (`sdk/typescript/src/rasp`)
  with the same rule ids. `src/Shield360/Rasp/Data/default-rules.json` and
  `dnslog-domains.json` are byte-identical copies of `sdk/rasp/rules/` and
  `sdk/rasp/testdata/`; update them together (a test checks). The ASP.NET Core
  middleware lives in `src/Shield360.AspNetCore` so the core package never pulls
  in the ASP.NET Core shared framework, and the EF Core interceptor in
  `src/Shield360.EntityFrameworkCore` for the same reason. Sink hooks
  (`src/Shield360/Rasp/Hooks`) never reference a driver: they use
  `DiagnosticListener` events read by name, explicit helpers, or a separate
  package. Every hook goes through `RaspHooks` and is listed in
  `tests/Rasp/RaspHookSpecs.cs`, so the contract kit (`RaspHookKit.cs`) runs it.
- Validate from `sdk/dotnet` with `dotnet build -warnaserror` and `dotnet test`.
  Check packaging with `dotnet pack src/Shield360/Shield360.csproj -c Release -o artifacts`
  (and the same for `src/Shield360.AspNetCore/Shield360.AspNetCore.csproj` and
  `src/Shield360.EntityFrameworkCore/Shield360.EntityFrameworkCore.csproj`).
- Do not publish the package from a branch. `Release / Packages` (tool
  `.NET SDK`) bumps `<Version>` in `src/Shield360/Shield360.csproj`, the only
  place the version is set, and publishes through the `shield360-dotnet` mirror;
  see `.github/RELEASING.md`.
