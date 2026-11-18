using System;
using System.Collections.Generic;
using Shield360.Internal;
using Xunit;

namespace Shield360.Tests;

public class OptionsTests
{
    [Fact]
    public void Defaults_match_the_other_SDKs()
    {
        var r = ResolvedOptions.Resolve(null, Env.Empty);

        Assert.Equal("http://127.0.0.1:4318", r.OtlpEndpoint);
        Assert.Equal("default", r.ApplicationName);
        Assert.Equal("default", r.Environment);
        Assert.False(r.CaptureMessageContent);
        Assert.False(r.DisableMetrics);
        Assert.False(r.DisableBatch);
        Assert.False(r.DisableTracing);
        Assert.Null(r.PricingJson);
        Assert.Empty(r.OtlpHeaders);
        Assert.Equal(TimeSpan.FromSeconds(10), r.ExportTimeout);
        Assert.Equal(TimeSpan.FromSeconds(30), r.MetricExportInterval);
    }

    [Fact]
    public void Environment_variables_fill_unset_options()
    {
        var env = Env.Of(
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel.example.com"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "x-team=ml, Authorization=Bearer abc=="),
            ("OTEL_SERVICE_NAME", "orders"),
            ("OTEL_DEPLOYMENT_ENVIRONMENT", "staging"),
            ("OTEL_SERVICE_VERSION", "2.0.0"),
            ("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "true"),
            ("SHIELD360_PRICING_JSON", "/etc/pricing.json"),
            ("SHIELD360_DISABLE_METRICS", "1"),
            ("SHIELD360_DISABLE_BATCH", "yes"),
            ("SHIELD360_DISABLED_INSTRUMENTORS", "openai, semantic-kernel"),
            ("SHIELD360_CUSTOM_SPAN_ATTRIBUTES", """{"team":"ml","tier":2}"""),
            ("OTEL_EXPORTER_OTLP_METRICS_EXPORT_INTERVAL", "5000"));

        var r = ResolvedOptions.Resolve(null, env);

        Assert.Equal("https://otel.example.com", r.OtlpEndpoint);
        Assert.Equal("ml", r.OtlpHeaders["x-team"]);
        Assert.Equal("Bearer abc==", r.OtlpHeaders["Authorization"]);
        Assert.Equal("orders", r.ApplicationName);
        Assert.Equal("staging", r.Environment);
        Assert.Equal("2.0.0", r.ServiceVersion);
        Assert.True(r.CaptureMessageContent);
        Assert.Equal("/etc/pricing.json", r.PricingJson);
        Assert.True(r.DisableMetrics);
        Assert.True(r.DisableBatch);
        Assert.False(r.IsInstrumentationEnabled("openai"));
        Assert.False(r.IsInstrumentationEnabled("Semantic-Kernel"));
        Assert.True(r.IsInstrumentationEnabled("azure-ai-inference"));
        Assert.Equal("ml", r.CustomSpanAttributes["team"]);
        Assert.Equal("2", r.CustomSpanAttributes["tier"]);
        Assert.Equal(TimeSpan.FromSeconds(5), r.MetricExportInterval);
    }

    [Fact]
    public void Options_win_over_environment_variables()
    {
        var env = Env.Of(
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://env.example.com"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "x-env=1"),
            ("OTEL_SERVICE_NAME", "env-app"),
            ("OTEL_DEPLOYMENT_ENVIRONMENT", "env"),
            ("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "true"),
            ("SHIELD360_DISABLE_METRICS", "true"));

        var r = ResolvedOptions.Resolve(new Shield360Options
        {
            OtlpEndpoint = "http://localhost:4318",
            OtlpHeaders = new Dictionary<string, string> { ["x-opt"] = "2" },
            ApplicationName = "opt-app",
            Environment = "prod",
            CaptureMessageContent = false,
            DisableMetrics = false,
        }, env);

        Assert.Equal("http://localhost:4318", r.OtlpEndpoint);
        Assert.Equal("2", r.OtlpHeaders["x-opt"]);
        Assert.False(r.OtlpHeaders.ContainsKey("x-env"));
        Assert.Equal("opt-app", r.ApplicationName);
        Assert.Equal("prod", r.Environment);
        Assert.False(r.CaptureMessageContent);
        Assert.False(r.DisableMetrics);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("false", false)]
    [InlineData("nonsense", false)]
    [InlineData("TRUE", true)]
    public void Content_capture_is_off_unless_asked_for(string? env, bool expected)
    {
        var r = ResolvedOptions.Resolve(null, env is null ? Env.Empty : Env.Of(("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", env)));
        Assert.Equal(expected, r.CaptureMessageContent);
    }

    [Fact]
    public void Shield360_url_and_key_resolve_to_the_ingest_route()
    {
        var r = ResolvedOptions.Resolve(null, Env.Of(
            ("SHIELD360_URL", "https://app.shield360.ai/"),
            ("SHIELD360_API_KEY", "s360_secret=")));

        Assert.Equal("https://app.shield360.ai/api/ingest/otlp", r.OtlpEndpoint);
        Assert.Equal("Bearer s360_secret=", r.OtlpHeaders["Authorization"]);
    }

    [Fact]
    public void An_explicit_endpoint_and_authorization_header_win_over_the_ingest_route()
    {
        var r = ResolvedOptions.Resolve(new Shield360Options
        {
            ApiKey = "s360_secret",
            Shield360Url = "https://app.shield360.ai",
            OtlpHeaders = new Dictionary<string, string> { ["authorization"] = "Bearer mine" },
        }, Env.Empty);

        Assert.Equal("https://app.shield360.ai/api/ingest/otlp", r.OtlpEndpoint);
        Assert.Equal("Bearer mine", r.OtlpHeaders["Authorization"]);

        var explicitEndpoint = ResolvedOptions.Resolve(new Shield360Options
        {
            ApiKey = "s360_secret",
            Shield360Url = "https://app.shield360.ai",
            OtlpEndpoint = "http://collector:4318",
        }, Env.Empty);
        Assert.Equal("http://collector:4318", explicitEndpoint.OtlpEndpoint);
        Assert.False(explicitEndpoint.OtlpHeaders.ContainsKey("Authorization"));
    }

    [Fact]
    public void The_api_key_is_never_sent_over_plain_http_to_another_host()
    {
        var e = Assert.Throws<Shield360Exception>(() => ResolvedOptions.Resolve(new Shield360Options
        {
            ApiKey = "s360_do_not_leak",
            Shield360Url = "http://app.shield360.ai",
        }, Env.Empty));

        Assert.DoesNotContain("s360_do_not_leak", e.ToString(), StringComparison.Ordinal);

        var local = ResolvedOptions.Resolve(new Shield360Options
        {
            ApiKey = "k",
            Shield360Url = "http://localhost:3000",
        }, Env.Empty);
        Assert.Equal("http://localhost:3000/api/ingest/otlp", local.OtlpEndpoint);
    }

    [Theory]
    [InlineData("a=b", "a", "b")]
    [InlineData("Authorization=Bearer key==", "Authorization", "Bearer key==")]
    [InlineData(" x = y , =skipped, novalue=", "x", "y")]
    public void OTLP_headers_split_on_the_first_equals_sign(string raw, string name, string value)
    {
        var headers = ResolvedOptions.ParseOtlpHeaders(raw);
        Assert.Single(headers);
        Assert.Equal(value, headers[name]);
    }

    [Theory]
    [InlineData("http://127.0.0.1:4318", "traces", "http://127.0.0.1:4318/v1/traces")]
    [InlineData("http://127.0.0.1:4318/", "metrics", "http://127.0.0.1:4318/v1/metrics")]
    [InlineData("https://app.example.com/api/ingest/otlp", "traces", "https://app.example.com/api/ingest/otlp/v1/traces")]
    [InlineData("https://app.example.com/otlp/v1/traces", "metrics", "https://app.example.com/otlp/v1/metrics")]
    public void Signal_endpoints_keep_the_base_path(string endpoint, string signal, string expected)
    {
        Assert.Equal(new Uri(expected), EndpointGuard.SignalEndpoint(endpoint, signal));
    }

    [Theory]
    [InlineData("http://localhost:3000", true)]
    [InlineData("http://127.0.0.1:3000", true)]
    [InlineData("http://[::1]:3000", true)]
    [InlineData("https://app.shield360.ai", true)]
    [InlineData("http://app.shield360.ai", false)]
    [InlineData("ftp://localhost", false)]
    [InlineData("not a url", false)]
    public void Only_https_or_localhost_urls_are_allowed(string url, bool allowed)
    {
        if (allowed)
        {
            EndpointGuard.RequireSecure(url, "Url");
        }
        else
        {
            Assert.Throws<Shield360Exception>(() => EndpointGuard.RequireSecure(url, "Url"));
        }
    }
}
