using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Shield360.Internal;

/// <summary>The SDK's own ActivitySource, Meter and GenAI histograms.</summary>
internal static class Shield360Telemetry
{
    private static readonly double[] DurationBuckets =
        { 0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92 };

    private static readonly long[] TokenBuckets =
        { 1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864 };

    private static readonly double[] TimeToFirstTokenBuckets =
        { 0.001, 0.005, 0.01, 0.02, 0.04, 0.06, 0.08, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0 };

    private static readonly double[] TimePerOutputTokenBuckets =
        { 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5, 0.75, 1.0, 2.5 };

    public static readonly ActivitySource Source = new(Shield360Sdk.ActivitySourceName, Shield360Sdk.Version);

    public static readonly Meter Meter = new(Shield360Sdk.MeterName, Shield360Sdk.Version);

    public static readonly Histogram<long> TokenUsage = Meter.CreateHistogram(
        SemanticConventions.GenAIClientTokenUsage, "{token}", "Number of input and output tokens used.",
        tags: null, advice: new InstrumentAdvice<long> { HistogramBucketBoundaries = TokenBuckets });

    public static readonly Histogram<double> OperationDuration = Meter.CreateHistogram(
        SemanticConventions.GenAIClientOperationDuration, "s", "GenAI operation duration.",
        tags: null, advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = DurationBuckets });

    public static readonly Histogram<double> Cost = Meter.CreateHistogram<double>(
        SemanticConventions.GenAIUsageCost, "USD", "Estimated cost of the GenAI operation.");

    public static readonly Histogram<double> TimeToFirstToken = Meter.CreateHistogram(
        SemanticConventions.GenAIServerTimeToFirstToken, "s", "Time to generate the first token for streaming responses.",
        tags: null, advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = TimeToFirstTokenBuckets });

    public static readonly Histogram<double> TimePerOutputToken = Meter.CreateHistogram(
        SemanticConventions.GenAIServerTimePerOutputToken, "s", "Time per output token after the first, for streaming responses.",
        tags: null, advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = TimePerOutputTokenBuckets });

    public static readonly Histogram<double> TimeToFirstChunk = Meter.CreateHistogram(
        SemanticConventions.GenAIClientOperationTimeToFirstChunk, "s", "Client time to the first streamed chunk.",
        tags: null, advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = DurationBuckets });

    public static readonly Histogram<double> TimePerOutputChunk = Meter.CreateHistogram(
        SemanticConventions.GenAIClientOperationTimePerOutputChunk, "s", "Client time between streamed chunks.",
        tags: null, advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = DurationBuckets });

    public static readonly Histogram<double> ServerRequestDuration = Meter.CreateHistogram(
        SemanticConventions.GenAIServerRequestDuration, "s", "Time to the last byte of a streaming response.",
        tags: null, advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = DurationBuckets });
}
