using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Shield360.Internal;

/// <summary>One record for <c>/api/guard/events</c>: <c>{ name, time, attrs }</c>.</summary>
internal sealed record GuardEvent(string Name, string Time, IReadOnlyDictionary<string, string> Attrs);

/// <summary>
/// Posts batches to <c>POST /api/guard/events</c>: the transport guard reports and
/// runtime protection (RASP) events share, as in the TypeScript SDK's
/// <c>postGuardEvents</c>. Retries a few times, gives up on a refusal, never
/// throws, and never writes the API key anywhere but the Authorization header.
/// </summary>
internal static class GuardEventsTransport
{
    public const string EventsPath = "/api/guard/events";
    public const int DefaultAttempts = 3;
    private static readonly int[] s_refusals = { 400, 401, 403, 413 };

    /// <summary>The events route under a Shield360 URL.</summary>
    public static string Endpoint(string shield360Url) => shield360Url.TrimEnd('/') + EventsPath;

    /// <summary>The JSON body: <c>{ "resource": {…}, "events": [{ "name", "time", "attrs" }] }</c>.</summary>
    public static string Payload(IReadOnlyDictionary<string, string> resource, IEnumerable<GuardEvent> events)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteStartObject("resource");
            foreach (var kv in resource)
            {
                w.WriteString(kv.Key, kv.Value);
            }

            w.WriteEndObject();
            w.WriteStartArray("events");
            foreach (var e in events)
            {
                w.WriteStartObject();
                w.WriteString("name", e.Name);
                w.WriteString("time", e.Time);
                w.WriteStartObject("attrs");
                foreach (var kv in e.Attrs)
                {
                    w.WriteString(kv.Key, kv.Value);
                }

                w.WriteEndObject();
                w.WriteEndObject();
            }

            w.WriteEndArray();
            w.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    /// <summary>
    /// Posts one batch. Returns whether it was accepted. <paramref name="label"/> names
    /// what the batch is in the warning when it cannot be delivered. The delay before
    /// retry n is <paramref name="retryDelay"/> × n.
    /// </summary>
    public static async Task<bool> PostAsync(
        HttpClient http,
        string endpoint,
        string apiKey,
        string payload,
        int eventCount,
        string label = "guard report",
        int attempts = DefaultAttempts,
        TimeSpan? retryDelay = null,
        CancellationToken cancellationToken = default)
    {
        var delay = retryDelay ?? TimeSpan.FromMilliseconds(500);
        for (var attempt = 0; attempt < attempts; attempt++)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
                {
                    Content = new StringContent(payload, Encoding.UTF8, "application/json"),
                };
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));
                using var response = await http.SendAsync(request, timeout.Token).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }

                if (Array.IndexOf(s_refusals, (int)response.StatusCode) >= 0)
                {
                    Trace.TraceWarning("Shield360 rejected {0}s: HTTP {1}", label, (int)response.StatusCode);
                    return false;
                }
            }
            catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException or InvalidOperationException)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return false;
                }

                // retried below
            }

            if (attempt + 1 < attempts)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(delay.TotalMilliseconds * (attempt + 1)), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return false;
                }
            }
        }

        Trace.TraceWarning("Could not deliver {0} {1}(s) to Shield360", eventCount, label);
        return false;
    }
}
