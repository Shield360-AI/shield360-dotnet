using System.Text.Json;

namespace Shield360.Tests;

/// <summary>
/// Parses JSON into a standalone <see cref="JsonElement"/>. A JsonDocument rents
/// pooled buffers until it is disposed, so the document is disposed here and the
/// root is cloned out of it (CA2026). JsonElement.Parse does the same, but only
/// from System.Text.Json 10, and these tests target net9.0.
/// </summary>
internal static class TestJson
{
    public static JsonElement Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }
}
