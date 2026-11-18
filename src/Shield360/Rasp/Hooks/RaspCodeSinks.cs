using System;
using System.IO;
using System.Reflection;
using System.Xml;

namespace Shield360.Rasp;

/// <summary>The .NET deserializers the RASP deserialization check knows (sdk/rasp/README.md, "Deserialization").</summary>
public enum RaspDeserializer
{
    /// <summary><c>BinaryFormatter</c>: untrusted input is always an attack (<c>deser.binaryformatter</c>).</summary>
    BinaryFormatter,

    /// <summary><c>SoapFormatter</c> (<c>deser.binaryformatter</c>).</summary>
    SoapFormatter,

    /// <summary><c>LosFormatter</c> (<c>deser.binaryformatter</c>).</summary>
    LosFormatter,

    /// <summary><c>NetDataContractSerializer</c> (<c>deser.binaryformatter</c>).</summary>
    NetDataContractSerializer,

    /// <summary><c>ObjectStateFormatter</c> (<c>deser.binaryformatter</c>).</summary>
    ObjectStateFormatter,

    /// <summary>
    /// JSON read with type names honored: Newtonsoft.Json with <c>TypeNameHandling</c> other
    /// than <c>None</c>, or <c>JavaScriptSerializer</c> with a type resolver. Fires when the
    /// text has <c>"$type"</c> or <c>"__type"</c> (<c>deser.typename</c>).
    /// </summary>
    JsonTypeNames,
}

/// <summary>The code, deserialization and XML sink checks.</summary>
internal static class RaspCodeSinks
{
    /// <summary>At most this much of a seekable stream is read for the deserialization check.</summary>
    public const int MaxStreamBytes = 1024 * 1024;

    private static readonly MethodInfo? s_settingsResolver =
        typeof(XmlReaderSettings).GetMethod("GetXmlResolver", BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);

    private static readonly MethodInfo? s_documentResolver =
        typeof(XmlDocument).GetMethod("GetResolver", BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);

    public static void CheckCode(string? code, string sink)
    {
        if (string.IsNullOrEmpty(code))
        {
            return;
        }

        RaspHooks.Run(sink, (_, inputs) => RaspDetect.Code(code, inputs));
    }

    /// <summary>The sink an engine's source call is named by in events when the caller names none.</summary>
    public static string TemplateSinkOf(string engine) => engine == "handlebars" ? "handlebars.Compile" : engine + ".Parse";

    /// <summary>
    /// One <c>code.template_injection</c> check of a template's source. Off for
    /// <c>code_injection</c>, an unknown engine or an empty source: no check at all.
    /// </summary>
    public static void CheckTemplate(string? engine, string? source, string? sink)
    {
        if (string.IsNullOrEmpty(source) || !RaspTemplate.Knows(engine) || !RaspEngine.IsActive)
        {
            return;
        }

        try
        {
            if (RaspEngine.ModeFor(RaspAttackType.CodeInjection) == RaspMode.Off)
            {
                return;
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return;
        }

        RaspHooks.Run(sink ?? TemplateSinkOf(engine!), (_, inputs) => RaspTemplate.Detect(source, inputs, engine));
    }

    public static DeserFormat FormatOf(RaspDeserializer deserializer) =>
        deserializer == RaspDeserializer.JsonTypeNames ? DeserFormat.TypeName : DeserFormat.BinaryFormatter;

    public static string SinkOf(RaspDeserializer deserializer) => deserializer switch
    {
        RaspDeserializer.SoapFormatter => "SoapFormatter.Deserialize",
        RaspDeserializer.LosFormatter => "LosFormatter.Deserialize",
        RaspDeserializer.NetDataContractSerializer => "NetDataContractSerializer.Deserialize",
        RaspDeserializer.ObjectStateFormatter => "ObjectStateFormatter.Deserialize",
        RaspDeserializer.JsonTypeNames => "JsonConvert.DeserializeObject",
        _ => "BinaryFormatter.Deserialize",
    };

    public static void CheckDeserialization(RaspDeserializer deserializer, string? data, string? sink)
    {
        if (string.IsNullOrEmpty(data))
        {
            return;
        }

        var format = FormatOf(deserializer);
        RaspHooks.Run(sink ?? SinkOf(deserializer), (_, inputs) => RaspDetect.Deserialization(format, data, inputs));
    }

    /// <summary>Bytes are compared as latin-1 (base64-encoded inputs are decoded by the detector).</summary>
    public static void CheckDeserialization(RaspDeserializer deserializer, byte[]? data, string? sink)
    {
        if (data is null || data.Length == 0)
        {
            return;
        }

        var format = FormatOf(deserializer);
        RaspHooks.Run(sink ?? SinkOf(deserializer), (_, inputs) => RaspDetect.Deserialization(format, RaspDetect.Latin1(data), inputs));
    }

    /// <summary>A seekable stream is read (at most <see cref="MaxStreamBytes"/>) and put back where it was; others are not checked.</summary>
    public static void CheckDeserialization(RaspDeserializer deserializer, Stream? data, string? sink)
    {
        if (data is null || !data.CanSeek || !data.CanRead || !RaspEngine.IsActive || RaspHooks.CurrentInputs().Count == 0)
        {
            return;
        }

        byte[] bytes;
        try
        {
            var start = data.Position;
            var length = (int)Math.Min(MaxStreamBytes, Math.Max(0, data.Length - start));
            bytes = new byte[length];
            var total = 0;
            try
            {
                while (total < length)
                {
                    var n = data.Read(bytes, total, length - total);
                    if (n == 0)
                    {
                        break;
                    }

                    total += n;
                }
            }
            finally
            {
                data.Position = start;
            }

            if (total < length)
            {
                Array.Resize(ref bytes, total);
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return;
        }

        CheckDeserialization(deserializer, bytes, sink);
    }

    /// <summary>
    /// Whether Newtonsoft.Json settings honor type names: <c>TypeNameHandling</c> other than
    /// <c>None</c> (read by name, so Newtonsoft.Json is not referenced). Null settings, or
    /// an object without that property, count as honoring them.
    /// </summary>
    public static bool HonorsTypeNames(object? serializerSettings)
    {
        if (serializerSettings is null)
        {
            return true;
        }

        var value = RaspReflect.Property(serializerSettings, "TypeNameHandling");
        if (value is null)
        {
            return true;
        }

        try
        {
            return Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture) != 0;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return true;
        }
    }

    /// <summary>
    /// Whether a reader with these settings fetches external entities: DTD processing on and
    /// a resolver set. When the resolver cannot be read it counts as set.
    /// </summary>
    public static bool ResolvesExternal(XmlReaderSettings? settings)
    {
        if (settings is null || settings.DtdProcessing != DtdProcessing.Parse)
        {
            return false;
        }

        try
        {
            return s_settingsResolver is null || s_settingsResolver.Invoke(settings, null) is not null;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return true;
        }
    }

    /// <summary>Whether an <see cref="XmlDocument"/> fetches external entities (it parses DTDs; it fetches with a resolver).</summary>
    public static bool ResolvesExternal(XmlDocument document)
    {
        try
        {
            return s_documentResolver is null || s_documentResolver.Invoke(document, null) is not null;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return true;
        }
    }

    public static void CheckXml(string? xml, bool resolvesExternal, string sink)
    {
        if (string.IsNullOrEmpty(xml))
        {
            return;
        }

        RaspHooks.Run(sink, (_, inputs) => RaspDetect.Xml(xml, inputs, resolvesExternal));
    }
}

/// <summary>
/// XML parsing with the RASP XXE check first (sdk/rasp/README.md, "XXE"): tainted XML whose
/// DTD declares external entities, uses a dangerous protocol or file path, or expands
/// entities recursively. In block mode a finding throws
/// <see cref="Shield360RaspBlockedException"/> before the parser sees the text.
/// </summary>
public static class RaspXml
{
    /// <summary>
    /// <see cref="XmlReader.Create(TextReader, XmlReaderSettings)"/> over <paramref name="xml"/>,
    /// checked. With <c>DtdProcessing.Parse</c> and an <c>XmlResolver</c> set, a finding
    /// is <c>xxe.external_entity</c>; otherwise <c>xxe.doctype</c>.
    /// </summary>
    public static XmlReader CreateReader(string xml, XmlReaderSettings? settings = null)
    {
        if (xml is null)
        {
            throw new ArgumentNullException(nameof(xml));
        }

        RaspCodeSinks.CheckXml(xml, RaspCodeSinks.ResolvesExternal(settings), "XmlReader.Create");
        return XmlReader.Create(new StringReader(xml), settings);
    }

    /// <summary><see cref="XmlDocument.LoadXml(string)"/> on <paramref name="document"/>, checked.</summary>
    public static void LoadXml(XmlDocument document, string xml)
    {
        if (document is null)
        {
            throw new ArgumentNullException(nameof(document));
        }

        RaspCodeSinks.CheckXml(xml, RaspCodeSinks.ResolvesExternal(document), "XmlDocument.LoadXml");
        document.LoadXml(xml);
    }
}
