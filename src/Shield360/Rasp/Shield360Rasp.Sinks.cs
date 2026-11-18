using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Xml;

namespace Shield360.Rasp;

// Sink checks for call sites RASP cannot see on its own. Each one runs the contract's
// detector against the untrusted input in scope and, in block mode, throws
// Shield360RaspBlockedException before the caller makes the call. In monitor mode it
// reports and returns; with RASP off it returns at once; any other failure lets the
// call through. `sink` names the call in events.
public static partial class Shield360Rasp
{
    /// <summary>
    /// Checks SQL text for injection before it is sent (<c>sqli.userinput</c>,
    /// <c>sqli.stacked</c>, <c>sqli.model_output</c>). SqlClient commands and EF Core
    /// (with <c>AddShield360Rasp()</c> from Shield360.EntityFrameworkCore) are checked
    /// without this call. Oracle (Oracle.ManagedDataAccess) and IBM Db2 (IBM.Data.Db2) raise
    /// no diagnostic events: with plain ADO.NET, call this before executing, with
    /// <see cref="RaspSqlDialect.Oracle"/> or <see cref="RaspSqlDialect.Db2"/>.
    /// </summary>
    /// <example>
    /// <code>
    /// Shield360Rasp.CheckSql(command.CommandText, RaspSqlDialect.Oracle, "oracle.ExecuteReader");
    /// using var reader = command.ExecuteReader();
    /// </code>
    /// </example>
    public static void CheckSql(string? sql, RaspSqlDialect dialect = RaspSqlDialect.Generic, string sink = "sql.query") =>
        RaspSql.Check(sink, sql, dialect);

    /// <summary>
    /// Checks MongoDB documents (a filter, an update, or a pipeline as an array of stages)
    /// before they reach the driver: an operator object (<c>$ne</c>, <c>$where</c>, …) that
    /// came from the request body or query (<c>nosqli.operator</c>), or tainted code in
    /// <c>$where</c> / <c>$function</c> (<c>nosqli.where</c>). A document may be a
    /// <c>BsonDocument</c>, a JSON string, a <c>JsonNode</c> or a dictionary.
    /// </summary>
    public static void CheckMongo(params object?[] documents) => RaspSql.CheckMongo("mongodb.command", documents ?? Array.Empty<object?>());

    /// <summary><see cref="CheckMongo(object[])"/> with the sink named in events (<c>mongodb.find</c>).</summary>
    public static void CheckMongo(string sink, IEnumerable<object?> documents)
    {
        if (documents is null)
        {
            return;
        }

        RaspSql.CheckMongo(sink, documents);
    }

    /// <summary>
    /// Checks a command line a shell will interpret (<c>cmdi.*</c>; <c>shell_spawn</c> for a
    /// shell or downloader started during a request, or a download piped to a shell).
    /// </summary>
    public static void CheckCommand(string? commandLine, string sink = "shell.command") =>
        RaspProcess.CheckCommandLine(commandLine ?? string.Empty, sink);

    /// <summary>
    /// Checks a process before it starts: an executable taken from input
    /// (<c>cmdi.executable</c>), the script of <c>sh -c</c>, <c>cmd /c</c> or
    /// <c>powershell -Command</c> for injection, and a shell or downloader started during a
    /// request (<c>shell_spawn</c>) unless <c>Allow.Commands</c> lists it.
    /// </summary>
    public static void CheckProcess(ProcessStartInfo startInfo)
    {
        if (startInfo is null)
        {
            throw new ArgumentNullException(nameof(startInfo));
        }

        RaspProcess.Check(startInfo, RaspProcess.Sink);
    }

    /// <summary><see cref="Process.Start(ProcessStartInfo)"/> after <see cref="CheckProcess"/>.</summary>
    public static Process? StartProcess(ProcessStartInfo startInfo)
    {
        CheckProcess(startInfo);
        return Process.Start(startInfo);
    }

    /// <summary>
    /// Starts <paramref name="fileName"/> with <paramref name="arguments"/> as separate
    /// arguments (no shell), after <see cref="CheckProcess"/>.
    /// </summary>
    public static Process? StartProcess(string fileName, params string[] arguments)
    {
        if (fileName is null)
        {
            throw new ArgumentNullException(nameof(fileName));
        }

        var info = new ProcessStartInfo(fileName) { UseShellExecute = false };
#if NET
        foreach (var a in arguments ?? Array.Empty<string>())
        {
            info.ArgumentList.Add(a);
        }
#else
        info.Arguments = string.Join(" ", Array.ConvertAll(arguments ?? Array.Empty<string>(), Quote));
#endif
        return StartProcess(info);
    }

#if !NET
    private static readonly char[] s_quoteChars = { ' ', '\t', '"' };

    private static string Quote(string a) =>
        a.Length > 0 && a.IndexOfAny(s_quoteChars) < 0 ? a : "\"" + a.Replace("\"", "\\\"") + "\"";
#endif

    /// <summary>
    /// Checks a file path before it is used (<c>path.*</c>, <c>file_write.*</c>). The
    /// <see cref="RaspFile"/> and <see cref="RaspDirectory"/> methods call it for you.
    /// </summary>
    public static void CheckPath(string? path, RaspFileOperation operation = RaspFileOperation.Read, string sink = "file") =>
        RaspFile.Check(path, RaspFile.Map(operation), sink);

    /// <summary>
    /// Checks a URL before a request you send yourself (<c>ssrf.*</c>, and
    /// <c>outbound.not_allowed</c> when <c>Allow.OutboundHosts</c> is set). <c>HttpClient</c>
    /// requests are checked without this call.
    /// </summary>
    public static void CheckUrl(Uri? url, string sink = "http.request")
    {
        if (url is null || !url.IsAbsoluteUri)
        {
            return;
        }

        var text = url.OriginalString;
        var always = RaspEngine.AlwaysAllowedHosts;
        RaspHooks.Run(
            sink,
            (_, inputs) => RaspEngine.Strongest(RaspDetect.Outbound(text, RaspEngine.AllowLists().OutboundHosts, always), RaspDetect.Ssrf(text, inputs)),
            requireInputs: false);
    }

    /// <summary>
    /// Checks code before a scripting engine evaluates it (Roslyn scripting, a dynamic LINQ or
    /// expression library, a JavaScript engine): tainted input spanning two or more tokens,
    /// or the whole code equal to an input (<c>code.eval</c>).
    /// </summary>
    public static void CheckCode(string? code, string sink = "code.eval") => RaspCodeSinks.CheckCode(code, sink);

    /// <summary>
    /// Checks a template's source before a template engine parses or compiles it: request
    /// input that adds a template delimiter or spans two or more expression tokens
    /// (<c>code.template_injection</c>). Pass the engine's name from the shared table:
    /// <c>"scriban"</c> for Scriban <c>Template.Parse</c>, <c>"liquid"</c> for Fluid
    /// <c>FluidParser.Parse</c>/<c>TryParse</c>, <c>"handlebars"</c> for Handlebars.Net
    /// <c>Handlebars.Compile</c>. Only the source is checked, never the model or data you render
    /// with; an engine not in the table is not checked. These engines raise no diagnostic
    /// events, so .NET cannot see the call on its own. <paramref name="sink"/> defaults to
    /// <c>handlebars.Compile</c> or <c>&lt;engine&gt;.Parse</c>.
    /// </summary>
    /// <example>
    /// <code>
    /// Shield360Rasp.CheckTemplate("scriban", source);
    /// var template = Template.Parse(source);
    /// </code>
    /// </example>
    public static void CheckTemplate(string engine, string? source, string? sink = null) =>
        RaspCodeSinks.CheckTemplate(engine, source, sink);

    /// <summary>
    /// Checks an assembly name or path before <c>Assembly.Load</c>, <c>Assembly.LoadFrom</c>,
    /// <c>Assembly.LoadFile</c> or <c>AssemblyLoadContext.LoadFromAssemblyPath</c> loads it:
    /// the name equal to an input, or holding an input that is an absolute path or holds
    /// <c>/</c>, <c>\</c>, <c>..</c> or a NUL (<c>code.include</c>). A fixed name, or the app's
    /// own path with no input in it, is never flagged. .NET cannot see these calls on its own.
    /// </summary>
    public static void CheckAssemblyLoad(string? nameOrPath, string sink = "assembly.load")
    {
        if (string.IsNullOrEmpty(nameOrPath))
        {
            return;
        }

        RaspHooks.Run(sink, (_, inputs) => RaspDetect.Include(nameOrPath, inputs));
    }

    /// <summary>Checks data before <paramref name="deserializer"/> reads it (<c>deser.binaryformatter</c>, <c>deser.typename</c>).</summary>
    public static void CheckDeserialization(RaspDeserializer deserializer, byte[]? data, string? sink = null) =>
        RaspCodeSinks.CheckDeserialization(deserializer, data, sink);

    /// <summary>Checks text before <paramref name="deserializer"/> reads it (ViewState for <c>LosFormatter</c>, JSON for type names).</summary>
    public static void CheckDeserialization(RaspDeserializer deserializer, string? data, string? sink = null) =>
        RaspCodeSinks.CheckDeserialization(deserializer, data, sink);

    /// <summary>
    /// Checks a stream before <paramref name="deserializer"/> reads it. A seekable stream is
    /// read (at most 1 MiB) and put back where it was; a stream that cannot seek is not checked.
    /// </summary>
    public static void CheckDeserialization(RaspDeserializer deserializer, Stream? data, string? sink = null) =>
        RaspCodeSinks.CheckDeserialization(deserializer, data, sink);

    /// <summary>
    /// Checks JSON before Newtonsoft.Json reads it with <paramref name="serializerSettings"/>
    /// (a <c>JsonSerializerSettings</c>, read by name): only when <c>TypeNameHandling</c> is
    /// not <c>None</c>, a tainted text with <c>"$type"</c> is <c>deser.typename</c>.
    /// </summary>
    public static void CheckJson(string? json, object? serializerSettings, string sink = "JsonConvert.DeserializeObject")
    {
        if (RaspCodeSinks.HonorsTypeNames(serializerSettings))
        {
            RaspCodeSinks.CheckDeserialization(RaspDeserializer.JsonTypeNames, json, sink);
        }
    }

    /// <summary>
    /// Checks XML before a parser reads it (<c>xxe.*</c>). With <paramref name="settings"/>
    /// that parse DTDs and have an <c>XmlResolver</c>, external entities are
    /// <c>xxe.external_entity</c>; otherwise <c>xxe.doctype</c>. <see cref="RaspXml"/> parses
    /// after the check.
    /// </summary>
    public static void CheckXml(string? xml, XmlReaderSettings? settings = null, string sink = "xml.parse") =>
        RaspCodeSinks.CheckXml(xml, RaspCodeSinks.ResolvesExternal(settings), sink);
}
