using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Shield360.Rasp;

/// <summary>The SQL dialect a query is lexed in (sdk/rasp/README.md, "SQL").</summary>
public enum RaspSqlDialect
{
    /// <summary>Any database: the lexer accepts every dialect's syntax.</summary>
    Generic,

    /// <summary>MySQL and MariaDB (backslash escapes, <c>#</c> comments).</summary>
    MySql,

    /// <summary>PostgreSQL (dollar-quoted strings).</summary>
    Postgres,

    /// <summary>SQLite.</summary>
    Sqlite,

    /// <summary>SQL Server (<c>[…]</c> identifiers).</summary>
    MsSql,

    /// <summary>Oracle Database (Oracle.ManagedDataAccess, Oracle.EntityFrameworkCore).</summary>
    Oracle,

    /// <summary>IBM Db2 (IBM.Data.Db2, IBM.EntityFrameworkCore).</summary>
    Db2,
}

/// <summary>
/// The SQL and NoSQL sink checks: SQL text before a driver sends it (the SqlClient
/// diagnostic events, the EF Core interceptor, <see cref="Shield360Rasp.CheckSql"/>),
/// and MongoDB filter, update and pipeline documents.
/// </summary>
internal static class RaspSql
{
    /// <summary>Commands a hook already checked, with the text it checked; the next hook on the same execution skips them.</summary>
    private static readonly ConditionalWeakTable<DbCommand, string> s_checked = new();

    public static SqlDialect Map(RaspSqlDialect dialect) => dialect switch
    {
        RaspSqlDialect.MySql => SqlDialect.MySql,
        RaspSqlDialect.Postgres => SqlDialect.Postgres,
        RaspSqlDialect.Sqlite => SqlDialect.Sqlite,
        RaspSqlDialect.MsSql => SqlDialect.MsSql,
        RaspSqlDialect.Oracle => SqlDialect.Oracle,
        RaspSqlDialect.Db2 => SqlDialect.Db2,
        _ => SqlDialect.Generic,
    };

    /// <summary>The dialect for an ADO.NET provider or EF Core provider name.</summary>
    public static RaspSqlDialect DialectOf(string? provider)
    {
        var p = provider ?? string.Empty;
        bool Has(string s) => p.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0;
        if (Has("SqlServer") || Has("SqlClient"))
        {
            return RaspSqlDialect.MsSql;
        }

        if (Has("Npgsql") || Has("Postgre"))
        {
            return RaspSqlDialect.Postgres;
        }

        if (Has("MySql") || Has("Maria"))
        {
            return RaspSqlDialect.MySql;
        }

        if (Has("Sqlite"))
        {
            return RaspSqlDialect.Sqlite;
        }

        // Oracle.ManagedDataAccess, Oracle.EntityFrameworkCore, Devart.Data.Oracle. Oracle's
        // own MySQL provider (MySql.EntityFrameworkCore) matched MySql above.
        if (Has("Oracle"))
        {
            return RaspSqlDialect.Oracle;
        }

        // IBM.Data.Db2, IBM.Data.DB2.Core, IBM.EntityFrameworkCore.
        return Has("Db2") || Has("IBM.EntityFrameworkCore") ? RaspSqlDialect.Db2 : RaspSqlDialect.Generic;
    }

    /// <summary>Checks SQL text. Throws only the block exception.</summary>
    public static void Check(string sink, string? sql, RaspSqlDialect dialect)
    {
        if (string.IsNullOrEmpty(sql))
        {
            return;
        }

        var d = Map(dialect);
        RaspHooks.Run(sink, (_, inputs) => RaspDetect.Sql(sql, inputs, d));
    }

    /// <summary>
    /// Checks a command's text (text commands only). With <paramref name="mark"/>, and only
    /// when the check let the command through, marks it checked for the next hook on this
    /// execution; the caller clears the mark when the execution ends (<see cref="ClearChecked"/>).
    /// </summary>
    public static void CheckCommand(string sink, DbCommand? command, RaspSqlDialect dialect, bool mark = true)
    {
        if (command is null || !RaspEngine.IsActive)
        {
            return;
        }

        string text;
        try
        {
            if (command.CommandType != CommandType.Text)
            {
                return;
            }

            text = command.CommandText ?? string.Empty;
            s_checked.Remove(command);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return;
        }

        // A block throws from here, so a refused command is never marked.
        Check(sink, text, dialect);
        if (mark)
        {
            try
            {
                s_checked.Add(command, text);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // unmarked: the next hook checks again
            }
        }
    }

    /// <summary>Drops a command's mark: the execution it was set for has ended.</summary>
    public static void ClearChecked(DbCommand? command)
    {
        if (command is null)
        {
            return;
        }

        try
        {
            s_checked.Remove(command);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // never
        }
    }

    /// <summary>
    /// True (once) when another hook already checked this command with its current
    /// text: the SqlClient event that follows an EF Core interceptor's check is skipped.
    /// </summary>
    public static bool TakeChecked(DbCommand command)
    {
        try
        {
            if (s_checked.TryGetValue(command, out var text))
            {
                s_checked.Remove(command);
                return string.Equals(text, command.CommandText, StringComparison.Ordinal);
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open: check again
        }

        return false;
    }

    /// <summary>A SqlClient <c>WriteCommandBefore</c> payload: checks its <c>Command</c> unless a hook did already.</summary>
    public static void OnSqlClientCommand(string eventName, object? payload)
    {
        if (!RaspEngine.IsActive || RaspReflect.Property(payload, "Command") is not DbCommand command || TakeChecked(command))
        {
            return;
        }

        var sink = eventName.StartsWith("System.", StringComparison.Ordinal) ? "System.Data.SqlClient.SqlCommand" : "Microsoft.Data.SqlClient.SqlCommand";
        CheckCommand(sink, command, RaspSqlDialect.MsSql, mark: false);
    }

    private static readonly ConditionalWeakTable<Type, FieldInfo?> s_parentField = new();

    /// <summary>
    /// After a block at SqlClient's <c>WriteCommandBefore</c>: the async methods that run
    /// through another (<c>ExecuteScalarAsync</c> through the reader) set
    /// <c>_parentOperationStarted</c> before the event and clear it when the operation ends.
    /// The block ends it before it starts, so it is cleared here; otherwise the command's next
    /// <c>ExecuteReaderAsync</c> would raise no event and go unchecked.
    /// </summary>
    public static void ResetParentOperation(object? command)
    {
        if (command is null)
        {
            return;
        }

        try
        {
            var field = s_parentField.GetValue(
                command.GetType(),
                t => t.GetField("_parentOperationStarted", BindingFlags.Instance | BindingFlags.NonPublic));
            if (field is not null && field.FieldType == typeof(bool))
            {
                field.SetValue(command, false);
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // fail open
        }
    }

    /// <summary>Checks MongoDB documents (filters, updates, pipeline stages) against the request's parsed body and query.</summary>
    public static void CheckMongo(string sink, IEnumerable<object?> documents)
    {
        RaspHooks.Run(sink, (ctx, inputs) =>
        {
            var trees = ctx?.TreesSnapshot() ?? Array.Empty<JsonNode?>();
            foreach (var doc in documents)
            {
                var node = ToNode(doc, 0);
                if (node is JsonArray stages)
                {
                    foreach (var stage in stages)
                    {
                        if (RaspDetect.NoSql(stage, trees, inputs) is { } hit)
                        {
                            return hit;
                        }
                    }
                }
                else if (RaspDetect.NoSql(node, trees, inputs) is { } found)
                {
                    return found;
                }
            }

            return null;
        });
    }

    /// <summary>
    /// A document as JSON: a JSON string, a <see cref="JsonNode"/> or <see cref="JsonElement"/>,
    /// a dictionary, a list, or an object with a <c>ToDictionary()</c> method (a MongoDB
    /// <c>BsonDocument</c>). Anything else is a leaf.
    /// </summary>
    internal static JsonNode? ToNode(object? value, int depth)
    {
        if (value is null || depth > 32)
        {
            return null;
        }

        switch (value)
        {
            case JsonNode n:
                return n;
            case JsonElement e:
                return e.ValueKind is JsonValueKind.Object or JsonValueKind.Array ? JsonNode.Parse(e.GetRawText()) : JsonValue.Create(e);
            case string s:
                if (depth == 0)
                {
                    try
                    {
                        return JsonNode.Parse(s);
                    }
                    catch (JsonException)
                    {
                        return null;
                    }
                }

                return JsonValue.Create(s);
            case bool b:
                return JsonValue.Create(b);
            case int or long or short or byte or sbyte or ushort or uint or ulong:
                return JsonValue.Create(Convert.ToInt64(value, CultureInfo.InvariantCulture));
            case double or float or decimal:
                return JsonValue.Create(Convert.ToDouble(value, CultureInfo.InvariantCulture));
            case IDictionary d:
                var obj = new JsonObject();
                foreach (DictionaryEntry kv in d)
                {
                    var key = Convert.ToString(kv.Key, CultureInfo.InvariantCulture);
                    if (key is not null && !obj.ContainsKey(key))
                    {
                        obj[key] = ToNode(kv.Value, depth + 1);
                    }
                }

                return obj;
            case IEnumerable<KeyValuePair<string, object?>> pairs:
                var o = new JsonObject();
                foreach (var kv in pairs)
                {
                    if (!o.ContainsKey(kv.Key))
                    {
                        o[kv.Key] = ToNode(kv.Value, depth + 1);
                    }
                }

                return o;
        }

        var toDictionary = value.GetType().GetMethod("ToDictionary", BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null);
        if (toDictionary is not null && typeof(IDictionary).IsAssignableFrom(toDictionary.ReturnType))
        {
            return ToNode(toDictionary.Invoke(value, null), depth);
        }

        if (value is IEnumerable list)
        {
            var arr = new JsonArray();
            foreach (var item in list)
            {
                arr.Add(ToNode(item, depth + 1));
            }

            return arr;
        }

        return JsonValue.Create(Convert.ToString(value, CultureInfo.InvariantCulture));
    }
}

/// <summary>Reads a named property of a diagnostic payload (anonymous or typed), with the lookups cached.</summary>
internal static class RaspReflect
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<(Type, string), PropertyInfo?> s_props = new();

    public static object? Property(object? payload, string name)
    {
        if (payload is null)
        {
            return null;
        }

        try
        {
            var p = s_props.GetOrAdd((payload.GetType(), name), k => k.Item1.GetProperty(k.Item2, BindingFlags.Public | BindingFlags.Instance));
            return p?.GetValue(payload);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return null;
        }
    }
}
