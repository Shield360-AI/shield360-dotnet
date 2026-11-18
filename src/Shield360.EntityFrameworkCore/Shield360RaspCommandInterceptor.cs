using System;
using System.Data.Common;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Shield360.EntityFrameworkCore;
using Shield360.Rasp;

namespace Shield360.EntityFrameworkCore
{
    /// <summary>
    /// Checks the SQL of every command Entity Framework Core executes (queries,
    /// <c>FromSql</c>, <c>ExecuteSql</c>, <c>SaveChanges</c>) for injection from request
    /// input or model output, before it is executed (sdk/rasp/README.md, "SQL"). In block
    /// mode a finding throws <see cref="Shield360RaspBlockedException"/> and the command
    /// never reaches the database. The dialect comes from the EF Core provider. A command
    /// checked here is not checked again by the SqlClient diagnostic hook.
    /// </summary>
    /// <remarks>Add it with <c>optionsBuilder.AddShield360Rasp()</c>.</remarks>
    public sealed class Shield360RaspCommandInterceptor : DbCommandInterceptor
    {
        /// <summary>The interceptor (it keeps no state).</summary>
        public static Shield360RaspCommandInterceptor Instance { get; } = new();

        private static void Check(DbCommand command, CommandEventData eventData, string sink)
        {
            if (!RaspEngine.IsActive)
            {
                return;
            }

            RaspSql.CheckCommand(sink, command, DialectFor(command, eventData));
        }

        /// <summary>
        /// The dialect from the EF Core provider name (SqlServer, Npgsql, MySQL, Sqlite,
        /// <c>Oracle.EntityFrameworkCore</c>, <c>IBM.EntityFrameworkCore</c>), else from the
        /// command's type; generic when neither says.
        /// </summary>
        internal static RaspSqlDialect DialectFor(DbCommand command, CommandEventData? eventData)
        {
            try
            {
                return RaspSql.DialectOf(eventData?.Context?.Database.ProviderName ?? command.GetType().FullName);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return RaspSqlDialect.Generic;
            }
        }

        // The execution ended (or never started): the mark set for it must not outlive it.

        /// <inheritdoc />
        public override DbDataReader ReaderExecuted(DbCommand command, CommandExecutedEventData eventData, DbDataReader result)
        {
            RaspSql.ClearChecked(command);
            return result;
        }

        /// <inheritdoc />
        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        {
            RaspSql.ClearChecked(command);
            return new ValueTask<DbDataReader>(result);
        }

        /// <inheritdoc />
        public override int NonQueryExecuted(DbCommand command, CommandExecutedEventData eventData, int result)
        {
            RaspSql.ClearChecked(command);
            return result;
        }

        /// <inheritdoc />
        public override ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            RaspSql.ClearChecked(command);
            return new ValueTask<int>(result);
        }

        /// <inheritdoc />
        public override object? ScalarExecuted(DbCommand command, CommandExecutedEventData eventData, object? result)
        {
            RaspSql.ClearChecked(command);
            return result;
        }

        /// <inheritdoc />
        public override ValueTask<object?> ScalarExecutedAsync(DbCommand command, CommandExecutedEventData eventData, object? result, CancellationToken cancellationToken = default)
        {
            RaspSql.ClearChecked(command);
            return new ValueTask<object?>(result);
        }

        /// <inheritdoc />
        public override void CommandFailed(DbCommand command, CommandErrorEventData eventData) => RaspSql.ClearChecked(command);

        /// <inheritdoc />
        public override Task CommandFailedAsync(DbCommand command, CommandErrorEventData eventData, CancellationToken cancellationToken = default)
        {
            RaspSql.ClearChecked(command);
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override void CommandCanceled(DbCommand command, CommandEndEventData eventData) => RaspSql.ClearChecked(command);

        /// <inheritdoc />
        public override Task CommandCanceledAsync(DbCommand command, CommandEndEventData eventData, CancellationToken cancellationToken = default)
        {
            RaspSql.ClearChecked(command);
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
        {
            Check(command, eventData, "efcore.ExecuteReader");
            return result;
        }

        /// <inheritdoc />
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Check(command, eventData, "efcore.ExecuteReader");
            return new ValueTask<InterceptionResult<DbDataReader>>(result);
        }

        /// <inheritdoc />
        public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
        {
            Check(command, eventData, "efcore.ExecuteNonQuery");
            return result;
        }

        /// <inheritdoc />
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Check(command, eventData, "efcore.ExecuteNonQuery");
            return new ValueTask<InterceptionResult<int>>(result);
        }

        /// <inheritdoc />
        public override InterceptionResult<object> ScalarExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<object> result)
        {
            Check(command, eventData, "efcore.ExecuteScalar");
            return result;
        }

        /// <inheritdoc />
        public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
        {
            Check(command, eventData, "efcore.ExecuteScalar");
            return new ValueTask<InterceptionResult<object>>(result);
        }
    }
}

namespace Microsoft.EntityFrameworkCore
{
    /// <summary>Adds the Shield360 RASP SQL check to a <c>DbContext</c>.</summary>
    public static class Shield360RaspDbContextOptionsBuilderExtensions
    {
        /// <summary>
        /// Adds <see cref="Shield360RaspCommandInterceptor"/>: every command this context
        /// executes is checked for SQL injection first. RASP itself is turned on by
        /// <c>AddShield360Rasp</c>, <c>Shield360Options.Rasp</c> or <c>SHIELD360_RASP</c>.
        /// </summary>
        /// <example>
        /// <code>
        /// services.AddDbContext&lt;OrdersDb&gt;(o => o.UseSqlServer(connectionString).AddShield360Rasp());
        /// </code>
        /// </example>
        public static DbContextOptionsBuilder AddShield360Rasp(this DbContextOptionsBuilder optionsBuilder)
        {
            if (optionsBuilder is null)
            {
                throw new ArgumentNullException(nameof(optionsBuilder));
            }

            return optionsBuilder.AddInterceptors(Shield360RaspCommandInterceptor.Instance);
        }

        /// <summary><see cref="AddShield360Rasp(DbContextOptionsBuilder)"/> for a typed builder.</summary>
        public static DbContextOptionsBuilder<TContext> AddShield360Rasp<TContext>(this DbContextOptionsBuilder<TContext> optionsBuilder)
            where TContext : DbContext
        {
            if (optionsBuilder is null)
            {
                throw new ArgumentNullException(nameof(optionsBuilder));
            }

            return optionsBuilder.AddInterceptors(Shield360RaspCommandInterceptor.Instance);
        }
    }
}
