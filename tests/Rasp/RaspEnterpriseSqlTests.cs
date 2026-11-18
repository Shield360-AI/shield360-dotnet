using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using Shield360.EntityFrameworkCore;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp
{
    /// <summary>
    /// SQL Server, Oracle and IBM Db2: the dialect chosen from the provider or command type,
    /// the EF Core interceptor on their commands (block, monitor, off, fail open), and the
    /// <see cref="Shield360Rasp.CheckSql"/> helper documented for plain ADO.NET. Stub
    /// commands named like the real drivers; no driver is referenced and nothing connects.
    /// </summary>
    public class RaspEnterpriseSqlTests : RaspStateTest
    {
        private const string Input = "x' OR '1'='1";
        private const string Query = "SELECT * FROM users WHERE name = '" + Input + "'";

        private static RaspInput[] Inputs(params string[] values) => values.Select((v, i) => new RaspInput(v, "query.k" + i)).ToArray();

        private static void InRequest(Action fn) => RaspScope.Run(new RaspContext(Inputs(Input), inRequest: true), () =>
        {
            fn();
            return 0;
        });

        private static ListSink Mode(RaspMode mode, IDictionary<RaspAttackType, RaspMode>? attacks = null) =>
            Configure(new EngineSettings(true, "entdb", mode, Attacks: attacks));

        public static IEnumerable<object[]> Commands() => new[]
        {
            new object[] { new Oracle.ManagedDataAccess.Client.OracleCommand(Query), RaspSqlDialect.Oracle },
            new object[] { new IBM.Data.Db2.DB2Command(Query), RaspSqlDialect.Db2 },
        };

        [Theory]
        [InlineData("Microsoft.EntityFrameworkCore.SqlServer", RaspSqlDialect.MsSql)]
        [InlineData("Microsoft.Data.SqlClient.SqlCommand", RaspSqlDialect.MsSql)]
        [InlineData("System.Data.SqlClient.SqlCommand", RaspSqlDialect.MsSql)]
        [InlineData("Oracle.EntityFrameworkCore", RaspSqlDialect.Oracle)]
        [InlineData("Oracle.ManagedDataAccess.Client.OracleCommand", RaspSqlDialect.Oracle)]
        [InlineData("Devart.Data.Oracle.OracleCommand", RaspSqlDialect.Oracle)]
        [InlineData("IBM.EntityFrameworkCore", RaspSqlDialect.Db2)]
        [InlineData("IBM.Data.Db2.DB2Command", RaspSqlDialect.Db2)]
        [InlineData("IBM.Data.DB2.Core.DB2Command", RaspSqlDialect.Db2)]
        [InlineData("MySql.EntityFrameworkCore", RaspSqlDialect.MySql)]
        [InlineData("Some.Other.Provider", RaspSqlDialect.Generic)]
        [InlineData(null, RaspSqlDialect.Generic)]
        public void Enterprise_providers_map_to_their_dialect(string? provider, RaspSqlDialect dialect) =>
            Assert.Equal(dialect, RaspSql.DialectOf(provider));

        [Theory]
        [MemberData(nameof(Commands))]
        public void The_interceptor_takes_the_dialect_from_the_command_without_a_context(DbCommand command, RaspSqlDialect dialect) =>
            Assert.Equal(dialect, Shield360RaspCommandInterceptor.DialectFor(command, null));

        [Theory]
        [MemberData(nameof(Commands))]
        public void The_interceptor_blocks_injection_in_block_mode(DbCommand command, RaspSqlDialect dialect)
        {
            _ = dialect;
            var sink = Mode(RaspMode.Block);
            InRequest(() => Assert.Throws<Shield360RaspBlockedException>(
                () => Shield360RaspCommandInterceptor.Instance.ReaderExecuting(command, null!, default)));
            var e = Assert.Single(sink.Events);
            Assert.Equal("efcore.ExecuteReader", e.Attrs["shield360.rasp.sink"]);
            Assert.Equal("blocked", e.Attrs["shield360.rasp.decision"]);
            Assert.Equal("sqli.userinput", e.Attrs["shield360.rasp.rule"]);
        }

        [Theory]
        [MemberData(nameof(Commands))]
        public void The_interceptor_reports_and_lets_the_command_through_in_monitor_mode(DbCommand command, RaspSqlDialect dialect)
        {
            _ = dialect;
            var sink = Mode(RaspMode.Monitor);
            InRequest(() => Shield360RaspCommandInterceptor.Instance.NonQueryExecuting(command, null!, default));
            var e = Assert.Single(sink.Events);
            Assert.Equal("efcore.ExecuteNonQuery", e.Attrs["shield360.rasp.sink"]);
            Assert.Equal("monitored", e.Attrs["shield360.rasp.decision"]);
        }

        [Theory]
        [MemberData(nameof(Commands))]
        public void The_interceptor_does_nothing_when_sql_injection_is_off(DbCommand command, RaspSqlDialect dialect)
        {
            _ = dialect;
            var sink = Mode(RaspMode.Block, new Dictionary<RaspAttackType, RaspMode> { [RaspAttackType.SqlInjection] = RaspMode.Off });
            InRequest(() => Shield360RaspCommandInterceptor.Instance.ScalarExecuting(command, null!, default));
            Assert.Empty(sink.Events);
        }

        [Fact]
        public void A_command_that_throws_while_read_fails_open()
        {
            var sink = Mode(RaspMode.Block);
            InRequest(() =>
            {
                Shield360RaspCommandInterceptor.Instance.ReaderExecuting(new Oracle.ManagedDataAccess.Client.OracleCommand(Query) { Broken = true }, null!, default);
                Shield360RaspCommandInterceptor.Instance.ReaderExecuting(new IBM.Data.Db2.DB2Command(Query) { Broken = true }, null!, default);
            });
            Assert.Empty(sink.Events);
        }

        [Fact]
        public void Parameterized_enterprise_SQL_passes()
        {
            var sink = Mode(RaspMode.Block);
            InRequest(() =>
            {
                Shield360RaspCommandInterceptor.Instance.ReaderExecuting(new Oracle.ManagedDataAccess.Client.OracleCommand("SELECT * FROM users WHERE name = :name"), null!, default);
                Shield360RaspCommandInterceptor.Instance.ReaderExecuting(new IBM.Data.Db2.DB2Command("SELECT * FROM users WHERE name = ?"), null!, default);
                Shield360Rasp.CheckSql("SELECT * FROM users WHERE name = @name", RaspSqlDialect.MsSql);
            });
            Assert.Empty(sink.Events);
        }

        [Theory]
        [InlineData(RaspSqlDialect.MsSql)]
        [InlineData(RaspSqlDialect.Oracle)]
        [InlineData(RaspSqlDialect.Db2)]
        public void CheckSql_covers_plain_ADO_NET_for_each_enterprise_dialect(RaspSqlDialect dialect)
        {
            var sink = Mode(RaspMode.Block);
            InRequest(() => Assert.Throws<Shield360RaspBlockedException>(() => Shield360Rasp.CheckSql(Query, dialect, "oracle.ExecuteReader")));
            Assert.Equal("oracle.ExecuteReader", Assert.Single(sink.Events).Attrs["shield360.rasp.sink"]);

            Configure(new EngineSettings(true, "entdb", RaspMode.Monitor));
            InRequest(() => Shield360Rasp.CheckSql(Query, dialect));
        }

        [Fact]
        public void Without_a_request_or_with_RASP_off_nothing_is_checked()
        {
            var sink = Mode(RaspMode.Block);
            Shield360RaspCommandInterceptor.Instance.ReaderExecuting(new Oracle.ManagedDataAccess.Client.OracleCommand(Query), null!, default);
            Assert.Empty(sink.Events);

            Configure(new EngineSettings(false, "entdb", RaspMode.Block));
            InRequest(() => Shield360Rasp.CheckSql(Query, RaspSqlDialect.Db2));
        }
    }

    /// <summary>A command with no driver behind it; <see cref="Broken"/> makes reading it throw.</summary>
    public abstract class StubCommand : DbCommand
    {
        private string _text;

        protected StubCommand(string text) => _text = text;

        public bool Broken { get; set; }

        [System.Diagnostics.CodeAnalysis.AllowNull]
        public override string CommandText
        {
            get => Broken ? throw new InvalidOperationException("broken") : _text;
            set => _text = value ?? string.Empty;
        }

        public override int CommandTimeout { get; set; }

        public override CommandType CommandType { get; set; } = CommandType.Text;

        public override bool DesignTimeVisible { get; set; }

        public override UpdateRowSource UpdatedRowSource { get; set; }

        protected override DbConnection? DbConnection { get; set; }

        protected override DbParameterCollection DbParameterCollection => throw new NotSupportedException();

        protected override DbTransaction? DbTransaction { get; set; }

        public override void Cancel()
        {
        }

        public override int ExecuteNonQuery() => throw new NotSupportedException();

        public override object? ExecuteScalar() => throw new NotSupportedException();

        public override void Prepare()
        {
        }

        protected override DbParameter CreateDbParameter() => throw new NotSupportedException();

        protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) => throw new NotSupportedException();
    }
}

// Named like the real drivers' command types, so the dialect comes from the type name.
namespace Oracle.ManagedDataAccess.Client
{
    public sealed class OracleCommand(string text) : Shield360.Tests.Rasp.StubCommand(text);
}

namespace IBM.Data.Db2
{
    public sealed class DB2Command(string text) : Shield360.Tests.Rasp.StubCommand(text);
}
