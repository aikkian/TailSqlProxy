using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TailSqlProxy.Configuration;
using TailSqlProxy.Routing;
using Xunit;

namespace TailSqlProxy.Tests.Routing;

public class ReadWriteRouterTests
{
    private static ReadWriteRouter CreateRouter(
        bool enabled = true,
        string[]? alwaysPrimaryApps = null,
        string[]? alwaysReadOnlyApps = null)
    {
        var options = new ReadWriteSplitOptions
        {
            Enabled = enabled,
            AlwaysPrimaryAppNames = alwaysPrimaryApps ?? [],
            AlwaysReadOnlyAppNames = alwaysReadOnlyApps ?? [],
        };
        return new ReadWriteRouter(options, NullLogger.Instance);
    }

    // ──────────────────── SQL Batch Routing ────────────────────

    [Theory]
    [InlineData("SELECT * FROM Orders")]
    [InlineData("SELECT Id, Name FROM Orders WHERE Id = 1")]
    [InlineData("SELECT TOP 10 * FROM Orders")]
    [InlineData("SELECT 1")]
    public void SqlBatch_ReadOnlyQueries_RouteToReadOnly(string sql)
    {
        var router = CreateRouter();
        router.RouteSqlBatch(sql, null).Should().Be(RouteTarget.ReadOnly);
    }

    [Theory]
    [InlineData("INSERT INTO Orders (Name) VALUES ('Test')")]
    [InlineData("UPDATE Orders SET Status = 'Active' WHERE Id = 1")]
    [InlineData("DELETE FROM Orders WHERE Id = 1")]
    [InlineData("EXEC sp_helpdb")]
    [InlineData("CREATE TABLE Test (Id INT)")]
    public void SqlBatch_WriteQueries_RouteToPrimary(string sql)
    {
        var router = CreateRouter();
        router.RouteSqlBatch(sql, null).Should().Be(RouteTarget.Primary);
    }

    [Fact]
    public void SqlBatch_Disabled_AlwaysRoutesToPrimary()
    {
        var router = CreateRouter(enabled: false);
        router.RouteSqlBatch("SELECT * FROM Orders", null).Should().Be(RouteTarget.Primary);
    }

    // ──────────────────── Transaction Awareness ────────────────────

    [Fact]
    public void SqlBatch_InTransaction_RoutesToPrimary()
    {
        var router = CreateRouter();

        // Start a transaction
        router.RouteSqlBatch("BEGIN TRAN", null).Should().Be(RouteTarget.Primary);

        // SELECT inside transaction must go to primary
        router.RouteSqlBatch("SELECT * FROM Orders", null).Should().Be(RouteTarget.Primary);

        // Commit ends the transaction
        router.RouteSqlBatch("COMMIT", null);

        // Now SELECT should go to read-only again
        router.RouteSqlBatch("SELECT * FROM Orders", null).Should().Be(RouteTarget.ReadOnly);
    }

    [Fact]
    public void SqlBatch_AfterRollback_RoutesToReadOnly()
    {
        var router = CreateRouter();

        router.RouteSqlBatch("BEGIN TRAN", null);
        router.RouteSqlBatch("SELECT * FROM Orders", null).Should().Be(RouteTarget.Primary);
        router.RouteSqlBatch("ROLLBACK", null);

        router.RouteSqlBatch("SELECT * FROM Orders", null).Should().Be(RouteTarget.ReadOnly);
    }

    // ──────────────────── App-name Overrides ────────────────────

    [Fact]
    public void SqlBatch_AlwaysPrimaryApp_RoutesToPrimary()
    {
        var router = CreateRouter(alwaysPrimaryApps: ["MigrationTool"]);

        router.RouteSqlBatch("SELECT * FROM Orders", "MigrationTool")
            .Should().Be(RouteTarget.Primary);
    }

    [Fact]
    public void SqlBatch_AlwaysPrimaryApp_CaseInsensitive()
    {
        var router = CreateRouter(alwaysPrimaryApps: ["migrationtool"]);

        router.RouteSqlBatch("SELECT * FROM Orders", "MigrationTool")
            .Should().Be(RouteTarget.Primary);
    }

    [Fact]
    public void SqlBatch_AlwaysReadOnlyApp_RoutesToReadOnly()
    {
        var router = CreateRouter(alwaysReadOnlyApps: ["PowerBI"]);

        // Even DML from a read-only app goes to read-only
        router.RouteSqlBatch("INSERT INTO Orders (Name) VALUES ('Test')", "PowerBI")
            .Should().Be(RouteTarget.ReadOnly);
    }

    [Fact]
    public void SqlBatch_AlwaysReadOnlyApp_CaseInsensitive()
    {
        var router = CreateRouter(alwaysReadOnlyApps: ["POWERBI"]);

        router.RouteSqlBatch("SELECT * FROM Orders", "powerbi")
            .Should().Be(RouteTarget.ReadOnly);
    }

    // ──────────────────── RPC Routing ────────────────────

    [Fact]
    public void Rpc_SpExecuteSqlWithSelect_RoutesToReadOnly()
    {
        var router = CreateRouter();
        router.RouteRpc("sp_executesql", "SELECT * FROM Orders", null)
            .Should().Be(RouteTarget.ReadOnly);
    }

    [Fact]
    public void Rpc_SpExecuteSqlWithInsert_RoutesToPrimary()
    {
        var router = CreateRouter();
        router.RouteRpc("sp_executesql", "INSERT INTO Orders (Name) VALUES ('Test')", null)
            .Should().Be(RouteTarget.Primary);
    }

    [Fact]
    public void Rpc_OtherProc_RoutesToPrimary()
    {
        var router = CreateRouter();
        router.RouteRpc("sp_custom_proc", "SELECT * FROM Orders", null)
            .Should().Be(RouteTarget.Primary);
    }

    [Fact]
    public void Rpc_InTransaction_RoutesToPrimary()
    {
        var router = CreateRouter();
        router.RouteSqlBatch("BEGIN TRAN", null);

        router.RouteRpc("sp_executesql", "SELECT * FROM Orders", null)
            .Should().Be(RouteTarget.Primary);
    }

    [Fact]
    public void Rpc_Disabled_RoutesToPrimary()
    {
        var router = CreateRouter(enabled: false);
        router.RouteRpc("sp_executesql", "SELECT * FROM Orders", null)
            .Should().Be(RouteTarget.Primary);
    }

    [Fact]
    public void Rpc_AlwaysReadOnlyApp_RoutesToReadOnly()
    {
        var router = CreateRouter(alwaysReadOnlyApps: ["ReportingService"]);
        router.RouteRpc("sp_custom_proc", null, "ReportingService")
            .Should().Be(RouteTarget.ReadOnly);
    }

    // ──────────────────── ReadOnlyConnectionUsed tracking ────────────────────

    [Fact]
    public void ReadOnlyConnectionUsed_InitiallyFalse()
    {
        var router = CreateRouter();
        router.ReadOnlyConnectionUsed.Should().BeFalse();
    }

    [Fact]
    public void ReadOnlyConnectionUsed_TrueAfterReadOnlyRoute()
    {
        var router = CreateRouter();
        router.RouteSqlBatch("SELECT * FROM Orders", null);
        router.ReadOnlyConnectionUsed.Should().BeTrue();
    }

    [Fact]
    public void ReadOnlyConnectionUsed_StillFalseAfterPrimaryRoute()
    {
        var router = CreateRouter();
        router.RouteSqlBatch("INSERT INTO Orders (Name) VALUES ('Test')", null);
        router.ReadOnlyConnectionUsed.Should().BeFalse();
    }

    // ──────────────────── Configuration defaults ────────────────────

    [Fact]
    public void Options_DefaultsToDisabled()
    {
        var opts = new ReadWriteSplitOptions();
        opts.Enabled.Should().BeFalse();
        opts.ReadOnlyHost.Should().BeNull();
        opts.ReadOnlyPort.Should().Be(1433);
        opts.AlwaysPrimaryAppNames.Should().BeEmpty();
        opts.AlwaysReadOnlyAppNames.Should().BeEmpty();
    }

    // ──────────────────── Edge cases ────────────────────

    [Fact]
    public void SqlBatch_NullSql_RoutesToPrimary()
    {
        var router = CreateRouter();
        router.RouteSqlBatch(null, null).Should().Be(RouteTarget.Primary);
    }

    [Fact]
    public void SqlBatch_EmptySql_RoutesToPrimary()
    {
        var router = CreateRouter();
        router.RouteSqlBatch("", null).Should().Be(RouteTarget.Primary);
    }

    [Fact]
    public void SqlBatch_InvalidSql_RoutesToPrimary()
    {
        var router = CreateRouter();
        router.RouteSqlBatch("NOT VALID SQL!!!", null).Should().Be(RouteTarget.Primary);
    }
}
