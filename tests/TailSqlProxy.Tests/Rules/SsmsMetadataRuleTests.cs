using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;
using TailSqlProxy.Rules;
using Xunit;

namespace TailSqlProxy.Tests.Rules;

public class SsmsMetadataRuleTests
{
    private readonly SsmsMetadataRule _rule;

    public SsmsMetadataRuleTests()
    {
        var options = Options.Create(new RuleOptions
        {
            SsmsMetadata = new SsmsMetadataOptions
            {
                Enabled = true,
                AllowedPatterns = [@"sys\.dm_exec_requests"]
            }
        });
        _rule = new SsmsMetadataRule(options, NullLogger<SsmsMetadataRule>.Instance);
    }

    private static QueryContext SqlCtx(string sql, string? appName = null) => new()
    {
        SqlText = sql,
        AppName = appName,
    };

    private static QueryContext RpcCtx(string procName, string? appName = null) => new()
    {
        SqlText = $"EXEC {procName}",
        ProcedureName = procName,
        IsRpc = true,
        AppName = appName,
    };

    // =============================================
    // BLOCKED — Core Catalog Views
    // =============================================

    [Theory]
    [InlineData("SELECT * FROM sys.databases")]
    [InlineData("SELECT name FROM sys.objects WHERE type = 'U'")]
    [InlineData("SELECT * FROM sys.tables")]
    [InlineData("SELECT * FROM sys.columns WHERE object_id = 12345")]
    [InlineData("SELECT * FROM sys.all_objects")]
    [InlineData("SELECT * FROM sys.all_columns")]
    [InlineData("SELECT * FROM sys.schemas")]
    [InlineData("SELECT * FROM sys.types")]
    [InlineData("SELECT * FROM sys.indexes")]
    [InlineData("SELECT * FROM sys.foreign_keys")]
    [InlineData("SELECT * FROM sys.views")]
    [InlineData("SELECT * FROM sys.procedures")]
    [InlineData("SELECT * FROM INFORMATION_SCHEMA.TABLES")]
    [InlineData("SELECT * FROM INFORMATION_SCHEMA.COLUMNS")]
    [InlineData("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")]
    public void Blocked_MetadataQueries(string sql)
    {
        _rule.Evaluate(SqlCtx(sql)).IsBlocked.Should().BeTrue($"'{sql}' should be blocked");
    }

    // =============================================
    // BLOCKED — New Catalog Views (IntelliSense + Object Explorer)
    // =============================================

    [Theory]
    [InlineData("SELECT * FROM sys.systypes")]
    [InlineData("SELECT * FROM sys.synonyms")]
    [InlineData("SELECT * FROM sys.triggers")]
    [InlineData("SELECT * FROM sys.computed_columns")]
    [InlineData("SELECT * FROM sys.identity_columns")]
    [InlineData("SELECT * FROM sys.sequences")]
    [InlineData("SELECT * FROM sys.extended_properties WHERE major_id = 123")]
    [InlineData("SELECT * FROM sys.check_constraints")]
    [InlineData("SELECT * FROM sys.default_constraints")]
    [InlineData("SELECT * FROM sys.configurations")]
    public void Blocked_ExtendedCatalogViews(string sql)
    {
        _rule.Evaluate(SqlCtx(sql)).IsBlocked.Should().BeTrue($"'{sql}' should be blocked");
    }

    // =============================================
    // BLOCKED — Security Catalog Views
    // =============================================

    [Theory]
    [InlineData("SELECT * FROM sys.server_principals")]
    [InlineData("SELECT * FROM sys.database_principals")]
    [InlineData("SELECT * FROM sys.database_permissions")]
    [InlineData("SELECT * FROM sys.server_permissions")]
    [InlineData("SELECT * FROM sys.database_role_members")]
    public void Blocked_SecurityCatalogViews(string sql)
    {
        _rule.Evaluate(SqlCtx(sql)).IsBlocked.Should().BeTrue($"'{sql}' should be blocked");
    }

    // =============================================
    // BLOCKED — Legacy Compatibility Views
    // =============================================

    [Theory]
    [InlineData("SELECT * FROM sys.syscolumns")]
    [InlineData("SELECT * FROM sys.sysobjects")]
    [InlineData("SELECT * FROM sys.sysindexes")]
    [InlineData("SELECT * FROM sys.sysusers")]
    [InlineData("SELECT * FROM sys.sysprocesses")]
    public void Blocked_LegacyCompatViews(string sql)
    {
        _rule.Evaluate(SqlCtx(sql)).IsBlocked.Should().BeTrue($"'{sql}' should be blocked");
    }

    // =============================================
    // BLOCKED — Stored Procedures (Original + New)
    // =============================================

    [Theory]
    [InlineData("sp_helpdb")]
    [InlineData("sp_helplogins")]
    [InlineData("sp_describe_undeclared_parameters")]
    [InlineData("sp_describe_first_result_set")]
    [InlineData("sp_help")]
    [InlineData("sp_columns")]
    [InlineData("sp_tables")]
    // New procedures
    [InlineData("sp_helptext")]
    [InlineData("sp_helpindex")]
    [InlineData("sp_columns_100")]
    [InlineData("sp_databases")]
    [InlineData("sp_datatype_info")]
    [InlineData("sp_datatype_info_100")]
    [InlineData("sp_describe_parameter_encryption")]
    [InlineData("sp_special_columns")]
    [InlineData("sp_helpuser")]
    [InlineData("sp_helprole")]
    [InlineData("sp_helprolemember")]
    [InlineData("sp_helpsrvrolemember")]
    public void Blocked_MetadataProcedures(string procName)
    {
        _rule.Evaluate(RpcCtx(procName)).IsBlocked.Should().BeTrue($"RPC '{procName}' should be blocked");
    }

    // =============================================
    // BLOCKED — Server Properties (when enabled)
    // =============================================

    [Theory]
    [InlineData("SELECT SERVERPROPERTY('Edition')")]
    [InlineData("SELECT SERVERPROPERTY('ProductVersion'), SERVERPROPERTY('ProductLevel')")]
    [InlineData("SELECT @@SERVERNAME")]
    [InlineData("SELECT @@SERVICENAME")]
    [InlineData("SELECT @@SPID")]
    public void Blocked_ServerProperties_WhenEnabled(string sql)
    {
        var options = Options.Create(new RuleOptions
        {
            SsmsMetadata = new SsmsMetadataOptions
            {
                Enabled = true,
                BlockServerProperties = true,
            }
        });
        var rule = new SsmsMetadataRule(options, NullLogger<SsmsMetadataRule>.Instance);

        rule.Evaluate(SqlCtx(sql)).IsBlocked.Should().BeTrue($"'{sql}' should be blocked");
    }

    [Fact]
    public void Allows_ServerProperties_WhenDisabled()
    {
        // Default: BlockServerProperties = false
        _rule.Evaluate(SqlCtx("SELECT SERVERPROPERTY('Edition')")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // BLOCKED — DMVs (when enabled)
    // =============================================

    [Theory]
    [InlineData("SELECT * FROM sys.dm_exec_sessions")]
    [InlineData("SELECT * FROM sys.dm_exec_connections")]
    [InlineData("SELECT * FROM sys.dm_os_performance_counters")]
    [InlineData("SELECT * FROM sys.dm_os_wait_stats")]
    [InlineData("SELECT * FROM sys.dm_db_index_usage_stats")]
    [InlineData("SELECT * FROM sys.dm_tran_locks")]
    public void Blocked_Dmvs_WhenEnabled(string sql)
    {
        var options = Options.Create(new RuleOptions
        {
            SsmsMetadata = new SsmsMetadataOptions
            {
                Enabled = true,
                BlockDmvs = true,
            }
        });
        var rule = new SsmsMetadataRule(options, NullLogger<SsmsMetadataRule>.Instance);

        rule.Evaluate(SqlCtx(sql)).IsBlocked.Should().BeTrue($"'{sql}' should be blocked");
    }

    [Fact]
    public void Allows_Dmvs_WhenDisabled()
    {
        // Default: BlockDmvs = false
        _rule.Evaluate(SqlCtx("SELECT * FROM sys.dm_exec_sessions")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // BLOCKED — SET Statements (when enabled)
    // =============================================

    [Theory]
    [InlineData("SET NOCOUNT ON")]
    [InlineData("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")]
    [InlineData("SET LOCK_TIMEOUT -1")]
    [InlineData("SET TEXTSIZE 2147483647")]
    public void Blocked_SetStatements_WhenEnabled(string sql)
    {
        var options = Options.Create(new RuleOptions
        {
            SsmsMetadata = new SsmsMetadataOptions
            {
                Enabled = true,
                BlockSetStatements = true,
            }
        });
        var rule = new SsmsMetadataRule(options, NullLogger<SsmsMetadataRule>.Instance);

        rule.Evaluate(SqlCtx(sql)).IsBlocked.Should().BeTrue($"'{sql}' should be blocked");
    }

    [Fact]
    public void Allows_SetStatements_WhenDisabled()
    {
        // Default: BlockSetStatements = false
        _rule.Evaluate(SqlCtx("SET NOCOUNT ON")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // APP NAME FILTERING
    // =============================================

    [Fact]
    public void Blocks_OnlyFromConfiguredAppNames()
    {
        var options = Options.Create(new RuleOptions
        {
            SsmsMetadata = new SsmsMetadataOptions
            {
                Enabled = true,
                BlockedAppNames = ["Microsoft SQL Server Management Studio"],
            }
        });
        var rule = new SsmsMetadataRule(options, NullLogger<SsmsMetadataRule>.Instance);

        // SSMS app name → blocked
        rule.Evaluate(SqlCtx("SELECT * FROM sys.tables", appName: "Microsoft SQL Server Management Studio"))
            .IsBlocked.Should().BeTrue();

        // Different app → allowed
        rule.Evaluate(SqlCtx("SELECT * FROM sys.tables", appName: "MyWebApp"))
            .IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void AppName_IsCaseInsensitive()
    {
        var options = Options.Create(new RuleOptions
        {
            SsmsMetadata = new SsmsMetadataOptions
            {
                Enabled = true,
                BlockedAppNames = ["microsoft sql server management studio"],
            }
        });
        var rule = new SsmsMetadataRule(options, NullLogger<SsmsMetadataRule>.Instance);

        rule.Evaluate(SqlCtx("SELECT * FROM sys.tables", appName: "Microsoft SQL Server Management Studio"))
            .IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void NullAppName_NotBlocked_WhenAppFilterConfigured()
    {
        var options = Options.Create(new RuleOptions
        {
            SsmsMetadata = new SsmsMetadataOptions
            {
                Enabled = true,
                BlockedAppNames = ["Microsoft SQL Server Management Studio"],
            }
        });
        var rule = new SsmsMetadataRule(options, NullLogger<SsmsMetadataRule>.Instance);

        rule.Evaluate(SqlCtx("SELECT * FROM sys.tables")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // ALLOWED — Regular Queries
    // =============================================

    [Theory]
    [InlineData("SELECT * FROM Customers")]
    [InlineData("SELECT Id, Name FROM Orders WHERE Status = 'Active'")]
    [InlineData("INSERT INTO Logs (Message) VALUES ('test')")]
    [InlineData("UPDATE Users SET LastLogin = GETDATE() WHERE Id = 1")]
    [InlineData("DELETE FROM TempData WHERE CreatedDate < '2020-01-01'")]
    [InlineData("SELECT COUNT(*) FROM Products")]
    public void Allowed_RegularQueries(string sql)
    {
        _rule.Evaluate(SqlCtx(sql)).IsBlocked.Should().BeFalse($"'{sql}' should be allowed");
    }

    [Fact]
    public void Allowed_AllowlistOverridesBlocklist()
    {
        // sys.dm_exec_requests is in the allowlist
        _rule.Evaluate(SqlCtx("SELECT * FROM sys.dm_exec_requests")).IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("sp_executesql")]
    [InlineData("sp_execute")]
    [InlineData("my_custom_proc")]
    public void Allowed_NonMetadataProcedures(string procName)
    {
        _rule.Evaluate(RpcCtx(procName)).IsBlocked.Should().BeFalse($"RPC '{procName}' should be allowed");
    }

    [Fact]
    public void Blocked_CaseInsensitive()
    {
        _rule.Evaluate(SqlCtx("SELECT * FROM SYS.DATABASES")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Disabled_DoesNotBlock()
    {
        var options = Options.Create(new RuleOptions
        {
            SsmsMetadata = new SsmsMetadataOptions { Enabled = false }
        });
        var rule = new SsmsMetadataRule(options, NullLogger<SsmsMetadataRule>.Instance);

        rule.Evaluate(SqlCtx("SELECT * FROM sys.databases")).IsBlocked.Should().BeFalse();
    }
}
