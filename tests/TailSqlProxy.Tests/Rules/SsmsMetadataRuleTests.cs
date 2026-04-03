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

    private static QueryContext SqlCtx(string sql) => new() { SqlText = sql };
    private static QueryContext RpcCtx(string procName) => new()
    {
        SqlText = $"EXEC {procName}",
        ProcedureName = procName,
        IsRpc = true
    };

    // --- BLOCKED SQL QUERIES ---

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
        var result = _rule.Evaluate(SqlCtx(sql));
        result.IsBlocked.Should().BeTrue($"'{sql}' should be blocked as metadata query");
    }

    // --- BLOCKED RPC CALLS ---

    [Theory]
    [InlineData("sp_helpdb")]
    [InlineData("sp_helplogins")]
    [InlineData("sp_describe_undeclared_parameters")]
    [InlineData("sp_describe_first_result_set")]
    [InlineData("sp_help")]
    [InlineData("sp_columns")]
    [InlineData("sp_tables")]
    public void Blocked_MetadataProcedures(string procName)
    {
        var result = _rule.Evaluate(RpcCtx(procName));
        result.IsBlocked.Should().BeTrue($"RPC '{procName}' should be blocked");
    }

    // --- ALLOWED QUERIES ---

    [Theory]
    [InlineData("SELECT * FROM Customers")]
    [InlineData("SELECT Id, Name FROM Orders WHERE Status = 'Active'")]
    [InlineData("INSERT INTO Logs (Message) VALUES ('test')")]
    [InlineData("UPDATE Users SET LastLogin = GETDATE() WHERE Id = 1")]
    [InlineData("DELETE FROM TempData WHERE CreatedDate < '2020-01-01'")]
    [InlineData("SELECT COUNT(*) FROM Products")]
    public void Allowed_RegularQueries(string sql)
    {
        var result = _rule.Evaluate(SqlCtx(sql));
        result.IsBlocked.Should().BeFalse($"'{sql}' should be allowed as regular query");
    }

    [Fact]
    public void Allowed_AllowlistOverridesBlocklist()
    {
        // sys.dm_exec_requests is in the allowlist
        var result = _rule.Evaluate(SqlCtx("SELECT * FROM sys.dm_exec_requests"));
        result.IsBlocked.Should().BeFalse("allowlisted patterns should not be blocked");
    }

    [Theory]
    [InlineData("sp_executesql")]
    [InlineData("sp_execute")]
    [InlineData("my_custom_proc")]
    public void Allowed_NonMetadataProcedures(string procName)
    {
        var result = _rule.Evaluate(RpcCtx(procName));
        result.IsBlocked.Should().BeFalse($"RPC '{procName}' should be allowed");
    }

    [Fact]
    public void Blocked_CaseInsensitive()
    {
        var result = _rule.Evaluate(SqlCtx("SELECT * FROM SYS.DATABASES"));
        result.IsBlocked.Should().BeTrue("matching should be case-insensitive");
    }

    [Fact]
    public void Disabled_DoesNotBlock()
    {
        var options = Options.Create(new RuleOptions
        {
            SsmsMetadata = new SsmsMetadataOptions { Enabled = false }
        });
        var rule = new SsmsMetadataRule(options, NullLogger<SsmsMetadataRule>.Instance);

        var result = rule.Evaluate(SqlCtx("SELECT * FROM sys.databases"));
        result.IsBlocked.Should().BeFalse("disabled rule should not block");
    }
}
