using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;
using TailSqlProxy.Rules;
using Xunit;

namespace TailSqlProxy.Tests.Rules;

public class UnboundedSelectRuleTests
{
    private readonly UnboundedSelectRule _rule;

    public UnboundedSelectRuleTests()
    {
        var options = Options.Create(new RuleOptions
        {
            UnboundedSelect = new UnboundedSelectOptions { Enabled = true }
        });
        _rule = new UnboundedSelectRule(options, NullLogger<UnboundedSelectRule>.Instance);
    }

    private static QueryContext Ctx(string sql) => new() { SqlText = sql };

    // --- SHOULD BE BLOCKED ---

    [Theory]
    [InlineData("SELECT * FROM Orders")]
    [InlineData("SELECT * FROM dbo.Orders")]
    [InlineData("SELECT * FROM [Orders]")]
    [InlineData("select * from Orders")]
    [InlineData("SELECT * FROM Orders o JOIN Items i ON o.Id = i.OrderId")]
    public void Blocked_SelectStarWithoutTopOrWhere(string sql)
    {
        var result = _rule.Evaluate(Ctx(sql));
        result.IsBlocked.Should().BeTrue($"'{sql}' should be blocked");
    }

    // --- SHOULD BE ALLOWED ---

    [Theory]
    [InlineData("SELECT * FROM Orders WHERE Id = 1")]
    [InlineData("SELECT * FROM Orders WHERE 1=1")]
    [InlineData("SELECT TOP 10 * FROM Orders")]
    [InlineData("SELECT TOP (100) * FROM Orders")]
    [InlineData("SELECT Id, Name FROM Orders")] // Not SELECT *
    [InlineData("SELECT COUNT(*) FROM Orders")] // Aggregation, not SELECT *
    [InlineData("SELECT 1")]
    [InlineData("SELECT GETDATE()")]
    [InlineData("SELECT @@VERSION")]
    [InlineData("INSERT INTO Orders (Name) VALUES ('Test')")]
    [InlineData("UPDATE Orders SET Name = 'Test' WHERE Id = 1")]
    [InlineData("DELETE FROM Orders WHERE Id = 1")]
    [InlineData("SELECT * FROM Orders WHERE Status = 'Active' ORDER BY Id")]
    [InlineData("SELECT TOP 5 * FROM Orders ORDER BY CreatedAt DESC")]
    public void Allowed_ValidQueries(string sql)
    {
        var result = _rule.Evaluate(Ctx(sql));
        result.IsBlocked.Should().BeFalse($"'{sql}' should be allowed");
    }

    [Fact]
    public void Allowed_EmptySql()
    {
        var result = _rule.Evaluate(Ctx(""));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void Allowed_InvalidSql()
    {
        var result = _rule.Evaluate(Ctx("THIS IS NOT VALID SQL !!!"));
        result.IsBlocked.Should().BeFalse("invalid SQL should be passed to server for error handling");
    }

    [Fact]
    public void Allowed_RpcNonSpExecuteSql()
    {
        var ctx = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            IsRpc = true,
            ProcedureName = "sp_some_other_proc"
        };
        var result = _rule.Evaluate(ctx);
        result.IsBlocked.Should().BeFalse("non sp_executesql RPCs should be allowed");
    }

    [Fact]
    public void Blocked_RpcSpExecuteSqlWithUnboundedSelect()
    {
        var ctx = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            IsRpc = true,
            ProcedureName = "sp_executesql"
        };
        var result = _rule.Evaluate(ctx);
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Disabled_DoesNotBlock()
    {
        var options = Options.Create(new RuleOptions
        {
            UnboundedSelect = new UnboundedSelectOptions { Enabled = false }
        });
        var rule = new UnboundedSelectRule(options, NullLogger<UnboundedSelectRule>.Instance);

        var result = rule.Evaluate(Ctx("SELECT * FROM Orders"));
        result.IsBlocked.Should().BeFalse("disabled rule should not block");
    }
}
