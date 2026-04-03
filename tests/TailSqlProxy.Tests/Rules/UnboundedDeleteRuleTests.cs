using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;
using TailSqlProxy.Rules;
using Xunit;

namespace TailSqlProxy.Tests.Rules;

public class UnboundedDeleteRuleTests
{
    private readonly UnboundedDeleteRule _rule;

    public UnboundedDeleteRuleTests()
    {
        var options = Options.Create(new RuleOptions
        {
            UnboundedDelete = new UnboundedDeleteOptions { Enabled = true }
        });
        _rule = new UnboundedDeleteRule(options, NullLogger<UnboundedDeleteRule>.Instance);
    }

    private static QueryContext Ctx(string sql) => new() { SqlText = sql };

    // --- SHOULD BE BLOCKED ---

    [Theory]
    [InlineData("DELETE FROM Orders")]
    [InlineData("DELETE FROM dbo.Orders")]
    [InlineData("DELETE FROM [Orders]")]
    [InlineData("delete from Orders")]
    [InlineData("DELETE Orders")]
    public void Blocked_DeleteWithoutWhereOrTop(string sql)
    {
        var result = _rule.Evaluate(Ctx(sql));
        result.IsBlocked.Should().BeTrue($"'{sql}' should be blocked");
    }

    // --- SHOULD BE ALLOWED ---

    [Theory]
    [InlineData("DELETE FROM Orders WHERE Id = 1")]
    [InlineData("DELETE FROM Orders WHERE Status = 'Expired'")]
    [InlineData("DELETE TOP (1000) FROM Orders")]
    [InlineData("DELETE TOP (100) FROM Orders WHERE CreatedDate < '2020-01-01'")]
    [InlineData("DELETE o FROM Orders o WHERE o.Date < '2020-01-01'")]
    [InlineData("SELECT * FROM Orders")] // Not a DELETE
    [InlineData("INSERT INTO Orders (Name) VALUES ('Test')")]
    [InlineData("UPDATE Orders SET Name = 'Test'")] // UPDATE is not DELETE
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
    public void Disabled_DoesNotBlock()
    {
        var options = Options.Create(new RuleOptions
        {
            UnboundedDelete = new UnboundedDeleteOptions { Enabled = false }
        });
        var rule = new UnboundedDeleteRule(options, NullLogger<UnboundedDeleteRule>.Instance);

        var result = rule.Evaluate(Ctx("DELETE FROM Orders"));
        result.IsBlocked.Should().BeFalse("disabled rule should not block");
    }

    [Fact]
    public void Blocked_SpExecuteSqlDelete()
    {
        var ctx = new QueryContext
        {
            SqlText = "DELETE FROM Orders",
            IsRpc = true,
            ProcedureName = "sp_executesql"
        };
        var result = _rule.Evaluate(ctx);
        result.IsBlocked.Should().BeTrue();
    }
}
