using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;
using TailSqlProxy.Rules;
using Xunit;

namespace TailSqlProxy.Tests.Rules;

public class RuleEngineBypassTests
{
    private static IRuleEngine CreateEngine(
        string[]? bypassUsers = null,
        string[]? bypassAppNames = null,
        string[]? bypassClientIps = null)
    {
        var ruleOptions = Options.Create(new RuleOptions
        {
            UnboundedSelect = new UnboundedSelectOptions { Enabled = true },
            UnboundedDelete = new UnboundedDeleteOptions { Enabled = true },
            BypassUsers = bypassUsers ?? [],
            BypassAppNames = bypassAppNames ?? [],
            BypassClientIps = bypassClientIps ?? [],
        });

        var rules = new IQueryRule[]
        {
            new UnboundedSelectRule(ruleOptions, NullLogger<UnboundedSelectRule>.Instance),
            new UnboundedDeleteRule(ruleOptions, NullLogger<UnboundedDeleteRule>.Instance),
        };

        return new RuleEngine(rules, ruleOptions, NullLogger<RuleEngine>.Instance);
    }

    [Fact]
    public void NormalUser_IsBlocked_ByUnboundedSelect()
    {
        var engine = CreateEngine();
        var context = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            Username = "regular_user",
        };

        engine.Evaluate(context).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void BypassUser_CanExecute_UnboundedSelect()
    {
        var engine = CreateEngine(bypassUsers: ["admin_user"]);
        var context = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            Username = "admin_user",
        };

        engine.Evaluate(context).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void BypassUser_IsCaseInsensitive()
    {
        var engine = CreateEngine(bypassUsers: ["Admin_User"]);
        var context = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            Username = "admin_user",
        };

        engine.Evaluate(context).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void BypassUser_CanExecute_UnboundedDelete()
    {
        var engine = CreateEngine(bypassUsers: ["db_owner_user"]);
        var context = new QueryContext
        {
            SqlText = "DELETE FROM Orders",
            Username = "db_owner_user",
        };

        engine.Evaluate(context).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void NonBypassUser_StillBlocked()
    {
        var engine = CreateEngine(bypassUsers: ["admin_user"]);
        var context = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            Username = "other_user",
        };

        engine.Evaluate(context).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void BypassAppName_AllowsBlockedQuery()
    {
        var engine = CreateEngine(bypassAppNames: ["DeployTool"]);
        var context = new QueryContext
        {
            SqlText = "DELETE FROM Orders",
            AppName = "DeployTool",
            Username = "regular_user",
        };

        engine.Evaluate(context).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void BypassAppName_IsCaseInsensitive()
    {
        var engine = CreateEngine(bypassAppNames: ["deploytool"]);
        var context = new QueryContext
        {
            SqlText = "DELETE FROM Orders",
            AppName = "DeployTool",
        };

        engine.Evaluate(context).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void BypassClientIp_AllowsBlockedQuery()
    {
        var engine = CreateEngine(bypassClientIps: ["10.0.0.50"]);
        var context = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            ClientIp = "10.0.0.50",
            Username = "regular_user",
        };

        engine.Evaluate(context).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void NonMatchingClientIp_StillBlocked()
    {
        var engine = CreateEngine(bypassClientIps: ["10.0.0.50"]);
        var context = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            ClientIp = "10.0.0.99",
            Username = "regular_user",
        };

        engine.Evaluate(context).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void MultipleBypassUsers_AllWork()
    {
        var engine = CreateEngine(bypassUsers: ["admin1", "admin2", "svc_deploy"]);

        foreach (var user in new[] { "admin1", "admin2", "svc_deploy" })
        {
            var context = new QueryContext
            {
                SqlText = "SELECT * FROM Orders",
                Username = user,
            };
            engine.Evaluate(context).IsBlocked.Should().BeFalse($"{user} should be bypassed");
        }
    }

    [Fact]
    public void EmptyBypassLists_NoBypass()
    {
        var engine = CreateEngine();
        var context = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            Username = "any_user",
            AppName = "AnyApp",
            ClientIp = "10.0.0.1",
        };

        engine.Evaluate(context).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void NullUsername_NotBypassed()
    {
        var engine = CreateEngine(bypassUsers: ["admin"]);
        var context = new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
        };

        engine.Evaluate(context).IsBlocked.Should().BeTrue();
    }
}
