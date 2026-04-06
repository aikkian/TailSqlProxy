using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;
using TailSqlProxy.Rules;
using Xunit;

namespace TailSqlProxy.Tests.Rules;

public class AccessControlRuleTests
{
    private static AccessControlRule CreateRule(params AccessControlPolicy[] policies)
    {
        var options = Options.Create(new RuleOptions
        {
            AccessControl = new AccessControlOptions
            {
                Enabled = true,
                Policies = policies,
            }
        });
        return new AccessControlRule(options, NullLogger<AccessControlRule>.Instance);
    }

    private static QueryContext Ctx(string sql, string? user = null, string? db = null, string? app = null, string? ip = null)
        => new()
        {
            SqlText = sql,
            Username = user,
            Database = db,
            AppName = app,
            ClientIp = ip,
        };

    // =============================================
    // TABLE-LEVEL BLOCKING
    // =============================================

    [Fact]
    public void Blocks_Select_OnDeniedTable()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block Salary table",
            ObjectPattern = @"^(dbo\.)?Employees$",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT * FROM Employees", user: "analyst")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_Select_OnDeniedTable_WithSchema()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block Salary table",
            ObjectPattern = @"^(dbo\.)?Employees$",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT * FROM dbo.Employees", user: "analyst")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Allows_Select_OnNonMatchingTable()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block Salary table",
            ObjectPattern = @"^(dbo\.)?Employees$",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT * FROM Products", user: "analyst")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // OPERATION-LEVEL BLOCKING
    // =============================================

    [Fact]
    public void Blocks_Delete_ButAllows_Select_OnSameTable()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block DELETE on Customers",
            ObjectPattern = @"^Customers$",
            Operations = [SqlOperation.Delete],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("DELETE FROM Customers WHERE id = 1")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("SELECT * FROM Customers WHERE id = 1")).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void Blocks_Update_OnDeniedTable()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block UPDATE on Orders",
            ObjectPattern = @"^Orders$",
            Operations = [SqlOperation.Update],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("UPDATE Orders SET status = 'cancelled' WHERE id = 1")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_Insert_OnDeniedTable()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block INSERT on AuditLog",
            ObjectPattern = @"^AuditLog$",
            Operations = [SqlOperation.Insert],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("INSERT INTO AuditLog (action) VALUES ('test')")).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // COLUMN-LEVEL BLOCKING
    // =============================================

    [Fact]
    public void Blocks_Select_OnDeniedColumn()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block SSN column",
            ObjectPattern = @"^Employees$",
            Columns = ["SSN", "Salary"],
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT SSN FROM Employees")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Allows_Select_OnNonDeniedColumn()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block SSN column",
            ObjectPattern = @"^Employees$",
            Columns = ["SSN", "Salary"],
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT Name, Email FROM Employees")).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void Blocks_Update_OnDeniedColumn()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block Salary update",
            ObjectPattern = @"^Employees$",
            Columns = ["Salary"],
            Operations = [SqlOperation.Update],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("UPDATE Employees SET Salary = 999999 WHERE id = 1")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Allows_Update_OnNonDeniedColumn()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block Salary update",
            ObjectPattern = @"^Employees$",
            Columns = ["Salary"],
            Operations = [SqlOperation.Update],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("UPDATE Employees SET Name = 'Bob' WHERE id = 1")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // USER-SCOPED POLICIES
    // =============================================

    [Fact]
    public void Blocks_SpecificUser_Only()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block analyst from Payments",
            Users = ["analyst"],
            ObjectPattern = @"^Payments$",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT * FROM Payments", user: "analyst")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("SELECT * FROM Payments", user: "admin")).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void UserMatch_IsCaseInsensitive()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block analyst",
            Users = ["Analyst"],
            ObjectPattern = @"^Payments$",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT * FROM Payments", user: "analyst")).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // APP NAME SCOPED POLICIES
    // =============================================

    [Fact]
    public void Blocks_SpecificAppName()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block SSMS from sensitive tables",
            AppNames = ["Microsoft SQL Server Management Studio"],
            ObjectPattern = @"^Salary$",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT * FROM Salary", app: "Microsoft SQL Server Management Studio")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("SELECT * FROM Salary", app: "MyWebApp")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // DATABASE SCOPED POLICIES
    // =============================================

    [Fact]
    public void Blocks_OnlyInSpecifiedDatabase()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block in production DB",
            Database = "ProductionDB",
            ObjectPattern = @"^Users$",
            Operations = [SqlOperation.Delete],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("DELETE FROM Users WHERE id = 1", db: "ProductionDB")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("DELETE FROM Users WHERE id = 1", db: "TestDB")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // PRIORITY ORDERING
    // =============================================

    [Fact]
    public void HigherPriority_DenyOverridesLowerAllow()
    {
        var rule = CreateRule(
            new AccessControlPolicy
            {
                Name = "Deny all from Salary",
                Priority = 100,
                ObjectPattern = @"^Salary$",
                Operations = [SqlOperation.Select],
                Action = PolicyAction.Deny,
            },
            new AccessControlPolicy
            {
                Name = "Allow admin",
                Priority = 50,
                Users = ["admin"],
                ObjectPattern = @"^Salary$",
                Operations = [SqlOperation.Select],
                Action = PolicyAction.Allow,
            }
        );

        // High-priority deny wins
        rule.Evaluate(Ctx("SELECT * FROM Salary", user: "admin")).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // JOIN QUERIES
    // =============================================

    [Fact]
    public void Blocks_Join_WhenOneTableIsDenied()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block Salary table",
            ObjectPattern = @"^Salary$",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT e.Name, s.Amount FROM Employees e JOIN Salary s ON e.id = s.emp_id"))
            .IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Allows_Join_WhenNoTableIsDenied()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block Salary table",
            ObjectPattern = @"^Salary$",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT o.id FROM Orders o JOIN Products p ON o.product_id = p.id"))
            .IsBlocked.Should().BeFalse();
    }

    // =============================================
    // MULTIPLE POLICIES
    // =============================================

    [Fact]
    public void MultiplePolicies_AllEvaluated()
    {
        var rule = CreateRule(
            new AccessControlPolicy
            {
                Name = "Block DELETE on Orders",
                ObjectPattern = @"^Orders$",
                Operations = [SqlOperation.Delete],
                Action = PolicyAction.Deny,
            },
            new AccessControlPolicy
            {
                Name = "Block SELECT on Secrets",
                ObjectPattern = @"^Secrets$",
                Operations = [SqlOperation.Select],
                Action = PolicyAction.Deny,
            }
        );

        rule.Evaluate(Ctx("DELETE FROM Orders WHERE id = 1")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("SELECT * FROM Secrets")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("SELECT * FROM Orders")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // CLIENT IP SCOPED
    // =============================================

    [Fact]
    public void Blocks_SpecificClientIp()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block external IP",
            ClientIps = ["192.168.1.100"],
            ObjectPattern = @"^.*$",
            Operations = [SqlOperation.Delete],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("DELETE FROM Users WHERE id = 1", ip: "192.168.1.100")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("DELETE FROM Users WHERE id = 1", ip: "10.0.0.1")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // DISABLED RULE
    // =============================================

    [Fact]
    public void Disabled_DoesNotBlock()
    {
        var options = Options.Create(new RuleOptions
        {
            AccessControl = new AccessControlOptions
            {
                Enabled = false,
                Policies =
                [
                    new AccessControlPolicy
                    {
                        ObjectPattern = @".*",
                        Operations = [SqlOperation.Select],
                        Action = PolicyAction.Deny,
                    }
                ]
            }
        });
        var rule = new AccessControlRule(options, NullLogger<AccessControlRule>.Instance);

        rule.Evaluate(Ctx("SELECT * FROM Anything")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // WILDCARD / REGEX PATTERNS
    // =============================================

    [Fact]
    public void Blocks_WildcardPattern_AllTables()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block all deletes for user",
            Users = ["readonly_user"],
            ObjectPattern = @".*",
            Operations = [SqlOperation.Delete, SqlOperation.Update, SqlOperation.Insert],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("DELETE FROM AnyTable WHERE id = 1", user: "readonly_user")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("UPDATE AnyTable SET x = 1", user: "readonly_user")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("SELECT * FROM AnyTable", user: "readonly_user")).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void Blocks_SuffixPattern()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            Name = "Block sensitive tables",
            ObjectPattern = @"_sensitive$",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("SELECT * FROM data_sensitive")).IsBlocked.Should().BeTrue();
        rule.Evaluate(Ctx("SELECT * FROM data_public")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // EMPTY / EDGE CASES
    // =============================================

    [Fact]
    public void NoPolicies_AllowsEverything()
    {
        var rule = CreateRule();
        rule.Evaluate(Ctx("SELECT * FROM Anything")).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void EmptySql_Allowed()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            ObjectPattern = @".*",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        rule.Evaluate(Ctx("")).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void NonTableQuery_Allowed()
    {
        var rule = CreateRule(new AccessControlPolicy
        {
            ObjectPattern = @".*",
            Operations = [SqlOperation.Select],
            Action = PolicyAction.Deny,
        });

        // SELECT without FROM clause — no table access
        rule.Evaluate(Ctx("SELECT 1")).IsBlocked.Should().BeFalse();
        rule.Evaluate(Ctx("SELECT GETDATE()")).IsBlocked.Should().BeFalse();
    }
}
