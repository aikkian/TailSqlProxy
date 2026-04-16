using FluentAssertions;
using TailSqlProxy.Routing;
using Xunit;

namespace TailSqlProxy.Tests.Routing;

public class QueryClassifierTests
{
    // ──────────────────── Read-only queries ────────────────────

    [Theory]
    [InlineData("SELECT * FROM Orders")]
    [InlineData("SELECT Id, Name FROM Orders WHERE Id = 1")]
    [InlineData("SELECT TOP 10 * FROM Orders ORDER BY Id")]
    [InlineData("SELECT COUNT(*) FROM Orders")]
    [InlineData("SELECT 1")]
    [InlineData("SELECT GETDATE()")]
    [InlineData("SELECT @@VERSION")]
    [InlineData("SELECT * FROM Orders o JOIN Items i ON o.Id = i.OrderId WHERE o.Status = 'Active'")]
    [InlineData("SELECT * FROM Orders; SELECT * FROM Items")]
    [InlineData("SELECT * FROM Orders UNION ALL SELECT * FROM ArchivedOrders")]
    public void IsReadOnly_SelectQueries(string sql)
    {
        QueryClassifier.IsReadOnly(sql).Should().BeTrue($"'{sql}' should be read-only");
    }

    [Theory]
    [InlineData("SET NOCOUNT ON")]
    [InlineData("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")]
    [InlineData("DECLARE @x INT = 1; SELECT @x")]
    [InlineData("PRINT 'hello'")]
    [InlineData("USE master")]
    public void IsReadOnly_SessionCommands(string sql)
    {
        QueryClassifier.IsReadOnly(sql).Should().BeTrue($"'{sql}' should be read-only");
    }

    // ──────────────────── Write queries ────────────────────

    [Theory]
    [InlineData("INSERT INTO Orders (Name) VALUES ('Test')")]
    [InlineData("UPDATE Orders SET Status = 'Active' WHERE Id = 1")]
    [InlineData("DELETE FROM Orders WHERE Id = 1")]
    [InlineData("DELETE FROM Orders")]
    [InlineData("MERGE INTO Target USING Source ON Target.Id = Source.Id WHEN MATCHED THEN UPDATE SET Name = Source.Name")]
    [InlineData("TRUNCATE TABLE Orders")]
    public void IsNotReadOnly_DmlQueries(string sql)
    {
        QueryClassifier.IsReadOnly(sql).Should().BeFalse($"'{sql}' should be read-write");
    }

    [Theory]
    [InlineData("CREATE TABLE Test (Id INT)")]
    [InlineData("ALTER TABLE Orders ADD Column1 INT")]
    [InlineData("DROP TABLE Orders")]
    [InlineData("CREATE INDEX IX_Test ON Orders (Id)")]
    [InlineData("CREATE VIEW vOrders AS SELECT * FROM Orders")]
    [InlineData("DROP VIEW vOrders")]
    [InlineData("CREATE PROCEDURE sp_Test AS SELECT 1")]
    [InlineData("DROP PROCEDURE sp_Test")]
    [InlineData("CREATE FUNCTION fn_Test() RETURNS INT AS BEGIN RETURN 1 END")]
    public void IsNotReadOnly_DdlQueries(string sql)
    {
        QueryClassifier.IsReadOnly(sql).Should().BeFalse($"'{sql}' should be read-write");
    }

    [Theory]
    [InlineData("EXEC sp_helpdb")]
    [InlineData("EXECUTE dbo.MyProc")]
    public void IsNotReadOnly_ExecQueries(string sql)
    {
        QueryClassifier.IsReadOnly(sql).Should().BeFalse($"'{sql}' should be read-write (exec may write)");
    }

    [Theory]
    [InlineData("BEGIN TRANSACTION")]
    [InlineData("BEGIN TRAN; SELECT * FROM Orders; COMMIT")]
    [InlineData("ROLLBACK TRANSACTION")]
    [InlineData("COMMIT TRANSACTION")]
    public void IsNotReadOnly_TransactionControl(string sql)
    {
        QueryClassifier.IsReadOnly(sql).Should().BeFalse($"'{sql}' should be read-write (transaction)");
    }

    [Fact]
    public void IsNotReadOnly_SelectInto()
    {
        var sql = "SELECT * INTO #TempOrders FROM Orders";
        QueryClassifier.IsReadOnly(sql).Should().BeFalse("SELECT INTO creates a table");
    }

    [Theory]
    [InlineData("GRANT SELECT ON Orders TO user1")]
    [InlineData("REVOKE SELECT ON Orders FROM user1")]
    [InlineData("DENY SELECT ON Orders TO user1")]
    public void IsNotReadOnly_SecurityStatements(string sql)
    {
        QueryClassifier.IsReadOnly(sql).Should().BeFalse($"'{sql}' should be read-write");
    }

    // ──────────────────── Edge cases ────────────────────

    [Fact]
    public void IsNotReadOnly_NullOrEmpty()
    {
        QueryClassifier.IsReadOnly(null).Should().BeFalse();
        QueryClassifier.IsReadOnly("").Should().BeFalse();
        QueryClassifier.IsReadOnly("   ").Should().BeFalse();
    }

    [Fact]
    public void IsNotReadOnly_InvalidSql()
    {
        QueryClassifier.IsReadOnly("THIS IS NOT VALID SQL !!!").Should().BeFalse("unparseable SQL routes to primary");
    }

    [Fact]
    public void IsNotReadOnly_MixedBatch()
    {
        var sql = "SELECT * FROM Orders; INSERT INTO Logs (Msg) VALUES ('read')";
        QueryClassifier.IsReadOnly(sql).Should().BeFalse("batch contains a write operation");
    }

    // ──────────────────── Transaction control detection ────────────────────

    [Theory]
    [InlineData("BEGIN TRANSACTION")]
    [InlineData("BEGIN TRAN")]
    [InlineData("COMMIT")]
    [InlineData("COMMIT TRANSACTION")]
    [InlineData("ROLLBACK")]
    [InlineData("ROLLBACK TRANSACTION")]
    [InlineData("SAVE TRANSACTION sp1")]
    public void ContainsTransactionControl_Detected(string sql)
    {
        QueryClassifier.ContainsTransactionControl(sql).Should().BeTrue();
    }

    [Theory]
    [InlineData("SELECT * FROM Orders")]
    [InlineData("INSERT INTO Orders (Name) VALUES ('Test')")]
    [InlineData("SET NOCOUNT ON")]
    public void ContainsTransactionControl_NotDetected(string sql)
    {
        QueryClassifier.ContainsTransactionControl(sql).Should().BeFalse();
    }

    [Fact]
    public void ContainsTransactionControl_NullOrEmpty()
    {
        QueryClassifier.ContainsTransactionControl(null).Should().BeFalse();
        QueryClassifier.ContainsTransactionControl("").Should().BeFalse();
    }
}
