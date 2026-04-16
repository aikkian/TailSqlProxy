using Microsoft.SqlServer.TransactSql.ScriptDom;

namespace TailSqlProxy.Routing;

/// <summary>
/// Classifies SQL queries as read-only or read-write using AST analysis.
/// Used by the read/write split router to decide which upstream connection to use.
/// </summary>
public static class QueryClassifier
{
    /// <summary>
    /// Returns true if the SQL batch contains only read-only statements (SELECT, SET, PRINT, etc.).
    /// Returns false for DML (INSERT, UPDATE, DELETE, MERGE), DDL, EXEC, transactions, or unparseable SQL.
    /// </summary>
    public static bool IsReadOnly(string? sqlText)
    {
        if (string.IsNullOrWhiteSpace(sqlText))
            return false; // Unknown intent — route to primary

        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(sqlText);
        var fragment = parser.Parse(reader, out var errors);

        if (errors.Count > 0)
            return false; // Can't parse — safe default is primary

        var visitor = new ReadOnlyVisitor();
        fragment.Accept(visitor);

        return visitor.HasStatements && !visitor.HasWriteOperation;
    }

    /// <summary>
    /// Returns true if the SQL text contains transaction control statements
    /// (BEGIN TRAN, COMMIT, ROLLBACK, SAVE TRANSACTION).
    /// </summary>
    public static bool ContainsTransactionControl(string? sqlText)
    {
        if (string.IsNullOrWhiteSpace(sqlText))
            return false;

        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(sqlText);
        var fragment = parser.Parse(reader, out var errors);

        if (errors.Count > 0)
            return false;

        var visitor = new TransactionControlVisitor();
        fragment.Accept(visitor);

        return visitor.HasTransactionControl;
    }

    private sealed class ReadOnlyVisitor : TSqlFragmentVisitor
    {
        public bool HasStatements { get; private set; }
        public bool HasWriteOperation { get; private set; }

        // --- Write operations ---

        public override void Visit(InsertSpecification node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(UpdateSpecification node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(DeleteSpecification node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(MergeSpecification node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(TruncateTableStatement node) { HasStatements = true; HasWriteOperation = true; }

        // DDL statements
        public override void Visit(CreateTableStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(AlterTableStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(DropTableStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(CreateIndexStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(AlterIndexStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(DropIndexStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(CreateViewStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(AlterViewStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(DropViewStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(CreateProcedureStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(AlterProcedureStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(DropProcedureStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(CreateFunctionStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(AlterFunctionStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(DropFunctionStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(CreateTriggerStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(AlterTriggerStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(DropTriggerStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(CreateSchemaStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(DropSchemaStatement node) { HasStatements = true; HasWriteOperation = true; }

        // Execute stored procedures — can't know if they write, so treat as write
        public override void Visit(ExecuteStatement node) { HasStatements = true; HasWriteOperation = true; }

        // Transaction control — must go to primary
        public override void Visit(BeginTransactionStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(CommitTransactionStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(RollbackTransactionStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(SaveTransactionStatement node) { HasStatements = true; HasWriteOperation = true; }

        // Grant/Revoke/Deny
        public override void Visit(GrantStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(RevokeStatement node) { HasStatements = true; HasWriteOperation = true; }
        public override void Visit(DenyStatement node) { HasStatements = true; HasWriteOperation = true; }

        // Bulk insert
        public override void Visit(BulkInsertStatement node) { HasStatements = true; HasWriteOperation = true; }

        // --- Read-only operations ---

        public override void Visit(SelectStatement node)
        {
            HasStatements = true;
            // SELECT INTO creates a table — it's a write operation
            if (node.Into != null)
                HasWriteOperation = true;
        }

        // SET statements are read-only session configuration
        public override void Visit(SetVariableStatement node) { HasStatements = true; }
        public override void Visit(PredicateSetStatement node) { HasStatements = true; }
        public override void Visit(SetTransactionIsolationLevelStatement node) { HasStatements = true; }

        // DECLARE is read-only
        public override void Visit(DeclareVariableStatement node) { HasStatements = true; }

        // PRINT and RAISERROR are read-only
        public override void Visit(PrintStatement node) { HasStatements = true; }
        public override void Visit(RaiseErrorStatement node) { HasStatements = true; }

        // USE database is read-only
        public override void Visit(UseStatement node) { HasStatements = true; }
    }

    private sealed class TransactionControlVisitor : TSqlFragmentVisitor
    {
        public bool HasTransactionControl { get; private set; }

        public override void Visit(BeginTransactionStatement node) => HasTransactionControl = true;
        public override void Visit(CommitTransactionStatement node) => HasTransactionControl = true;
        public override void Visit(RollbackTransactionStatement node) => HasTransactionControl = true;
        public override void Visit(SaveTransactionStatement node) => HasTransactionControl = true;
    }
}
