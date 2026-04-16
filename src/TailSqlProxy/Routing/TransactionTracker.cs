using Microsoft.SqlServer.TransactSql.ScriptDom;

namespace TailSqlProxy.Routing;

/// <summary>
/// Tracks transaction state across a client session.
/// When a transaction is active, all queries must be routed to the primary connection
/// to maintain transactional consistency.
/// </summary>
public sealed class TransactionTracker
{
    private int _transactionDepth;

    /// <summary>True if there is an active transaction (one or more nested BEGIN TRAN).</summary>
    public bool InTransaction => _transactionDepth > 0;

    /// <summary>Current nesting depth of transactions.</summary>
    public int Depth => _transactionDepth;

    /// <summary>
    /// Analyzes a SQL batch and updates the transaction depth.
    /// Call this before routing each query.
    /// </summary>
    public void TrackSqlBatch(string? sqlText)
    {
        if (string.IsNullOrWhiteSpace(sqlText))
            return;

        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(sqlText);
        var fragment = parser.Parse(reader, out var errors);

        if (errors.Count > 0)
            return; // Can't parse — don't change state

        var visitor = new TransactionVisitor();
        fragment.Accept(visitor);

        _transactionDepth += visitor.BeginCount;
        _transactionDepth -= visitor.CommitCount;
        _transactionDepth -= visitor.RollbackCount;

        // Rollback resets everything regardless of nesting
        if (visitor.HasFullRollback)
            _transactionDepth = 0;

        // Clamp to 0 (extra COMMIT/ROLLBACK without matching BEGIN)
        if (_transactionDepth < 0)
            _transactionDepth = 0;
    }

    /// <summary>Resets transaction tracking (e.g., on connection reset).</summary>
    public void Reset() => _transactionDepth = 0;

    private sealed class TransactionVisitor : TSqlFragmentVisitor
    {
        public int BeginCount { get; private set; }
        public int CommitCount { get; private set; }
        public int RollbackCount { get; private set; }
        public bool HasFullRollback { get; private set; }

        public override void Visit(BeginTransactionStatement node)
        {
            BeginCount++;
        }

        public override void Visit(CommitTransactionStatement node)
        {
            CommitCount++;
        }

        public override void Visit(RollbackTransactionStatement node)
        {
            // ROLLBACK without a savepoint name rolls back the entire transaction
            if (node.Name == null)
                HasFullRollback = true;
            else
                RollbackCount++;
        }
    }
}
