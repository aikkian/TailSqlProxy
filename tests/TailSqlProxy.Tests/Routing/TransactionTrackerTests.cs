using FluentAssertions;
using TailSqlProxy.Routing;
using Xunit;

namespace TailSqlProxy.Tests.Routing;

public class TransactionTrackerTests
{
    [Fact]
    public void InitialState_NoTransaction()
    {
        var tracker = new TransactionTracker();
        tracker.InTransaction.Should().BeFalse();
        tracker.Depth.Should().Be(0);
    }

    [Fact]
    public void BeginTran_EntersTransaction()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("BEGIN TRANSACTION");
        tracker.InTransaction.Should().BeTrue();
        tracker.Depth.Should().Be(1);
    }

    [Fact]
    public void BeginAndCommit_ExitsTransaction()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("BEGIN TRANSACTION");
        tracker.TrackSqlBatch("COMMIT");
        tracker.InTransaction.Should().BeFalse();
        tracker.Depth.Should().Be(0);
    }

    [Fact]
    public void BeginAndRollback_ExitsTransaction()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("BEGIN TRANSACTION");
        tracker.TrackSqlBatch("ROLLBACK");
        tracker.InTransaction.Should().BeFalse();
        tracker.Depth.Should().Be(0);
    }

    [Fact]
    public void NestedTransactions_TracksDepth()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("BEGIN TRAN");
        tracker.TrackSqlBatch("BEGIN TRAN");
        tracker.Depth.Should().Be(2);
        tracker.InTransaction.Should().BeTrue();

        tracker.TrackSqlBatch("COMMIT");
        tracker.Depth.Should().Be(1);
        tracker.InTransaction.Should().BeTrue();

        tracker.TrackSqlBatch("COMMIT");
        tracker.Depth.Should().Be(0);
        tracker.InTransaction.Should().BeFalse();
    }

    [Fact]
    public void FullRollback_ResetsAllNesting()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("BEGIN TRAN");
        tracker.TrackSqlBatch("BEGIN TRAN");
        tracker.TrackSqlBatch("BEGIN TRAN");
        tracker.Depth.Should().Be(3);

        // Full ROLLBACK (no savepoint name) resets everything
        tracker.TrackSqlBatch("ROLLBACK");
        tracker.Depth.Should().Be(0);
        tracker.InTransaction.Should().BeFalse();
    }

    [Fact]
    public void RollbackToSavepoint_DecrementsDepth()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("BEGIN TRAN");
        tracker.TrackSqlBatch("SAVE TRANSACTION sp1");
        tracker.Depth.Should().Be(1); // SAVE doesn't increase depth

        tracker.TrackSqlBatch("ROLLBACK TRANSACTION sp1");
        // Named rollback decrements depth
        tracker.Depth.Should().Be(0);
    }

    [Fact]
    public void ExtraCommit_ClampedToZero()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("COMMIT"); // No BEGIN — should not go negative
        tracker.Depth.Should().Be(0);
        tracker.InTransaction.Should().BeFalse();
    }

    [Fact]
    public void Reset_ClearsState()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("BEGIN TRAN");
        tracker.TrackSqlBatch("BEGIN TRAN");
        tracker.Reset();
        tracker.InTransaction.Should().BeFalse();
        tracker.Depth.Should().Be(0);
    }

    [Fact]
    public void NullOrEmpty_NoEffect()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch(null);
        tracker.TrackSqlBatch("");
        tracker.TrackSqlBatch("   ");
        tracker.InTransaction.Should().BeFalse();
    }

    [Fact]
    public void SelectsDoNotAffectTransaction()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("BEGIN TRAN");
        tracker.TrackSqlBatch("SELECT * FROM Orders");
        tracker.TrackSqlBatch("SELECT * FROM Items");
        tracker.Depth.Should().Be(1);
        tracker.InTransaction.Should().BeTrue();
    }

    [Fact]
    public void BatchWithMultipleStatements()
    {
        var tracker = new TransactionTracker();
        tracker.TrackSqlBatch("BEGIN TRAN; BEGIN TRAN");
        tracker.Depth.Should().Be(2);

        tracker.TrackSqlBatch("COMMIT; COMMIT");
        tracker.Depth.Should().Be(0);
    }
}
