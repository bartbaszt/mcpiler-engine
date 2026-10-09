using MCPiler.Engine.Host.Managed;
using Xunit;

namespace MCPiler.Engine.IntegrationTests.Managed;

/// <summary>
/// The pending-reconciliation queue is bounded and coalescing: repeated rotations of one slot keep
/// one entry, and a distinct-slot burst cannot grow the queue without limit or evict the newest
/// authoritative revision (MTH-ENG-10).
/// </summary>
public sealed class PendingReconciliationQueueTests
{
    [Fact]
    public void Repeated_rotations_of_one_slot_coalesce_to_a_single_newest_entry()
    {
        var queue = new PendingReconciliationQueue();

        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 1, runtimeRevision: 2);

        Assert.Equal(1, queue.Count);
        PendingReconciliation entry = Assert.Single(queue.Snapshot());
        Assert.Equal(2, entry.RuntimeRevision);
    }

    [Fact]
    public void A_distinct_slot_burst_is_bounded_and_keeps_the_newest_revision()
    {
        var queue = new PendingReconciliationQueue(maximumEntries: 3);

        for (var index = 0; index < 10; index++)
        {
            queue.Add("/mcp/connector", "profile", "slot-" + index, authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        }

        // Bounded: never more than the configured capacity.
        Assert.Equal(3, queue.Count);

        // The newest authoritative revision is retained, never silently dropped.
        Assert.Contains(
            queue.Snapshot(),
            entry => string.Equals(entry.Slot, "slot-9", StringComparison.Ordinal));
    }

    [Fact]
    public void An_acknowledgement_below_a_newer_queued_revision_does_not_drop_it()
    {
        var queue = new PendingReconciliationQueue();

        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 2);

        // A delayed acknowledgement for an older revision must not remove the newer queued one.
        queue.Acknowledge("/mcp/connector", "profile", "refreshToken", runtimeRevision: 1);

        Assert.Equal(1, queue.Count);

        queue.Acknowledge("/mcp/connector", "profile", "refreshToken", runtimeRevision: 2);

        Assert.Equal(0, queue.Count);
    }
}
