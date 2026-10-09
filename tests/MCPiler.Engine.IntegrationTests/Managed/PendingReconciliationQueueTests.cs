using System;
using System.Collections.Generic;
using System.Threading.Tasks;

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

        // Coalescing keeps the earliest base, not the previous revision of the newest rotation: the
        // Platform is still at revision 0 and must accept 0 -> 2 as one atomic transition (R4.1).
        Assert.Equal(0, entry.PreviousRuntimeRevision);
    }

    [Fact]
    public void Coalesced_rotations_keep_the_earliest_unreconciled_base_across_a_longer_chain()
    {
        var queue = new PendingReconciliationQueue();

        for (var revision = 1; revision <= 5; revision++)
        {
            queue.Add(
                "/mcp/connector",
                "profile",
                "refreshToken",
                authorityEpoch: 4,
                previousRuntimeRevision: revision - 1,
                runtimeRevision: revision);
        }

        PendingReconciliation entry = Assert.Single(queue.Snapshot());
        Assert.Equal(0, entry.PreviousRuntimeRevision);
        Assert.Equal(5, entry.RuntimeRevision);
        Assert.Equal(4, entry.AuthorityEpoch);
    }

    [Fact]
    public void A_rotation_under_a_new_authority_epoch_rebases_instead_of_merging()
    {
        var queue = new PendingReconciliationQueue();

        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);

        // A rotation under a new authority epoch is not a continuation of the earlier base; it must
        // rebase to its own previous revision so the Platform can match the current epoch.
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 2, previousRuntimeRevision: 1, runtimeRevision: 2);

        PendingReconciliation entry = Assert.Single(queue.Snapshot());
        Assert.Equal(2, entry.AuthorityEpoch);
        Assert.Equal(1, entry.PreviousRuntimeRevision);
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

    [Fact]
    public void An_older_replay_after_a_newer_live_rotation_keeps_the_higher_revision()
    {
        var queue = new PendingReconciliationQueue();

        // A live rotation commits revision 5 first.
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 4, runtimeRevision: 5);

        // A replay then queues the earlier pair. It must not overwrite the newer queued rotation,
        // which the Platform would refuse as RevisionNotSequential, dropping the report.
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 3, runtimeRevision: 4);

        PendingReconciliation entry = Assert.Single(queue.Snapshot());
        Assert.Equal(5, entry.RuntimeRevision);
        Assert.Equal(4, entry.PreviousRuntimeRevision);
    }

    [Fact]
    public void An_overflow_eviction_is_reported_by_a_bounded_non_secret_diagnostic()
    {
        var diagnostics = new List<string>();
        var queue = new PendingReconciliationQueue(maximumEntries: 2, diagnostics: diagnostics.Add);

        for (var index = 0; index < 5; index++)
        {
            queue.Add("/mcp/connector", "profile", "slot-" + index, authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        }

        Assert.Equal(2, queue.Count);
        Assert.NotEmpty(diagnostics);

        // The diagnostic is bounded and names no identity or value.
        Assert.DoesNotContain("slot-", string.Join('\n', diagnostics), StringComparison.Ordinal);

        // The newest admitted identity is retained.
        Assert.Contains(
            queue.Snapshot(),
            entry => string.Equals(entry.Slot, "slot-4", StringComparison.Ordinal));
    }

    [Fact]
    public void An_acknowledgement_read_raced_by_a_newer_rotation_does_not_remove_the_newer_entry()
    {
        var queue = new PendingReconciliationQueue();
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 1, runtimeRevision: 2);

        // The exact TOCTOU Acknowledge(N) raced by Add(N+1): after Acknowledge reads revision 2, a
        // newer revision 3 is admitted before the remove. The remove must target only the read pair,
        // so the newer report is not silently dropped.
        queue.OnAcknowledgeRead = () =>
        {
            queue.OnAcknowledgeRead = null;
            queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 2, runtimeRevision: 3);
        };

        queue.Acknowledge("/mcp/connector", "profile", "refreshToken", runtimeRevision: 2);

        Assert.Equal(1, queue.Count);
        Assert.Equal(3, Assert.Single(queue.Snapshot()).RuntimeRevision);
    }

    [Fact]
    public void An_add_read_raced_by_a_newer_rotation_keeps_the_newer_revision()
    {
        var queue = new PendingReconciliationQueue();

        // Add(4) reads no entry, then a concurrent Add(5) wins before Add(4) writes. The compare-and-
        // swap retry must re-decide against revision 5 and refuse to overwrite it with revision 4.
        queue.OnAddRead = () =>
        {
            queue.OnAddRead = null;
            queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 4, runtimeRevision: 5);
        };

        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 3, runtimeRevision: 4);

        PendingReconciliation entry = Assert.Single(queue.Snapshot());
        Assert.Equal(5, entry.RuntimeRevision);
        Assert.Equal(4, entry.PreviousRuntimeRevision);
    }

    [Fact]
    public void Concurrent_add_and_acknowledge_converge_on_the_highest_revision()
    {
        var queue = new PendingReconciliationQueue();

        Parallel.For(0, 500, index =>
        {
            queue.Add(
                "/mcp/connector",
                "profile",
                "refreshToken",
                authorityEpoch: 1,
                previousRuntimeRevision: index,
                runtimeRevision: index + 1);

            // An acknowledgement for an older revision must never remove a newer queued entry.
            queue.Acknowledge("/mcp/connector", "profile", "refreshToken", runtimeRevision: index);
        });

        // No acknowledgement names revision 500, so the highest rotation must remain queued.
        PendingReconciliation entry = Assert.Single(queue.Snapshot());
        Assert.Equal(500, entry.RuntimeRevision);
    }
}
