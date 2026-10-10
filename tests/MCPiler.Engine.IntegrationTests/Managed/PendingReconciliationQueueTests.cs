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
        queue.Acknowledge("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, runtimeRevision: 1);

        Assert.Equal(1, queue.Count);

        queue.Acknowledge("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, runtimeRevision: 2);

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
    public void An_overflow_eviction_requests_recovery_and_the_evicted_identity_can_be_re_derived()
    {
        var queue = new PendingReconciliationQueue(maximumEntries: 2);

        queue.Add("/mcp/connector", "profile", "slot-0", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        queue.Add("/mcp/connector", "profile", "slot-1", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        queue.Add("/mcp/connector", "profile", "slot-2", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);

        // slot-0 was evicted, so the worker must be told to re-derive it from its durable record rather
        // than waiting for a generation activation that may never arrive (R8.5).
        Assert.True(queue.RecoveryRequested);
        Assert.DoesNotContain(
            queue.Snapshot(),
            entry => string.Equals(entry.Slot, "slot-0", StringComparison.Ordinal));

        // A recovery replay re-admits the evicted identity (as the batch replay would), so it is not
        // stranded. Re-admitting into the full queue evicts another identity and bumps the version again.
        queue.Add("/mcp/connector", "profile", "slot-0", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        Assert.Contains(
            queue.Snapshot(),
            entry => string.Equals(entry.Slot, "slot-0", StringComparison.Ordinal));
        Assert.True(queue.RecoveryRequested);

        // Acknowledging only the version observed before the replay would leave a later eviction
        // uncovered; acknowledging the current version completes the recovery (R9.2).
        queue.AcknowledgeRecovery(queue.RecoveryVersion);
        Assert.False(queue.RecoveryRequested);

        // The capacity is exposed for a bounded per-pass replay.
        Assert.Equal(2, queue.Capacity);
    }

    [Fact]
    public void An_eviction_during_a_recovery_replay_keeps_recovery_requested()
    {
        var queue = new PendingReconciliationQueue(maximumEntries: 2);

        queue.Add("/mcp/connector", "profile", "slot-0", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        queue.Add("/mcp/connector", "profile", "slot-1", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        queue.Add("/mcp/connector", "profile", "slot-2", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);

        // The worker observes the version before the replay.
        var observed = queue.RecoveryVersion;

        // A further eviction happens before the worker acknowledges (a concurrent rotation, or the replay
        // itself re-overflowing the fixed-order head).
        queue.Add("/mcp/connector", "profile", "slot-3", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);

        queue.AcknowledgeRecovery(observed);
        Assert.True(queue.RecoveryRequested);

        queue.AcknowledgeRecovery(queue.RecoveryVersion);
        Assert.False(queue.RecoveryRequested);
    }

    [Fact]
    public void A_recovery_replay_does_not_re_admit_an_acknowledged_version()
    {
        var queue = new PendingReconciliationQueue();

        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        queue.Acknowledge("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, runtimeRevision: 1);
        Assert.Equal(0, queue.Count);

        // Until the next generation is delivered, the manifest still declares the older revision, so a
        // recovery replay would see the durable record ahead of the declaration. It must not resend a
        // version the Platform already decided (R8.5).
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        Assert.Equal(0, queue.Count);

        // A genuinely newer revision is still admitted.
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, previousRuntimeRevision: 1, runtimeRevision: 2);
        Assert.Equal(1, queue.Count);

        // A newer authority epoch with a lower revision supersedes the same slot's queued entry
        // (epoch is the outer ordering).
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 2, previousRuntimeRevision: 1, runtimeRevision: 1);
        PendingReconciliation newest = Assert.Single(queue.Snapshot());
        Assert.Equal(2, newest.AuthorityEpoch);
        Assert.Equal(1, newest.RuntimeRevision);
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

        queue.Acknowledge("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, runtimeRevision: 2);

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
            queue.Acknowledge("/mcp/connector", "profile", "refreshToken", authorityEpoch: 1, runtimeRevision: index);
        });

        // No acknowledgement names revision 500, so the highest rotation must remain queued.
        PendingReconciliation entry = Assert.Single(queue.Snapshot());
        Assert.Equal(500, entry.RuntimeRevision);
    }

    [Fact]
    public void A_rotation_under_a_newer_epoch_with_a_lower_revision_supersedes_the_older_entry()
    {
        var queue = new PendingReconciliationQueue();

        // An older-epoch entry with a high revision is queued first.
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 10, previousRuntimeRevision: 14, runtimeRevision: 15);

        // A newer authority epoch carries a lower revision. Epoch is the outer ordering, so the newer
        // rotation must supersede the older entry rather than being dropped by a revision-only
        // comparison (epoch 11 revision 1 vs epoch 10 revision 15) and losing the newer credential.
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 11, previousRuntimeRevision: 0, runtimeRevision: 1);

        PendingReconciliation entry = Assert.Single(queue.Snapshot());
        Assert.Equal(11, entry.AuthorityEpoch);
        Assert.Equal(1, entry.RuntimeRevision);
        Assert.Equal(0, entry.PreviousRuntimeRevision);
    }

    [Fact]
    public void An_acknowledgement_for_an_older_epoch_does_not_remove_a_newer_epoch_entry()
    {
        var queue = new PendingReconciliationQueue();

        // An older-epoch entry with a high revision is queued and reconciled.
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 10, previousRuntimeRevision: 14, runtimeRevision: 15);

        // Before the acknowledgement arrives, a newer authority epoch replaces it with a lower revision.
        queue.Add("/mcp/connector", "profile", "refreshToken", authorityEpoch: 11, previousRuntimeRevision: 0, runtimeRevision: 1);

        // The stale acknowledgement names epoch 10 revision 15. It must not remove the epoch-11 entry
        // merely because 1 <= 15; the full version identifies which report was processed (R7.1).
        queue.Acknowledge("/mcp/connector", "profile", "refreshToken", authorityEpoch: 10, runtimeRevision: 15);

        PendingReconciliation entry = Assert.Single(queue.Snapshot());
        Assert.Equal(11, entry.AuthorityEpoch);
        Assert.Equal(1, entry.RuntimeRevision);

        // The newer epoch is acknowledged on its own version and then removed.
        queue.Acknowledge("/mcp/connector", "profile", "refreshToken", authorityEpoch: 11, runtimeRevision: 1);
        Assert.Equal(0, queue.Count);
    }
    
    [Fact]
    public void An_overflow_trim_raced_by_a_newer_replacement_keeps_the_newer_entry()
    {
        var queue = new PendingReconciliationQueue(maximumEntries: 2);

        queue.Add("/mcp/connector", "profile", "slot-0", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);
        queue.Add("/mcp/connector", "profile", "slot-1", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);

        // When the third identity overflows and Trim snapshots slot-0 as the oldest candidate, a
        // concurrent rotation replaces slot-0 with a newer revision before Trim removes anything. The
        // conditional removal must not delete the newer replacement (R6.6).
        queue.OnTrimSnapshot = () =>
        {
            queue.OnTrimSnapshot = null;
            queue.Add("/mcp/connector", "profile", "slot-0", authorityEpoch: 1, previousRuntimeRevision: 1, runtimeRevision: 2);
        };

        queue.Add("/mcp/connector", "profile", "slot-2", authorityEpoch: 1, previousRuntimeRevision: 0, runtimeRevision: 1);

        Assert.Equal(2, queue.Count);
        PendingReconciliation replaced = Assert.Single(
            queue.Snapshot(),
            entry => string.Equals(entry.Slot, "slot-0", StringComparison.Ordinal));
        Assert.Equal(2, replaced.RuntimeRevision);
    }
}
