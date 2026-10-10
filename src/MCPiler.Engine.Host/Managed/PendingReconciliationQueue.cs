using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json;

namespace MCPiler.Engine.Host.Managed;

/// <summary>
/// The rotations this process has committed locally and has not yet reconciled with Platform.
///
/// <para>
/// Only identities are queued — mount, profile, slot, epoch and revision — never a value. A
/// pending report is regenerated from the authoritative encrypted record at send time, which is
/// what keeps the queue from being a second copy of a credential: a rotation superseded before it
/// is acknowledged is simply never sent, and one the store no longer holds disappears on its own.
/// </para>
///
/// <para>
/// The queue is in memory by design. Persisting it would make an unsent report outlive the process
/// that committed the rotation it describes, and the record it names is durable already.
/// </para>
/// </summary>
internal sealed class PendingReconciliationQueue
{
    /// <summary>The default maximum number of distinct pending slot identities retained.</summary>
    public const int DefaultMaximumEntries = 256;

    private readonly ConcurrentDictionary<Key, Entry> _pending = new();
    private readonly int _maximumEntries;
    private readonly Action<string>? _diagnostics;
    private long _sequence;

    /// <summary>Creates the queue with a bounded capacity.</summary>
    /// <param name="maximumEntries">The most distinct pending slot identities retained.</param>
    /// <param name="diagnostics">Where a bounded-capacity eviction is reported, or null for none.</param>
    public PendingReconciliationQueue(int maximumEntries = DefaultMaximumEntries, Action<string>? diagnostics = null)
    {
        _maximumEntries = maximumEntries > 0 ? maximumEntries : DefaultMaximumEntries;
        _diagnostics = diagnostics;
    }

    /// <summary>
    /// Test seam: invoked after <see cref="Add"/> has read the current entry and before it applies
    /// its conditional write, so a test can interleave a concurrent mutation deterministically.
    /// Production code never sets it.
    /// </summary>
    internal Action? OnAddRead { get; set; }

    /// <summary>
    /// Test seam: invoked after <see cref="Acknowledge"/> has read the current entry and before it
    /// applies its conditional remove, so a test can interleave a concurrent mutation deterministically.
    /// Production code never sets it.
    /// </summary>
    internal Action? OnAcknowledgeRead { get; set; }

    /// <summary>
    /// Test seam: invoked after <see cref="Trim"/> has computed its eviction candidates and before it
    /// removes any, so a test can interleave a concurrent replacement deterministically. Production
    /// code never sets it.
    /// </summary>
    internal Action? OnTrimSnapshot { get; set; }

    /// <summary>Records one committed rotation as awaiting acknowledgement.</summary>
    public void Add(
        string mount,
        string profileId,
        string slot,
        long authorityEpoch,
        long previousRuntimeRevision,
        long runtimeRevision)
    {
        var key = new Key(mount, profileId, slot);
        var sequence = Interlocked.Increment(ref _sequence);

        // A compare-and-swap loop: read-decide-write must be one atomic unit. A plain
        // TryGetValue-then-indexer set lets two concurrent Add calls interleave so an older revision
        // overwrites a newer one, and the Platform would then refuse the report as
        // RevisionNotSequential and the newer credential change would be lost.
        while (true)
        {
            _pending.TryGetValue(key, out var queued);
            OnAddRead?.Invoke();

            // Keep the newest authoritative rotation. Authority epoch is the outer ordering: a rotation
            // under a newer epoch supersedes an older-epoch entry regardless of its revision, so an
            // epoch-11/revision-1 rotation must not be dropped because an epoch-10/revision-15 entry is
            // queued (R6.4). Within one epoch the higher revision wins.
            if (queued is not null && IsNotNewer(queued, authorityEpoch, runtimeRevision))
            {
                return;
            }

            // Coalescing must preserve the BASE the Platform has to advance from, not the previous
            // revision of the newest rotation. Two sequential rotations (0->1 then 1->2) before the
            // first send report previous=0, revision=2 so the Platform can accept them as one atomic
            // forward transition (R4.1). Sending previous=1 while the Platform is still at 0 would be
            // refused as a revision mismatch and the newer credential would be lost.
            var basePrevious = queued is not null && queued.AuthorityEpoch == authorityEpoch
                ? queued.PreviousRuntimeRevision
                : previousRuntimeRevision;
            var candidate = new Entry(authorityEpoch, basePrevious, runtimeRevision, sequence);
            if (queued is null)
            {
                if (_pending.TryAdd(key, candidate))
                {
                    break;
                }
            }
            else if (_pending.TryUpdate(key, candidate, queued))
            {
                break;
            }

            // The entry changed under us; re-read and re-decide against the current value.
        }

        Trim();
    }

    /// <summary>
    /// Whether an already-queued entry is at least as new as an incoming rotation, ordered by authority
    /// epoch first and then by runtime revision within the same epoch.
    /// </summary>
    private static bool IsNotNewer(Entry queued, long authorityEpoch, long runtimeRevision)
        => queued.AuthorityEpoch > authorityEpoch
        || (queued.AuthorityEpoch == authorityEpoch && queued.RuntimeRevision >= runtimeRevision);

    /// <summary>
    /// Applies the bounded capacity by evicting the oldest queued identities. The record just
    /// admitted carries the highest sequence and is therefore never the one evicted, so the newest
    /// authoritative revision is not silently dropped. An eviction is reported, bounded and
    /// non-secret, so a dropped identity can be re-derived at the next activation replay rather than
    /// vanishing without a trace.
    /// </summary>
    private void Trim()
    {
        if (_pending.Count <= _maximumEntries)
        {
            return;
        }

        var overflow = _pending
            .OrderBy(pair => pair.Value.Sequence)
            .Take(_pending.Count - _maximumEntries)
            .ToArray();

        OnTrimSnapshot?.Invoke();

        // Remove only the exact pair that was observed. A plain TryRemove(key) could delete a newer
        // entry admitted after the overflow snapshot - a concurrent Add(N+1) replacing the observed
        // entry - which would drop the newer rotation report even though the capacity decision was made
        // against the older one (R6.6). An entry that changed under us is left in place; Add re-trims.
        var removed = 0;
        foreach (var pair in overflow)
        {
            if (_pending.TryRemove(new KeyValuePair<Key, Entry>(pair.Key, pair.Value)))
            {
                removed++;
            }
        }

        if (removed == 0)
        {
            return;
        }

        _diagnostics?.Invoke(
            $"The pending-reconciliation queue exceeded its capacity of {_maximumEntries} identities and "
            + $"evicted {removed} oldest entr{(removed == 1 ? "y" : "ies")}; the affected "
            + "rotations are re-derived from their durable records at the next activation replay.");
    }

    /// <summary>The reports awaiting acknowledgement, ordinally ordered for a deterministic send order.</summary>
    public IReadOnlyList<PendingReconciliation> Snapshot()
        => [.. _pending
            .OrderBy(pair => pair.Key.Mount, StringComparer.Ordinal)
            .ThenBy(pair => pair.Key.ProfileId, StringComparer.Ordinal)
            .ThenBy(pair => pair.Key.Slot, StringComparer.Ordinal)
            .Select(pair => new PendingReconciliation(
                pair.Key.Mount,
                pair.Key.ProfileId,
                pair.Key.Slot,
                pair.Value.AuthorityEpoch,
                pair.Value.PreviousRuntimeRevision,
                pair.Value.RuntimeRevision))];

    /// <summary>
    /// Removes a pending report, but only when the acknowledged full version is the one still queued.
    /// A rotation that advanced past the acknowledged revision stays pending, and - because the
    /// authority epoch is part of the identity - a rotation under a newer epoch is never removed by an
    /// acknowledgement for an older epoch, so a delayed acknowledgement cannot silently drop a newer
    /// credential change (R7.1).
    /// </summary>
    public void Acknowledge(string mount, string profileId, string slot, long authorityEpoch, long runtimeRevision)
    {
        var key = new Key(mount, profileId, slot);

        if (!_pending.TryGetValue(key, out var entry))
        {
            return;
        }

        OnAcknowledgeRead?.Invoke();

        // Only the processed version (same authority epoch, revision at or below what was reconciled)
        // is removed. A newer epoch is a different authority generation and must be acknowledged on its
        // own; a higher revision in the same epoch is a newer rotation that still needs reconciliation.
        if (entry.AuthorityEpoch != authorityEpoch || entry.RuntimeRevision > runtimeRevision)
        {
            return;
        }

        // Remove only the exact pair that was read. A plain TryRemove(key) could delete a newer entry
        // admitted after the read - a concurrent Add(N+1) racing Acknowledge(N) - which would drop the
        // newer rotation report even though it was never acknowledged.
        _pending.TryRemove(new KeyValuePair<Key, Entry>(key, entry));
    }

    /// <summary>How many reports are still awaiting acknowledgement.</summary>
    public int Count => _pending.Count;

    private readonly record struct Key(string Mount, string ProfileId, string Slot);

    private sealed record Entry(
        long AuthorityEpoch,
        long PreviousRuntimeRevision,
        long RuntimeRevision,
        long Sequence);
}

/// <summary>One queued rotation, identified without carrying its value.</summary>
/// <param name="Mount">The mount the rotation happened under.</param>
/// <param name="ProfileId">The manifest-local profile identity.</param>
/// <param name="Slot">The rotated slot.</param>
/// <param name="AuthorityEpoch">The authority epoch the rotation happened under.</param>
/// <param name="PreviousRuntimeRevision">
/// The base revision the Platform must advance from: the previous revision of the earliest
/// unreconciled rotation for this identity, so coalesced rotations are reported as one atomic
/// forward transition.
/// </param>
/// <param name="RuntimeRevision">The newest revision the rotations established.</param>
internal sealed record PendingReconciliation(
    string Mount,
    string ProfileId,
    string Slot,
    long AuthorityEpoch,
    long PreviousRuntimeRevision,
    long RuntimeRevision);

/// <summary>The Platform's answer to one reconciliation report.</summary>
internal enum ReconciliationOutcome
{
    /// <summary>The Platform accepted the replacement.</summary>
    Recorded,

    /// <summary>The Platform refused it; the report describes state it no longer holds.</summary>
    Refused,

    /// <summary>The report could not be delivered; it stays queued for the next poll.</summary>
    Unreachable,
}
