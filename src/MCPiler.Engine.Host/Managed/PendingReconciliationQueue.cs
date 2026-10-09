using System.Collections.Concurrent;
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
    private long _sequence;

    /// <summary>Creates the queue with a bounded capacity.</summary>
    public PendingReconciliationQueue(int maximumEntries = DefaultMaximumEntries)
    {
        _maximumEntries = maximumEntries > 0 ? maximumEntries : DefaultMaximumEntries;
    }

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
        _pending[key] = new Entry(
            authorityEpoch,
            previousRuntimeRevision,
            runtimeRevision,
            Interlocked.Increment(ref _sequence));

        Trim();
    }

    /// <summary>
    /// Applies the bounded capacity by evicting the oldest queued identities. The record just
    /// admitted carries the highest sequence and is therefore never the one evicted, so the newest
    /// authoritative revision is not silently dropped.
    /// </summary>
    private void Trim()
    {
        if (_pending.Count <= _maximumEntries)
        {
            return;
        }

        var overflow = _pending
            .OrderBy(pair => pair.Value.Sequence)
            .Take(_pending.Count - _maximumEntries);
        foreach (var pair in overflow)
        {
            _pending.TryRemove(pair.Key, out _);
        }
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
    /// Removes a pending report, but only when the acknowledged revision is the one still queued.
    /// A rotation that advanced past the acknowledged revision stays pending, so a delayed
    /// acknowledgement cannot silently drop a newer credential change.
    /// </summary>
    public void Acknowledge(string mount, string profileId, string slot, long runtimeRevision)
    {
        var key = new Key(mount, profileId, slot);

        if (_pending.TryGetValue(key, out var entry) && entry.RuntimeRevision <= runtimeRevision)
        {
            _pending.TryRemove(key, out _);
        }
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
/// <param name="PreviousRuntimeRevision">The revision before the rotation.</param>
/// <param name="RuntimeRevision">The revision the rotation established.</param>
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
