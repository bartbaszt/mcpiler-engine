namespace MCPiler.Engine.Execution.RuntimeState;

/// <summary>
/// One runtime-owned mutable credential slot: a value the upstream rotates at runtime, such as a
/// refresh token the provider replaced when it issued a new access token.
/// </summary>
/// <remarks>
/// Only a slot the Manifest declares as mutable may be stored here. A static credential, a
/// managed provider value and an ephemeral access/session token are all excluded by construction:
/// the first two are deployment inputs rather than runtime state, and the last is derived material
/// that is cheap to re-acquire and expensive to keep.
/// </remarks>
/// <param name="ProfileId">The manifest-local profile identity that owns the slot.</param>
/// <param name="Slot">The slot identity within the profile, for example <c>refreshToken</c>.</param>
/// <param name="ScopeFingerprint">
/// The non-secret scope identity the value belongs to. A record whose fingerprint disagrees with
/// the deployed profile is never used: the value was minted for a different configuration.
/// </param>
/// <param name="AuthorityEpoch">The authority epoch the value was obtained under.</param>
/// <param name="RuntimeRevision">The runtime revision the value records.</param>
/// <param name="Value">The secret material. Never logged or reported.</param>
public sealed record MutableSlotRecord(
    string ProfileId,
    string Slot,
    string? ScopeFingerprint,
    long AuthorityEpoch,
    long RuntimeRevision,
    string Value);

/// <summary>
/// The narrow port through which OAuth refresh-token rotation reaches durable state.
/// </summary>
/// <remarks>
/// <para>
/// Engine core cannot touch a database or a file: reading and writing host state is the
/// deployable's business, and the authentication layer is deliberately host-free. This port is
/// the whole of what the strategy logic is allowed to know about persistence, so replacing the
/// implementation cannot change when a rotation becomes authoritative.
/// </para>
/// <para>
/// A provider that invalidates the presented refresh token when it returns a replacement makes
/// this a correctness boundary rather than a cache: the replacement must be committed before the
/// access token it produced is published anywhere, or a crash between the two leaves the
/// deployment holding an access token whose refresh credential the provider has already retired.
/// </para>
/// </remarks>
public interface IMutableSlotStore
{
    /// <summary>
    /// Loads the record for <paramref name="profileId"/> and <paramref name="slot"/>, or null
    /// when none exists.
    /// </summary>
    /// <remarks>
    /// A record from an older authority epoch MUST NOT be returned as a usable value; the caller
    /// treats a stale record exactly as it treats no record, because an explicit operator decision
    /// supersedes anything the runtime rotated under the previous epoch.
    /// </remarks>
    ValueTask<MutableSlotRecord?> LoadAsync(
        string profileId,
        string slot,
        CancellationToken cancellationToken);

    /// <summary>
    /// Commits <paramref name="record"/> as the authoritative value for its slot. After this
    /// returns, a fresh load MUST observe the record.
    /// </summary>
    ValueTask ReplaceAsync(MutableSlotRecord record, CancellationToken cancellationToken);
}

/// <summary>
/// A process-lifetime <see cref="IMutableSlotStore"/> for tests and for deployments that have not
/// configured durable runtime state.
/// </summary>
/// <remarks>
/// The default for a standalone Engine before a runtime-state key is provisioned, and the
/// substrate every strategy test drives. It is deliberately not durable: restarting the process
/// loses the rotated value, which is exactly what a deployment without a configured runtime store
/// has. The durable file-backed adapter arrives with the bounded encrypted store.
/// </remarks>
public sealed class InMemoryMutableSlotStore : IMutableSlotStore
{
    private readonly Dictionary<(string ProfileId, string Slot), MutableSlotRecord> _records = [];
    private readonly object _gate = new();

    /// <summary>Test seam: runs after the record is staged and before it is visible.</summary>
    public Func<CancellationToken, ValueTask>? OnBeforeCommitAsync { get; set; }

    /// <inheritdoc />
    public ValueTask<MutableSlotRecord?> LoadAsync(
        string profileId,
        string slot,
        CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _records.TryGetValue((profileId, slot), out var record);
            return ValueTask.FromResult(record);
        }
    }

    /// <inheritdoc />
    public async ValueTask ReplaceAsync(MutableSlotRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (OnBeforeCommitAsync is { } hook)
        {
            await hook(cancellationToken).ConfigureAwait(false);
        }

        lock (_gate)
        {
            _records[(record.ProfileId, record.Slot)] = record;
        }
    }

    /// <summary>The number of committed records. For bounded-state assertions.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _records.Count;
            }
        }
    }
}
