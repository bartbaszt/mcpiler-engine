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

/// <summary>The authoritative local state of one runtime-owned OAuth refresh slot.</summary>
public enum MutableSlotDecisionKind
{
    Authorized,
    Cleared,
}

/// <summary>
/// A committed authenticated local decision. <see cref="Version"/> is an opaque compare token
/// obtained from a read, not a caller-supplied authority or a secret to serialize.
/// Legacy v1 records have no declaration/configuration binding and may only be superseded by an
/// explicit higher-epoch decision, never refreshed using the v2 compare-and-commit path.
/// </summary>
public sealed record MutableSlotDecision(
    string ProfileId,
    string Slot,
    string? ScopeFingerprint,
    string? DeclarationFingerprint,
    string? ConfigurationFingerprint,
    long AuthorityEpoch,
    long RuntimeRevision,
    MutableSlotDecisionKind Kind,
    string? RefreshToken,
    string Version = "",
    bool IsLegacy = false);

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


    /// <summary>Reads the local decision, including cleared and legacy states; null means absent.</summary>
    ValueTask<MutableSlotDecision?> LoadDecisionAsync(
        string profileId, string slot, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically compares the previously observed record version and commits the successor.
    /// Null <paramref name="expectedVersion"/> means the record was absent. The declared epoch
    /// is a lower bound on explicit local authorization/clear epochs.
    /// </summary>
    ValueTask<MutableSlotDecision> CompareAndCommitAsync(
        MutableSlotDecision successor, string? expectedVersion, long declaredEpoch,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically replaces whatever is stored for a slot with an authenticated fail-closed
    /// baseline, without requiring the predecessor to be readable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists only for the explicitly acknowledged destructive reset. Every ordinary
    /// transition observes the predecessor through <see cref="LoadDecisionAsync"/> and commits
    /// through <see cref="CompareAndCommitAsync"/>; this one does not, because the whole reason it
    /// is needed is that the predecessor cannot be authenticated with the configured key.
    /// </para>
    /// <para>
    /// Ordering is the safety argument. A reset must not retire unreadable data and then fail,
    /// because the slot would become absent and the Manifest-declared credential would apply
    /// again. The replacement is therefore the single commit point: the unreadable envelope is
    /// retired by being overwritten, never by being removed first. A caller MUST NOT delete a
    /// record before establishing the baseline.
    /// </para>
    /// </remarks>
    /// <param name="baseline">
    /// The fail-closed decision to write. It must be a cleared tombstone with revision zero and a
    /// non-empty declaration/configuration binding.
    /// </param>
    /// <param name="declaredEpoch">The Manifest-declared epoch, a lower bound on the baseline.</param>
    /// <param name="cancellationToken">The commit deadline.</param>
    ValueTask<MutableSlotDecision> EstablishBaselineAsync(
        MutableSlotDecision baseline, long declaredEpoch, CancellationToken cancellationToken);
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
    private readonly Dictionary<(string ProfileId, string Slot), string> _legacyVersions = [];
    private readonly Dictionary<(string ProfileId, string Slot), MutableSlotDecision> _decisions = [];
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
            if (_decisions.ContainsKey((profileId, slot)))
            {
                throw new RuntimeStateStoreException(profileId, slot,
                    "an authoritative local decision requires decision-aware resolution.");
            }
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
            if (_decisions.ContainsKey((record.ProfileId, record.Slot)))
            {
                throw new RuntimeStateStoreException(record.ProfileId, record.Slot,
                    "legacy replacement cannot overwrite an authoritative local decision.");
            }
            _records[(record.ProfileId, record.Slot)] = record;
            _legacyVersions[(record.ProfileId, record.Slot)] = Guid.NewGuid().ToString("N");
        }
    }

    public ValueTask<MutableSlotDecision?> LoadDecisionAsync(
        string profileId, string slot, CancellationToken cancellationToken)
    {
        MutableSlotDecisionRules.ValidateIdentity(profileId, slot);
        lock (_gate)
        {
            return ValueTask.FromResult(FindDecisionLocked(profileId, slot));
        }
    }

    public ValueTask<MutableSlotDecision> CompareAndCommitAsync(
        MutableSlotDecision successor, string? expectedVersion, long declaredEpoch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(successor);
        MutableSlotDecisionRules.ValidateIdentity(successor.ProfileId, successor.Slot);
        lock (_gate)
        {
            var key = (successor.ProfileId, successor.Slot);
            var prior = FindDecisionLocked(successor.ProfileId, successor.Slot);
            if (prior?.Version != expectedVersion)
            {
                throw new RuntimeStateStoreException(successor.ProfileId, successor.Slot,
                    "the observed authority version has changed.");
            }

            MutableSlotDecisionRules.Validate(successor, prior, declaredEpoch);
            var committed = successor with { Version = Guid.NewGuid().ToString("N"), IsLegacy = false };
            _records.Remove(key);
            _legacyVersions.Remove(key);
            _decisions[key] = committed;
            return ValueTask.FromResult(committed);
        }
    }

    public ValueTask<MutableSlotDecision> EstablishBaselineAsync(
        MutableSlotDecision baseline, long declaredEpoch, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        MutableSlotDecisionRules.ValidateBaselineShape(baseline, declaredEpoch);
        lock (_gate)
        {
            var key = (baseline.ProfileId, baseline.Slot);
            var prior = FindDecisionLocked(baseline.ProfileId, baseline.Slot);

            // The memory store always has a readable predecessor, so it can keep the monotonicity
            // guarantee the file store gives up when the predecessor cannot be authenticated.
            if (prior is not null && baseline.AuthorityEpoch <= prior.AuthorityEpoch)
            {
                throw new RuntimeStateStoreException(baseline.ProfileId, baseline.Slot,
                    "the proposed reset baseline does not advance the current authority.");
            }

            var committed = baseline with { Version = Guid.NewGuid().ToString("N"), IsLegacy = false };
            _records.Remove(key);
            _legacyVersions.Remove(key);
            _decisions[key] = committed;
            return ValueTask.FromResult(committed);
        }
    }

    private MutableSlotDecision? FindDecisionLocked(string profileId, string slot)
    {
        if (_decisions.TryGetValue((profileId, slot), out var decision))
        {
            return decision;
        }

        if (_records.TryGetValue((profileId, slot), out var legacy))
        {
            return new MutableSlotDecision(profileId, slot, legacy.ScopeFingerprint, null, null,
                legacy.AuthorityEpoch, legacy.RuntimeRevision, MutableSlotDecisionKind.Authorized,
                legacy.Value, _legacyVersions[(profileId, slot)],
                IsLegacy: true);
        }

        return null;
    }

    /// <summary>The number of committed records. For bounded-state assertions.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _records.Count + _decisions.Count;
            }
        }
    }
}

/// <summary>Shared invariants for memory and encrypted file authority transitions.</summary>
internal static class MutableSlotDecisionRules
{
    public static void ValidateIdentity(string profileId, string slot)
    {
        // File stores retain the v1 identity hash for migration. Neither side of that hash may
        // contain its separator, or distinct (mount, profile, slot) tuples can alias one file.
        if (string.IsNullOrWhiteSpace(profileId) || string.IsNullOrWhiteSpace(slot)
            || profileId.Contains('\u001f') || slot.Contains('\u001f'))
        {
            throw new RuntimeStateStoreException(profileId, slot,
                "the local authority slot identity is invalid.");
        }
    }

    /// <summary>
    /// The shape a fail-closed reset baseline must have, checked without any readable predecessor.
    /// </summary>
    /// <remarks>
    /// A baseline is deliberately the narrowest decision the model can express: a cleared
    /// tombstone, revision zero, bound to the current declaration and configuration. It carries no
    /// secret, so an operator who has lost the key still ends up with authenticated authority
    /// rather than an absent slot the Manifest could fill again.
    /// </remarks>
    public static void ValidateBaselineShape(MutableSlotDecision baseline, long declaredEpoch)
    {
        ValidateIdentity(baseline.ProfileId, baseline.Slot);
        if (baseline.Kind != MutableSlotDecisionKind.Cleared
            || baseline.RefreshToken is not null
            || string.IsNullOrWhiteSpace(baseline.DeclarationFingerprint)
            || string.IsNullOrWhiteSpace(baseline.ConfigurationFingerprint)
            || baseline.RuntimeRevision != 0
            || declaredEpoch < 0
            || baseline.AuthorityEpoch <= declaredEpoch)
        {
            throw new RuntimeStateStoreException(baseline.ProfileId, baseline.Slot,
                "the proposed reset baseline is not a valid fail-closed authority baseline.");
        }
    }

    public static void Validate(MutableSlotDecision next, MutableSlotDecision? prior, long declaredEpoch)
    {
        ValidateIdentity(next.ProfileId, next.Slot);
        if (string.IsNullOrWhiteSpace(next.ProfileId) || string.IsNullOrWhiteSpace(next.Slot)
            || string.IsNullOrWhiteSpace(next.DeclarationFingerprint)
            || string.IsNullOrWhiteSpace(next.ConfigurationFingerprint)
            || next.Kind is not (MutableSlotDecisionKind.Authorized or MutableSlotDecisionKind.Cleared)
            || next.AuthorityEpoch < 0 || next.RuntimeRevision < 0 || declaredEpoch < 0
            || (next.Kind == MutableSlotDecisionKind.Authorized && string.IsNullOrEmpty(next.RefreshToken))
            || (next.Kind == MutableSlotDecisionKind.Cleared && next.RefreshToken is not null))
        {
            throw new RuntimeStateStoreException(next.ProfileId, next.Slot,
                "the proposed local authority decision is invalid.");
        }

        if (prior is not null && next.AuthorityEpoch == prior.AuthorityEpoch)
        {
            if (prior.IsLegacy || prior.Kind != MutableSlotDecisionKind.Authorized
                || next.Kind != MutableSlotDecisionKind.Authorized
                || next.ScopeFingerprint != prior.ScopeFingerprint
                || next.DeclarationFingerprint != prior.DeclarationFingerprint
                || next.ConfigurationFingerprint != prior.ConfigurationFingerprint
                || prior.RuntimeRevision == long.MaxValue
                || next.RuntimeRevision != prior.RuntimeRevision + 1)
            {
                throw new RuntimeStateStoreException(next.ProfileId, next.Slot,
                    "the proposed refresh does not advance the bound revision.");
            }

            return;
        }

        if (next.AuthorityEpoch <= declaredEpoch
            || (prior is not null && next.AuthorityEpoch <= prior.AuthorityEpoch)
            || next.RuntimeRevision != 0)
        {
            throw new RuntimeStateStoreException(next.ProfileId, next.Slot,
                "the proposed explicit authority epoch is not newer than the current authority.");
        }
    }
}
