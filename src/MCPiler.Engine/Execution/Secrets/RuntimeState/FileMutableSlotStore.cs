using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

using MCPiler.Engine.Execution.RuntimeState;

namespace MCPiler.Engine.Execution.Secrets.RuntimeState;

/// <summary>
/// A bounded, file-backed <see cref="IMutableSlotStore"/> that encrypts every record with a
/// deployment-supplied Engine runtime-state key.
/// </summary>
/// <remarks>
/// <para>
/// This is the durable half of Engine's runtime-owned mutable authentication state. It exists for
/// exactly one class of value: a credential the upstream replaces when it is used, where losing
/// the replacement makes the deployment unable to authenticate at all. Everything else — static
/// credentials, managed payloads, access tokens, exchange and challenge material, signing output —
/// is deliberately not storable here; the port has no way to express them and this adapter adds no
/// way of its own.
/// </para>
/// <para>
/// A record is a complete, self-describing envelope. Its non-secret identity fields (mount,
/// profile, slot, scope fingerprint, authority epoch, runtime revision) are authenticated as
/// associated data together with the format byte, so a record cannot be re-labelled as another
/// slot, moved to another mount or replayed under an older epoch without the decryption failing.
/// The plaintext is only ever the slot value.
/// </para>
/// <para>
/// Replacement is write-then-rename over a sibling temporary file: the target is either the
/// complete previous record or the complete new one, and nothing reads a temporary file. A
/// failure before the rename leaves the previous record authoritative and the temporary file
/// abandoned — unreadable by construction, since resolution never looks for it.
/// </para>
/// <para>
/// Reading is fail-closed. A missing file means "no record"; a file that cannot be read,
/// authenticated or parsed raises <see cref="RuntimeStateStoreException"/> rather than being
/// treated as absent, because falling back to the declared credential after a corrupt record
/// would present a token the provider has likely already retired.
/// </para>
/// </remarks>
public sealed class FileMutableSlotStore : IMutableSlotStore
{
    /// <summary>The existing mutable-secret rotation format, retained for compatibility.</summary>
    public const byte FormatVersion = 1;

    /// <summary>The authenticated local authority decision format.</summary>
    public const byte AuthorityFormatVersion = 2;

    /// <summary>Length of the AES-GCM nonce, in bytes.</summary>
    public const int NonceLength = 12;

    /// <summary>Length of the AES-GCM authentication tag, in bytes.</summary>
    public const int TagLength = 16;

    /// <summary>File extension of a committed record.</summary>
    public const string RecordExtension = ".rstate";

    /// <summary>Temporary-file suffix used while a record is being written.</summary>
    public const string TemporarySuffix = ".tmp-";

    /// <summary>
    /// The default maximum number of committed records this store retains. A deployment's runtime
    /// state is bounded: stale/superseded records are compacted down to this cap, always keeping the
    /// newest record for every slot.
    /// </summary>
    public const int DefaultMaximumRecords = 1024;

    private const int HeaderLengthBytes = 2;
    private const int FixedPrefixLength = 1 + HeaderLengthBytes;
    private const int MinimumEnvelopeLength = FixedPrefixLength + NonceLength + TagLength;

    /// <summary>
    /// The bounded number of unreachable files (a header that does not match its path, or a
    /// duplicate of a live identity) one compaction pass reclaims. A bound keeps a pathological
    /// directory from turning maintenance into an unbounded scan-and-delete.
    /// </summary>
    private const int MaximumUnreachableRemovalsPerPass = 64;

    private static readonly JsonSerializerOptions HeaderOptions = new()
    {
        WriteIndented = false,
    };

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <summary>
    /// Roots whose stale temporaries have already been reclaimed by this process. Cleanup runs at
    /// most once per root: stores are constructed for every reconcile read and generation build, and
    /// an unconditional sweep per construction could delete a temp another writer is still filling.
    /// </summary>
    private static readonly ConcurrentDictionary<string, byte> ReclaimedRoots = new(StringComparer.Ordinal);

    /// <summary>
    /// Process-wide, reference-counted keyed gates shared by every store instance. A replacement holds
    /// a mount-scope gate (so the mount's capacity reservation is atomic across distinct slot
    /// identities) and a slot-scope gate (so its read-compare-write is atomic against another
    /// replacement of the same identity). An entry is removed once its last holder releases, so churn
    /// through distinct identities - including identities refused at the cap - does not grow process
    /// state without bound.
    /// </summary>
    private static readonly KeyedGatePool IdentityGates = new();

    private readonly string _root;
    private readonly string _mountIdentity;
    private readonly byte[] _key;

    /// <summary>Creates a store over one mount's section of a runtime-state directory.</summary>
    /// <param name="root">The directory holding this mount's records. Created when absent.</param>
    /// <param name="mountIdentity">
    /// The mount's stable identity. It binds every record to the mount that wrote it, so a record
    /// copied between mounts cannot be used.
    /// </param>
    /// <param name="key">The 32-byte runtime-state key. Never written anywhere.</param>
    public FileMutableSlotStore(string root, string mountIdentity, ReadOnlyMemory<byte> key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentException.ThrowIfNullOrWhiteSpace(mountIdentity);

        if (key.Length != 32)
        {
            throw new ArgumentException(
                "The runtime-state key must be exactly 32 bytes.",
                nameof(key));
        }

        _root = Normalize(root);
        _mountIdentity = mountIdentity;
        _key = key.ToArray();

        EnsureRoot();
        ReclaimStaleTemporariesOnce();
    }

    /// <summary>Test seam: runs after the ciphertext reaches the temporary file, before the flush.</summary>
    internal Func<CancellationToken, ValueTask>? TempWrittenBarrier { get; set; }

    /// <summary>Test seam: runs after the flush, before the atomic replacement.</summary>
    internal Func<CancellationToken, ValueTask>? TempFlushedBarrier { get; set; }

    /// <summary>Test seam: invoked at the start of a maintenance pass; returns normally in production.</summary>
    internal Action? CompactionBarrier { get; set; }

    /// <summary>
    /// The age beyond which an abandoned temporary file is reclaimed on the first open of a root. A
    /// temp younger than this is kept: it may belong to a concurrent replacement that has written it
    /// but not yet renamed it.
    /// </summary>
    internal TimeSpan StaleTemporaryGrace { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Test seam for establishing a restrictive mode on a committed path. Returns <c>true</c> when the
    /// mode is established (or the platform has none), <c>false</c> when it cannot be established.
    /// The default implementation is the platform behavior; tests override it to force a failure.
    /// </summary>
    internal Func<string, bool>? PermissionSetter { get; set; }

    /// <summary>
    /// Test seam replacing the Windows ACL applier. When set, it decides whether the contract holds
    /// instead of the real ACL implementation; tests use it to force the fail-closed path.
    /// </summary>
    internal static Func<string, bool, bool>? WindowsAclApplierForTesting { get; set; }

    /// <summary>The bounded number of committed records retained after a successful replacement.</summary>
    internal int MaximumRecords { get; set; } = DefaultMaximumRecords;

    /// <summary>The directory this store reads and writes.</summary>
    public string Root => _root;

    /// <inheritdoc />
    public ValueTask<MutableSlotRecord?> LoadAsync(
        string profileId,
        string slot,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(profileId);
        ArgumentException.ThrowIfNullOrWhiteSpace(slot);

        var path = RecordPath(_mountIdentity, profileId, slot);

        byte[] envelope;
        try
        {
            envelope = ReadEnvelope(path);
        }
        catch (FileNotFoundException)
        {
            return ValueTask.FromResult<MutableSlotRecord?>(null);
        }
        catch (DirectoryNotFoundException)
        {
            return ValueTask.FromResult<MutableSlotRecord?>(null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw Failed(profileId, slot, "the record cannot be read.", ex);
        }

        // This record-only view cannot express a cleared floor: returning the value for a cleared
        // record, or null for it, would let a caller resurrect a source the operator cleared. The
        // OAuth acquisition path resolves the effective authority through LoadDecisionAsync
        // instead, so this guard is the fail-closed boundary for any record-only caller that
        // remains (for example the managed reconciliation reader).
        if (envelope.Length > 0 && envelope[0] == AuthorityFormatVersion)
        {
            throw Failed(profileId, slot,
                "the local authority decision requires decision-aware OAuth resolution.");
        }

        return ValueTask.FromResult(Decode(profileId, slot, envelope));
    }

    /// <inheritdoc />
    public ValueTask<MutableSlotDecision?> LoadDecisionAsync(
        string profileId, string slot, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(profileId);
        ArgumentException.ThrowIfNullOrWhiteSpace(slot);
        EnsureDecisionIdentity(profileId, slot);
        return ValueTask.FromResult(ReadDecision(profileId, slot));
    }

    /// <inheritdoc />
    public async ValueTask<MutableSlotDecision> CompareAndCommitAsync(
        MutableSlotDecision successor, string? expectedVersion, long declaredEpoch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(successor);
        EnsureDecisionIdentity(successor.ProfileId, successor.Slot);
        using (await IdentityGates.AcquireAsync(MountGateKey(_root, _mountIdentity), cancellationToken).ConfigureAwait(false))
        using (await IdentityGates.AcquireAsync(SlotGateKey(_root, _mountIdentity, successor.ProfileId, successor.Slot), cancellationToken).ConfigureAwait(false))
        {
            var prior = ReadDecision(successor.ProfileId, successor.Slot);
            if (!string.Equals(prior?.Version, expectedVersion, StringComparison.Ordinal))
            {
                throw Failed(successor.ProfileId, successor.Slot, "the observed authority version has changed.");
            }

            MutableSlotDecisionRules.Validate(successor, prior, declaredEpoch);
            var envelope = EncodeDecision(successor);
            EnsureCapacityFor(new MutableSlotRecord(successor.ProfileId, successor.Slot, successor.ScopeFingerprint,
                successor.AuthorityEpoch, successor.RuntimeRevision, string.Empty));
            await CommitEnvelopeAsync(successor.ProfileId, successor.Slot, envelope, cancellationToken).ConfigureAwait(false);
            return successor with { Version = Convert.ToHexString(SHA256.HashData(envelope)), IsLegacy = false };
        }
    }

    /// <inheritdoc />
    public async ValueTask<MutableSlotDecision> EstablishBaselineAsync(
        MutableSlotDecision baseline, long declaredEpoch, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        EnsureDecisionIdentity(baseline.ProfileId, baseline.Slot);
        MutableSlotDecisionRules.ValidateBaselineShape(baseline, declaredEpoch);

        using (await IdentityGates.AcquireAsync(MountGateKey(_root, _mountIdentity), cancellationToken).ConfigureAwait(false))
        using (await IdentityGates.AcquireAsync(SlotGateKey(_root, _mountIdentity, baseline.ProfileId, baseline.Slot), cancellationToken).ConfigureAwait(false))
        {
            // A predecessor that can still be authenticated bounds the baseline: this operation is
            // for authority the deployment cannot read, and a readable newer decision must not be
            // regressed by it. An unreadable predecessor is not compared here; the atomic
            // replacement below retires it in the same write, so no intermediate state exists in
            // which the slot is absent and the Manifest-declared credential applies again.
            MutableSlotDecision? readable = TryReadReadableDecision(baseline.ProfileId, baseline.Slot);
            if (readable is not null && baseline.AuthorityEpoch <= readable.AuthorityEpoch)
            {
                throw Failed(baseline.ProfileId, baseline.Slot,
                    "the proposed reset baseline does not advance the readable current authority.");
            }

            var envelope = EncodeDecision(baseline);
            EnsureCapacityFor(new MutableSlotRecord(baseline.ProfileId, baseline.Slot, baseline.ScopeFingerprint,
                baseline.AuthorityEpoch, baseline.RuntimeRevision, string.Empty));
            await CommitEnvelopeAsync(baseline.ProfileId, baseline.Slot, envelope, cancellationToken).ConfigureAwait(false);
            return baseline with { Version = Convert.ToHexString(SHA256.HashData(envelope)), IsLegacy = false };
        }
    }

    /// <summary>
    /// Reads the decision, or null when it is absent or cannot be authenticated with this key.
    /// </summary>
    /// <remarks>
    /// Used only to bound a destructive reset. Swallowing the unreadable case is the point: the
    /// reset exists for that case, and reporting it as absent is exactly what the ordinary read
    /// path must never do.
    /// </remarks>
    private MutableSlotDecision? TryReadReadableDecision(string profileId, string slot)
    {
        try
        {
            return ReadDecision(profileId, slot);
        }
        catch (RuntimeStateStoreException)
        {
            return null;
        }
    }

    private MutableSlotDecision? ReadDecision(string profileId, string slot)
    {
        byte[] envelope;
        try
        {
            envelope = ReadEnvelope(RecordPath(_mountIdentity, profileId, slot));
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw Failed(profileId, slot, "the record cannot be read.", ex);
        }

        string version = Convert.ToHexString(SHA256.HashData(envelope));
        if (envelope.Length > 0 && envelope[0] == FormatVersion)
        {
            MutableSlotRecord legacy = Decode(profileId, slot, envelope)!;
            if (legacy.AuthorityEpoch < 0 || legacy.RuntimeRevision < 0
                || string.IsNullOrEmpty(legacy.Value))
            {
                throw Failed(profileId, slot, "the legacy authority record is invalid.");
            }
            return new MutableSlotDecision(profileId, slot, legacy.ScopeFingerprint,
                null, null, legacy.AuthorityEpoch, legacy.RuntimeRevision,
                MutableSlotDecisionKind.Authorized, legacy.Value, version, IsLegacy: true);
        }

        if (envelope.Length < MinimumEnvelopeLength || envelope[0] != AuthorityFormatVersion)
        {
            throw Failed(profileId, slot, "the authority record is not in a supported format.");
        }

        int headerLength = envelope[1] | (envelope[2] << 8);
        if (headerLength <= 0 || envelope.Length < FixedPrefixLength + headerLength + NonceLength + TagLength)
        {
            throw Failed(profileId, slot, "the authority record is truncated.");
        }

        var nonce = envelope.AsSpan(FixedPrefixLength + headerLength, NonceLength);
        var ciphertext = envelope.AsSpan(FixedPrefixLength + headerLength + NonceLength,
            envelope.Length - FixedPrefixLength - headerLength - NonceLength - TagLength);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(_key, TagLength);
            aes.Decrypt(nonce, ciphertext, envelope.AsSpan(envelope.Length - TagLength),
                plaintext, AssociatedData(envelope, headerLength));
        }
        catch (CryptographicException ex)
        {
            throw Failed(profileId, slot, "the authority record cannot be authenticated with the configured key.", ex);
        }

        RuntimeStateHeader header;
        try
        {
            // A duplicated identity/binding field must not acquire a different meaning under a
            // different JSON reader. The header is authenticated but may outlive this reader.
            using (var document = JsonDocument.Parse(envelope.AsMemory(FixedPrefixLength, headerLength)))
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw new JsonException("The authority header must be an object.");
                }

                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    if (!names.Add(property.Name))
                    {
                        throw new JsonException("The authority header contains duplicate fields.");
                    }
                }
            }

            header = JsonSerializer.Deserialize<RuntimeStateHeader>(
                envelope.AsSpan(FixedPrefixLength, headerLength), HeaderOptions)
                ?? throw new JsonException("Empty authority header.");
        }
        catch (JsonException ex)
        {
            throw Failed(profileId, slot, "the authority record header is not readable.", ex);
        }

        if (header.Format != AuthorityFormatVersion
            || !string.Equals(header.Mount, _mountIdentity, StringComparison.Ordinal)
            || !string.Equals(header.Profile, profileId, StringComparison.Ordinal)
            || !string.Equals(header.Slot, slot, StringComparison.Ordinal))
        {
            throw Failed(profileId, slot, "the authority record belongs to a different mount/profile/slot.");
        }

        var kind = header.DecisionKind switch
        {
            "authorized" => MutableSlotDecisionKind.Authorized,
            "cleared" => MutableSlotDecisionKind.Cleared,
            _ => throw Failed(profileId, slot, "the authority record kind is unsupported."),
        };
        string? refresh;
        try
        {
            refresh = kind == MutableSlotDecisionKind.Authorized
                ? StrictUtf8.GetString(plaintext)
                : null;
        }
        catch (DecoderFallbackException ex)
        {
            throw Failed(profileId, slot, "the authority record contains invalid UTF-8 material.", ex);
        }
        if (string.IsNullOrWhiteSpace(header.DeclarationFingerprint)
            || string.IsNullOrWhiteSpace(header.ConfigurationFingerprint)
            || header.AuthorityEpoch < 0 || header.RuntimeRevision < 0
            || (kind == MutableSlotDecisionKind.Cleared && (plaintext.Length != 0 || header.RuntimeRevision != 0))
            || (kind == MutableSlotDecisionKind.Authorized && string.IsNullOrEmpty(refresh)))
        {
            throw Failed(profileId, slot, "the authenticated authority record is invalid.");
        }

        return new MutableSlotDecision(profileId, slot, header.ScopeFingerprint,
            header.DeclarationFingerprint, header.ConfigurationFingerprint,
            header.AuthorityEpoch, header.RuntimeRevision, kind, refresh, version);
    }

    private void EnsureDecisionIdentity(string profileId, string slot)
    {
        MutableSlotDecisionRules.ValidateIdentity(profileId, slot);
        if (_mountIdentity.Contains('\u001f'))
        {
            throw Failed(profileId, slot, "the local authority mount identity is invalid.");
        }
    }

    private byte[] EncodeDecision(MutableSlotDecision decision)
    {
        var header = new RuntimeStateHeader
        {
            Format = AuthorityFormatVersion,
            Mount = _mountIdentity,
            Profile = decision.ProfileId,
            Slot = decision.Slot,
            ScopeFingerprint = decision.ScopeFingerprint,
            DeclarationFingerprint = decision.DeclarationFingerprint,
            ConfigurationFingerprint = decision.ConfigurationFingerprint,
            AuthorityEpoch = decision.AuthorityEpoch,
            RuntimeRevision = decision.RuntimeRevision,
            DecisionKind = decision.Kind == MutableSlotDecisionKind.Authorized ? "authorized" : "cleared",
        };
        return EncodeEnvelope(header, AuthorityFormatVersion, decision.RefreshToken ?? string.Empty);
    }

    /// <inheritdoc />
    public async ValueTask ReplaceAsync(MutableSlotRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        // A capacity cap is a count over the mount, so two writers creating two *different* new slots
        // must not both pass the count-then-insert decision: that is a mount-scope decision taken under
        // a mount-scope gate (R10.3). The per-slot gate still serializes the read-compare-write of one
        // identity, so an older writer cannot regress a newer revision (R4.3). The gates are
        // reference-counted and removed once idle, so distinct-identity churn cannot grow process state
        // without bound (R10.7). Cross-process serialization is not provided here; the Platform runs a
        // single Engine process against the store (a second process writing the same root is undefined).
        using (await IdentityGates.AcquireAsync(MountGateKey(_root, _mountIdentity), cancellationToken).ConfigureAwait(false))
        using (await IdentityGates.AcquireAsync(SlotGateKey(_root, _mountIdentity, record.ProfileId, record.Slot), cancellationToken).ConfigureAwait(false))
        {
            await ReplaceLockedAsync(record, cancellationToken).ConfigureAwait(false);
        }
    }

    private static string MountGateKey(string root, string mount)
        => string.Concat("mount\u001f", root, "\u001f", mount);

    private static string SlotGateKey(string root, string mount, string profileId, string slot)
        => string.Concat("slot\u001f", root, "\u001f", mount, "\u001f", profileId, "\u001f", slot);

    /// <summary>Diagnostic/test view: how many identity gates are retained for a root right now.</summary>
    internal static int TrackedIdentityGateCountForRoot(string root) => IdentityGates.CountForRoot(root);

    private async ValueTask ReplaceLockedAsync(MutableSlotRecord record, CancellationToken cancellationToken)
    {
        // Monotonicity: a record may only advance its identity. A write whose authority epoch is
        // older, or whose runtime revision does not advance within the same epoch, is refused
        // fail-closed rather than allowed to overwrite a newer committed value — which would lose a
        // refresh token the provider already retired in favour of the newer one. A newer authority
        // epoch supersedes unconditionally, because the revision counter is scoped to its epoch.
        var target = RecordPath(_mountIdentity, record.ProfileId, record.Slot);
        var existing = ReadExisting(record.ProfileId, record.Slot, target);
        if (existing is not null && IsRegressive(record, existing))
        {
            throw Failed(
                record.ProfileId,
                record.Slot,
                "the runtime-state record is not newer than the stored revision and was refused.");
        }

        // Refuse a new identity at the cap before anything is written, so a bounded store never
        // has to evict a live identity to make room.
        EnsureCapacityFor(record);

        var envelope = Encode(record);
        await CommitEnvelopeAsync(record.ProfileId, record.Slot, envelope, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask CommitEnvelopeAsync(
        string profileId, string slot, byte[] envelope, CancellationToken cancellationToken)
    {
        var target = RecordPath(_mountIdentity, profileId, slot);
        var temporary = target + TemporarySuffix + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));

        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous))
            {
                await stream.WriteAsync(envelope, cancellationToken).ConfigureAwait(false);

                if (TempWrittenBarrier is { } written)
                {
                    await written(cancellationToken).ConfigureAwait(false);
                }

                stream.Flush(flushToDisk: true);
            }

            if (TempFlushedBarrier is { } flushed)
            {
                await flushed(cancellationToken).ConfigureAwait(false);
            }

            if (!TryRestrict(temporary, out string? reason))
            {
                TryRemove(temporary);
                throw Failed(
                    profileId,
                    slot,
                    "the record could not be stored with a restrictive file mode"
                    + Reason(reason));
            }

            File.Move(temporary, target, overwrite: true);
        }
        catch (Exception ex) when (ex is not RuntimeStateStoreException and not OperationCanceledException)
        {
            TryRemove(temporary);
            throw Failed(
                profileId,
                slot,
                "the replacement could not be committed.",
                ex);
        }
        catch (OperationCanceledException)
        {
            TryRemove(temporary);
            throw;
        }

        // Maintenance is best-effort and runs after the commit: a committed write must never be
        // reported as failed because the directory could not be compacted.
        TryCompactBestEffort();
    }

    /// <summary>
    /// A process-wide keyed async gate whose entries exist only while a caller holds or waits for them.
    /// </summary>
    private sealed class KeyedGatePool
    {
        private readonly object _sync = new();
        private readonly Dictionary<string, Gate> _gates = new(StringComparer.Ordinal);

        public int CountForRoot(string root)
        {
            lock (_sync)
            {
                var count = 0;
                foreach (var key in _gates.Keys)
                {
                    if (key.Contains("\u001f" + root + "\u001f", StringComparison.Ordinal))
                    {
                        count++;
                    }
                }

                return count;
            }
        }

        public async ValueTask<IDisposable> AcquireAsync(string key, CancellationToken cancellationToken)
        {
            Gate gate;
            lock (_sync)
            {
                if (!_gates.TryGetValue(key, out gate!))
                {
                    gate = new Gate();
                    _gates.Add(key, gate);
                }

                gate.References++;
            }

            try
            {
                await gate.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // A cancelled or failed wait never produces a lease, so the reference reserved above must
                // be released here; otherwise the entry (and its count) leaks.
                ReleaseReference(key, gate);
                throw;
            }

            return new Lease(this, key, gate);
        }

        private void ReleaseReference(string key, Gate gate)
        {
            lock (_sync)
            {
                gate.References--;
                if (gate.References == 0 && _gates.Remove(key))
                {
                    gate.Dispose();
                }
            }
        }

        private sealed class Gate : IDisposable
        {
            public SemaphoreSlim Semaphore { get; } = new(1, 1);

            public int References;

            public void Dispose() => Semaphore.Dispose();
        }

        private sealed class Lease(KeyedGatePool pool, string key, Gate gate) : IDisposable
        {
            private int _released;

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _released, 1) != 0)
                {
                    return;
                }

                gate.Semaphore.Release();
                pool.ReleaseReference(key, gate);
            }
        }
    }

    /// <summary>
    /// Reads the current record for one identity, or null when none exists. A record that exists but
    /// cannot be read or authenticated is reported fail-closed rather than treated as absent, so a
    /// replacement never silently overwrites evidence it could not interpret.
    /// </summary>
    private MutableSlotRecord? ReadExisting(string profileId, string slot, string target)
    {
        byte[] envelope;
        try
        {
            envelope = ReadEnvelope(target);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw Failed(profileId, slot, "the record cannot be read.", ex);
        }

        return Decode(profileId, slot, envelope);
    }

    /// <summary>
    /// True when <paramref name="incoming"/> is strictly older than <paramref name="existing"/> and
    /// must not replace it: a lower authority epoch, or a lower runtime revision within the same
    /// epoch. An equal revision is not older and is committed as the newest value: the revision is
    /// derived from the declared generation, so two rotations can carry the same declared revision
    /// before reconciliation, and the later commit is the newer credential the provider issued.
    /// </summary>
    private static bool IsRegressive(MutableSlotRecord incoming, MutableSlotRecord existing)
        => incoming.AuthorityEpoch < existing.AuthorityEpoch
            || (incoming.AuthorityEpoch == existing.AuthorityEpoch
                && incoming.RuntimeRevision < existing.RuntimeRevision);

    /// <summary>
    /// Reads one record's complete bytes while permitting a concurrent atomic replacement.
    /// </summary>
    /// <remarks>
    /// <c>File.ReadAllBytes</c> shares read only, so on Windows a rename over a record fails
    /// while any reader holds it open. Production replacement can happen with concurrent
    /// readers, and a reader must see either the complete predecessor or the complete
    /// successor, so the read shares read, write and delete instead.
    /// </remarks>
    private static byte[] ReadEnvelope(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        byte[] envelope = new byte[stream.Length];
        stream.ReadExactly(envelope);
        return envelope;
    }

    private MutableSlotRecord? Decode(string profileId, string slot, byte[] envelope)
    {
        if (envelope.Length < MinimumEnvelopeLength || envelope[0] != FormatVersion)
        {
            throw Failed(profileId, slot, "the record is not in a supported format.");
        }

        var headerLength = envelope[1] | (envelope[2] << 8);

        if (headerLength <= 0 || envelope.Length < FixedPrefixLength + headerLength + NonceLength + TagLength)
        {
            throw Failed(profileId, slot, "the record is truncated.");
        }

        var headerBytes = envelope.AsSpan(FixedPrefixLength, headerLength);
        var nonce = envelope.AsSpan(FixedPrefixLength + headerLength, NonceLength);
        var ciphertext = envelope.AsSpan(FixedPrefixLength + headerLength + NonceLength, envelope.Length - FixedPrefixLength - headerLength - NonceLength - TagLength);
        var tag = envelope.AsSpan(envelope.Length - TagLength);
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(_key, TagLength);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, AssociatedData(envelope, headerLength));
        }
        catch (CryptographicException ex)
        {
            throw Failed(profileId, slot, "the record cannot be authenticated with the configured key.", ex);
        }

        RuntimeStateHeader header;
        try
        {
            header = JsonSerializer.Deserialize<RuntimeStateHeader>(headerBytes, HeaderOptions)
                ?? throw new JsonException("The header is empty.");
        }
        catch (JsonException ex)
        {
            throw Failed(profileId, slot, "the record header is not readable.", ex);
        }

        if (header.Format != FormatVersion
            || !string.Equals(header.Mount, _mountIdentity, StringComparison.Ordinal))
        {
            throw Failed(profileId, slot, "the record belongs to a different mount or format.");
        }

        if (!string.Equals(header.Profile, profileId, StringComparison.Ordinal)
            || !string.Equals(header.Slot, slot, StringComparison.Ordinal))
        {
            throw Failed(profileId, slot, "the record identifies a different profile or slot.");
        }

        return new MutableSlotRecord(
            header.Profile,
            header.Slot,
            header.ScopeFingerprint,
            header.AuthorityEpoch,
            header.RuntimeRevision,
            Encoding.UTF8.GetString(plaintext));
    }

    private byte[] Encode(MutableSlotRecord record)
    {
        var header = new RuntimeStateHeader
        {
            Format = FormatVersion,
            Mount = _mountIdentity,
            Profile = record.ProfileId,
            Slot = record.Slot,
            ScopeFingerprint = record.ScopeFingerprint,
            AuthorityEpoch = record.AuthorityEpoch,
            RuntimeRevision = record.RuntimeRevision,
        };

        return EncodeEnvelope(header, FormatVersion, record.Value);
    }

    private byte[] EncodeEnvelope(RuntimeStateHeader header, byte format, string value)
    {
        var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header, HeaderOptions);
        if (headerBytes.Length > ushort.MaxValue)
        {
            throw Failed(header.Profile, header.Slot, "the authenticated record header exceeds its format limit.");
        }
        var valueBytes = Encoding.UTF8.GetBytes(value);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var ciphertext = new byte[valueBytes.Length];
        var tag = new byte[TagLength];

        var envelope = new byte[FixedPrefixLength + headerBytes.Length + NonceLength + ciphertext.Length + TagLength];
        envelope[0] = format;
        envelope[1] = (byte)(headerBytes.Length & 0xFF);
        envelope[2] = (byte)((headerBytes.Length >> 8) & 0xFF);
        headerBytes.CopyTo(envelope.AsSpan(FixedPrefixLength));

        using (var aes = new AesGcm(_key, TagLength))
        {
            aes.Encrypt(
                nonce,
                valueBytes,
                ciphertext,
                tag,
                envelope.AsSpan(0, FixedPrefixLength + headerBytes.Length));
        }

        nonce.CopyTo(envelope.AsSpan(FixedPrefixLength + headerBytes.Length));
        ciphertext.CopyTo(envelope.AsSpan(FixedPrefixLength + headerBytes.Length + NonceLength));
        tag.CopyTo(envelope.AsSpan(envelope.Length - TagLength));
        return envelope;
    }

    private static byte[] AssociatedData(byte[] envelope, int headerLength)
    {
        var associated = new byte[FixedPrefixLength + headerLength];
        envelope.AsSpan(0, associated.Length).CopyTo(associated);
        return associated;
    }

    private string RecordPath(string mount, string profileId, string slot)
    {
        var identity = string.Join('\u001f', mount, profileId, slot);
        var name = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        return Path.Combine(_root, name + RecordExtension);
    }

    /// <summary>
    /// Refuses a write for a slot identity this mount does not already own once the store holds its
    /// bounded number of live identities. Replacing an existing identity is always allowed; the cap
    /// only limits how many distinct identities one mount's section may hold, and it never evicts a
    /// live identity to make room.
    /// </summary>
    private void EnsureCapacityFor(MutableSlotRecord record)
    {
        if (MaximumRecords <= 0)
        {
            return;
        }

        // Replacing an existing identity adds no new identity, so it is always admitted.
        if (File.Exists(RecordPath(_mountIdentity, record.ProfileId, record.Slot)))
        {
            return;
        }

        FileInfo[] records;
        try
        {
            records = EnumerateRecords();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            // A directory that cannot be enumerated is reported by the write itself, which fails
            // closed; capacity admission is best-effort and does not block a legitimate write.
            return;
        }

        // Fast path: fewer total files than the cap means this mount cannot be at its cap.
        if (records.Length < MaximumRecords)
        {
            return;
        }

        var owned = 0;
        foreach (var info in records)
        {
            if (!TryReadIdentity(info.FullName, out var identity))
            {
                continue;
            }

            if (!string.Equals(identity.Mount, _mountIdentity, StringComparison.Ordinal))
            {
                continue;
            }

            owned++;
            if (owned >= MaximumRecords)
            {
                throw Failed(
                    record.ProfileId,
                    record.Slot,
                    "the runtime-state store has reached its bounded capacity and refuses a new slot identity.");
            }
        }
    }

    private FileInfo[] EnumerateRecords()
        => Directory.EnumerateFiles(_root, "*" + RecordExtension)
            .Select(path => new FileInfo(path))
            .ToArray();

    private void EnsureRoot()
    {
        try
        {
            Directory.CreateDirectory(_root);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                "The runtime-state directory could not be created or is not writable.",
                ex);
        }

        if (!TryRestrictDirectory(_root, out string? reason))
        {
            throw new InvalidOperationException(
                "The runtime-state directory could not be established with a restrictive file mode"
                + Reason(reason));
        }
    }

    private bool TryRestrictDirectory(string path, out string? reason)
    {
        if (PermissionSetter is { } setter)
        {
            reason = null;
            return setter(path);
        }

        if (OperatingSystem.IsWindows())
        {
            return ApplyWindowsAcl(path, isDirectory: true, out reason);
        }

        try
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            reason = null;
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            reason = null;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            reason = Category(ex);
            return false;
        }
    }

    /// <summary>
    /// Establishes a restrictive mode on a committed path, failing closed. Returns <c>false</c> when
    /// the platform has a mode but it cannot be established, so the caller refuses to publish a
    /// secret whose file mode could not be tightened. <paramref name="reason"/> names the category of
    /// the failure, because a fail-closed refusal an operator cannot diagnose is a refusal an
    /// operator cannot correct.
    /// </summary>
    private bool TryRestrict(string path, out string? reason)
    {
        if (PermissionSetter is { } setter)
        {
            reason = null;
            return setter(path);
        }

        return DefaultPermissionSetter(path, out reason);
    }

    private static bool DefaultPermissionSetter(string path, out string? reason)
    {
        if (OperatingSystem.IsWindows())
        {
            return ApplyWindowsAcl(path, isDirectory: false, out reason);
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            reason = null;
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            // The platform has no file-mode concept; the contract is satisfied vacuously.
            reason = null;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            reason = Category(ex);
            return false;
        }
    }

    private static bool ApplyWindowsAcl(string path, bool isDirectory, out string? reason)
        => WindowsAclApplierForTesting is { } applier
            ? Apply(applier, path, isDirectory, out reason)
            : TryApplyRestrictiveWindowsAcl(path, isDirectory, out reason);

    private static bool Apply(Func<string, bool, bool> applier, string path, bool isDirectory, out string? reason)
    {
        if (applier(path, isDirectory))
        {
            reason = null;
            return true;
        }

        reason = "the substituted access-control applier refused it.";
        return false;
    }

    /// <summary>Names the category of a mode failure without repeating a path or a secret.</summary>
    private static string Category(Exception exception) => $" ({exception.GetType().Name}).";

    private static string Reason(string? reason) => reason is null ? "." : $" ({reason})";

    /// <summary>
    /// Establishes and verifies a restrictive ACL on Windows: inheritance is disabled and only the
    /// running account, LocalSystem and the built-in Administrators may hold an allow rule. Returns
    /// <c>false</c> when the contract cannot be established or verified, so the caller fails closed
    /// rather than accepting an unrestricted runtime-state directory. <paramref name="reason"/> names
    /// which half of the contract failed.
    /// </summary>
    private static bool TryApplyRestrictiveWindowsAcl(string path, bool isDirectory, out string? reason)
    {
        if (!OperatingSystem.IsWindows())
        {
            reason = "the platform is not Windows.";
            return false;
        }

        try
        {
            var owner = WindowsIdentity.GetCurrent().User;
            if (owner is null)
            {
                reason = "the running account has no security identifier.";
                return false;
            }

            FileSystemSecurity security;
            if (isDirectory)
            {
                security = new DirectorySecurity();
            }
            else
            {
                security = new FileSecurity();
            }

            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var inheritance = isDirectory
                ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
                : InheritanceFlags.None;
            foreach (var sid in AllowedSids(owner))
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    sid,
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }

            if (isDirectory)
            {
                new DirectoryInfo(path).SetAccessControl((DirectorySecurity)security);
            }
            else
            {
                new FileInfo(path).SetAccessControl((FileSecurity)security);
            }

            return IsRestrictiveWindowsAcl(path, isDirectory, owner, out reason);
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or PlatformNotSupportedException
            or SecurityException
            or IdentityNotMappedException
            or ArgumentException
            or InvalidOperationException)
        {
            reason = $"the file system refused the change ({ex.GetType().Name}).";
            return false;
        }
    }

    /// <summary>
    /// Whether <paramref name="path"/> currently carries the restrictive Windows ACL contract for the
    /// running account. Used by the post-apply verification and by tests.
    /// </summary>
    internal static bool IsRestrictiveWindowsAcl(string path, bool isDirectory)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        var owner = WindowsIdentity.GetCurrent().User;
        return owner is not null && IsRestrictiveWindowsAcl(path, isDirectory, owner, out _);
    }

    [SupportedOSPlatform("windows")]
    private static bool IsRestrictiveWindowsAcl(
        string path, bool isDirectory, SecurityIdentifier owner, out string? reason)
    {
        try
        {
            FileSystemSecurity security;
            if (isDirectory)
            {
                security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
            }
            else
            {
                security = new FileInfo(path).GetAccessControl(AccessControlSections.Access);
            }

            if (!security.AreAccessRulesProtected)
            {
                reason = "the applied access rules are reported as not protected.";
                return false;
            }

            var allowed = AllowedSids(owner);
            var ownerAllowed = false;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow
                    || rule.IdentityReference is not SecurityIdentifier sid)
                {
                    continue;
                }

                if (!allowed.Contains(sid))
                {
                    reason = "an allow rule names an account outside the permitted set.";
                    return false;
                }

                if (sid.Equals(owner))
                {
                    ownerAllowed = true;
                }
            }

            if (!ownerAllowed)
            {
                reason = "the running account holds no allow rule.";
                return false;
            }

            reason = null;
            return true;
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or PlatformNotSupportedException
            or SecurityException
            or ArgumentException
            or InvalidOperationException)
        {
            reason = $"the applied access rules could not be read back ({ex.GetType().Name}).";
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private static HashSet<SecurityIdentifier> AllowedSids(SecurityIdentifier owner)
    {
        var allowed = new HashSet<SecurityIdentifier> { owner };
        AddWellKnownSid(allowed, WellKnownSidType.LocalSystemSid);
        AddWellKnownSid(allowed, WellKnownSidType.BuiltinAdministratorsSid);
        return allowed;
    }

    [SupportedOSPlatform("windows")]
    private static void AddWellKnownSid(HashSet<SecurityIdentifier> allowed, WellKnownSidType type)
    {
        try
        {
            allowed.Add(new SecurityIdentifier(type, null));
        }
        catch (IdentityNotMappedException)
        {
            // A host without the well-known account cannot be constrained by it; the running
            // account alone still satisfies the contract.
        }
    }

    /// <summary>
    /// Reclaims abandoned temporary files once per root per process. A temporary file is never an
    /// authoritative record, but it may belong to a concurrent replacement that has written it and
    /// not yet renamed it, so only temps older than <see cref="StaleTemporaryGrace"/> are removed.
    /// </summary>
    private void ReclaimStaleTemporariesOnce()
    {
        if (!ReclaimedRoots.TryAdd(_root, 0))
        {
            return;
        }

        try
        {
            var cutoff = DateTime.UtcNow - StaleTemporaryGrace;
            foreach (var path in Directory.EnumerateFiles(_root, "*" + TemporarySuffix + "*"))
            {
                if (!Path.GetFileName(path).Contains(TemporarySuffix, StringComparison.Ordinal))
                {
                    continue;
                }

                if (File.GetLastWriteTimeUtc(path) < cutoff)
                {
                    TryRemove(path);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            // A directory that cannot be enumerated is reported by the next read/write, which
            // already fails closed; stale-temp cleanup is best-effort.
        }
    }

    /// <summary>
    /// Reclaims only files that are unreachable by any read, under a bound: a file whose header
    /// identity does not match its own path (corrupt, or copied to a foreign name), or a duplicate of
    /// a live identity. A live record for any identity — including another mount sharing this root —
    /// is never removed. Capacity is enforced by refusing new identities, not by eviction.
    /// </summary>
    private void Compact()
    {
        // Test seam: lets a test prove that a maintenance failure after a committed write is
        // best-effort. In production this is null.
        CompactionBarrier?.Invoke();

        FileInfo[] records;
        try
        {
            records = EnumerateRecords();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            return;
        }

        var newest = new Dictionary<RecordIdentity, FileInfo>();
        var unreachable = new List<FileInfo>();
        foreach (var info in records)
        {
            if (!TryReadIdentity(info.FullName, out var identity))
            {
                // Unreadable: leave it. A read of the matching identity fails closed and reports it;
                // a blind delete could remove a record a concurrent writer is still establishing.
                continue;
            }

            // This store can only maintain its own mount. A foreign mount may use a different key,
            // and even a syntactically valid header is not authenticated until its tag is checked.
            if (!string.Equals(identity.Mount, _mountIdentity, StringComparison.Ordinal))
            {
                continue;
            }

            if (!PathMatchesIdentity(info, identity))
            {
                // Never let a corrupted/tampered header cause deletion of a live cleared floor.
                // Its JSON can still parse and point to another identity while its GCM tag fails.
                if (HasAuthenticatedEnvelope(info.FullName))
                {
                    unreachable.Add(info);
                }
                continue;
            }

            if (newest.TryGetValue(identity, out var current))
            {
                if (info.LastWriteTimeUtc > current.LastWriteTimeUtc)
                {
                    unreachable.Add(current);
                    newest[identity] = info;
                }
                else
                {
                    unreachable.Add(info);
                }
            }
            else
            {
                newest[identity] = info;
            }
        }

        var removals = 0;
        foreach (var info in unreachable)
        {
            if (removals >= MaximumUnreachableRemovalsPerPass)
            {
                break;
            }

            TryRemove(info.FullName);
            removals++;
        }
    }

    private bool HasAuthenticatedEnvelope(string path)
    {
        try
        {
            var envelope = ReadEnvelope(path);
            if (envelope.Length < MinimumEnvelopeLength
                || envelope[0] is not (FormatVersion or AuthorityFormatVersion))
            {
                return false;
            }

            var headerLength = envelope[1] | envelope[2] << 8;
            if (headerLength <= 0
                || envelope.Length < FixedPrefixLength + headerLength + NonceLength + TagLength)
            {
                return false;
            }

            var nonceOffset = FixedPrefixLength + headerLength;
            var payloadLength = envelope.Length - nonceOffset - NonceLength - TagLength;
            var plaintext = new byte[payloadLength];
            using var aes = new AesGcm(_key, TagLength);
            aes.Decrypt(envelope.AsSpan(nonceOffset, NonceLength),
                envelope.AsSpan(nonceOffset + NonceLength, payloadLength),
                envelope.AsSpan(envelope.Length - TagLength), plaintext,
                envelope.AsSpan(0, nonceOffset));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return false;
        }
    }

    private void TryCompactBestEffort()
    {
        try
        {
            Compact();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Best-effort maintenance runs after the commit and must not turn a committed write
            // into a reported failure.
        }
    }

    private bool TryReadIdentity(string path, out RecordIdentity identity)
    {
        identity = default;
        try
        {
            var envelope = ReadEnvelope(path);
            if (envelope.Length < MinimumEnvelopeLength
                || envelope[0] is not (FormatVersion or AuthorityFormatVersion))
            {
                return false;
            }

            var headerLength = envelope[1] | (envelope[2] << 8);
            if (headerLength <= 0 || envelope.Length < FixedPrefixLength + headerLength + NonceLength + TagLength)
            {
                return false;
            }

            var headerBytes = envelope.AsSpan(FixedPrefixLength, headerLength);
            var header = JsonSerializer.Deserialize<RuntimeStateHeader>(headerBytes, HeaderOptions);
            if (header is null)
            {
                return false;
            }

            identity = new RecordIdentity(header.Mount, header.Profile, header.Slot);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// True when a record file's name is the one its own header identity resolves to. A file whose
    /// name and header disagree cannot be reached by any <see cref="LoadAsync"/> call.
    /// </summary>
    private bool PathMatchesIdentity(FileInfo info, RecordIdentity identity)
    {
        var expected = Path.GetFileName(RecordPath(identity.Mount, identity.Profile, identity.Slot));
        return string.Equals(info.Name, expected, StringComparison.Ordinal);
    }

    /// <summary>The authenticated, non-secret identity of one record: mount, profile and slot.</summary>
    private readonly record struct RecordIdentity(string Mount, string Profile, string Slot);

    private static void TryRemove(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static string Normalize(string path)
        => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static RuntimeStateStoreException Failed(
        string profileId,
        string slot,
        string message,
        Exception? inner = null) => new(profileId, slot, message, inner);

    /// <summary>The authenticated, non-secret identity of one record.</summary>
    private sealed record RuntimeStateHeader
    {
        public byte Format { get; init; }

        public string Mount { get; init; } = string.Empty;

        public string Profile { get; init; } = string.Empty;

        public string Slot { get; init; } = string.Empty;

        public string? ScopeFingerprint { get; init; }

        public long AuthorityEpoch { get; init; }

        public long RuntimeRevision { get; init; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? DeclarationFingerprint { get; init; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? ConfigurationFingerprint { get; init; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? DecisionKind { get; init; }
    }
}
