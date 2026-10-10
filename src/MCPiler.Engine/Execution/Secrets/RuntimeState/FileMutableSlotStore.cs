using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

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
    /// <summary>The format version this adapter writes and the only one it reads.</summary>
    public const byte FormatVersion = 1;

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
            envelope = File.ReadAllBytes(path);
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

        return ValueTask.FromResult(Decode(profileId, slot, envelope));
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

            if (!TryRestrict(temporary))
            {
                TryRemove(temporary);
                throw Failed(
                    record.ProfileId,
                    record.Slot,
                    "the record could not be stored with a restrictive file mode.");
            }

            File.Move(temporary, target, overwrite: true);
        }
        catch (Exception ex) when (ex is not RuntimeStateStoreException and not OperationCanceledException)
        {
            TryRemove(temporary);
            throw Failed(
                record.ProfileId,
                record.Slot,
                "the replacement could not be committed.",
                ex);
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
            envelope = File.ReadAllBytes(target);
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

        var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header, HeaderOptions);
        var valueBytes = Encoding.UTF8.GetBytes(record.Value);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var ciphertext = new byte[valueBytes.Length];
        var tag = new byte[TagLength];

        var envelope = new byte[FixedPrefixLength + headerBytes.Length + NonceLength + ciphertext.Length + TagLength];
        envelope[0] = FormatVersion;
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

        if (!TryRestrictDirectory(_root))
        {
            throw new InvalidOperationException(
                "The runtime-state directory could not be established with a restrictive file mode.");
        }
    }

    private bool TryRestrictDirectory(string path)
    {
        if (PermissionSetter is { } setter)
        {
            return setter(path);
        }

        if (OperatingSystem.IsWindows())
        {
            return ApplyWindowsAcl(path, isDirectory: true);
        }

        try
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Establishes a restrictive mode on a committed path, failing closed. Returns <c>false</c> when
    /// the platform has a mode but it cannot be established, so the caller refuses to publish a
    /// secret whose file mode could not be tightened.
    /// </summary>
    private bool TryRestrict(string path)
    {
        if (PermissionSetter is { } setter)
        {
            return setter(path);
        }

        return DefaultPermissionSetter(path);
    }

    private static bool DefaultPermissionSetter(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return ApplyWindowsAcl(path, isDirectory: false);
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            // The platform has no file-mode concept; the contract is satisfied vacuously.
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool ApplyWindowsAcl(string path, bool isDirectory)
        => WindowsAclApplierForTesting is { } applier
            ? applier(path, isDirectory)
            : TryApplyRestrictiveWindowsAcl(path, isDirectory);

    /// <summary>
    /// Establishes and verifies a restrictive ACL on Windows: inheritance is disabled and only the
    /// running account, LocalSystem and the built-in Administrators may hold an allow rule. Returns
    /// <c>false</c> when the contract cannot be established or verified, so the caller fails closed
    /// rather than accepting an unrestricted runtime-state directory.
    /// </summary>
    private static bool TryApplyRestrictiveWindowsAcl(string path, bool isDirectory)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            var owner = WindowsIdentity.GetCurrent().User;
            if (owner is null)
            {
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

            return IsRestrictiveWindowsAcl(path, isDirectory, owner);
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or PlatformNotSupportedException
            or SecurityException
            or IdentityNotMappedException
            or ArgumentException
            or InvalidOperationException)
        {
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
        return owner is not null && IsRestrictiveWindowsAcl(path, isDirectory, owner);
    }

    [SupportedOSPlatform("windows")]
    private static bool IsRestrictiveWindowsAcl(string path, bool isDirectory, SecurityIdentifier owner)
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
                    return false;
                }

                if (sid.Equals(owner))
                {
                    ownerAllowed = true;
                }
            }

            return ownerAllowed;
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or PlatformNotSupportedException
            or SecurityException
            or ArgumentException
            or InvalidOperationException)
        {
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

            if (!PathMatchesIdentity(info, identity))
            {
                unreachable.Add(info);
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
            var envelope = File.ReadAllBytes(path);
            if (envelope.Length < MinimumEnvelopeLength || envelope[0] != FormatVersion)
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
    }
}
