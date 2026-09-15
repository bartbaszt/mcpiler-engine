using System.Security.Cryptography;
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

    private const int HeaderLengthBytes = 2;
    private const int FixedPrefixLength = 1 + HeaderLengthBytes;
    private const int MinimumEnvelopeLength = FixedPrefixLength + NonceLength + TagLength;

    private static readonly JsonSerializerOptions HeaderOptions = new()
    {
        WriteIndented = false,
    };

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
    }

    /// <summary>Test seam: runs after the ciphertext reaches the temporary file, before the flush.</summary>
    internal Func<CancellationToken, ValueTask>? TempWrittenBarrier { get; set; }

    /// <summary>Test seam: runs after the flush, before the atomic replacement.</summary>
    internal Func<CancellationToken, ValueTask>? TempFlushedBarrier { get; set; }

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

        var path = RecordPath(profileId, slot);

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

        var envelope = Encode(record);
        var target = RecordPath(record.ProfileId, record.Slot);
        var temporary = target + ".tmp-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));

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

            Restrict(temporary);
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

    private string RecordPath(string profileId, string slot)
    {
        var identity = string.Join('\u001f', _mountIdentity, profileId, slot);
        var name = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        return Path.Combine(_root, name + RecordExtension);
    }

    private void EnsureRoot()
    {
        try
        {
            Directory.CreateDirectory(_root);
            RestrictDirectory(_root);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                "The runtime-state directory could not be created or is not writable.",
                ex);
        }
    }

    private void Restrict(string path)
    {
        // A restrictive mode is part of the contract wherever the platform has one. Windows
        // inherits the directory's ACL, which the deployment already scopes, so a no-op there
        // is correct rather than a silent weakening.
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // A mode that cannot be tightened is reported by the deployment's own permissions;
            // refusing the write here would trade a durability guarantee for a cosmetic one.
        }
    }

    private static void RestrictDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
        }
    }

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
