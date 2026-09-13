using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

using MCPiler.Engine.Files;

namespace MCPiler.Engine.Execution.Files;

/// <summary>
/// Engine's only durable state: content addressed by an unguessable handle, with a record
/// beside it and a lifetime attached.
/// </summary>
/// <remarks>
/// <para>
/// There is no transaction available. A filesystem gives ordering and nothing else, so the
/// ordering IS the safety argument: content is written first and the record second, and
/// removal reverses that. The consequence is that a failure can leave content with no record,
/// which is unreachable — every read starts from a record — and reclaimable by the sweep. The
/// consequence it must never have is a record whose content is absent, because that is a handle
/// a caller holds and the store cannot honour.
/// </para>
/// <para>
/// Storage names are generated, never derived from a declared filename. That removes the whole
/// class of questions about what a name may contain: a traversal sequence, a device name, a
/// control character and a trailing dot are all equally irrelevant to a path built from
/// entropy. The declared name is kept as a record field for echoing, sanitized so that echoing
/// it is safe, and never consulted when resolving a path.
/// </para>
/// <para>
/// Nothing here decides what content is admissible beyond the ceiling and the declared type.
/// Scanning is an extension point, and with none configured the record says so rather than
/// claiming a clean result.
/// </para>
/// </remarks>
public sealed class FileHandleStore
{
    /// <summary>The extension a content file carries.</summary>
    public const string ContentExtension = ".bin";

    /// <summary>The extension a record carries.</summary>
    public const string RecordExtension = ".json";

    /// <summary>
    /// The name the construction-time writability probe uses.
    /// </summary>
    /// <remarks>
    /// Named rather than random so that the check itself is testable: making this path
    /// unwritable is the portable way to arrange an unwritable root, where filesystem
    /// permissions differ per platform and per privilege level.
    /// </remarks>
    public const string WriteProbeName = ".mcpiler-write-probe";

    private const int IdBytes = 32;
    private const int CopyBufferBytes = 81920;

    /// <summary>
    /// Characters that separate a name from what precedes it on some platform.
    /// </summary>
    /// <remarks>
    /// All three regardless of the platform running. A declared filename arrives from a remote
    /// contract, so the separator that matters is whichever one the eventual consumer honours,
    /// not whichever one this process does.
    /// </remarks>
    private static readonly char[] NameSeparators = ['/', '\\', ':'];

    private readonly string _root;
    private readonly FileHandleStoreOptions _options;
    private readonly TimeSpan _orphanGrace;
    private readonly TimeProvider _clock;
    private readonly IFileContentScanner? _scanner;
    private readonly IFileHandleAuditSink? _audit;
    private readonly object _indexGate = new();
    private readonly Dictionary<string, string> _wireIndex = new(StringComparer.Ordinal);

    /// <summary>
    /// Creates a store over <paramref name="options"/>, refusing a root it cannot use.
    /// </summary>
    /// <remarks>
    /// The refusals happen here rather than on first use. A store that accepted an unusable
    /// root would fail on the first execution that produced a file, which is both later than
    /// necessary and reported as an execution failure rather than as the configuration mistake
    /// it is.
    /// </remarks>
    /// <exception cref="FileRuntimeException">
    /// The root does not exist, cannot be written to, or sits inside a directory the process
    /// serves.
    /// </exception>
    public FileHandleStore(
        FileHandleStoreOptions options,
        TimeProvider? clock = null,
        IFileContentScanner? scanner = null,
        IFileHandleAuditSink? audit = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        _root = Normalize(options.Root);
        _options = options;
        _orphanGrace = options.OrphanGrace;
        _clock = clock ?? TimeProvider.System;
        _scanner = scanner;
        _audit = audit;

        VerifyExists();
        VerifyOutsideServedRoots(options.ServedContentRoots);
        VerifyWritable();
    }

    /// <summary>The verified root, normalized.</summary>
    public string Root => _root;

    /// <summary>
    /// A hook that runs after content is written and before its record is, used to prove the
    /// failure invariant holds at that boundary.
    /// </summary>
    /// <remarks>
    /// Internal, and null in every shipped path. It exists because the boundary that matters
    /// cannot be reached from outside: the identifier is generated inside this method, so no
    /// caller can arrange for the record write to fail for a specific handle. Without the hook
    /// the invariant would be an argument rather than a test.
    /// </remarks>
    internal Func<string, CancellationToken, Task>? RecordWriteBarrier { get; set; }

    /// <summary>
    /// A hook that runs after the durable record is written but before issuance is published to
    /// the in-memory index, used to prove compensation removes both halves of the handle.
    /// </summary>
    /// <remarks>
    /// Internal and null in production. This is the first point at which both durable files
    /// exist, so a failure here is the regression boundary for "record without content" states.
    /// A process crash at this point is different: both files are coherent and may safely remain
    /// as an unobserved handle until expiry/reclamation.
    /// </remarks>
    internal Func<string, CancellationToken, Task>? RecordWrittenBarrier { get; set; }

    /// <summary>
    /// Admits <paramref name="content"/> and returns the handle that refers to it.
    /// </summary>
    /// <exception cref="FileRuntimeException">
    /// The payload exceeds the ceiling, contradicts its declared media type under a rejecting
    /// policy, or a scanner identified it as malicious.
    /// </exception>
    public async Task<FileHandleReference> IssueAsync(
        Stream content,
        string? declaredFileName,
        string? declaredMediaType,
        string scope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentException.ThrowIfNullOrEmpty(scope);

        var id = NewId();
        var contentPath = Resolve(id + ContentExtension);
        var recordPath = Resolve(id + RecordExtension);

        long length;
        string hash;
        var probe = new byte[ContentSignature.ProbeLength];
        var probeLength = 0;

        try
        {
            await using var destination = new FileStream(
                contentPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None);

            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            var buffer = new byte[CopyBufferBytes];
            long written = 0;

            while (true)
            {
                var read = await content.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                written += read;

                if (written > _options.UploadSizeLimitBytes)
                {
                    // Refused while streaming rather than after buffering. A ceiling enforced
                    // on a payload already in memory is a ceiling on nothing.
                    throw new FileRuntimeException(
                        $"The payload exceeds the configured size limit of {_options.UploadSizeLimitBytes} bytes.");
                }

                if (probeLength < probe.Length)
                {
                    var take = Math.Min(probe.Length - probeLength, read);
                    buffer.AsSpan(0, take).CopyTo(probe.AsSpan(probeLength));
                    probeLength += take;
                }

                digest.AppendData(buffer, 0, read);
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }

            length = written;
            hash = Convert.ToHexStringLower(digest.GetHashAndReset());
        }
        catch
        {
            Discard(contentPath);
            throw;
        }

        FileHandleReference reference;
        try
        {
            var signature = ContentSignature.Evaluate(declaredMediaType, probe.AsSpan(0, probeLength));

            if (signature == SignatureVerdict.Conflict && _options.RejectMagicMismatch)
            {
                throw new FileRuntimeException(
                    $"The declared media type '{ContentSignature.Essence(declaredMediaType)}' contradicts the content signature.");
            }

            var verdict = await ScanAsync(contentPath, declaredFileName, declaredMediaType, cancellationToken)
                .ConfigureAwait(false);

            if (verdict == FileScanVerdict.Infected)
            {
                throw new FileRuntimeException("A content scanner identified the payload as malicious.");
            }

            reference = new FileHandleReference(
                id,
                SanitizeFileName(declaredFileName),
                // Recorded as declared, parameters included. The essence is what the signature
                // check compares against; it is not what the reference carries. A charset on a
                // text payload is information the consumer needs, and dropping it here would
                // also disagree with the other implementation, which the shared corpus pins.
                declaredMediaType?.Trim() is { Length: > 0 } declared
                    ? declared
                    : "application/octet-stream",
                length,
                hash,
                id + ContentExtension,
                scope,
                Expiry(),
                verdict,
                signature);

            var wireHandle = HandleCodec.NewWire();
            Remember(wireHandle, reference.Id);

            if (RecordWriteBarrier is { } barrier)
            {
                await barrier(id, cancellationToken).ConfigureAwait(false);
            }

            await File.WriteAllTextAsync(
                recordPath,
                Serialize(reference).ToJsonString(),
                cancellationToken).ConfigureAwait(false);

            if (RecordWrittenBarrier is { } writtenBarrier)
            {
                await writtenBarrier(id, cancellationToken).ConfigureAwait(false);
            }

        }
        catch
        {
            Forget(id);

            // Reverse the publication order. If record creation completed (or partially wrote)
            // before the later failure, remove it before its content so no externally resolvable
            // record can ever point at bytes already gone. If the record cannot be removed, keep
            // its content too: the pair is coherent, the capability was never returned, and a
            // later sweep may reclaim it after expiry.
            if (TryDiscard(recordPath))
            {
                Discard(contentPath);
            }

            throw;
        }

        _audit?.Record(new FileHandleAuditEvent(
            FileHandleAuditAction.Issued,
            id,
            scope,
            $"admitted {length} bytes, scan {reference.ScanVerdict}, signature {reference.SignatureVerdict}",
            reference.Length,
            reference.MediaType,
            reference.ContentHash));

        return reference;
    }

    /// <summary>Resolves <paramref name="id"/> and opens its content.</summary>
    /// <remarks>
    /// Expiry is enforced here as well as by the sweep. A store that only expired on a sweep
    /// would honour every handle in the window between its lifetime ending and the next pass,
    /// which makes the configured lifetime a lower bound rather than the limit it is stated to
    /// be.
    /// </remarks>
    public async Task<FileHandleLookup> OpenAsync(string id, CancellationToken cancellationToken)
    {
        var record = await ReadRecordAsync(id, cancellationToken).ConfigureAwait(false);

        if (record is null)
        {
            return FileHandleLookup.NotFound;
        }

        if (IsExpired(record))
        {
            Remove(record, "lifetime elapsed", FileHandleAuditAction.Expired);
            return FileHandleLookup.Expired(record);
        }

        var contentPath = Resolve(record.StoragePointer);

        if (!File.Exists(contentPath))
        {
            // A record whose content is absent is the state the write ordering exists to
            // prevent. Reporting it as absent rather than as a partial success means a caller
            // never receives a truncated or empty payload under a handle that claimed a length.
            return FileHandleLookup.NotFound;
        }

        var content = new FileStream(contentPath, FileMode.Open, FileAccess.Read, FileShare.Read);

        _audit?.Record(new FileHandleAuditEvent(
            FileHandleAuditAction.Redeemed,
            record.Id,
            record.Scope,
            "content opened",
            record.Length,
            record.MediaType,
            record.ContentHash));

        return FileHandleLookup.Available(record, content);
    }

    /// <summary>Resolves <paramref name="id"/> without opening its content.</summary>
    public async Task<FileHandleLookup> DescribeAsync(string id, CancellationToken cancellationToken)
    {
        var record = await ReadRecordAsync(id, cancellationToken).ConfigureAwait(false);

        if (record is null)
        {
            return FileHandleLookup.NotFound;
        }

        if (IsExpired(record))
        {
            Remove(record, "lifetime elapsed", FileHandleAuditAction.Expired);
            return FileHandleLookup.Expired(record);
        }

        return File.Exists(Resolve(record.StoragePointer))
            ? FileHandleLookup.Available(record, Stream.Null)
            : FileHandleLookup.NotFound;
    }

    /// <summary>Removes <paramref name="id"/>, content and record together.</summary>
    /// <returns>True when a record was found and removed.</returns>
    public async Task<bool> RemoveAsync(string id, CancellationToken cancellationToken)
    {
        var record = await ReadRecordAsync(id, cancellationToken).ConfigureAwait(false);

        if (record is null)
        {
            return false;
        }

        Remove(record, "removed on request", FileHandleAuditAction.Removed);
        return true;
    }

    /// <summary>
    /// Every handle the store currently holds a record for, expired ones included.
    /// </summary>
    /// <remarks>
    /// Metadata only, and deliberately non-mutating. See <see cref="FileHandleListing"/> for why
    /// an expired handle is reported rather than removed or hidden.
    /// </remarks>
    public async Task<IReadOnlyList<FileHandleListing>> ListAsync(CancellationToken cancellationToken)
    {
        var listings = new List<FileHandleListing>();

        foreach (var recordPath in Directory.EnumerateFiles(_root, "*" + RecordExtension).Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var record = await TryParseAsync(recordPath, cancellationToken).ConfigureAwait(false);

            if (record is null)
            {
                // Reported by the sweep, which is the surface that may act on it. A listing that
                // invented an identifier for an unparseable record would be describing a handle
                // nobody holds.
                continue;
            }

            listings.Add(new FileHandleListing(
                record,
                IsExpired(record),
                File.Exists(Resolve(record.StoragePointer))));
        }

        return listings;
    }

    /// <summary>
    /// Removes every expired handle and reclaims content that no record refers to.
    /// </summary>
    /// <returns>What was removed, separated by reason.</returns>
    public async Task<FileSweepReport> SweepAsync(CancellationToken cancellationToken)
    {
        var expired = new List<string>();
        var unreadable = new List<string>();
        var withoutContent = new List<string>();
        var reclaimed = new List<string>();
        var now = _clock.GetUtcNow().UtcDateTime;

        foreach (var recordPath in Directory.EnumerateFiles(_root, "*" + RecordExtension).Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var record = await TryParseAsync(recordPath, cancellationToken).ConfigureAwait(false);

            if (record is null)
            {
                // A record that will not parse refers to nothing this store can honour. Left in
                // place it would be swept on every pass forever.
                Discard(recordPath);
                unreadable.Add(Path.GetFileNameWithoutExtension(recordPath));
                continue;
            }

            if (IsExpired(record))
            {
                Remove(record, "lifetime elapsed", FileHandleAuditAction.Expired);
                expired.Add(record.Id);
                continue;
            }

            if (!File.Exists(Resolve(record.StoragePointer)))
            {
                Discard(recordPath);
                Forget(record.Id);
                _audit?.Record(new FileHandleAuditEvent(
                    FileHandleAuditAction.Removed,
                    record.Id,
                    record.Scope,
                    "record removed because its content was absent",
                    record.Length,
                    record.MediaType,
                    record.ContentHash));
                withoutContent.Add(record.Id);
            }
        }

        foreach (var contentPath in Directory.EnumerateFiles(_root, "*" + ContentExtension).Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var id = Path.GetFileNameWithoutExtension(contentPath);

            if (File.Exists(Resolve(id + RecordExtension)))
            {
                continue;
            }

            if (now - File.GetLastWriteTimeUtc(contentPath) < _orphanGrace)
            {
                // Still inside the window in which an admission may be mid-flight.
                continue;
            }

            Discard(contentPath);
            _audit?.Record(new FileHandleAuditEvent(
                FileHandleAuditAction.Reclaimed,
                id,
                string.Empty,
                "content had no record"));
            reclaimed.Add(id);
        }

        return new FileSweepReport(expired, unreadable, withoutContent, reclaimed);
    }

    private DateTime? Expiry()
    {
        var lifetime = _options.HandleLifetime;

        // A non-positive lifetime is read as "no lifetime configured" rather than "expires
        // immediately". A store that issued handles nothing could ever redeem would be a
        // configuration mistake reported as a runtime one, on every single execution.
        return lifetime <= TimeSpan.Zero
            ? null
            : _clock.GetUtcNow().UtcDateTime + lifetime;
    }

    private bool IsExpired(FileHandleReference record)
        => record.ExpiresAtUtc is { } expiry && expiry <= _clock.GetUtcNow().UtcDateTime;

    /// <summary>
    /// The wire form the handle named <paramref name="id"/> travels as, or empty when unknown.
    /// </summary>
    /// <remarks>
    /// Known only for capabilities issued by this process. The durable file reference remains
    /// protocol-independent and carries no wire capability.
    /// </remarks>
    public string WireFormFor(string id)
    {
        if (!IsWellFormedId(id))
        {
            return string.Empty;
        }

        lock (_indexGate)
        {
            foreach (var (wire, own) in _wireIndex)
            {
                if (string.Equals(own, id, StringComparison.Ordinal))
                {
                    return wire;
                }
            }

            return string.Empty;
        }
    }

    /// <summary>
    /// Resolves a presented wire handle back to the internal file reference without opening content.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A wire form is an unrelated random value held only by the protocol adapter. The durable
    /// record contains the protocol-independent file reference, so a process restart invalidates
    /// outstanding wire capabilities while preserving the stored reference for lifecycle/sweep.
    /// </para>
    /// <para>
    /// The shape is checked first. A value with no handle shape has no meaning to resolve and is
    /// answered as absent rather than as a malformed guess.
    /// </para>
    /// </remarks>
    public async Task<FileHandleLookup> TryResolveWire(string wire, CancellationToken cancellationToken)
    {
        if (!HandleCodec.IsWireForm(wire))
        {
            return FileHandleLookup.NotFound;
        }

        string? id;

        lock (_indexGate)
        {
            _wireIndex.TryGetValue(wire, out id);
        }

        return id is null
            ? FileHandleLookup.NotFound
            : await DescribeAsync(id, cancellationToken).ConfigureAwait(false);
    }

    private void Remember(string wire, string id)
    {
        if (!HandleCodec.IsWireForm(wire) || !IsWellFormedId(id))
        {
            return;
        }

        lock (_indexGate)
        {
            _wireIndex[wire] = id;
        }
    }

    private void Forget(string id)
    {
        if (!IsWellFormedId(id))
        {
            return;
        }

        lock (_indexGate)
        {
            string? wire = _wireIndex
                .FirstOrDefault(pair => string.Equals(pair.Value, id, StringComparison.Ordinal))
                .Key;

            if (wire is not null)
            {
                _wireIndex.Remove(wire);
            }
        }
    }

    private void Remove(FileHandleReference record, string reason, FileHandleAuditAction action)
    {
        // The record goes first. Reversed, an interrupted removal would leave a handle that
        // resolves to content already gone — the one state the ordering exists to exclude.
        Discard(Resolve(record.Id + RecordExtension));
        Discard(Resolve(record.StoragePointer));

        Forget(record.Id);
        _audit?.Record(new FileHandleAuditEvent(
            action,
            record.Id,
            record.Scope,
            reason,
            record.Length,
            record.MediaType,
            record.ContentHash));
    }

    private async Task<FileHandleReference?> ReadRecordAsync(string id, CancellationToken cancellationToken)
    {
        if (!IsWellFormedId(id))
        {
            // A malformed identifier is indistinguishable from a guess, and answering it
            // differently from an unknown one would confirm which shapes exist.
            return null;
        }

        var recordPath = Resolve(id + RecordExtension);

        return File.Exists(recordPath)
            ? await TryParseAsync(recordPath, cancellationToken).ConfigureAwait(false)
            : null;
    }

    private async ValueTask<FileScanVerdict> ScanAsync(
        string contentPath,
        string? declaredFileName,
        string? declaredMediaType,
        CancellationToken cancellationToken)
    {
        if (_scanner is null)
        {
            return FileScanVerdict.NotScanned;
        }

        await using var content = new FileStream(contentPath, FileMode.Open, FileAccess.Read, FileShare.Read);

        return await _scanner.ScanAsync(
            content,
            SanitizeFileName(declaredFileName),
            ContentSignature.Essence(declaredMediaType),
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<FileHandleReference?> TryParseAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            var text = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            return Deserialize(JsonNode.Parse(text)?.AsObject());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    private static JsonObject Serialize(FileHandleReference reference) => new()
    {
        ["id"] = reference.Id,
        ["fileName"] = reference.FileName,
        ["mediaType"] = reference.MediaType,
        ["length"] = reference.Length,
        ["contentHash"] = reference.ContentHash,
        ["storagePointer"] = reference.StoragePointer,
        ["scope"] = reference.Scope,
        ["expiresAtUtc"] = reference.ExpiresAtUtc?.ToString("O", CultureInfo.InvariantCulture),
        ["scanVerdict"] = reference.ScanVerdict.ToString(),
        ["signatureVerdict"] = reference.SignatureVerdict.ToString(),
    };

    private static FileHandleReference? Deserialize(JsonObject? record)
    {
        if (record is null)
        {
            return null;
        }

        var id = record["id"]?.GetValue<string>();
        var pointer = record["storagePointer"]?.GetValue<string>();

        if (id is null || pointer is null || !IsWellFormedId(id))
        {
            return null;
        }

        var expiry = record["expiresAtUtc"]?.GetValue<string>();

        return new FileHandleReference(
            id,
            record["fileName"]?.GetValue<string>() ?? "download",
            record["mediaType"]?.GetValue<string>() ?? "application/octet-stream",
            record["length"]?.GetValue<long>() ?? 0,
            record["contentHash"]?.GetValue<string>() ?? string.Empty,
            pointer,
            record["scope"]?.GetValue<string>() ?? string.Empty,
            expiry is null
                ? null
                : DateTime.Parse(expiry, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            Enum.TryParse<FileScanVerdict>(record["scanVerdict"]?.GetValue<string>(), out var verdict)
                ? verdict
                : FileScanVerdict.NotScanned,
            Enum.TryParse<SignatureVerdict>(record["signatureVerdict"]?.GetValue<string>(), out var signature)
                ? signature
                : SignatureVerdict.Undefined);
    }

    private static string NewId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(IdBytes));

    /// <summary>True when <paramref name="id"/> has the shape this store generates.</summary>
    /// <remarks>
    /// Checked before a path is built from it. A path assembled from an unvalidated identifier
    /// would rely entirely on the containment check to catch a traversal; requiring the shape
    /// first means a hostile identifier never reaches the filesystem at all.
    /// </remarks>
    public static bool IsWellFormedId(string? id)
    {
        if (id is null || id.Length != IdBytes * 2)
        {
            return false;
        }

        foreach (var character in id)
        {
            if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// The declared name reduced to something safe to record and echo.
    /// </summary>
    /// <remarks>
    /// Never used to build a path — storage names are generated — so this is about what a
    /// consumer might do with the value, not about this store's own safety. A name carrying
    /// separators, control characters or a trailing dot has been used to mislead a downstream
    /// reader often enough that recording it verbatim is not worth the fidelity.
    /// </remarks>
    public static string SanitizeFileName(string? declared)
    {
        if (string.IsNullOrWhiteSpace(declared))
        {
            return "download";
        }

        var lastSegment = declared;

        foreach (var separator in NameSeparators)
        {
            var index = lastSegment.LastIndexOf(separator);
            if (index >= 0)
            {
                lastSegment = lastSegment[(index + 1)..];
            }
        }

        var cleaned = new string([.. lastSegment.Where(static c => !char.IsControl(c))])
            .Trim()
            .TrimEnd('.', ' ');

        return cleaned.Length == 0 ? "download" : cleaned;
    }

    /// <summary>
    /// The absolute path of <paramref name="name"/> inside the root, refused if it escapes.
    /// </summary>
    private string Resolve(string name)
    {
        var candidate = Path.GetFullPath(Path.Combine(_root, name));

        // Compared after normalization, because before it every escaping path looks like an
        // ordinary relative name. Redundant separators and dot segments are exactly what
        // normalization exists to collapse, and comparing the authored text would let both
        // through.
        if (!candidate.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new FileRuntimeException("A stored path resolved outside the configured file root.");
        }

        return candidate;
    }

    private static void Discard(string path)
        => _ = TryDiscard(path);

    private static bool TryDiscard(string path)
    {
        try
        {
            File.Delete(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Nothing useful remains to do. The leftover is unreachable in both directions —
            // content with no record, or a record the caller was never given — and the sweep
            // will try again.
            return false;
        }
    }

    private static string Normalize(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
    }

    private void VerifyExists()
    {
        if (!Directory.Exists(_root))
        {
            throw new FileRuntimeException($"The configured file root '{_root}' does not exist.");
        }
    }

    private void VerifyWritable()
    {
        var probe = Path.Combine(_root, WriteProbeName);

        try
        {
            using (var stream = new FileStream(probe, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                stream.WriteByte(0);
            }

            File.Delete(probe);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new FileRuntimeException($"The configured file root '{_root}' is not writable.", ex);
        }
    }

    private void VerifyOutsideServedRoots(IReadOnlyList<string> servedContentRoots)
    {
        foreach (var served in servedContentRoots)
        {
            if (string.IsNullOrWhiteSpace(served))
            {
                continue;
            }

            var normalized = Normalize(served);

            // Both directions. A store inside a served root is served; a served root inside the
            // store is the store serving itself. Either way an unguessable handle stops being
            // the only way to reach a payload, which is the entire access control this store
            // has.
            if (string.Equals(_root, normalized, StringComparison.Ordinal)
                || _root.StartsWith(normalized + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                || normalized.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                throw new FileRuntimeException(
                    $"The configured file root '{_root}' overlaps served content root '{normalized}'.");
            }
        }
    }
}
