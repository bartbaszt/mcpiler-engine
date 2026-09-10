namespace MCPiler.Engine.Execution;

/// <summary>What a content scan concluded about a stored payload.</summary>
/// <remarks>
/// <para>
/// <see cref="NotScanned"/> exists because it is the truth in the shipped configuration, and
/// because the alternative is worse than useless. A store with no scanner that records
/// <see cref="Clean"/> tells every later reader that the payload passed a check nobody ran; an
/// operator auditing what was admitted cannot then distinguish a scanned file from an
/// unscanned one, and the record is confidently wrong rather than merely incomplete.
/// </para>
/// <para>
/// <see cref="Unknown"/> is a scanner's own inconclusive answer. It is not the absence of a
/// scanner.
/// </para>
/// </remarks>
public enum FileScanVerdict
{
    /// <summary>No scanner was configured, so no scan was performed.</summary>
    NotScanned,

    /// <summary>A scanner examined the content and raised nothing.</summary>
    Clean,

    /// <summary>A scanner identified the content as malicious.</summary>
    Infected,

    /// <summary>A scanner examined the content and could not conclude.</summary>
    Unknown,
}

/// <summary>How a declared media type compares with the content's own signature.</summary>
public enum SignatureVerdict
{
    /// <summary>No signature is defined for the declared media type, so nothing was compared.</summary>
    Undefined,

    /// <summary>The content begins the way the declared media type requires.</summary>
    Match,

    /// <summary>The content contradicts the declared media type.</summary>
    Conflict,
}

/// <summary>
/// A stored payload, described independently of how any protocol exposes it.
/// </summary>
/// <remarks>
/// <para>
/// These are the eight properties a file has inside the product: what it is called, what it
/// claims to be, how large it is, what it hashes to, where it sits, who owns it, when it stops
/// being valid, and which identifier refers to it. None of them is an MCP concept, and nothing
/// here says which protocol version will eventually carry it or in what shape.
/// </para>
/// <para>
/// The scan verdict travels with the reference rather than being recomputed on read. It is a
/// statement about what happened when the payload was admitted, and a store that re-derived it
/// later would be reporting a different event under the same name.
/// </para>
/// </remarks>
/// <param name="Id">The opaque, unguessable identifier.</param>
/// <param name="FileName">The declared name, sanitized for echoing and never used as a path.</param>
/// <param name="MediaType">The declared media type.</param>
/// <param name="Length">The stored byte length.</param>
/// <param name="ContentHash">Lower-case hexadecimal SHA-256 of the stored bytes.</param>
/// <param name="StoragePointer">Where the content sits, relative to the store's root.</param>
/// <param name="Scope">The owning scope, which a later transfer surface will authorize against.</param>
/// <param name="ExpiresAtUtc">When the handle stops resolving, or null when it does not expire.</param>
/// <param name="ScanVerdict">What a scan concluded, or that none was performed.</param>
/// <param name="SignatureVerdict">How the declared media type compared with the content signature.</param>
public sealed record FileHandleReference(
    string Id,
    string FileName,
    string MediaType,
    long Length,
    string ContentHash,
    string StoragePointer,
    string Scope,
    DateTime? ExpiresAtUtc,
    FileScanVerdict ScanVerdict,
    SignatureVerdict SignatureVerdict);

/// <summary>Why a handle lookup did not produce content.</summary>
public enum FileHandleStatus
{
    /// <summary>The handle resolves and its content is available.</summary>
    Available,

    /// <summary>No handle with that identifier is recorded.</summary>
    NotFound,

    /// <summary>The handle was recorded and its lifetime has passed.</summary>
    Expired,
}

/// <summary>The outcome of resolving a handle.</summary>
/// <remarks>
/// Expiry is a distinct outcome from absence. They call for different explanations — one is a
/// caller holding a handle too long, the other a caller holding a handle that never existed —
/// and collapsing them would make an ordinary timeout indistinguishable from a bug or an
/// attempt to guess an identifier.
/// </remarks>
public sealed class FileHandleLookup
{
    private FileHandleLookup(FileHandleStatus status, FileHandleReference? reference, Stream? content)
    {
        Status = status;
        Reference = reference;
        Content = content;
    }

    /// <summary>Why the lookup ended the way it did.</summary>
    public FileHandleStatus Status { get; }

    /// <summary>The stored description, present unless the handle is unknown.</summary>
    public FileHandleReference? Reference { get; }

    /// <summary>The content stream, present only when the handle resolves.</summary>
    public Stream? Content { get; }

    /// <summary>No handle with that identifier is recorded.</summary>
    public static FileHandleLookup NotFound { get; } = new(FileHandleStatus.NotFound, null, null);

    /// <summary>The handle exists and its lifetime has passed.</summary>
    public static FileHandleLookup Expired(FileHandleReference reference)
        => new(FileHandleStatus.Expired, reference, null);

    /// <summary>The handle resolves.</summary>
    public static FileHandleLookup Available(FileHandleReference reference, Stream content)
        => new(FileHandleStatus.Available, reference, content);
}

/// <summary>Something that happened to a stored payload, recorded for an operator.</summary>
public enum FileHandleAuditAction
{
    /// <summary>A payload was admitted and a handle issued.</summary>
    Issued,

    /// <summary>A handle was resolved and its content read.</summary>
    Redeemed,

    /// <summary>A handle was refused because its lifetime had passed.</summary>
    Expired,

    /// <summary>A handle's content and record were removed together.</summary>
    Removed,

    /// <summary>Content with no record was reclaimed.</summary>
    Reclaimed,
}

/// <summary>One audit record about a stored payload.</summary>
/// <remarks>
/// Carries an identifier, a scope and a reason. Never a filename, never a media type, never a
/// byte of content: an audit trail that reproduced payload metadata would become a second copy
/// of the thing whose lifetime the store exists to bound.
/// </remarks>
/// <param name="Action">What happened.</param>
/// <param name="HandleId">Which handle it happened to.</param>
/// <param name="Scope">The owning scope.</param>
/// <param name="Reason">A short explanation, safe to record.</param>
public sealed record FileHandleAuditEvent(
    FileHandleAuditAction Action,
    string HandleId,
    string Scope,
    string Reason);

/// <summary>Where the store's audit records go.</summary>
/// <remarks>
/// A port rather than a logger because Engine depends on no logging package, and because
/// removal being auditable is a property of the store rather than of whatever eventually
/// listens.
/// </remarks>
public interface IFileHandleAuditSink
{
    /// <summary>Records one event.</summary>
    void Record(FileHandleAuditEvent record);
}

/// <summary>An extension point for examining content before it is admitted.</summary>
/// <remarks>
/// Nothing ships behind it. That is deliberate: the store records that no scan was performed
/// rather than pretending a default check is a scan, and an operator who wants scanning
/// supplies one.
/// </remarks>
public interface IFileContentScanner
{
    /// <summary>Examines <paramref name="content"/> and returns what it concluded.</summary>
    /// <remarks>
    /// The stream is positioned at the beginning and is seekable. An implementation MUST NOT
    /// assume it may buffer the whole payload: the size ceiling exists precisely because a
    /// payload can be larger than memory.
    /// </remarks>
    ValueTask<FileScanVerdict> ScanAsync(
        Stream content,
        string fileName,
        string mediaType,
        CancellationToken cancellationToken);
}
