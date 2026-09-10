using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;

namespace MCPiler.Engine.Runtime;

/// <summary>One stored handle, described in terms an operator reads.</summary>
/// <param name="Id">The handle identifier.</param>
/// <param name="FileName">The sanitized declared name.</param>
/// <param name="MediaType">The declared media type.</param>
/// <param name="Length">Stored byte length.</param>
/// <param name="ContentHash">Lower-case hexadecimal SHA-256 of the stored bytes.</param>
/// <param name="Scope">The owning scope.</param>
/// <param name="ExpiresAtUtc">When the handle stops resolving, or null when it does not expire.</param>
/// <param name="ScanVerdict">What a scan concluded, or that none was performed.</param>
/// <param name="SignatureVerdict">How the declared media type compared with the content signature.</param>
/// <param name="Expired">Whether its lifetime has passed.</param>
/// <param name="ContentPresent">Whether the content the record points at is still on disk.</param>
/// <remarks>
/// The content hash is here and the content is not. A hash lets an operator answer "is this
/// the file I think it is" against something they already hold; printing bytes would put
/// payload into a terminal, a scrollback buffer and whatever collects it.
/// </remarks>
public sealed record StoredHandle(
    string Id,
    string FileName,
    string MediaType,
    long Length,
    string ContentHash,
    string Scope,
    DateTime? ExpiresAtUtc,
    string ScanVerdict,
    string SignatureVerdict,
    bool Expired,
    bool ContentPresent);

/// <summary>What one sweep reclaimed, by reason.</summary>
/// <param name="ExpiredHandles">Handles removed because their lifetime had passed.</param>
/// <param name="UnreadableRecords">Records that would not parse.</param>
/// <param name="RecordsWithoutContent">Records whose content was already gone.</param>
/// <param name="ReclaimedContent">Orphan content past the grace window.</param>
public sealed record SweepOutcome(
    IReadOnlyList<string> ExpiredHandles,
    IReadOnlyList<string> UnreadableRecords,
    IReadOnlyList<string> RecordsWithoutContent,
    IReadOnlyList<string> ReclaimedContent)
{
    /// <summary>How many entries were removed in total.</summary>
    public int Total =>
        ExpiredHandles.Count + UnreadableRecords.Count + RecordsWithoutContent.Count + ReclaimedContent.Count;
}

/// <summary>
/// Reading and reclaiming the file store from outside a serving process.
/// </summary>
/// <remarks>
/// <para>
/// The store is the only durable state Engine owns, and until now nothing could see it. An
/// operator whose disk was filling had no way to learn what was holding it and no way to
/// reclaim anything except by deleting files under a running process.
/// </para>
/// <para>
/// Listing and showing do not mutate. Redemption removes an expired handle because a caller
/// asked for content and must not receive it; an operator asking what exists has asked for
/// nothing to change. Only the sweep removes, and it says what it removed.
/// </para>
/// </remarks>
public sealed class FileStoreInspection
{
    private readonly FileHandleStore _store;

    private FileStoreInspection(FileHandleStore store) => _store = store;

    /// <summary>Opens the store at <paramref name="root"/>, or explains why it cannot.</summary>
    /// <param name="root">The configured file-store root.</param>
    /// <param name="refusal">Why the store is unusable, when this returns null.</param>
    /// <remarks>
    /// The same verification a serving process performs, so an operator inspecting a root
    /// learns about an unusable one here rather than at the next deployment.
    /// </remarks>
    public static FileStoreInspection? Open(string root, out StartupRefusal? refusal)
    {
        ArgumentException.ThrowIfNullOrEmpty(root);

        try
        {
            var opened = new FileStoreInspection(new FileHandleStore(FileHandleStoreOptions.For(root)));
            refusal = null;
            return opened;
        }
        catch (FileRuntimeException ex)
        {
            refusal = new StartupRefusal(string.Empty, "host/file-store-unusable", ex.Message)
            {
                Setting = "file-store-root",
                Attempted = root,
            };

            return null;
        }
    }

    /// <summary>Every handle the store holds a record for, expired ones included.</summary>
    public async Task<IReadOnlyList<StoredHandle>> ListAsync(CancellationToken cancellationToken)
        => [.. (await _store.ListAsync(cancellationToken).ConfigureAwait(false)).Select(Project)];

    /// <summary>One handle by identifier, or null when the store holds no record for it.</summary>
    /// <remarks>
    /// Resolved through the same listing the operator would otherwise read, so an expired
    /// handle is reported as expired rather than removed on the way past. A read that
    /// silently reclaims is a worse surface than one that reports an inconvenient truth.
    /// </remarks>
    public async Task<StoredHandle?> ShowAsync(string id, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        return (await ListAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(handle => string.Equals(handle.Id, id, StringComparison.Ordinal));
    }

    /// <summary>Reclaims expired handles and orphan content, reporting what went.</summary>
    public async Task<SweepOutcome> SweepAsync(CancellationToken cancellationToken)
    {
        FileSweepReport report = await _store.SweepAsync(cancellationToken).ConfigureAwait(false);

        return new SweepOutcome(
            report.ExpiredHandles,
            report.UnreadableRecords,
            report.RecordsWithoutContent,
            report.ReclaimedContent);
    }

    private static StoredHandle Project(FileHandleListing listing)
        => new(
            listing.Reference.Id,
            listing.Reference.FileName,
            listing.Reference.MediaType,
            listing.Reference.Length,
            listing.Reference.ContentHash,
            listing.Reference.Scope,
            listing.Reference.ExpiresAtUtc,
            listing.Reference.ScanVerdict.ToString(),
            listing.Reference.SignatureVerdict.ToString(),
            listing.Expired,
            listing.ContentPresent);
}
