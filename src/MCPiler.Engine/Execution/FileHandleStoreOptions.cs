using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution;

/// <summary>Where the store keeps payloads and what it refuses.</summary>
/// <param name="Root">
/// The directory that holds content and records. Verified at construction.
/// </param>
/// <param name="HandleLifetime">
/// How long an issued handle resolves. Zero or negative means a handle never expires.
/// </param>
/// <param name="UploadSizeLimitBytes">The ceiling one payload may reach.</param>
/// <param name="RejectMagicMismatch">
/// Whether content whose leading bytes contradict its declared media type is refused.
/// </param>
/// <param name="ServedContentRoots">
/// Directories the process serves to clients. The store root must be outside all of them.
/// </param>
/// <param name="OrphanGrace">
/// How long content with no record is left alone before it is reclaimed.
/// </param>
/// <remarks>
/// <para>
/// The numbers are values rather than a manifest section. The store is an adapter over a
/// filesystem, and a manifest type in its signature would make the directory that exists to
/// hold no product knowledge the place where a policy is interpreted. Projecting the section
/// here keeps the interpretation in the host-free half, where it can be read and tested without
/// a disk.
/// </para>
/// <para>
/// The grace period exists because content is written before its record, so an orphan is the
/// normal appearance of an admission that is still in progress. A sweep with no grace would
/// race the writer and delete a payload a caller is about to be handed.
/// </para>
/// </remarks>
public sealed record FileHandleStoreOptions(
    string Root,
    TimeSpan HandleLifetime,
    long UploadSizeLimitBytes,
    bool RejectMagicMismatch,
    IReadOnlyList<string> ServedContentRoots,
    TimeSpan OrphanGrace)
{
    /// <summary>The grace period applied when a caller states none.</summary>
    public static TimeSpan DefaultOrphanGrace { get; } = TimeSpan.FromMinutes(5);

    /// <summary>Projects a manifest's file policy onto a store rooted at <paramref name="root"/>.</summary>
    /// <param name="root">The directory that will hold content and records.</param>
    /// <param name="policy">The governing file policy, or null for the manifest default.</param>
    /// <param name="servedContentRoots">Directories the process serves to clients.</param>
    /// <param name="orphanGrace">
    /// How long orphan content is left alone, or null for <see cref="DefaultOrphanGrace"/>.
    /// </param>
    public static FileHandleStoreOptions For(
        string root,
        FilePolicy? policy = null,
        IReadOnlyList<string>? servedContentRoots = null,
        TimeSpan? orphanGrace = null)
    {
        var effective = policy ?? FilePolicy.Default;

        return new FileHandleStoreOptions(
            root,
            effective.HandleLifetime,
            effective.UploadSizeLimitBytes,
            effective.RejectMagicMismatch,
            servedContentRoots ?? [],
            orphanGrace ?? DefaultOrphanGrace);
    }
}
