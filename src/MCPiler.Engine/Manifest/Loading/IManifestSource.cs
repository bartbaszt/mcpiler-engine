using System.Diagnostics.CodeAnalysis;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Where a manifest's bytes come from.
/// </summary>
/// <remarks>
/// The loader never touches the filesystem directly. That keeps the whole loader testable
/// against hostile bundles without writing them to disk, and it means a future transport such
/// as an unpacked archive stream needs no loader change.
/// </remarks>
public interface IManifestSource
{
    /// <summary>
    /// A stable description of this source for diagnostics. Must not be a secret.
    /// </summary>
    string Description { get; }

    /// <summary>The root document bytes.</summary>
    ReadOnlyMemory<byte> ReadRoot();

    /// <summary>
    /// Reads a section payload by its declared bundle-relative path.
    /// </summary>
    /// <param name="declaredPath">The path exactly as written in the section index.</param>
    /// <param name="payload">The payload bytes when the section exists.</param>
    /// <param name="failure">
    /// The reason the section could not be read, when <paramref name="payload"/> is not
    /// produced.
    /// </param>
    bool TryReadSection(
        string declaredPath,
        out ReadOnlyMemory<byte> payload,
        [NotNullWhen(false)] out ManifestSourceFailure? failure);
}

/// <summary>Why a section payload could not be read.</summary>
/// <param name="Verdict">The path verdict, when the path itself was refused.</param>
/// <param name="Reason">An operator-facing explanation.</param>
public sealed record ManifestSourceFailure(ManifestPathVerdict Verdict, string Reason)
{
    /// <summary>True when the path itself was refused rather than the file being absent.</summary>
    public bool IsPathViolation => Verdict != ManifestPathVerdict.Accepted;
}
