using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// One section's payload after the index has been resolved and verified.
/// </summary>
/// <param name="Name">The section name.</param>
/// <param name="Bytes">
/// The exact payload bytes, as read. Kept so a digest is verified against what was actually
/// loaded rather than against a re-serialization of it.
/// </param>
/// <param name="Document">
/// The parsed payload, or <c>null</c> for a binary section such as the vector matrix.
/// </param>
/// <param name="WasInline">Whether the payload came from the root document.</param>
/// <param name="DeclaredPath">The declared path for an external payload.</param>
/// <param name="IntegrityVerified">
/// Whether a declared digest was present and matched. <c>false</c> means the section loaded
/// unverified, not that it failed.
/// </param>
public sealed record ResolvedSection(
    string Name,
    ReadOnlyMemory<byte> Bytes,
    JsonNode? Document,
    bool WasInline,
    string? DeclaredPath = null,
    bool IntegrityVerified = false);

/// <summary>The outcome of loading a manifest.</summary>
/// <param name="Root">
/// The parsed root, or <c>null</c> when the root itself could not be read. A non-null root
/// alongside errors means the root parsed but a section did not.
/// </param>
/// <param name="Sections">Resolved section payloads keyed by section name.</param>
/// <param name="Diagnostics">
/// Every finding, not only the first. The loader is also the authoring tool for hand-written
/// manifests, so stopping at the first error would make it useless for that job.
/// </param>
public sealed record ManifestLoadResult(
    ManifestRoot? Root,
    IReadOnlyDictionary<string, ResolvedSection> Sections,
    IReadOnlyList<ManifestDiagnostic> Diagnostics)
{
    /// <summary>True when the manifest may be used.</summary>
    public bool Succeeded => Root is not null && !HasErrors;

    /// <summary>True when at least one finding blocks loading.</summary>
    public bool HasErrors => Diagnostics.Any(static diagnostic => diagnostic.IsError);

    /// <summary>Only the blocking findings.</summary>
    public IEnumerable<ManifestDiagnostic> Errors
        => Diagnostics.Where(static diagnostic => diagnostic.IsError);

    /// <summary>Only the non-blocking findings.</summary>
    public IEnumerable<ManifestDiagnostic> Warnings
        => Diagnostics.Where(static diagnostic => !diagnostic.IsError);

    /// <summary>Returns the resolved section, or <c>null</c> when it was not declared.</summary>
    public ResolvedSection? Section(string name)
        => Sections.TryGetValue(name, out var section) ? section : null;

    /// <summary>Creates a failed result carrying only diagnostics.</summary>
    public static ManifestLoadResult Failed(params ManifestDiagnostic[] diagnostics)
        => new(
            Root: null,
            Sections: new Dictionary<string, ResolvedSection>(StringComparer.Ordinal),
            Diagnostics: diagnostics);
}
