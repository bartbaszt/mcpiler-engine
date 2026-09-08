using System.Text.Json.Nodes;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The manifest root document: format identity, the section index, and optional seal and
/// provenance.
/// </summary>
/// <param name="FormatVersion">
/// The declared manifest format version. Its versioning policy is stated in
/// <c>docs/manifest.md</c> and is independent of the Engine assembly version.
/// </param>
/// <param name="Sections">The section index, keyed by <see cref="ManifestSectionName"/>.</param>
/// <param name="Generator">Diagnostic-only producer information.</param>
/// <param name="Completeness">Present only in a sealed manifest.</param>
/// <param name="Provenance">
/// Opaque to Engine. Engine parses it as an object, never reads a member, and never fails on
/// its content. It is where Studio-only identity and diagnostics live so they cannot
/// contaminate the runtime contract.
/// </param>
public sealed record ManifestRoot(
    ManifestFormatVersion FormatVersion,
    IReadOnlyDictionary<string, ManifestSectionEntry> Sections,
    ManifestGenerator? Generator = null,
    ManifestCompleteness? Completeness = null,
    JsonObject? Provenance = null)
{
    /// <summary>True when the manifest carries a completeness seal.</summary>
    public bool IsSealed => Completeness is not null;

    /// <summary>Returns the entry for <paramref name="sectionName"/>, or <c>null</c>.</summary>
    public ManifestSectionEntry? Section(string sectionName)
        => Sections.TryGetValue(sectionName, out var entry) ? entry : null;
}

/// <summary>Producer information, carried for diagnostics only.</summary>
/// <param name="Name">Producing tool, for example <c>mcpiler-studio</c>.</param>
/// <param name="Version">Producing tool version.</param>
/// <param name="ProducedAtUtc">
/// Production timestamp. Excluded from the completeness hash so that resealing an unchanged
/// manifest reproduces the same seal.
/// </param>
public sealed record ManifestGenerator(
    string? Name = null,
    string? Version = null,
    DateTime? ProducedAtUtc = null);

/// <summary>The completeness seal over the canonicalized section index.</summary>
/// <param name="Algorithm">Fixed to <see cref="Sha256"/> in format 0.x.</param>
/// <param name="Value">Lowercase hex digest.</param>
/// <remarks>
/// Hashing the index rather than the concatenated payloads is what makes a *removed* section
/// detectable instead of inferred from the surviving parts.
/// </remarks>
public sealed record ManifestCompleteness(string Algorithm, string Value)
{
    /// <summary>The only algorithm accepted in format 0.x.</summary>
    public const string Sha256 = "sha256";
}

/// <summary>
/// One entry of the section index: either an inline payload or a reference to a file inside
/// the bundle.
/// </summary>
/// <remarks>
/// <para>
/// Exactly one of <see cref="Inline"/> and <see cref="Path"/> is populated. A hand-written
/// single-file manifest is the all-inline degenerate case and a Studio export is normally
/// all-external, but both go through one loader and one schema so the format does not fork.
/// </para>
/// <para>
/// <see cref="Sha256"/> and <see cref="Bytes"/> are advisory. In a standalone bundle the
/// index and the payloads are writable by the same actor, so self-verification detects
/// accidental corruption and partial copies but not tampering; tamper-evidence is delegated
/// to a detached signature or an image digest.
/// </para>
/// </remarks>
public sealed record ManifestSectionEntry
{
    private ManifestSectionEntry()
    {
    }

    /// <summary>The inline payload, or <c>null</c> when the section is external.</summary>
    public JsonNode? Inline { get; private init; }

    /// <summary>The bundle-relative payload path, or <c>null</c> when the section is inline.</summary>
    public string? Path { get; private init; }

    /// <summary>Expected lowercase hex SHA-256 of the payload bytes, when declared.</summary>
    public string? Sha256 { get; private init; }

    /// <summary>Expected payload length in bytes, when declared.</summary>
    public long? Bytes { get; private init; }

    /// <summary>Additional members carried on an external <c>vectors</c> entry.</summary>
    public VectorSectionMetadata? Vectors { get; private init; }

    /// <summary>True when the payload is embedded in the root document.</summary>
    public bool IsInline => Inline is not null;

    /// <summary>Creates an inline entry.</summary>
    public static ManifestSectionEntry FromInline(JsonNode payload)
        => new() { Inline = payload ?? throw new ArgumentNullException(nameof(payload)) };

    /// <summary>Creates an external entry.</summary>
    public static ManifestSectionEntry FromPath(
        string path,
        string? sha256 = null,
        long? bytes = null,
        VectorSectionMetadata? vectors = null)
        => new()
        {
            Path = string.IsNullOrWhiteSpace(path)
                ? throw new ArgumentException("A section path must be a non-empty relative path.", nameof(path))
                : path,
            Sha256 = sha256,
            Bytes = bytes,
            Vectors = vectors,
        };
}

/// <summary>
/// Embedding-matrix metadata that must cross the boundary because Engine needs it to decide
/// whether a query embedding is comparable.
/// </summary>
/// <param name="Model">Embedding model identifier.</param>
/// <param name="Dimension">Vector dimension.</param>
/// <remarks>
/// The producing AI provider profile identity stays in Platform state and is deliberately
/// absent here.
/// </remarks>
public sealed record VectorSectionMetadata(string? Model = null, int? Dimension = null);
