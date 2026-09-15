using System.Text.Json.Nodes;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// One fully read manifest: every section parsed, defaults resolved, ready for cross-section
/// validation and for serving.
/// </summary>
/// <remarks>
/// <para>
/// The four required sections are constructor-required rather than nullable, so a
/// <see cref="ManifestDocument"/> instance cannot represent a partially read bundle. That is what
/// keeps cross-section validation honest: a validator that had to tolerate a missing
/// <c>operations</c> section would be guessing about half its invariants.
/// </para>
/// <para>
/// The optional sections are genuinely optional rather than defaulted, because
/// <c>null</c> and "present but empty" mean different things: an absent <c>tools</c> section
/// means "derive it", while an empty one means "advertise nothing".
/// </para>
/// </remarks>
/// <param name="FormatVersion">The declared root format version.</param>
/// <param name="Server">Routing identity and per-surface exposure.</param>
/// <param name="Policy">Outbound execution policy, after local narrowing.</param>
/// <param name="Operations">The effective HTTP operation model.</param>
/// <param name="AgentSurface">Agent operations, groups and bindings.</param>
/// <param name="Credentials">Credential slot declarations. Absent means no credentials.</param>
/// <param name="Authentication">
/// Generic authentication profiles. Absent means every executing binding is unauthenticated,
/// exactly as if it referenced no profile.
/// </param>
/// <param name="Tools">Explicit advertised tool set, or <c>null</c> to derive it.</param>
/// <param name="Search">Explicit lexical index, or <c>null</c> to derive it.</param>
/// <param name="Vectors">Vector matrix metadata, when the bundle carries one.</param>
/// <param name="VectorPayload">
/// The raw vector matrix bytes. Never parsed during loading; an unreadable matrix degrades
/// ranking rather than failing the manifest.
/// </param>
/// <param name="Provenance">
/// Producer-defined data. Engine parses it as an object and reads nothing from it.
/// </param>
/// <param name="IsSealed">Whether the manifest carried a completeness seal.</param>
public sealed record ManifestDocument(
    ManifestFormatVersion FormatVersion,
    ServerSection Server,
    PolicySection Policy,
    OperationsSection Operations,
    AgentSurfaceSection AgentSurface,
    CredentialsSection? Credentials = null,
    AuthenticationSection? Authentication = null,
    ToolsSection? Tools = null,
    SearchSection? Search = null,
    VectorSectionMetadata? Vectors = null,
    ReadOnlyMemory<byte> VectorPayload = default,
    JsonObject? Provenance = null,
    bool IsSealed = false)
{
    /// <summary>
    /// The parsed <c>operations</c> section document, retained for reference resolution.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A <c>$ref</c> is a fragment-only pointer into its own section document, and resolution
    /// is lazy by design, so the document has to survive loading. Discarding it and keeping
    /// only the typed model would force eager inlining — the exact size amplification that
    /// made a serialized intermediate document unusable as the boundary contract.
    /// </para>
    /// <para>
    /// Optional only so a hand-built model stays usable in a test. A manifest produced by the
    /// reader always carries it, and a test asserts that.
    /// </para>
    /// </remarks>
    public JsonNode? OperationsDocument { get; init; }

    /// <summary>
    /// The parsed <c>agentSurface</c> section document, retained for reference resolution.
    /// </summary>
    public JsonNode? AgentSurfaceDocument { get; init; }

    /// <summary>The declared credentials, or an empty set.</summary>
    public CredentialsSection EffectiveCredentials => Credentials ?? CredentialsSection.Empty;

    /// <summary>The declared authentication profiles, or an empty set.</summary>
    public AuthenticationSection EffectiveAuthentication => Authentication ?? AuthenticationSection.Empty;

    /// <summary>True when the bundle carries a vector matrix payload.</summary>
    public bool HasVectors => Vectors is not null && !VectorPayload.IsEmpty;

    /// <summary>
    /// Returns the surface serving <paramref name="slug"/>, or the default surface when
    /// <paramref name="slug"/> is <c>null</c> or empty.
    /// </summary>
    /// <remarks>
    /// A disabled surface is not resolvable and discloses nothing, mirroring the current
    /// published-surface routing behavior where a disabled surface is indistinguishable from
    /// one that does not exist.
    /// </remarks>
    public ManifestSurface? ResolveSurface(string? slug)
    {
        ManifestSurface? surface = string.IsNullOrEmpty(slug)
            ? Server.DefaultSurface
            : Server.Surface(slug);

        return surface is { Enabled: true } ? surface : null;
    }
}
