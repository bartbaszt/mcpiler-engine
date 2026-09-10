namespace MCPiler.Engine.Runtime;

/// <summary>
/// One advertised tool, described without a protocol type and without a manifest type.
/// </summary>
/// <remarks>
/// <para>
/// This is what a transport renders. Everything a listing shows is already decided here, so
/// converting it into whatever an SDK wants is a mechanical mapping with nowhere to make a
/// choice. That is the whole reason the type exists on the seam rather than a manifest tool
/// being handed across.
/// </para>
/// <para>
/// <see cref="InputSchemaJson"/> is text rather than a JSON object on purpose. A node handed
/// to a caller can be mutated, and its serialization depends on the writer that eventually
/// runs; the text is the bytes. Two transports rendering the same catalogue therefore
/// advertise the same schema because they were given the same bytes, not because two
/// serializers happened to agree.
/// </para>
/// <para>
/// The schema is the one derivation produced, verbatim, and nothing here re-derives,
/// resolves, flattens or truncates it. Derivation is also where a manifest-local reference is
/// relocated into the schema's own components, because the surface fingerprint is taken over
/// the advertised facts and a listing showing something the fingerprint did not cover would
/// make equal fingerprints stop meaning equal listings.
/// </para>
/// </remarks>
/// <param name="Name">The advertised tool name.</param>
/// <param name="Title">The advertised human-readable title.</param>
/// <param name="Description">The advertised description, including any disclosures.</param>
/// <param name="InputSchemaJson">The advertised input schema, as JSON text.</param>
/// <param name="ReadOnly">Whether the tool is advertised as making no modification.</param>
/// <param name="Destructive">Whether the tool is advertised as destructive.</param>
/// <param name="Idempotent">Whether the tool is advertised as safe to repeat.</param>
/// <param name="OpenWorld">Whether the tool is advertised as reaching an open world.</param>
public sealed record CatalogueTool(
    string Name,
    string Title,
    string Description,
    string InputSchemaJson,
    bool ReadOnly,
    bool Destructive,
    bool Idempotent,
    bool OpenWorld)
{
    /// <summary>
    /// The agent operation this tool invokes, or <c>null</c> for a Navigator tool.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Carried so that resolving a called name and dispatching it are one lookup rather than
    /// two. A transport does not read this: it hands a name back and is told what happened.
    /// A transport that branched on it would be deciding which operation a call reaches, which
    /// is the decision the seam exists to keep on this side.
    /// </para>
    /// <para>
    /// Absent means the tool has no backing operation, which is what a Navigator tool is. It
    /// is not "unknown": a Navigator tool is advertised deliberately and is invoked through a
    /// different path.
    /// </para>
    /// </remarks>
    public string? Operation { get; init; }
}
