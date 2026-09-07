using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Turns a resolved section payload into its typed model.
/// </summary>
/// <remarks>
/// <para>
/// Section reading is deliberately separate from loading. The loader answers "which bytes
/// belong to which section and can they be trusted"; this type answers "what do those bytes
/// mean". Keeping them apart is what stops a packaging failure from being reported as a
/// semantic one, and it lets a caller read one section in isolation, which is what the
/// authoring tooling needs.
/// </para>
/// <para>
/// Every reader is strict. An unknown member, a wrongly typed member, an unrecognized
/// vocabulary token, and a duplicate identity are all refusals. A reader returns
/// <see langword="null"/> only when the section cannot be represented at all; otherwise it
/// returns the model it could build and reports everything it found, because reporting one
/// problem per pass makes a hand-authored manifest tedious to fix.
/// </para>
/// <para>
/// The <c>formatVersion</c> member is optional in every section. A hand-authored minimal
/// manifest should not have to repeat a constant eight times, and an absent version simply
/// means "the version this Engine implements". A version that is present but unsupported is
/// still refused, because it is a statement the author expects to be honored.
/// </para>
/// </remarks>
public static class SectionReader
{
    /// <summary>Reads the <c>server</c> section.</summary>
    /// <param name="document">The section payload.</param>
    /// <param name="diagnostics">Where findings are appended.</param>
    public static ServerSection? ReadServer(JsonNode? document, ICollection<ManifestDiagnostic> diagnostics)
        => ServerSectionReader.Read(document, Context(ManifestSectionName.Server, diagnostics));

    /// <summary>Reads the <c>policy</c> section.</summary>
    /// <param name="document">The section payload.</param>
    /// <param name="diagnostics">Where findings are appended.</param>
    public static PolicySection? ReadPolicy(JsonNode? document, ICollection<ManifestDiagnostic> diagnostics)
        => PolicySectionReader.Read(document, Context(ManifestSectionName.Policy, diagnostics));

    /// <summary>Reads the <c>credentials</c> section.</summary>
    /// <param name="document">The section payload.</param>
    /// <param name="diagnostics">Where findings are appended.</param>
    /// <param name="allowInlineSecrets">
    /// Whether a literal secret is permitted. Defaults to <see langword="false"/> so an
    /// inline secret is refused unless an operator opted in explicitly.
    /// </param>
    public static CredentialsSection? ReadCredentials(
        JsonNode? document,
        ICollection<ManifestDiagnostic> diagnostics,
        bool allowInlineSecrets = false)
        => CredentialsSectionReader.Read(
            document,
            Context(ManifestSectionName.Credentials, diagnostics),
            allowInlineSecrets);

    /// <summary>Reads the <c>operations</c> section.</summary>
    /// <param name="document">The section payload.</param>
    /// <param name="diagnostics">Where findings are appended.</param>
    public static OperationsSection? ReadOperations(
        JsonNode? document,
        ICollection<ManifestDiagnostic> diagnostics)
        => OperationsSectionReader.Read(document, Context(ManifestSectionName.Operations, diagnostics));

    /// <summary>Reads the <c>agentSurface</c> section.</summary>
    /// <param name="document">The section payload.</param>
    /// <param name="diagnostics">Where findings are appended.</param>
    public static AgentSurfaceSection? ReadAgentSurface(
        JsonNode? document,
        ICollection<ManifestDiagnostic> diagnostics)
        => AgentSurfaceSectionReader.Read(document, Context(ManifestSectionName.AgentSurface, diagnostics));

    /// <summary>Reads the optional <c>tools</c> section.</summary>
    /// <param name="document">The section payload.</param>
    /// <param name="diagnostics">Where findings are appended.</param>
    public static ToolsSection? ReadTools(JsonNode? document, ICollection<ManifestDiagnostic> diagnostics)
        => DerivedSectionReader.ReadTools(document, Context(ManifestSectionName.Tools, diagnostics));

    /// <summary>Reads the optional <c>search</c> section.</summary>
    /// <param name="document">The section payload.</param>
    /// <param name="diagnostics">Where findings are appended.</param>
    public static SearchSection? ReadSearch(JsonNode? document, ICollection<ManifestDiagnostic> diagnostics)
        => DerivedSectionReader.ReadSearch(document, Context(ManifestSectionName.Search, diagnostics));

    private static SectionReadContext Context(string section, ICollection<ManifestDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);

        return new SectionReadContext(section, diagnostics);
    }
}
