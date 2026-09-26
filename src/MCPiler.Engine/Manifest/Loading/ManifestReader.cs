using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// The outcome of reading a manifest bundle end to end.
/// </summary>
/// <param name="Manifest">
/// The fully read manifest, or <c>null</c> when reading stopped before a complete model
/// existed.
/// </param>
/// <param name="Diagnostics">Every finding, in the order it was produced.</param>
public sealed record ManifestReadResult(
    ManifestDocument? Manifest,
    IReadOnlyList<ManifestDiagnostic> Diagnostics)
{
    /// <summary>True when a manifest was produced and nothing failed.</summary>
    public bool Succeeded => Manifest is not null && !HasErrors;

    /// <summary>True when any finding is an error.</summary>
    public bool HasErrors => Diagnostics.Any(static diagnostic => diagnostic.IsError);

    /// <summary>The error findings.</summary>
    public IEnumerable<ManifestDiagnostic> Errors
        => Diagnostics.Where(static diagnostic => diagnostic.IsError);

    /// <summary>The warning findings.</summary>
    public IEnumerable<ManifestDiagnostic> Warnings
        => Diagnostics.Where(static diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Reads a manifest bundle: resolve the index, parse every section, apply local narrowing,
/// then validate what spans sections.
/// </summary>
/// <remarks>
/// <para>
/// The order matters and is not interchangeable. Local narrowing runs before validation so
/// every later check sees the perimeter and the bounds that will actually be enforced; running
/// it afterwards would validate a policy the deployment never uses.
/// </para>
/// <para>
/// A section that failed to parse stops the read before cross-section validation. Continuing
/// would mean validating references against a half-built model, which produces confident
/// diagnostics about the wrong thing. This matches the strict-artifact precedent: a partial
/// parse is rejected wholesale rather than served in part.
/// </para>
/// </remarks>
public static class ManifestReader
{
    /// <summary>The sections a manifest cannot omit.</summary>
    /// <remarks>
    /// <c>credentials</c> is absent for an unauthenticated upstream, and <c>tools</c>,
    /// <c>search</c> and <c>vectors</c> are derivable or optional, so only these four are
    /// structurally required.
    /// </remarks>
    public static IReadOnlyList<string> RequiredSections { get; } =
    [
        ManifestSectionName.Server,
        ManifestSectionName.Policy,
        ManifestSectionName.Operations,
        ManifestSectionName.AgentSurface,
    ];

    /// <summary>
    /// Reads <paramref name="source"/> into a validated manifest.
    /// </summary>
    /// <param name="source">Where the bundle bytes come from.</param>
    /// <param name="options">Operator-controlled loading behavior.</param>
    /// <param name="overrides">Local narrowing applied before validation.</param>
    /// <param name="expressionValidator">
    /// How to classify a JMESPath expression without interpreting it in this process. A host
    /// that can confine an evaluation supplies one; when it is null, a manifest carrying a
    /// JMESPath projection is refused.
    /// </param>
    public static ManifestReadResult Read(
        IManifestSource source,
        ManifestLoadOptions? options = null,
        PolicyOverrides? overrides = null,
        IProjectionExpressionValidator? expressionValidator = null)
    {
        ArgumentNullException.ThrowIfNull(source);

        ManifestLoadOptions effectiveOptions = options ?? ManifestLoadOptions.Default;
        ManifestLoadResult loaded = ManifestLoader.Load(source, effectiveOptions);
        List<ManifestDiagnostic> diagnostics = [.. loaded.Diagnostics];

        if (loaded.Root is not { } root)
        {
            return new ManifestReadResult(Manifest: null, diagnostics);
        }

        foreach (string required in RequiredSections)
        {
            if (loaded.Section(required) is null)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SectionMissing,
                    $"The manifest declares no '{required}' section. Sections " +
                    $"{DiagnosticText.List(RequiredSections)} are required.",
                    section: required));
            }
        }

        ServerSection? server = SectionReader.ReadServer(Document(loaded, ManifestSectionName.Server), diagnostics);
        PolicySection? policy = SectionReader.ReadPolicy(Document(loaded, ManifestSectionName.Policy), diagnostics);
        OperationsSection? operations = SectionReader.ReadOperations(
            Document(loaded, ManifestSectionName.Operations),
            diagnostics);
        AgentSurfaceSection? agentSurface = SectionReader.ReadAgentSurface(
            Document(loaded, ManifestSectionName.AgentSurface),
            diagnostics);

        CredentialsSection? credentials = loaded.Section(ManifestSectionName.Credentials) is null
            ? null
            : SectionReader.ReadCredentials(
                Document(loaded, ManifestSectionName.Credentials),
                diagnostics,
                effectiveOptions.AllowInlineSecrets,
                effectiveOptions.AllowProviderReferences);

        AuthenticationSection? authentication = loaded.Section(ManifestSectionName.Authentication) is null
            ? null
            : SectionReader.ReadAuthentication(
                Document(loaded, ManifestSectionName.Authentication),
                diagnostics);

        ToolsSection? tools = loaded.Section(ManifestSectionName.Tools) is null
            ? null
            : SectionReader.ReadTools(Document(loaded, ManifestSectionName.Tools), diagnostics);

        SearchSection? search = loaded.Section(ManifestSectionName.Search) is null
            ? null
            : SectionReader.ReadSearch(Document(loaded, ManifestSectionName.Search), diagnostics);

        if (server is null || policy is null || operations is null || agentSurface is null)
        {
            return new ManifestReadResult(Manifest: null, diagnostics);
        }

        PolicySection narrowed = PolicyNarrowing.Apply(policy, overrides, diagnostics);

        if (server.IsMinimal)
        {
            server = server with
            {
                Surfaces = [ManifestSurface.Synthesize(server.Name, agentSurface.Operations.Select(static operation => operation.Slug))],
            };
        }

        ResolvedSection? vectors = loaded.Section(ManifestSectionName.Vectors);

        ManifestDocument manifest = new(
            FormatVersion: root.FormatVersion,
            Server: server,
            Policy: narrowed,
            Operations: operations,
            AgentSurface: agentSurface,
            Credentials: credentials,
            Authentication: authentication,
            Tools: tools,
            Search: search,
            Vectors: root.Section(ManifestSectionName.Vectors)?.Vectors,
            VectorPayload: vectors?.Bytes ?? default,
            Provenance: root.Provenance,
            IsSealed: root.IsSealed)
        {
            OperationsDocument = Document(loaded, ManifestSectionName.Operations),
            AgentSurfaceDocument = Document(loaded, ManifestSectionName.AgentSurface),
        };

        diagnostics.AddRange(ManifestValidator.Validate(manifest, expressionValidator));

        return new ManifestReadResult(manifest, diagnostics);
    }

    private static System.Text.Json.Nodes.JsonNode? Document(ManifestLoadResult loaded, string section)
        => loaded.Section(section)?.Document;
}
