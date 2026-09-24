using System.Text.Json.Nodes;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The <c>agentSurface</c> section: agent-facing operations, groups, bindings, annotations,
/// and search metadata.
/// </summary>
/// <param name="Operations">The agent operations, keyed by slug.</param>
/// <param name="Groups">Declared groups. An operation may only name a group declared here.</param>
/// <param name="Components">Local component space for agent-facing schemas.</param>
public sealed record AgentSurfaceSection(
    IReadOnlyList<AgentOperationEntry> Operations = null!,
    IReadOnlyList<OperationGroupEntry> Groups = null!,
    JsonObject? Components = null)
{
    /// <summary>The section format version this model represents.</summary>
    /// <remarks>
    /// Version 2 added the credential scope an <c>http</c> binding authorizes. Version 3 adds
    /// the authentication profile reference an <c>http</c> binding names. The section version
    /// moved rather than only the root version because each change is confined to this
    /// section's payload.
    /// </remarks>
    public const int FormatVersion = 4;

    /// <summary>The declared operations, never null.</summary>
    public IReadOnlyList<AgentOperationEntry> Operations { get; init; } = Operations ?? [];

    /// <summary>The declared groups, never null.</summary>
    public IReadOnlyList<OperationGroupEntry> Groups { get; init; } = Groups ?? [];

    /// <summary>Returns the operation with the given slug, or <c>null</c>.</summary>
    public AgentOperationEntry? Operation(string slug)
        => Operations.FirstOrDefault(operation => string.Equals(operation.Slug, slug, StringComparison.Ordinal));

    /// <summary>Returns the group with the given name, or <c>null</c>.</summary>
    /// <remarks>
    /// The join is by name, ordinal, case-sensitive. This pins what is only a convention in
    /// the current code, where the operation holds group names while the group record holds
    /// an unrelated identifier with no linking code at all.
    /// </remarks>
    public OperationGroupEntry? Group(string name)
        => Groups.FirstOrDefault(group => string.Equals(group.Name, name, StringComparison.Ordinal));
}

/// <summary>One agent-facing operation.</summary>
/// <param name="Slug">
/// Required and unique. The manifest-local identity referenced by surface exposure lists,
/// compound steps, and the derivable tool and search sections.
/// </param>
/// <param name="Name">Required. The human-facing operation name and the tool-name source.</param>
/// <param name="Binding">Required. How the operation executes.</param>
/// <param name="Kind">
/// How the operation is backed. Derived from <paramref name="Binding"/> when absent, and
/// validated against it rather than trusted.
/// </param>
/// <param name="Summary">Short description, preferred as the tool description.</param>
/// <param name="Description">Long description.</param>
/// <param name="Groups">Group names. Each must be declared on the section.</param>
/// <param name="Tags">Free-form tags.</param>
/// <param name="InputSchema">
/// The agent-facing input schema. <c>null</c> means unmodelled, which Engine treats as
/// "accept an empty object".
/// </param>
/// <param name="OutputSchema">The agent-facing output schema, or <c>null</c> when unmodelled.</param>
/// <param name="OutputSchemaPolicy">Generation and advertisement policy.</param>
/// <param name="Annotations">The four MCP tool annotation booleans.</param>
/// <param name="Risk">
/// The resolved risk string, either <c>none</c> or ordinal-sorted comma-joined camelCase
/// flags. Engine never runs risk detection; only the resolved effective value crosses the
/// boundary.
/// </param>
/// <param name="Search">Search metadata, never advertised to clients.</param>
public sealed record AgentOperationEntry(
    string Slug,
    string Name,
    ManifestBinding Binding,
    AgentOperationKind? Kind = null,
    string? Summary = null,
    string? Description = null,
    IReadOnlyList<string> Groups = null!,
    IReadOnlyList<string> Tags = null!,
    ManifestSchema? InputSchema = null,
    ManifestSchema? OutputSchema = null,
    OutputSchemaPolicySettings? OutputSchemaPolicy = null,
    ToolAnnotations? Annotations = null,
    string? Risk = null,
    SearchMetadataEntry? Search = null,
    ResponseCachePolicySettings? ResponseCache = null)
{
    /// <summary>The risk string meaning "no risk flags set".</summary>
    public const string NoRisk = "none";

    /// <summary>The declared group names, never null.</summary>
    public IReadOnlyList<string> Groups { get; init; } = Groups ?? [];

    /// <summary>The declared tags, never null.</summary>
    public IReadOnlyList<string> Tags { get; init; } = Tags ?? [];

    /// <summary>The effective output schema policy.</summary>
    public OutputSchemaPolicySettings EffectiveOutputSchemaPolicy
        => OutputSchemaPolicy ?? OutputSchemaPolicySettings.Default;

    /// <summary>The effective search metadata.</summary>
    public SearchMetadataEntry EffectiveSearch => Search ?? SearchMetadataEntry.Empty;

    /// <summary>The effective risk string.</summary>
    public string EffectiveRisk => Risk ?? NoRisk;

    /// <summary>The operation kind implied by the binding when none is declared.</summary>
    /// <remarks>
    /// Resolved through <see cref="ManifestBindingDispatcher"/> rather than by a local type
    /// test, so this cannot drift from what validation and execution conclude about the same
    /// binding.
    /// </remarks>
    public AgentOperationKind DerivedKind => ManifestBindingDispatcher.DeriveKind(Binding);

    /// <summary>The effective operation kind.</summary>
    public AgentOperationKind EffectiveKind => Kind ?? DerivedKind;

    /// <summary>The description text advertised for this operation's tool.</summary>
    public string ToolDescription => Summary ?? Description ?? Name;

    /// <summary>
    /// The annotations actually advertised, derived when absent.
    /// </summary>
    /// <remarks>
    /// Derivation order is deliberate: an explicit object wins; otherwise the resolved risk
    /// string is used; otherwise the HTTP method is used. That keeps a minimal hand-authored
    /// manifest sane without inventing semantics the authoring side does not have.
    /// </remarks>
    /// <param name="method">
    /// The HTTP method of the bound operation, when it can be resolved. Ignored when
    /// annotations or risk are explicit.
    /// </param>
    public ToolAnnotations EffectiveAnnotations(string? method = null)
    {
        if (Annotations is { } declared)
        {
            return declared;
        }

        if (Risk is { } risk)
        {
            return ToolAnnotations.FromRisk(risk);
        }

        return ToolAnnotations.FromMethod(method);
    }
}

/// <summary>Optional per-operation upstream response cache policy.</summary>
public sealed record ResponseCachePolicySettings(int TtlSeconds);

/// <summary>A declared operation group.</summary>
/// <param name="Name">The group name. The join key for an operation's group list.</param>
/// <param name="Priority">
/// A Studio budget-selection input with no Engine runtime effect in format 0.x. It is
/// retained because Navigator output groups operations.
/// </param>
public sealed record OperationGroupEntry(string Name, int Priority = 0);

/// <summary>Output schema generation and advertisement policy.</summary>
/// <param name="Generate">Whether Studio generates an output schema at all.</param>
/// <param name="Advertise">Whether the schema is advertised to clients.</param>
/// <param name="UseInternally">
/// Whether the schema is used for internal structured-content validation even when it is not
/// advertised.
/// </param>
public sealed record OutputSchemaPolicySettings(
    bool Generate = true,
    OutputSchemaAdvertisement Advertise = OutputSchemaAdvertisement.Auto,
    bool UseInternally = false)
{
    /// <summary>The policy applied when none is declared.</summary>
    public static OutputSchemaPolicySettings Default { get; } = new();
}

/// <summary>The four MCP tool annotation booleans.</summary>
/// <param name="ReadOnly">The operation does not modify upstream state.</param>
/// <param name="Destructive">The operation may irreversibly remove or overwrite state.</param>
/// <param name="Idempotent">Repeating the call with the same arguments has the same effect.</param>
/// <param name="OpenWorld">The operation reaches a system outside the caller's control.</param>
public sealed record ToolAnnotations(
    bool ReadOnly = false,
    bool Destructive = false,
    bool Idempotent = false,
    bool OpenWorld = false)
{
    /// <summary>Derives annotations from a resolved risk string.</summary>
    public static ToolAnnotations FromRisk(string risk)
    {
        ArgumentNullException.ThrowIfNull(risk);

        var flags = risk.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        return new ToolAnnotations(
            ReadOnly: Has(flags, "readOnly"),
            Destructive: Has(flags, "destructive"),
            Idempotent: Has(flags, "idempotent"),
            OpenWorld: Has(flags, "openWorld"));

        static bool Has(string[] flags, string name)
            => flags.Contains(name, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Derives annotations from an HTTP method, for a manifest that declares neither
    /// annotations nor risk.
    /// </summary>
    public static ToolAnnotations FromMethod(string? method) => method?.ToUpperInvariant() switch
    {
        "GET" or "HEAD" => new ToolAnnotations(ReadOnly: true, Idempotent: true, OpenWorld: true),
        "DELETE" => new ToolAnnotations(Destructive: true, Idempotent: true, OpenWorld: true),
        "PUT" => new ToolAnnotations(Idempotent: true, OpenWorld: true),
        _ => new ToolAnnotations(OpenWorld: true),
    };
}

/// <summary>Search metadata that improves discovery without being advertised.</summary>
/// <param name="Aliases">Alternative names.</param>
/// <param name="Keywords">Additional index terms.</param>
/// <param name="ExampleIntents">Phrasings a caller might use.</param>
public sealed record SearchMetadataEntry(
    IReadOnlyList<string> Aliases = null!,
    IReadOnlyList<string> Keywords = null!,
    IReadOnlyList<string> ExampleIntents = null!)
{
    /// <summary>No metadata, which is the default.</summary>
    public static SearchMetadataEntry Empty { get; } = new();

    /// <summary>The declared aliases, never null.</summary>
    public IReadOnlyList<string> Aliases { get; init; } = Aliases ?? [];

    /// <summary>The declared keywords, never null.</summary>
    public IReadOnlyList<string> Keywords { get; init; } = Keywords ?? [];

    /// <summary>The declared example intents, never null.</summary>
    public IReadOnlyList<string> ExampleIntents { get; init; } = ExampleIntents ?? [];
}
