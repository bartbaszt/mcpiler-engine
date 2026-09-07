namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The <c>tools</c> section: the compiled advertised tool set per surface.
/// </summary>
/// <remarks>
/// Optional and derivable. When omitted, Engine derives the tool set from <c>server</c>,
/// <c>agentSurface</c> and <c>operations</c>. A golden test proves that an explicit section
/// and an omitted one produce byte-identical tool listings; when they differ the explicit
/// section wins with a loud diagnostic, never a silent divergence.
/// </remarks>
/// <param name="Surfaces">Tool sets keyed by surface slug.</param>
public sealed record ToolsSection(IReadOnlyDictionary<string, SurfaceToolSet> Surfaces = null!)
{
    /// <summary>The section format version this model represents.</summary>
    public const int FormatVersion = 1;

    /// <summary>The declared tool sets, never null.</summary>
    public IReadOnlyDictionary<string, SurfaceToolSet> Surfaces { get; init; } =
        Surfaces ?? new Dictionary<string, SurfaceToolSet>(StringComparer.Ordinal);
}

/// <summary>The advertised tool set for one surface.</summary>
/// <param name="Tools">The tools, in advertisement order.</param>
public sealed record SurfaceToolSet(IReadOnlyList<ManifestTool> Tools = null!)
{
    /// <summary>The declared tools, never null.</summary>
    public IReadOnlyList<ManifestTool> Tools { get; init; } = Tools ?? [];
}

/// <summary>One advertised MCP tool.</summary>
/// <param name="Name">The advertised tool name.</param>
/// <param name="Description">The advertised description.</param>
/// <param name="InputSchema">
/// The advertised input schema. File-slot extension keywords are retained here and stripped
/// only immediately before schema evaluation; they are presentation metadata and never a
/// security gate.
/// </param>
/// <param name="OutputSchema">The advertised output schema, when one is advertised.</param>
/// <param name="Operation">
/// The backing <c>agentSurface</c> slug, or <c>null</c> for a Navigator tool.
/// </param>
/// <param name="OperationKey">The backing execution key, for diagnostics.</param>
/// <param name="Annotations">The advertised annotations.</param>
/// <param name="SizeBytes">Studio budget accounting. Engine never reads it.</param>
/// <param name="SizeTokens">Studio budget accounting. Engine never reads it.</param>
public sealed record ManifestTool(
    string Name,
    string Description,
    ManifestSchema? InputSchema = null,
    ManifestSchema? OutputSchema = null,
    string? Operation = null,
    string? OperationKey = null,
    ToolAnnotations? Annotations = null,
    int? SizeBytes = null,
    int? SizeTokens = null)
{
    /// <summary>Maximum advertised tool name length.</summary>
    public const int MaxNameLength = 128;

    /// <summary>Name prefix reserved for Navigator tools.</summary>
    /// <remarks>
    /// A tool without an operation identity is legal only when its name starts with this
    /// prefix. That rule already governs compiled artifacts and is carried forward as a
    /// manifest validation rule.
    /// </remarks>
    public const string NavigatorPrefix = "catalogue.";

    /// <summary>The Navigator discovery tool name.</summary>
    public const string NavigatorDiscover = NavigatorPrefix + "discover";

    /// <summary>The Navigator describe tool name.</summary>
    public const string NavigatorDescribe = NavigatorPrefix + "describe";

    /// <summary>The Navigator invoke tool name.</summary>
    public const string NavigatorInvoke = NavigatorPrefix + "invoke";

    /// <summary>True when this tool has no backing agent operation.</summary>
    public bool IsNavigatorTool => Operation is null;

    /// <summary>The effective annotations.</summary>
    public ToolAnnotations EffectiveAnnotations => Annotations ?? new ToolAnnotations();
}

/// <summary>
/// The <c>search</c> section: the lexical index.
/// </summary>
/// <remarks>
/// Optional and derivable. The wire shape follows the existing lexical index serializer with
/// one change: the per-operation identifier is the manifest slug rather than a Studio
/// identifier. Field weights are part of the format so a Studio-built and an Engine-built
/// index rank identically.
/// </remarks>
/// <param name="Operations">Per-operation index documents.</param>
/// <param name="IndexedFields">The fields that were indexed.</param>
/// <param name="Scoring">The scoring profile.</param>
/// <param name="BuilderVersion">The index builder version that produced this section.</param>
public sealed record SearchSection(
    IReadOnlyList<SearchDocumentEntry> Operations = null!,
    IReadOnlyList<string> IndexedFields = null!,
    SearchScoring? Scoring = null,
    int BuilderVersion = SearchScoring.BuilderVersion)
{
    /// <summary>The section format version this model represents.</summary>
    public const int FormatVersion = 1;

    /// <summary>The declared index documents, never null.</summary>
    public IReadOnlyList<SearchDocumentEntry> Operations { get; init; } = Operations ?? [];

    /// <summary>The declared indexed fields, never null.</summary>
    public IReadOnlyList<string> IndexedFields { get; init; } = IndexedFields ?? [];

    /// <summary>The effective scoring profile.</summary>
    public SearchScoring EffectiveScoring => Scoring ?? SearchScoring.Default;
}

/// <summary>One operation's lexical index document.</summary>
/// <param name="Operation">The manifest slug this document indexes.</param>
/// <param name="Summary">The truncated summary shown in discovery results.</param>
/// <param name="Risk">The resolved risk string shown in discovery results.</param>
/// <param name="Terms">Index terms keyed by field name.</param>
public sealed record SearchDocumentEntry(
    string Operation,
    string Summary = "",
    string Risk = AgentOperationEntry.NoRisk,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Terms = null!)
{
    /// <summary>The declared terms, never null.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Terms { get; init; } =
        Terms ?? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
}

/// <summary>The lexical scoring profile and the bounds the index was built under.</summary>
/// <param name="QuantizationStep">Score quantization step.</param>
/// <param name="MetaMultiplier">Multiplier applied to metadata-derived matches.</param>
/// <param name="VectorScale">Scale applied to a vector similarity before blending.</param>
/// <param name="FieldWeights">Per-field milli-score weights.</param>
public sealed record SearchScoring(
    int QuantizationStep = 1,
    int MetaMultiplier = 2,
    int VectorScale = 10000,
    IReadOnlyDictionary<string, int> FieldWeights = null!)
{
    /// <summary>The index builder version this model represents.</summary>
    public const int BuilderVersion = 1;

    /// <summary>Maximum index terms retained per operation.</summary>
    public const int MaxTermsPerOperation = 512;

    /// <summary>Maximum schema nodes walked while extracting terms.</summary>
    public const int MaxSchemaNodes = 256;

    /// <summary>Maximum schema depth walked while extracting terms.</summary>
    public const int MaxSchemaDepth = 6;

    /// <summary>Maximum characters retained from a summary.</summary>
    public const int MaxSummaryCharacters = 200;

    /// <summary>Maximum length of a single index token.</summary>
    public const int MaxTokenLength = 64;

    /// <summary>Maximum length of text accepted for tokenization.</summary>
    public const int MaxInputLength = 512;

    /// <summary>The default scoring profile.</summary>
    public static SearchScoring Default { get; } = new();

    /// <summary>The declared field weights, never null.</summary>
    public IReadOnlyDictionary<string, int> FieldWeights { get; init; } =
        FieldWeights ?? new Dictionary<string, int>(StringComparer.Ordinal);
}
