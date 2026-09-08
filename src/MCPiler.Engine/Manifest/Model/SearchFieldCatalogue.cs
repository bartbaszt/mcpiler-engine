namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The fixed vocabulary of indexed search fields: wire names, per-field weights, and the
/// metadata subset.
/// </summary>
/// <remarks>
/// <para>
/// The vocabulary is enumerated rather than inferred from whatever an operation happens to
/// carry, so an index is inspectable and a match can be explained by the class of field it
/// occurred in without ever reproducing the matched value. That matters because the metadata
/// fields hold curated authoring text that is deliberately never advertised.
/// </para>
/// <para>
/// Weights are integer milli-score units. Only their ordering expresses intent; the absolute
/// values are calibration. They are part of the manifest format because a pinned index and a
/// derived index must rank identically, which is only true if both sides agree on the
/// weights rather than each holding a private copy.
/// </para>
/// </remarks>
public static class SearchFieldCatalogue
{
    /// <summary>The curated operation name.</summary>
    public const string Name = "name";

    /// <summary>The curated short summary.</summary>
    public const string Summary = "summary";

    /// <summary>The curated long description.</summary>
    public const string Description = "description";

    /// <summary>Curated tags.</summary>
    public const string Tags = "tags";

    /// <summary>Group names the operation belongs to.</summary>
    public const string Groups = "groups";

    /// <summary>The HTTP method and path template of the bound operation.</summary>
    public const string HttpPath = "httpPath";

    /// <summary>Top-level input schema property names.</summary>
    public const string ParameterName = "parameterName";

    /// <summary>Top-level input schema property descriptions.</summary>
    public const string ParameterDescription = "parameterDescription";

    /// <summary>Nested input schema titles, descriptions, and enumerated values.</summary>
    public const string RequestSchema = "requestSchema";

    /// <summary>Output schema text, indexed only when the schema is used internally.</summary>
    public const string ResponseSchema = "responseSchema";

    /// <summary>Curated alternative names. Metadata: indexed, weighted, never advertised.</summary>
    public const string Alias = "alias";

    /// <summary>Curated additional terms. Metadata: indexed, weighted, never advertised.</summary>
    public const string Keyword = "keyword";

    /// <summary>Curated example phrasings. Metadata: indexed, weighted, never advertised.</summary>
    public const string ExampleIntent = "exampleIntent";

    /// <summary>Compound step names.</summary>
    public const string StepName = "stepName";

    /// <summary>Compound step summaries.</summary>
    public const string StepSummary = "stepSummary";

    /// <summary>The indexed field set, in declaration order.</summary>
    public static IReadOnlyList<string> IndexedFields { get; } =
    [
        Name,
        Summary,
        Description,
        Tags,
        Groups,
        HttpPath,
        ParameterName,
        ParameterDescription,
        RequestSchema,
        ResponseSchema,
        Alias,
        Keyword,
        ExampleIntent,
        StepName,
        StepSummary,
    ];

    /// <summary>The default per-field weights in milli-score units.</summary>
    public static IReadOnlyDictionary<string, int> DefaultWeights { get; } =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [Name] = 12000,
            [Alias] = 11000,
            [Keyword] = 9000,
            [Summary] = 7000,
            [ExampleIntent] = 6500,
            [HttpPath] = 5000,
            [StepName] = 5000,
            [ParameterName] = 4500,
            [Tags] = 4000,
            [Groups] = 4000,
            [StepSummary] = 3500,
            [Description] = 3000,
            [ParameterDescription] = 2500,
            [RequestSchema] = 1500,
            [ResponseSchema] = 1500,
        };

    /// <summary>The metadata field subset: indexed and weighted, never advertised.</summary>
    public static IReadOnlySet<string> MetadataFields { get; } =
        new HashSet<string>(StringComparer.Ordinal) { Alias, Keyword, ExampleIntent };

    /// <summary>True when the name belongs to the fixed vocabulary.</summary>
    /// <param name="field">The candidate field name.</param>
    public static bool IsKnown(string? field)
        => field is not null && DefaultWeights.ContainsKey(field);

    /// <summary>True when the field is curated metadata rather than advertised text.</summary>
    /// <param name="field">The field name.</param>
    public static bool IsMetadata(string? field)
        => field is not null && MetadataFields.Contains(field);

    /// <summary>
    /// The default weight of a field, or zero when the name is outside the vocabulary.
    /// </summary>
    /// <remarks>
    /// An unknown field scores nothing rather than being rejected: an index produced by a
    /// later builder may carry a field this Engine does not model, and the sane behaviour is
    /// to ignore that field's contribution, not to refuse the whole index.
    /// </remarks>
    /// <param name="field">The field name.</param>
    public static int DefaultWeight(string? field)
        => field is not null && DefaultWeights.TryGetValue(field, out var weight) ? weight : 0;
}
