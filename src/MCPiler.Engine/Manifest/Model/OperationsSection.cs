using System.Text.Json.Nodes;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The <c>operations</c> section: the effective HTTP operation model plus the local schema
/// components it references.
/// </summary>
/// <remarks>
/// This is the executable request contract and normally the largest section. It is
/// deliberately not a serialized copy of the Platform intermediate document: the Platform
/// schema mapper resolves every reference by value into every use site, which is why a
/// measured intermediate document is 1.4 to 4.0 times its source and a large API reaches
/// tens of megabytes. Permitting local references collapses that and simultaneously makes
/// the section hand-authorable.
/// </remarks>
/// <param name="Operations">The declared operations, keyed by <see cref="ManifestOperation.Key"/>.</param>
/// <param name="Servers">Document-level server URLs.</param>
/// <param name="SecuritySchemes">Named security schemes, for diagnostics and probing hints.</param>
/// <param name="Security">Document-level security requirements.</param>
/// <param name="Components">
/// The local component space that <c>$ref</c> pointers resolve into. Held as raw JSON so
/// resolution stays a pointer walk over the section document.
/// </param>
public sealed record OperationsSection(
    IReadOnlyList<ManifestOperation> Operations = null!,
    IReadOnlyList<string> Servers = null!,
    IReadOnlyDictionary<string, ManifestSecurityScheme> SecuritySchemes = null!,
    IReadOnlyList<IReadOnlyDictionary<string, IReadOnlyList<string>>> Security = null!,
    JsonObject? Components = null)
{
    /// <summary>The section format version this model represents.</summary>
    public const int FormatVersion = 1;

    /// <summary>The declared operations, never null.</summary>
    public IReadOnlyList<ManifestOperation> Operations { get; init; } = Operations ?? [];

    /// <summary>The declared servers, never null.</summary>
    public IReadOnlyList<string> Servers { get; init; } = Servers ?? [];

    /// <summary>The declared security schemes, never null.</summary>
    public IReadOnlyDictionary<string, ManifestSecurityScheme> SecuritySchemes { get; init; } =
        SecuritySchemes ?? new Dictionary<string, ManifestSecurityScheme>(StringComparer.Ordinal);

    /// <summary>The declared document-level security requirements, never null.</summary>
    public IReadOnlyList<IReadOnlyDictionary<string, IReadOnlyList<string>>> Security { get; init; } =
        Security ?? [];

    /// <summary>Returns the operation with the given execution key, or <c>null</c>.</summary>
    public ManifestOperation? Operation(string key)
        => Operations.FirstOrDefault(operation => string.Equals(operation.Key, key, StringComparison.Ordinal));
}

/// <summary>One effective HTTP operation.</summary>
/// <param name="Key">
/// The durable execution address in the form <c>"{METHOD} {normalizedPath}"</c>. Required,
/// unique within the section, and the value an HTTP binding refers to.
/// </param>
/// <param name="Method">The HTTP method. Must agree with <paramref name="Key"/>.</param>
/// <param name="Path">The path template. Must agree with <paramref name="Key"/>.</param>
/// <param name="UpstreamId">The upstream operation identifier, for diagnostics.</param>
/// <param name="Summary">Upstream summary text.</param>
/// <param name="Description">Upstream description text.</param>
/// <param name="Deprecated">Whether the upstream marks the operation deprecated.</param>
/// <param name="Tags">Upstream tags.</param>
/// <param name="Parameters">Declared parameters.</param>
/// <param name="RequestBody">Declared request body, when the operation accepts one.</param>
/// <param name="Responses">
/// Declared responses keyed by status code or <c>default</c>. Not decoration: binary
/// response classification and structured-content validation both read this, so omitting it
/// changes runtime behavior.
/// </param>
/// <param name="Security">Operation-level security requirements, overriding the document.</param>
/// <param name="Servers">Operation-level server URLs, overriding the document.</param>
public sealed record ManifestOperation(
    string Key,
    string Method,
    string Path,
    string? UpstreamId = null,
    string? Summary = null,
    string? Description = null,
    bool Deprecated = false,
    IReadOnlyList<string> Tags = null!,
    IReadOnlyList<ManifestParameter> Parameters = null!,
    ManifestRequestBody? RequestBody = null,
    IReadOnlyDictionary<string, ManifestResponse> Responses = null!,
    IReadOnlyList<IReadOnlyDictionary<string, IReadOnlyList<string>>>? Security = null,
    IReadOnlyList<string>? Servers = null)
{
    /// <summary>The response key standing for "any status not otherwise declared".</summary>
    public const string DefaultResponseKey = "default";

    /// <summary>The declared tags, never null.</summary>
    public IReadOnlyList<string> Tags { get; init; } = Tags ?? [];

    /// <summary>The declared parameters, never null.</summary>
    public IReadOnlyList<ManifestParameter> Parameters { get; init; } = Parameters ?? [];

    /// <summary>The declared responses, never null.</summary>
    public IReadOnlyDictionary<string, ManifestResponse> Responses { get; init; } =
        Responses ?? new Dictionary<string, ManifestResponse>(StringComparer.Ordinal);

    /// <summary>Builds the execution key for a method and path.</summary>
    public static string BuildKey(string method, string path)
        => $"{method.ToUpperInvariant()} {path}";

    /// <summary>True when <see cref="Key"/> agrees with <see cref="Method"/> and <see cref="Path"/>.</summary>
    public bool KeyAgreesWithMethodAndPath()
        => string.Equals(Key, BuildKey(Method, Path), StringComparison.Ordinal);
}

/// <summary>One declared parameter.</summary>
/// <param name="Name">The parameter name as transmitted.</param>
/// <param name="In">Where the parameter is transmitted.</param>
/// <param name="Required">Whether the parameter must be supplied.</param>
/// <param name="Description">Human-readable description.</param>
/// <param name="Style">Serialization style. Defaults per location when absent.</param>
/// <param name="Explode">Explode flag. Defaults per location and style when absent.</param>
/// <param name="AllowReserved">Whether reserved characters are left unescaped.</param>
/// <param name="AllowEmptyValue">Whether an empty value is transmitted.</param>
/// <param name="Deprecated">Whether the upstream marks the parameter deprecated.</param>
/// <param name="Schema">The value schema.</param>
/// <param name="Content">Media-typed representation, used instead of <paramref name="Schema"/>.</param>
public sealed record ManifestParameter(
    string Name,
    ParameterLocation In,
    bool Required = false,
    string? Description = null,
    ParameterStyle? Style = null,
    bool? Explode = null,
    bool AllowReserved = false,
    bool AllowEmptyValue = false,
    bool Deprecated = false,
    ManifestSchema? Schema = null,
    IReadOnlyDictionary<string, ManifestMediaType>? Content = null)
{
    /// <summary>The style actually applied, resolving the per-location default.</summary>
    public ParameterStyle EffectiveStyle => Style ?? Vocabulary.DefaultStyle(In);

    /// <summary>The explode flag actually applied, resolving the per-location default.</summary>
    public bool EffectiveExplode => Explode ?? Vocabulary.DefaultExplode(In, EffectiveStyle);
}

/// <summary>A declared request body.</summary>
/// <param name="Content">Representations keyed by media type.</param>
/// <param name="Required">Whether a body must be supplied.</param>
/// <param name="Description">Human-readable description.</param>
public sealed record ManifestRequestBody(
    IReadOnlyDictionary<string, ManifestMediaType> Content,
    bool Required = false,
    string? Description = null);

/// <summary>A declared response.</summary>
/// <param name="Content">Representations keyed by media type.</param>
/// <param name="Description">Human-readable description.</param>
public sealed record ManifestResponse(
    IReadOnlyDictionary<string, ManifestMediaType>? Content = null,
    string? Description = null)
{
    /// <summary>The declared representations, never null.</summary>
    public IReadOnlyDictionary<string, ManifestMediaType> Content { get; init; } =
        Content ?? new Dictionary<string, ManifestMediaType>(StringComparer.Ordinal);
}

/// <summary>One media-typed representation.</summary>
/// <param name="MediaType">The media type this representation applies to.</param>
/// <param name="Schema">The payload schema.</param>
/// <param name="ItemSchema">Schema for each item of a streamed or multipart array payload.</param>
/// <param name="Encoding">Per-property encoding, keyed by property name.</param>
/// <param name="ItemEncoding">Encoding applied to every item of an array payload.</param>
/// <param name="PrefixEncoding">Positional encoding for the leading items of an array payload.</param>
public sealed record ManifestMediaType(
    string MediaType,
    ManifestSchema? Schema = null,
    ManifestSchema? ItemSchema = null,
    IReadOnlyDictionary<string, ManifestEncoding>? Encoding = null,
    ManifestEncoding? ItemEncoding = null,
    IReadOnlyList<ManifestEncoding>? PrefixEncoding = null)
{
    /// <summary>The declared per-property encodings, never null.</summary>
    public IReadOnlyDictionary<string, ManifestEncoding> Encoding { get; init; } =
        Encoding ?? new Dictionary<string, ManifestEncoding>(StringComparer.Ordinal);

    /// <summary>The declared positional encodings, never null.</summary>
    public IReadOnlyList<ManifestEncoding> PrefixEncoding { get; init; } = PrefixEncoding ?? [];
}

/// <summary>Encoding for one part of a composite payload.</summary>
/// <param name="PropertyName">The property this encoding applies to.</param>
/// <param name="ContentType">The part's media type.</param>
/// <param name="Headers">Additional part headers, keyed by header name.</param>
/// <param name="Style">Serialization style for a form-encoded part.</param>
/// <param name="Explode">Explode flag for a form-encoded part.</param>
/// <param name="AllowReserved">Whether reserved characters are left unescaped.</param>
public sealed record ManifestEncoding(
    string PropertyName,
    string? ContentType = null,
    IReadOnlyDictionary<string, ManifestSchema>? Headers = null,
    ParameterStyle? Style = null,
    bool? Explode = null,
    bool AllowReserved = false)
{
    /// <summary>The declared part headers, never null.</summary>
    public IReadOnlyDictionary<string, ManifestSchema> Headers { get; init; } =
        Headers ?? new Dictionary<string, ManifestSchema>(StringComparer.Ordinal);
}

/// <summary>A named security scheme.</summary>
/// <param name="Scheme">The scheme identifier, for example <c>bearer</c>.</param>
/// <param name="BearerFormat">The bearer token format hint.</param>
/// <param name="In">Where the credential is transmitted, when applicable.</param>
/// <param name="Description">Human-readable description.</param>
/// <remarks>
/// Engine does not derive credential application from this; that comes from the
/// <c>credentials</c> section. This exists so diagnostics can explain what the upstream
/// declares.
/// </remarks>
public sealed record ManifestSecurityScheme(
    string? Scheme = null,
    string? BearerFormat = null,
    string? In = null,
    string? Description = null);
