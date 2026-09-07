using System.Text.Json.Nodes;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// A schema carried by the manifest, held as JSON rather than as a mirrored record
/// hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is not a typed record tree.</b> Modelling every schema keyword as a typed
/// member would be a second implementation of the Platform intermediate schema model inside
/// Engine. Two independent schema models drift, and every drift is a silent round-trip loss
/// on a customer's contract. Keeping the JSON as-is makes round-trip fidelity structural
/// instead of something a test has to chase, and validation already runs on a JSON Schema
/// evaluator that consumes JSON directly.
/// </para>
/// <para>
/// <b>Two documented deviations from plain JSON Schema</b>, both required for fidelity with
/// the Platform schema model:
/// </para>
/// <list type="number">
///   <item><c>nullable</c> is a boolean keyword. Representing it as
///     <c>type: ["string","null"]</c> would lose the distinction between "declared nullable"
///     and "a union that happens to include null".</item>
///   <item>numeric bounds are preserved lexically. <c>minimum</c>, <c>maximum</c>,
///     <c>exclusiveMinimum</c>, <c>exclusiveMaximum</c> and <c>multipleOf</c> keep the
///     original token, which is why canonicalization does not renormalize numbers.</item>
/// </list>
/// <para>
/// An absent <c>type</c> means "any", matching the intermediate model's unconstrained state.
/// </para>
/// </remarks>
public sealed record ManifestSchema
{
    /// <summary>The JSON Pointer reference keyword.</summary>
    public const string RefKeyword = "$ref";

    private ManifestSchema(JsonNode node) => Node = node;

    /// <summary>The raw schema JSON. Never mutated by Engine.</summary>
    public JsonNode Node { get; }

    /// <summary>The schema object, or <c>null</c> when the schema is a boolean.</summary>
    public JsonObject? Object => Node as JsonObject;

    /// <summary>
    /// True for the boolean schema <c>true</c> or <c>false</c>, which JSON Schema permits
    /// wherever a schema is expected.
    /// </summary>
    public bool IsBoolean => Node is JsonValue value && value.TryGetValue<bool>(out _);

    /// <summary>
    /// The <c>$ref</c> pointer when this schema is a reference, otherwise <c>null</c>.
    /// </summary>
    /// <remarks>
    /// References are fragment-only JSON Pointers into the same section document. There is
    /// no base URI, no document graph, and no network fetch anywhere in the format.
    /// </remarks>
    public string? RefPointer => Text(RefKeyword);

    /// <summary>True when this schema is a reference to another node.</summary>
    public bool IsReference => RefPointer is not null;

    /// <summary>The declared <c>type</c>, or <c>null</c> meaning any.</summary>
    public string? Type => Text("type");

    /// <summary>The declared <c>format</c>.</summary>
    public string? Format => Text("format");

    /// <summary>The declared <c>contentEncoding</c>.</summary>
    public string? ContentEncoding => Text("contentEncoding");

    /// <summary>The declared <c>contentMediaType</c>.</summary>
    public string? ContentMediaType => Text("contentMediaType");

    /// <summary>The declared <c>nullable</c> flag. See the deviation note on this type.</summary>
    public bool Nullable => Flag("nullable");

    /// <summary>Wraps a schema node.</summary>
    public static ManifestSchema From(JsonNode node)
        => new(node ?? throw new ArgumentNullException(nameof(node)));

    /// <summary>Wraps a schema node, or returns <c>null</c> for an absent schema.</summary>
    public static ManifestSchema? FromOrNull(JsonNode? node)
        => node is null ? null : new ManifestSchema(node);

    /// <summary>Returns the schema at <paramref name="keyword"/>, or <c>null</c>.</summary>
    public ManifestSchema? Child(string keyword) => FromOrNull(Object?[keyword]);

    private string? Text(string keyword)
        => Object?[keyword] is JsonValue value && value.TryGetValue<string>(out var text)
            ? text
            : null;

    private bool Flag(string keyword)
        => Object?[keyword] is JsonValue value
            && value.TryGetValue<bool>(out var flag)
            && flag;
}
