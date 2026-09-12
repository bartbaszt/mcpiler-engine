using System.Text.Json;
using System.Text.Json.Nodes;

namespace MCPiler.Engine.Mcp;

/// <summary>
/// Shapes an agent-facing output schema and its value into MCPiler's object-rooted wire envelope.
/// </summary>
/// <remarks>
/// <para>
/// The pointer rewrite is schema-position-aware: it descends only through positions the JSON
/// Schema draft 2020-12 vocabulary defines as holding schemas, plus the legacy forms the format
/// still accepts. A <c>$ref</c>-shaped value inside <c>const</c>, <c>enum</c>, <c>examples</c> or
/// <c>default</c> is data the schema compares against, and rewriting it would change what the
/// schema accepts. Unknown members are treated the same way: a position the vocabulary does not
/// define is left byte for byte rather than guessed at.
/// </para>
/// <para>
/// The vocabulary and its consequences are shared with the Platform implementation through an
/// authored corpus both suites replay; a traversal change on one side alone breaks byte identity
/// between the two, which the corpus exists to catch.
/// </para>
/// </remarks>
internal static class OutputSchemaEnvelope
{
    internal const string ResultProperty = "result";

    /// <summary>Keyword positions whose value is exactly one schema.</summary>
    private static readonly string[] SingleSchemaKeywords =
    [
        "additionalItems",
        "unevaluatedItems",
        "contains",
        "not",
        "additionalProperties",
        "unevaluatedProperties",
        "propertyNames",
        "contentSchema",
        "if",
        "then",
        "else",
    ];

    /// <summary>Keyword positions whose value is a list of schemas.</summary>
    private static readonly string[] SchemaListKeywords =
        ["allOf", "anyOf", "oneOf", "prefixItems"];

    /// <summary>Keyword positions whose value maps names to schemas.</summary>
    private static readonly string[] SchemaMapKeywords =
        ["properties", "patternProperties", "dependentSchemas", "$defs", "definitions"];

    /// <summary>
    /// Every keyword position the traversal descends through: the two <c>items</c> forms, the
    /// single-schema positions, the list positions, and the name-map positions.
    /// </summary>
    /// <remarks>
    /// Exposed for the corpus guard, which asserts a shared corpus case exercises each entry,
    /// so a keyword added to the traversal without a case fails rather than passes silently.
    /// </remarks>
    internal static IReadOnlyList<string> TraversalKeywords { get; } =
        ["items", .. SingleSchemaKeywords, .. SchemaListKeywords, .. SchemaMapKeywords];

    /// <summary>
    /// Returns the schema that may be advertised and whether the synthetic result member was added.
    /// </summary>
    internal static (JsonObject Schema, bool Wrapped) Shape(JsonNode authored)
    {
        ArgumentNullException.ThrowIfNull(authored);

        JsonNode copy = authored.DeepClone();

        if (copy is JsonObject root && IsObjectRoot(root))
        {
            return (root, false);
        }

        return (new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                [ResultProperty] = RewritePointers(authored),
            },
            ["required"] = new JsonArray(ResultProperty),
        }, true);
    }

    /// <summary>Mirrors a payload into the same envelope its schema uses.</summary>
    internal static JsonElement Mirror(JsonElement payload, bool wrapped)
    {
        if (!wrapped)
        {
            return payload.Clone();
        }

        JsonObject envelope = new()
        {
            [ResultProperty] = JsonNode.Parse(payload.GetRawText()),
        };

        return JsonSerializer.SerializeToElement(envelope);
    }

    private static bool IsObjectRoot(JsonObject root)
    {
        switch (root["type"])
        {
            case JsonValue value when value.TryGetValue<string>(out string? type):
                return string.Equals(type, "object", StringComparison.Ordinal);

            case JsonArray types:
                List<string> names = [];

                foreach (JsonNode? member in types)
                {
                    if (member is not JsonValue value
                        || !value.TryGetValue<string>(out string? name)
                        || name is null)
                    {
                        return false;
                    }

                    names.Add(name);
                }

                if (names.Contains("object", StringComparer.Ordinal)
                    && names.All(static name => name is "object" or "null"))
                {
                    root["type"] = "object";
                    return true;
                }

                return false;

            default:
                return false;
        }
    }

    /// <summary>
    /// Rebuilds a schema with every internal JSON Pointer reference under it rebased:
    /// <c>#</c> becomes <c>#/properties/result</c> and <c>#/...</c> becomes
    /// <c>#/properties/result/...</c>. Anchor and external references are left as authored.
    /// </summary>
    /// <remarks>
    /// The walk is pure: the authored schema is never mutated, and members are copied in
    /// document order so a schema that needed no rewriting serializes to the bytes it
    /// arrived as.
    /// </remarks>
    private static JsonNode RewritePointers(JsonNode schema)
    {
        if (schema is not JsonObject document)
        {
            // A boolean schema is a leaf; no reference can live under it.
            return schema.DeepClone();
        }

        JsonObject rewritten = [];

        foreach ((string keyword, JsonNode? value) in document)
        {
            rewritten[keyword] = RewriteMember(keyword, value);
        }

        return rewritten;
    }

    private static JsonNode? RewriteMember(string keyword, JsonNode? value)
    {
        if (value is null)
        {
            return null;
        }

        if (keyword is "$ref" or "$dynamicRef"
            && value is JsonValue pointer
            && pointer.TryGetValue<string>(out string? reference))
        {
            return RewriteReference(reference);
        }

        // The draft 2020-12 single-schema form and the legacy draft-07 tuple form are both
        // schema positions; neither form's references may dangle inside the envelope.
        if (string.Equals(keyword, "items", StringComparison.Ordinal))
        {
            return value is JsonArray tuple ? RewriteList(tuple) : RewritePointers(value);
        }

        if (Array.IndexOf(SingleSchemaKeywords, keyword) >= 0)
        {
            return RewritePointers(value);
        }

        if (Array.IndexOf(SchemaListKeywords, keyword) >= 0 && value is JsonArray list)
        {
            return RewriteList(list);
        }

        if (Array.IndexOf(SchemaMapKeywords, keyword) >= 0 && value is JsonObject map)
        {
            return RewriteMap(map);
        }

        // Every other position - const, enum, examples, default, and everything the vocabulary
        // does not define as a schema - is data. A reference-shaped value there is a literal
        // the schema compares against, and rewriting it would change what the schema accepts.
        return value.DeepClone();
    }

    private static JsonArray RewriteList(JsonArray list)
    {
        JsonArray rewritten = [];

        foreach (JsonNode? element in list)
        {
            rewritten.Add(element is null ? null : RewritePointers(element));
        }

        return rewritten;
    }

    private static JsonObject RewriteMap(JsonObject map)
    {
        JsonObject rewritten = [];

        foreach ((string name, JsonNode? member) in map)
        {
            rewritten[name] = member is null ? null : RewritePointers(member);
        }

        return rewritten;
    }

    private static string RewriteReference(string reference)
        => reference switch
        {
            "#" => "#/properties/result",
            _ when reference.StartsWith("#/", StringComparison.Ordinal)
                => "#/properties/result" + reference[1..],
            _ => reference,
        };
}