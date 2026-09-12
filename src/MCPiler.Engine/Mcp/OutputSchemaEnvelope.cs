using System.Text.Json;
using System.Text.Json.Nodes;

namespace MCPiler.Engine.Mcp;

/// <summary>
/// Shapes an agent-facing output schema and its value into MCPiler's object-rooted wire envelope.
/// </summary>
internal static class OutputSchemaEnvelope
{
    internal const string ResultProperty = "result";

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

        RewritePointers(copy);

        return (new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                [ResultProperty] = copy,
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

    private static void RewritePointers(JsonNode node)
    {
        switch (node)
        {
            case JsonObject properties:
                foreach ((string name, JsonNode? value) in properties.ToArray())
                {
                    if (value is null)
                    {
                        continue;
                    }

                    if (name is "$ref" or "$dynamicRef"
                        && value is JsonValue pointer
                        && pointer.TryGetValue<string>(out string? reference))
                    {
                        properties[name] = RewriteReference(reference);
                    }
                    else
                    {
                        RewritePointers(value);
                    }
                }

                break;

            case JsonArray items:
                foreach (JsonNode? item in items)
                {
                    if (item is not null)
                    {
                        RewritePointers(item);
                    }
                }

                break;
        }
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
