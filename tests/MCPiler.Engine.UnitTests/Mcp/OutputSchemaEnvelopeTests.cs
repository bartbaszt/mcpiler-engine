using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Mcp;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>The object-rooted schema and value envelope owned by the MCP adapter.</summary>
public sealed class OutputSchemaEnvelopeTests
{
    [Fact]
    public void An_array_root_has_the_exact_golden_envelope()
    {
        JsonNode authored = JsonNode.Parse("""{"type":"array","items":{"type":"string"}}""")!;

        var shaped = OutputSchemaEnvelope.Shape(authored);

        Assert.True(shaped.Wrapped);
        Assert.Equal(
            """{"type":"object","properties":{"result":{"type":"array","items":{"type":"string"}}},"required":["result"]}""",
            shaped.Schema.ToJsonString());
    }

    [Fact]
    public void An_object_root_is_carried_byte_for_byte_without_a_synthetic_member()
    {
        JsonNode authored = JsonNode.Parse(
            """{"type":"object","properties":{"b":{"type":"string"},"a":{"type":"integer"}},"required":["b"]}""")!;

        var shaped = OutputSchemaEnvelope.Shape(authored);

        Assert.False(shaped.Wrapped);
        Assert.Equal(authored.ToJsonString(), shaped.Schema.ToJsonString());
        Assert.Null(shaped.Schema["properties"]?["result"]);
    }

    [Theory]
    [InlineData("[\"object\",\"null\"]")]
    [InlineData("[\"null\",\"object\"]")]
    public void Object_null_roots_collapse_without_mutating_the_authored_schema(string types)
    {
        JsonObject authored = JsonNode.Parse("{\"type\":" + types + ",\"properties\":{}}")!.AsObject();
        string before = authored.ToJsonString();

        var shaped = OutputSchemaEnvelope.Shape(authored);

        Assert.False(shaped.Wrapped);
        Assert.Equal("object", shaped.Schema["type"]!.GetValue<string>());
        Assert.Equal(before, authored.ToJsonString());
    }

    [Fact]
    public void An_object_union_with_another_value_type_is_not_collapsed()
    {
        JsonNode authored = JsonNode.Parse("""{"type":["object","string","null"]}""")!;

        var shaped = OutputSchemaEnvelope.Shape(authored);

        Assert.True(shaped.Wrapped);
        Assert.Equal("object", shaped.Schema["type"]!.GetValue<string>());
        Assert.Equal("string", shaped.Schema["properties"]!["result"]!["type"]![1]!.GetValue<string>());
    }

    [Theory]
    [InlineData("{\"type\":[\"object\",1]}")]
    [InlineData("{\"type\":[{\"const\":\"object\"},\"null\"]}")]
    public void A_non_text_type_member_is_preserved_inside_the_envelope(string schema)
    {
        JsonNode authored = JsonNode.Parse(schema)!;

        var shaped = OutputSchemaEnvelope.Shape(authored);

        Assert.True(shaped.Wrapped);
        Assert.Equal(authored.ToJsonString(), shaped.Schema["properties"]!["result"]!.ToJsonString());
    }

    [Fact]
    public void Only_internal_pointer_references_are_rebased()
    {
        JsonNode authored = JsonNode.Parse(
            """
            {
              "$ref": "#",
              "$defs": {
                "node": {
                  "$dynamicRef": "#/$defs/node",
                  "anchor": { "$ref": "#node" },
                  "external": { "$ref": "https://example.test/schema.json#/node" }
                }
              }
            }
            """)!;

        var shaped = OutputSchemaEnvelope.Shape(authored);
        JsonNode result = shaped.Schema["properties"]!["result"]!;

        Assert.Equal("#/properties/result", result["$ref"]!.GetValue<string>());
        Assert.Equal(
            "#/properties/result/$defs/node",
            result["$defs"]!["node"]!["$dynamicRef"]!.GetValue<string>());
        Assert.Equal("#node", result["$defs"]!["node"]!["anchor"]!["$ref"]!.GetValue<string>());
        Assert.Equal(
            "https://example.test/schema.json#/node",
            result["$defs"]!["node"]!["external"]!["$ref"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("[1,2]", true, "{\"result\":[1,2]}")]
    [InlineData("{\"answer\":42}", false, "{\"answer\":42}")]
    [InlineData("null", true, "{\"result\":null}")]
    public void A_payload_mirrors_the_schema_envelope(string payload, bool wrapped, string expected)
    {
        using JsonDocument document = JsonDocument.Parse(payload);

        JsonElement mirrored = OutputSchemaEnvelope.Mirror(document.RootElement, wrapped);

        Assert.Equal(expected, mirrored.GetRawText());
    }
}
