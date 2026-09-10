using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Loading;

/// <summary>
/// A manifest may reference; an advertised schema may not. These cover the translation
/// between the two, and in particular that a recursive contract survives it intact rather
/// than being reduced.
/// </summary>
public sealed class SchemaSelfContainmentTests
{
    private static JsonNode Document(string text) => JsonNode.Parse(text)!;

    private static ManifestSchema Schema(string text) => ManifestSchema.From(JsonNode.Parse(text)!);

    private static SchemaReferenceResolver Resolver(JsonNode document, SchemaBounds? bounds = null)
        => new(document, bounds ?? SchemaBounds.Default);

    [Fact]
    public void A_schema_that_references_nothing_is_returned_unchanged()
    {
        var schema = Schema("""{"type":"object","properties":{"id":{"type":"string"}}}""");

        var contained = Resolver(Document("{}")).SelfContain(schema);

        // The same instance, not an equal copy. Byte identity for the common case is then a
        // property of the method rather than of whichever writer serializes the result.
        Assert.Same(schema, contained);
    }

    [Fact]
    public void A_reference_at_the_root_is_inlined_rather_than_advertised_as_a_pointer()
    {
        var document = Document(
            """{"components":{"schemas":{"Pet":{"type":"object","properties":{"name":{"type":"string"}}}}}}""");

        var contained = Resolver(document).SelfContain(Schema("""{"$ref":"#/components/schemas/Pet"}"""));

        // A consumer expects a typed schema at this position, and a bare pointer declares no
        // type at all.
        Assert.Equal(
            """{"type":"object","properties":{"name":{"type":"string"}}}""",
            contained.Node.ToJsonString());
    }

    [Fact]
    public void A_nested_reference_becomes_a_component_of_the_advertised_schema()
    {
        var document = Document(
            """{"components":{"schemas":{"Tag":{"type":"string","maxLength":16}}}}""");

        var contained = Resolver(document).SelfContain(
            Schema("""{"type":"object","properties":{"tag":{"$ref":"#/components/schemas/Tag"}}}"""));

        Assert.Equal(
            """{"type":"object","properties":{"tag":{"$ref":"#/$defs/Tag"}},"$defs":{"Tag":{"type":"string","maxLength":16}}}""",
            contained.Node.ToJsonString());
    }

    [Fact]
    public void A_self_referential_component_stays_recursive_and_terminates()
    {
        var document = Document(
            """
            {
              "components": { "schemas": {
                "Node": {
                  "type": "object",
                  "properties": {
                    "id": { "type": "string" },
                    "children": { "type": "array", "items": { "$ref": "#/components/schemas/Node" } }
                  }
                }
              } }
            }
            """);

        var contained = Resolver(document).SelfContain(Schema("""{"$ref":"#/components/schemas/Node"}"""));

        // The root is the component inlined, and the recursion points at the component. No
        // bound was reached and nothing was disclosed as reduced, because nothing was.
        Assert.Equal(
            """{"type":"object","properties":{"id":{"type":"string"},"children":{"type":"array","items":{"$ref":"#/$defs/Node"}}},"$defs":{"Node":{"type":"object","properties":{"id":{"type":"string"},"children":{"type":"array","items":{"$ref":"#/$defs/Node"}}}}}}""",
            contained.Node.ToJsonString());
    }

    [Fact]
    public void A_mutual_cycle_produces_one_component_per_participant()
    {
        var document = Document(
            """
            {
              "components": { "schemas": {
                "A": { "type": "object", "properties": { "b": { "$ref": "#/components/schemas/B" } } },
                "B": { "type": "object", "properties": { "a": { "$ref": "#/components/schemas/A" } } }
              } }
            }
            """);

        var contained = Resolver(document).SelfContain(
            Schema("""{"type":"object","properties":{"a":{"$ref":"#/components/schemas/A"}}}"""));

        var defs = contained.Object!["$defs"]!.AsObject();

        Assert.Equal(["B", "A"], defs.Select(static entry => entry.Key));
        Assert.Equal(
            """{"$ref":"#/$defs/A"}""",
            defs["B"]!["properties"]!["a"]!.ToJsonString());
        Assert.Equal(
            """{"$ref":"#/$defs/B"}""",
            defs["A"]!["properties"]!["b"]!.ToJsonString());
    }

    [Fact]
    public void A_chain_of_references_lands_on_the_schema_the_chain_reaches()
    {
        var document = Document(
            """
            {
              "components": { "schemas": {
                "A": { "$ref": "#/components/schemas/B" },
                "B": { "type": "integer" }
              } }
            }
            """);

        var contained = Resolver(document).SelfContain(
            Schema("""{"type":"object","properties":{"n":{"$ref":"#/components/schemas/A"}}}"""));

        // The component is what the chain arrives at, not the intermediate hop. A consumer
        // never has to follow a pointer whose target is another pointer.
        Assert.Equal(
            """{"type":"object","properties":{"n":{"$ref":"#/$defs/A"}},"$defs":{"A":{"type":"integer"}}}""",
            contained.Node.ToJsonString());
    }

    [Fact]
    public void Two_pointers_ending_in_the_same_token_get_distinct_component_names()
    {
        var document = Document(
            """
            {
              "components": {
                "schemas": { "Item": { "type": "string" } },
                "responses": { "Item": { "type": "integer" } }
              }
            }
            """);

        var contained = Resolver(document).SelfContain(
            Schema(
                """
                {
                  "type": "object",
                  "properties": {
                    "one": { "$ref": "#/components/schemas/Item" },
                    "two": { "$ref": "#/components/responses/Item" }
                  }
                }
                """));

        var defs = contained.Object!["$defs"]!.AsObject();

        Assert.Equal(["Item", "Item-2"], defs.Select(static entry => entry.Key));
        Assert.Equal("string", defs["Item"]!["type"]!.GetValue<string>());
        Assert.Equal("integer", defs["Item-2"]!["type"]!.GetValue<string>());
    }

    [Fact]
    public void A_component_name_the_schema_already_uses_is_not_overwritten()
    {
        var document = Document("""{"components":{"schemas":{"Tag":{"type":"integer"}}}}""");

        var contained = Resolver(document).SelfContain(
            Schema(
                """
                {
                  "type": "object",
                  "properties": { "tag": { "$ref": "#/components/schemas/Tag" } },
                  "$defs": { "Tag": { "type": "boolean" } }
                }
                """));

        var defs = contained.Object!["$defs"]!.AsObject();

        // The manifest's own component keeps its name and its meaning; the relocated one is
        // renamed. Overwriting would silently change what the schema accepts.
        Assert.Equal("boolean", defs["Tag"]!["type"]!.GetValue<string>());
        Assert.Equal("integer", defs["Tag-2"]!["type"]!.GetValue<string>());
        Assert.Equal("""{"$ref":"#/$defs/Tag-2"}""", contained.Object["properties"]!["tag"]!.ToJsonString());
    }

    [Fact]
    public void A_reference_that_does_not_resolve_is_left_alone()
    {
        var schema = Schema("""{"type":"object","properties":{"x":{"$ref":"#/components/schemas/Absent"}}}""");

        var contained = Resolver(Document("{}")).SelfContain(schema);

        // Loading already refuses this manifest. Reporting it again here would make the answer
        // depend on whether validation had run.
        Assert.Same(schema, contained);
    }

    [Fact]
    public void An_external_reference_is_left_alone()
    {
        var schema = Schema("""{"$ref":"https://attacker.example.com/schema.json#/definitions/Q"}""");

        Assert.Same(schema, Resolver(Document("{}")).SelfContain(schema));
    }

    [Fact]
    public void A_reference_in_a_data_position_is_not_rewritten()
    {
        var document = Document("""{"components":{"schemas":{"Tag":{"type":"string"}}}}""");

        var schema = Schema(
            """{"type":"object","properties":{"kind":{"const":{"$ref":"#/components/schemas/Tag"}}}}""");

        // 'const' carries a value, not a schema. Rewriting it would change which instance the
        // schema accepts.
        Assert.Same(schema, Resolver(document).SelfContain(schema));
    }

    [Fact]
    public void A_reference_beside_other_keywords_keeps_them_and_still_relocates()
    {
        var document = Document("""{"components":{"schemas":{"Tag":{"type":"string"}}}}""");

        var contained = Resolver(document).SelfContain(
            Schema("""{"$ref":"#/components/schemas/Tag","description":"a tag","deprecated":true}"""));

        // A reference with siblings is legal, so the root is not inlined here: inlining would
        // have to decide what happens to the siblings, and the reference form does not.
        Assert.Equal(
            """{"$ref":"#/$defs/Tag","description":"a tag","deprecated":true,"$defs":{"Tag":{"type":"string"}}}""",
            contained.Node.ToJsonString());
    }

    [Fact]
    public void Containment_is_byte_stable_across_repeated_calls()
    {
        var document = Document(
            """
            {
              "components": { "schemas": {
                "A": { "type": "object", "properties": { "b": { "$ref": "#/components/schemas/B" } } },
                "B": { "type": "object", "properties": { "a": { "$ref": "#/components/schemas/A" } } }
              } }
            }
            """);

        var resolver = Resolver(document);
        var schema = """{"type":"object","properties":{"a":{"$ref":"#/components/schemas/A"},"b":{"$ref":"#/components/schemas/B"}}}""";

        Assert.Equal(
            resolver.SelfContain(Schema(schema)).Node.ToJsonString(),
            resolver.SelfContain(Schema(schema)).Node.ToJsonString());
    }

    [Fact]
    public void Member_order_is_the_order_the_manifest_wrote()
    {
        var document = Document("""{"components":{"schemas":{"Tag":{"type":"string"}}}}""");

        var contained = Resolver(document).SelfContain(
            Schema(
                """
                {
                  "title": "z",
                  "type": "object",
                  "additionalProperties": false,
                  "properties": { "b": { "$ref": "#/components/schemas/Tag" }, "a": { "type": "integer" } }
                }
                """));

        Assert.Equal(
            """{"title":"z","type":"object","additionalProperties":false,"properties":{"b":{"$ref":"#/$defs/Tag"},"a":{"type":"integer"}},"$defs":{"Tag":{"type":"string"}}}""",
            contained.Node.ToJsonString());
    }
}
