using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Loading;

public sealed class SchemaReferenceResolverTests
{
    private static JsonNode Document(string text) => JsonNode.Parse(text)!;

    private static ManifestSchema Schema(string text) => ManifestSchema.From(JsonNode.Parse(text)!);

    private static SchemaReferenceResolver Resolver(JsonNode document, SchemaBounds? bounds = null)
        => new(document, bounds ?? SchemaBounds.Default);

    [Fact]
    public void Resolves_a_local_pointer_into_the_same_section()
    {
        var document = Document(
            """{ "components": { "schemas": { "Pet": { "type": "object", "title": "Pet" } } } }""");

        Assert.True(Resolver(document).TryResolve(
            Schema("""{ "$ref": "#/components/schemas/Pet" }"""),
            out var resolved,
            out var failure));

        Assert.Null(failure);
        Assert.Equal("object", resolved.Type);
        Assert.Equal("Pet", resolved.Object!["title"]!.GetValue<string>());
    }

    [Fact]
    public void Resolves_a_chain_of_references()
    {
        var document = Document(
            """
            {
              "components": { "schemas": {
                "A": { "$ref": "#/components/schemas/B" },
                "B": { "type": "string" }
              } }
            }
            """);

        Assert.True(Resolver(document).TryResolve(
            Schema("""{ "$ref": "#/components/schemas/A" }"""),
            out var resolved,
            out _));

        Assert.Equal("string", resolved.Type);
    }

    [Fact]
    public void A_non_reference_resolves_to_itself()
    {
        Assert.True(Resolver(Document("{}")).TryResolve(
            Schema("""{ "type": "integer" }"""),
            out var resolved,
            out _));

        Assert.Equal("integer", resolved.Type);
    }

    [Theory]
    [InlineData("https://example.com/schema.json")]
    [InlineData("./other.json#/components/schemas/Pet")]
    [InlineData("other.json")]
    [InlineData("file:///etc/passwd")]
    public void Refuses_a_reference_that_is_not_fragment_only(string reference)
    {
        // There is no base URI and no document graph in the format, so a non-local reference
        // has nothing to resolve against and must never trigger a fetch.
        Assert.False(Resolver(Document("{}")).TryResolve(
            Schema($$"""{ "$ref": "{{reference}}" }"""),
            out _,
            out var failure));

        Assert.Equal(ManifestDiagnosticCodes.RefNotLocal, failure!.Code);
    }

    [Theory]
    [InlineData("#/components/schemas/Absent")]
    [InlineData("#/nothing/here")]
    [InlineData("#Pet")]
    [InlineData("#/components/schemas/Pet/properties/absent")]
    public void Refuses_a_pointer_that_does_not_resolve(string reference)
    {
        var document = Document("""{ "components": { "schemas": { "Pet": { "type": "object" } } } }""");

        Assert.False(Resolver(document).TryResolve(
            Schema($$"""{ "$ref": "{{reference}}" }"""),
            out _,
            out var failure));

        Assert.Equal(ManifestDiagnosticCodes.RefUnresolvable, failure!.Code);
    }

    [Fact]
    public void Refuses_a_reference_cycle_that_never_reaches_a_schema()
    {
        var document = Document(
            """
            {
              "components": { "schemas": {
                "A": { "$ref": "#/components/schemas/B" },
                "B": { "$ref": "#/components/schemas/A" }
              } }
            }
            """);

        Assert.False(Resolver(document).TryResolve(
            Schema("""{ "$ref": "#/components/schemas/A" }"""),
            out _,
            out var failure));

        Assert.Equal(ManifestDiagnosticCodes.RefUnresolvable, failure!.Code);
        Assert.Contains("cycle", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_a_reference_chain_longer_than_the_depth_bound()
    {
        var schemas = new JsonObject();

        for (var index = 0; index < 12; index++)
        {
            schemas["S" + index.ToString(System.Globalization.CultureInfo.InvariantCulture)] =
                new JsonObject
                {
                    ["$ref"] = "#/components/schemas/S"
                        + (index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
                };
        }

        schemas["S12"] = new JsonObject { ["type"] = "string" };

        var document = new JsonObject
        {
            ["components"] = new JsonObject { ["schemas"] = schemas },
        };

        var resolver = Resolver(document, new SchemaBounds(MaxDepth: 4, MaxNodes: 2048, MaxPropertiesPerLevel: 256));

        Assert.False(resolver.TryResolve(
            Schema("""{ "$ref": "#/components/schemas/S0" }"""),
            out _,
            out var failure));

        Assert.Equal(ManifestDiagnosticCodes.SchemaBoundExceeded, failure!.Code);
    }

    [Fact]
    public void Validate_accepts_a_legitimately_recursive_schema()
    {
        // This is the whole point of resolving lazily: a self-referential type terminates on
        // the data, not on a bound, so it must not be reported as a violation.
        var document = Document(
            """
            {
              "components": { "schemas": {
                "Node": {
                  "type": "object",
                  "properties": {
                    "name": { "type": "string" },
                    "children": { "type": "array", "items": { "$ref": "#/components/schemas/Node" } }
                  }
                }
              } }
            }
            """);

        var diagnostics = Resolver(document).Validate(
            Schema("""{ "$ref": "#/components/schemas/Node" }"""),
            section: "operations",
            pointer: "/operations/0");

        Assert.Empty(diagnostics);
    }

    [Fact]
    public void Validate_reports_a_broken_reference_nested_deep_in_a_schema()
    {
        var document = Document("""{ "components": { "schemas": { } } }""");

        var diagnostics = Resolver(document).Validate(
            Schema(
                """
                {
                  "type": "object",
                  "properties": {
                    "wrapper": {
                      "type": "object",
                      "properties": { "pet": { "$ref": "#/components/schemas/Pet" } }
                    }
                  }
                }
                """),
            section: "operations",
            pointer: string.Empty);

        var diagnostic = Assert.Single(diagnostics);

        Assert.Equal(ManifestDiagnosticCodes.RefUnresolvable, diagnostic.Code);
        Assert.Equal("/properties/wrapper/properties/pet", diagnostic.Pointer);
        Assert.Equal("operations", diagnostic.Section);
    }

    [Fact]
    public void Validate_walks_composition_keywords()
    {
        var diagnostics = Resolver(Document("{}")).Validate(
            Schema(
                """
                {
                  "allOf": [ { "$ref": "#/absent" } ],
                  "anyOf": [ { "type": "string" } ],
                  "oneOf": [ { "not": { "$ref": "#/also-absent" } } ]
                }
                """),
            section: null,
            pointer: string.Empty);

        Assert.Equal(2, diagnostics.Count);
        Assert.Equal("/allOf/0", diagnostics[0].Pointer);
        Assert.Equal("/oneOf/0/not", diagnostics[1].Pointer);
    }

    [Fact]
    public void Validate_refuses_a_schema_deeper_than_the_depth_bound()
    {
        var schema = new JsonObject { ["type"] = "string" };

        for (var index = 0; index < 10; index++)
        {
            schema = new JsonObject
            {
                ["type"] = "object",
                ["properties"] = new JsonObject { ["child"] = schema },
            };
        }

        var resolver = Resolver(
            Document("{}"),
            new SchemaBounds(MaxDepth: 4, MaxNodes: 2048, MaxPropertiesPerLevel: 256));

        var diagnostics = resolver.Validate(ManifestSchema.From(schema), section: null, pointer: string.Empty);

        Assert.Contains(
            ManifestDiagnosticCodes.SchemaBoundExceeded,
            diagnostics.Select(static d => d.Code),
            StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_refuses_more_properties_at_one_level_than_the_bound_permits()
    {
        var properties = new JsonObject();

        for (var index = 0; index < 40; index++)
        {
            properties["p" + index.ToString(System.Globalization.CultureInfo.InvariantCulture)] =
                new JsonObject { ["type"] = "string" };
        }

        var resolver = Resolver(
            Document("{}"),
            new SchemaBounds(MaxDepth: 32, MaxNodes: 2048, MaxPropertiesPerLevel: 8));

        var diagnostics = resolver.Validate(
            ManifestSchema.From(new JsonObject { ["type"] = "object", ["properties"] = properties }),
            section: null,
            pointer: string.Empty);

        var diagnostic = Assert.Single(diagnostics);

        Assert.Equal(ManifestDiagnosticCodes.SchemaBoundExceeded, diagnostic.Code);
        Assert.Equal("/properties", diagnostic.Pointer);
    }

    [Fact]
    public void Validate_refuses_a_schema_that_reaches_more_nodes_than_the_bound_permits()
    {
        var properties = new JsonObject();

        for (var index = 0; index < 40; index++)
        {
            properties["p" + index.ToString(System.Globalization.CultureInfo.InvariantCulture)] =
                new JsonObject { ["type"] = "string" };
        }

        var resolver = Resolver(
            Document("{}"),
            new SchemaBounds(MaxDepth: 32, MaxNodes: 6, MaxPropertiesPerLevel: 256));

        var diagnostics = resolver.Validate(
            ManifestSchema.From(new JsonObject { ["type"] = "object", ["properties"] = properties }),
            section: null,
            pointer: string.Empty);

        Assert.Contains(
            ManifestDiagnosticCodes.SchemaBoundExceeded,
            diagnostics.Select(static d => d.Code),
            StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_charges_a_shared_component_once_rather_than_once_per_use_site()
    {
        var document = Document(
            """
            {
              "components": { "schemas": {
                "Shared": { "type": "object", "properties": {
                  "a": { "type": "string" }, "b": { "type": "string" }, "c": { "type": "string" }
                } }
              } }
            }
            """);

        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject(),
        };

        for (var index = 0; index < 20; index++)
        {
            ((JsonObject)schema["properties"]!)["use" + index.ToString(System.Globalization.CultureInfo.InvariantCulture)] =
                new JsonObject { ["$ref"] = "#/components/schemas/Shared" };
        }

        var resolver = Resolver(
            document,
            new SchemaBounds(MaxDepth: 32, MaxNodes: 40, MaxPropertiesPerLevel: 256));

        Assert.Empty(resolver.Validate(ManifestSchema.From(schema), section: null, pointer: string.Empty));
    }

    [Fact]
    public void Validate_accepts_a_boolean_schema_as_a_leaf()
    {
        Assert.Empty(Resolver(Document("{}")).Validate(
            Schema("""{ "type": "object", "additionalProperties": false }"""),
            section: null,
            pointer: string.Empty));
    }

    [Fact]
    public void Validate_refuses_a_node_that_is_not_a_schema_at_all()
    {
        var diagnostics = Resolver(Document("{}")).Validate(
            Schema("""{ "type": "object", "properties": { "a": "not-a-schema" } }"""),
            section: null,
            pointer: string.Empty);

        var diagnostic = Assert.Single(diagnostics);

        Assert.Equal(ManifestDiagnosticCodes.SchemaInvalid, diagnostic.Code);
        Assert.Equal("/properties/a", diagnostic.Pointer);
    }

    [Fact]
    public void Validate_walks_local_definition_containers()
    {
        var diagnostics = Resolver(Document("{}")).Validate(
            Schema("""{ "$defs": { "A": { "$ref": "#/absent" } } }"""),
            section: null,
            pointer: string.Empty);

        Assert.Equal("/$defs/A", Assert.Single(diagnostics).Pointer);
    }
}
