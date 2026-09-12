using System.Text.Json;

using MCPiler.Engine.Mcp;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>Validation of the value against the exact schema a session read.</summary>
public sealed class StructuredContentValidatorTests
{
    [Fact]
    public void A_conforming_value_has_no_failure_location()
    {
        using JsonDocument value = JsonDocument.Parse("""{"result":["a","b"]}""");

        string? location = StructuredContentValidator.Validate(
            value.RootElement,
            """{"type":"object","properties":{"result":{"type":"array","items":{"type":"string"}}},"required":["result"]}""");

        Assert.Null(location);
    }

    [Fact]
    public void A_type_mismatch_names_the_specific_schema_location()
    {
        using JsonDocument value = JsonDocument.Parse("""{"result":[1]}""");

        string? location = StructuredContentValidator.Validate(
            value.RootElement,
            """{"type":"object","properties":{"result":{"type":"array","items":{"type":"string"}}},"required":["result"]}""");

        Assert.NotNull(location);
        Assert.Contains("result", location, StringComparison.Ordinal);
        Assert.Contains("items", location, StringComparison.Ordinal);
    }

    [Fact]
    public void The_advertised_document_is_the_one_that_decides()
    {
        using JsonDocument value = JsonDocument.Parse("""{"result":"ok","extra":true}""");
        const string advertised =
            """{"type":"object","properties":{"result":{"type":"string"}},"required":["result"],"additionalProperties":false}""";

        string? location = StructuredContentValidator.Validate(value.RootElement, advertised);

        Assert.NotNull(location);
        Assert.Contains("additionalProperties", location, StringComparison.Ordinal);
    }

    [Fact]
    public void An_uninterpretable_schema_fails_closed_at_the_root()
    {
        using JsonDocument value = JsonDocument.Parse("{}");

        Assert.Equal("#", StructuredContentValidator.Validate(value.RootElement, "not json"));
    }

    [Theory]
    [InlineData("{\"type\":1}")]
    [InlineData("{\"type\":[\"object\",1]}")]
    [InlineData("{\"pattern\":\"[\"}")]
    [InlineData("{\"$schema\":\"not a uri\"}")]
    [InlineData("{\"$ref\":\"#/$defs/missing\"}")]
    public void Hostile_schema_keywords_fail_closed_without_escaping_the_validator(string schema)
    {
        using JsonDocument value = JsonDocument.Parse("\"value\"");

        Assert.NotNull(StructuredContentValidator.Validate(value.RootElement, schema));
    }
}
