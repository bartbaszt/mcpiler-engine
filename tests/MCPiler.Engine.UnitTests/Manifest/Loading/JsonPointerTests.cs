using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Loading;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Loading;

public sealed class JsonPointerTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a/b", "a~1b")]
    [InlineData("a~b", "a~0b")]
    [InlineData("a~1b", "a~01b")]
    [InlineData("", "")]
    public void Escapes_a_reference_token(string token, string expected)
    {
        Assert.Equal(expected, JsonPointer.Escape(token));
    }

    [Theory]
    [InlineData("plain")]
    [InlineData("a/b")]
    [InlineData("a~b")]
    [InlineData("a~1b")]
    [InlineData("~/~")]
    public void Escaping_round_trips(string token)
    {
        Assert.Equal(token, JsonPointer.Unescape(JsonPointer.Escape(token)));
    }

    [Fact]
    public void Builds_a_pointer_from_unescaped_tokens()
    {
        Assert.Equal("", JsonPointer.Build());
        Assert.Equal("/sections/policy", JsonPointer.Build("sections", "policy"));
        Assert.Equal("/sections/a~1b", JsonPointer.Build("sections", "a/b"));
    }

    [Theory]
    [InlineData("#/components/schemas/Pet", true)]
    [InlineData("#", true)]
    [InlineData("components/schemas/Pet", false)]
    [InlineData("./other.json#/x", false)]
    [InlineData("https://example.com/schema.json#/x", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Recognizes_only_a_fragment_only_reference(string? reference, bool expected)
    {
        Assert.Equal(expected, JsonPointer.IsLocalFragment(reference));
    }

    [Fact]
    public void Resolves_an_object_pointer()
    {
        var document = JsonNode.Parse("""
            { "components": { "schemas": { "Pet": { "type": "object" } } } }
            """)!;

        Assert.True(JsonPointer.TryResolve(document, "#/components/schemas/Pet", out var target));
        Assert.Equal("object", target!["type"]!.GetValue<string>());
    }

    [Fact]
    public void Resolves_an_array_index()
    {
        var document = JsonNode.Parse("""{ "operations": [ { "key": "GET /a" }, { "key": "GET /b" } ] }""")!;

        Assert.True(JsonPointer.TryResolve(document, "#/operations/1/key", out var target));
        Assert.Equal("GET /b", target!.GetValue<string>());
    }

    [Fact]
    public void Resolves_an_escaped_member_name()
    {
        var document = JsonNode.Parse("""{ "components": { "schemas": { "a/b": { "type": "string" } } } }""")!;

        Assert.True(JsonPointer.TryResolve(document, "#/components/schemas/a~1b", out var target));
        Assert.Equal("string", target!["type"]!.GetValue<string>());
    }

    [Fact]
    public void An_empty_fragment_resolves_to_the_whole_document()
    {
        var document = JsonNode.Parse("""{ "x": 1 }""")!;

        Assert.True(JsonPointer.TryResolve(document, "#", out var target));
        Assert.Same(document, target);
    }

    [Theory]
    [InlineData("#Pet")]
    [InlineData("#components/schemas/Pet")]
    public void Refuses_a_plain_name_fragment_instead_of_guessing_a_pointer(string reference)
    {
        var document = JsonNode.Parse("""{ "components": { "schemas": { "Pet": {} } } }""")!;

        Assert.False(JsonPointer.TryResolve(document, reference, out var target));
        Assert.Null(target);
    }

    [Theory]
    [InlineData("#/components/schemas/Missing")]
    [InlineData("#/components/missing/Pet")]
    [InlineData("#/operations/0")]
    [InlineData("#/components/schemas/Pet/type/deeper")]
    public void Reports_an_unresolvable_pointer_rather_than_returning_the_last_match(string reference)
    {
        var document = JsonNode.Parse("""{ "components": { "schemas": { "Pet": { "type": "object" } } } }""")!;

        Assert.False(JsonPointer.TryResolve(document, reference, out var target));
        Assert.Null(target);
    }

    [Theory]
    [InlineData("#/operations/2")]
    [InlineData("#/operations/-1")]
    [InlineData("#/operations/x")]
    public void Refuses_an_out_of_range_or_non_numeric_array_index(string reference)
    {
        var document = JsonNode.Parse("""{ "operations": [ { "key": "GET /a" } ] }""")!;

        Assert.False(JsonPointer.TryResolve(document, reference, out _));
    }

    [Fact]
    public void Refuses_a_non_local_reference_without_attempting_resolution()
    {
        var document = JsonNode.Parse("""{ "components": {} }""")!;

        Assert.False(JsonPointer.TryResolve(document, "https://evil.example.com/x.json#/a", out _));
        Assert.False(JsonPointer.TryResolve(document, "other.json#/a", out _));
    }
}
