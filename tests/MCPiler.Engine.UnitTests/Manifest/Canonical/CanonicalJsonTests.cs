using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Canonical;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Canonical;

public sealed class CanonicalJsonTests
{
    private static string Canonical(string json)
        => Encoding.UTF8.GetString(CanonicalJson.Serialize(CanonicalJson.Parse(Encoding.UTF8.GetBytes(json))));

    [Fact]
    public void Sorts_object_members_by_utf16_ordinal_at_every_depth()
    {
        const string Input = """
            { "zeta": 1, "b": 2, "B": 3, "a": 4, "A": 5, "_u": 6, "0d": 7, "": 8,
              "nested": { "y": { "second": 1, "first": 2 } } }
            """;

        Assert.Equal(
            """{"":8,"0d":7,"A":5,"B":3,"_u":6,"a":4,"b":2,"nested":{"y":{"first":2,"second":1}},"zeta":1}""",
            Canonical(Input));
    }

    [Fact]
    public void Sorts_non_bmp_member_names_before_private_use_because_ordering_is_utf16_not_utf8()
    {
        // The leading surrogate U+D83D is below U+E000 in UTF-16, while the emoji's UTF-8
        // bytes are above U+E000's. An implementation that sorts by UTF-8 byte order
        // produces the opposite order and breaks every existing digest.
        const string Input = """{ "\ue000private": 1, "\ud83d\ude00emoji": 2 }""";

        Assert.Equal("""{"\uD83D\uDE00emoji":2,"\uE000private":1}""", Canonical(Input));
    }

    [Fact]
    public void Preserves_array_order_because_it_is_semantic()
    {
        Assert.Equal("""[3,1,2,"b","a",null,true]""", Canonical("""[3, 1, 2, "b", "a", null, true]"""));
    }

    [Theory]
    [InlineData("1", "1")]
    [InlineData("1.0", "1.0")]
    [InlineData("1.50", "1.50")]
    [InlineData("1e3", "1e3")]
    [InlineData("1E+2", "1E+2")]
    [InlineData("1.5e-7", "1.5e-7")]
    [InlineData("-0", "-0")]
    [InlineData("0.010", "0.010")]
    [InlineData("9007199254740993", "9007199254740993")]
    [InlineData("0.10000000000000000555", "0.10000000000000000555")]
    public void Preserves_the_original_lexical_number_token(string input, string expected)
    {
        Assert.Equal($"{{\"n\":{expected}}}", Canonical($"{{ \"n\": {input} }}"));
    }

    [Fact]
    public void Emits_no_insignificant_whitespace()
    {
        var output = Canonical("""
            {
                "a" : [ 1 , 2 ] ,
                "b" : { }
            }
            """);

        Assert.Equal("""{"a":[1,2],"b":{}}""", output);
        Assert.DoesNotContain(" ", output, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Emits_utf8_without_a_byte_order_mark()
    {
        var bytes = CanonicalJson.Serialize(JsonNode.Parse("""{"é":"ü"}"""));

        Assert.False(
            bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF,
            "Canonical output must not carry a UTF-8 byte-order mark.");
    }

    [Fact]
    public void Escapes_non_ascii_and_html_sensitive_characters_with_uppercase_hex()
    {
        // Not RFC 8785 minimal escaping. Kept for byte agreement with already-sealed
        // documents; see the fixture README.
        Assert.Equal("""{"a":"\u00E9"}""", Canonical("""{"a":"é"}"""));
        Assert.Equal("""{"a":"\u003Cb\u003E"}""", Canonical("""{"a":"<b>"}"""));
        Assert.Equal("""{"a":"\u0026"}""", Canonical("""{"a":"&"}"""));
        Assert.Equal("""{"a":"1\u002B1"}""", Canonical("""{"a":"1+1"}"""));
    }

    [Fact]
    public void Treats_an_escaped_and_a_literal_character_as_the_same_member_name()
    {
        Assert.Equal(Canonical("""{"abc":1}"""), Canonical("""{"a\u0062c":1}"""));
    }

    [Fact]
    public void Distinguishes_a_precomposed_character_from_a_combining_sequence()
    {
        Assert.NotEqual(Canonical("""{"a":"\u00e9"}"""), Canonical("""{"a":"e\u0301"}"""));
    }

    [Fact]
    public void Is_idempotent()
    {
        const string Input = """{ "b": [ { "d": 1, "c": 2 } ], "a": 1.50 }""";

        var once = Canonical(Input);
        var twice = Canonical(once);

        Assert.Equal(once, twice);
    }

    [Fact]
    public void Produces_identical_bytes_for_documents_that_differ_only_in_member_order()
    {
        var first = CanonicalJson.Serialize(JsonNode.Parse("""{"a":1,"b":{"c":2,"d":3}}"""));
        var second = CanonicalJson.Serialize(JsonNode.Parse("""{"b":{"d":3,"c":2},"a":1}"""));

        Assert.Equal(first, second);
    }

    [Fact]
    public void Produces_identical_bytes_for_documents_that_differ_only_in_whitespace()
    {
        var minified = CanonicalJson.Serialize(JsonNode.Parse("""{"a":[1,2]}"""));
        var indented = CanonicalJson.Serialize(JsonNode.Parse("{\n  \"a\": [\n    1,\n    2\n  ]\n}"));

        Assert.Equal(minified, indented);
    }

    [Fact]
    public void Serializes_a_null_node_as_json_null()
    {
        Assert.Equal("null", Encoding.UTF8.GetString(CanonicalJson.Serialize(null)));
    }

    [Fact]
    public void Hash_is_lowercase_sha256_hex_of_the_canonical_bytes()
    {
        var hash = CanonicalJson.Hash(JsonNode.Parse("""{"a":1}"""));

        Assert.Equal(64, hash.Length);
        Assert.Equal(hash.ToLowerInvariant(), hash);
        Assert.Equal(
            CanonicalJson.ComputeHash(Encoding.UTF8.GetBytes("""{"a":1}""")),
            hash);
    }

    [Fact]
    public void Hash_ignores_member_order_and_whitespace_but_not_number_spelling()
    {
        Assert.Equal(
            CanonicalJson.Hash(JsonNode.Parse("""{"a":1,"b":2}""")),
            CanonicalJson.Hash(JsonNode.Parse("{ \"b\": 2,\n \"a\": 1 }")));

        Assert.NotEqual(
            CanonicalJson.Hash(JsonNode.Parse("""{"a":1}""")),
            CanonicalJson.Hash(JsonNode.Parse("""{"a":1.0}""")));
    }

    [Fact]
    public void Accepts_a_document_at_the_documented_depth_limit()
    {
        var node = BuildNestedObject(CanonicalJson.MaximumDocumentDepth - 2);

        var bytes = CanonicalJson.Serialize(node);

        Assert.NotEmpty(bytes);
    }

    [Fact]
    public void Refuses_to_parse_a_document_beyond_the_documented_depth_limit()
    {
        var json = Encoding.UTF8.GetBytes(BuildNestedJson(CanonicalJson.MaximumDocumentDepth + 8));

        // JsonReaderException derives from JsonException; assert the contract, not the leaf type.
        var error = Assert.ThrowsAny<JsonException>(() => CanonicalJson.Parse(json));

        Assert.Contains(
            CanonicalJson.MaximumDocumentDepth.ToString(CultureInfo.InvariantCulture),
            error.Message,
            StringComparison.Ordinal);
    }

    private static JsonNode BuildNestedObject(int depth)
    {
        JsonNode node = JsonValue.Create(1);

        for (var i = 0; i < depth; i++)
        {
            node = new JsonObject { ["z"] = node };
        }

        return node;
    }

    private static string BuildNestedJson(int depth)
    {
        var builder = new StringBuilder(depth * 6);

        for (var i = 0; i < depth; i++)
        {
            builder.Append("{\"z\":");
        }

        builder.Append('1');

        for (var i = 0; i < depth; i++)
        {
            builder.Append('}');
        }

        return builder.ToString();
    }
}
