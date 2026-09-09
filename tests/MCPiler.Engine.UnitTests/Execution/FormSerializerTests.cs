using System.Text;
using System.Text.Json.Nodes;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Serialization;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Covers form-urlencoded body writing, which the corpus exercises with one case. Rows 6, 7 and 8 of
/// the change's adversarial matrix.
/// </summary>
public sealed class FormSerializerTests
{
    private static string Serialize(string json)
        => Encoding.UTF8.GetString(FormSerializer.Serialize(JsonNode.Parse(json)));

    [Fact]
    public void A_flat_object_becomes_ampersand_separated_pairs()
        => Assert.Equal("a=1&b=two", Serialize("""{"a":1,"b":"two"}"""));

    [Fact]
    public void An_array_repeats_its_key_rather_than_joining_its_items()
        => Assert.Equal("ids=1&ids=2", Serialize("""{"ids":[1,2]}"""));

    [Fact]
    public void A_nested_object_is_flattened_into_bracket_notation()
        => Assert.Equal("meta%5Ba%5D=x&meta%5Bb%5D=y", Serialize("""{"meta":{"a":"x","b":"y"}}"""));

    [Fact]
    public void Nesting_is_flattened_to_any_depth()
        => Assert.Equal("a%5Bb%5D%5Bc%5D=1", Serialize("""{"a":{"b":{"c":1}}}"""));

    [Fact]
    public void An_array_inside_a_nested_object_repeats_the_bracketed_key()
        => Assert.Equal("a%5Bb%5D=1&a%5Bb%5D=2", Serialize("""{"a":{"b":[1,2]}}"""));

    [Fact]
    public void A_reserved_character_is_always_encoded_because_a_body_declares_no_allowance()
    {
        // Unlike a parameter, a form body has nowhere to state allowReserved, so the encoding is
        // unconditional. A slash in a key or a value is therefore never preserved.
        Assert.Equal("a%2Fb=x%2Fy", Serialize("""{"a/b":"x/y"}"""));
    }

    [Fact]
    public void A_space_becomes_a_percent_triplet_rather_than_a_plus()
    {
        // The historical HTML form spelling of a space is "+"; this writer uses percent-encoding
        // throughout, which is what the recorded golden carries.
        Assert.Equal("q=a%20b", Serialize("""{"q":"a b"}"""));
    }

    [Fact]
    public void A_non_ascii_value_expands_per_utf8_byte()
        => Assert.Equal("q=%E4%B8%AD", Serialize("""{"q":"\u4e2d"}"""));

    [Fact]
    public void An_empty_object_produces_an_empty_body()
        => Assert.Equal(string.Empty, Serialize("{}"));

    [Fact]
    public void An_empty_array_member_contributes_nothing_and_leaves_no_separator()
    {
        // The separator is written before a pair rather than after it, so a member that yields no
        // pairs cannot leave a dangling ampersand.
        Assert.Equal("a=1&c=3", Serialize("""{"a":1,"b":[],"c":3}"""));
    }

    [Fact]
    public void An_empty_nested_object_member_contributes_nothing()
        => Assert.Equal("a=1", Serialize("""{"a":1,"b":{}}"""));

    [Fact]
    public void A_null_member_keeps_its_key_with_an_empty_value()
    {
        // The key survives because the containing object still has the member; the value collapses
        // because the node model represents a JSON null as a null reference. So a form body can state
        // "this field is present and empty" but never "this field is null".
        Assert.Equal("a=", Serialize("""{"a":null}"""));
    }

    [Fact]
    public void Member_order_is_preserved_and_not_sorted()
    {
        Assert.Equal("b=2&a=1", Serialize("""{"b":2,"a":1}"""));
        Assert.Equal("a=1&b=2", Serialize("""{"a":1,"b":2}"""));
    }

    [Theory]
    [InlineData("[1,2]")]
    [InlineData("\"text\"")]
    [InlineData("42")]
    [InlineData("null")]
    public void A_body_that_is_not_an_object_is_refused(string json)
        => Assert.Throws<UnsupportedSerializationException>(
            () => FormSerializer.Serialize(JsonNode.Parse(json)));
}
