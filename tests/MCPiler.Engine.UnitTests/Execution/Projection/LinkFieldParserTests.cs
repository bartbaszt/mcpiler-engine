using System.Collections.Generic;

using MCPiler.Engine.Execution.Projection;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Projection;

/// <summary>
/// The RFC 8288 link-field parser: quoted parameter values, escaped quotes, relation lists,
/// repeated field-values and the parsed-value ceiling.
/// </summary>
/// <remarks>
/// The parser is the one place where a naive split would be wrong. Each case here is a field a
/// delimiter-based implementation parses into the wrong number of values or the wrong target, so
/// a green run is evidence that the grammar is consumed rather than approximated.
/// </remarks>
public sealed class LinkFieldParserTests
{
    [Fact]
    public void One_simple_next_link_parses()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<https://api.example/items?cursor=abc>; rel=\"next\""]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        ParsedLinkValue value = Assert.Single(result.Values);
        Assert.Equal("https://api.example/items?cursor=abc", value.Target);
        Assert.Equal(["next"], value.Relations);
        Assert.Null(value.Anchor);
    }

    [Fact]
    public void A_comma_inside_a_quoted_parameter_does_not_split_the_value()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<items?cursor=a>; title=\"one, two\"; rel=next"]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        Assert.Equal("items?cursor=a", Assert.Single(result.Values).Target);
    }

    [Fact]
    public void A_semicolon_inside_a_quoted_parameter_does_not_split_the_parameters()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<items?cursor=a>; title=\"one; two\"; rel=\"next\""]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        Assert.Contains("next", Assert.Single(result.Values).Relations);
    }

    [Fact]
    public void An_escaped_quote_inside_a_parameter_survives()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<items?cursor=a>; title=\"a \\\"quoted\\\" word\"; rel=next"]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        Assert.Contains("next", Assert.Single(result.Values).Relations);
    }

    [Fact]
    public void A_relation_list_is_split_into_its_types()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<items?cursor=a>; rel=\"next last\""]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        Assert.Equal(["next", "last"], Assert.Single(result.Values).Relations);
    }

    [Fact]
    public void Multiple_link_values_in_one_field_are_all_parsed()
    {
        LinkParseResult result = LinkFieldParser.Parse(
            ["<a>; rel=prev, <b>; rel=next, <c>; rel=\"first\""]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        Assert.Equal(3, result.Values.Count);
        Assert.Equal(["prev"], result.Values[0].Relations);
        Assert.Equal(["next"], result.Values[1].Relations);
        Assert.Equal(["first"], result.Values[2].Relations);
    }

    [Fact]
    public void Repeated_field_values_are_parsed_as_a_list()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<a>; rel=prev", "<b>; rel=next"]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        Assert.Equal(2, result.Values.Count);
    }

    [Fact]
    public void Relation_types_are_matched_case_insensitively()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<a>; rel=\"NEXT\""]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        Assert.Equal(["next"], Assert.Single(result.Values).Relations);
    }

    [Fact]
    public void An_anchor_parameter_is_reported()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<a>; rel=next; anchor=\"/collection\""]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        Assert.Equal("/collection", Assert.Single(result.Values).Anchor);
    }

    [Fact]
    public void An_unterminated_target_is_malformed()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<unterminated; rel=next"]);

        Assert.Equal(LinkParseOutcome.Malformed, result.Outcome);
    }

    [Fact]
    public void A_value_without_a_relation_is_malformed()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<a>; title=\"only a title\""]);

        Assert.Equal(LinkParseOutcome.Malformed, result.Outcome);
    }

    [Fact]
    public void An_unterminated_quoted_parameter_is_malformed()
    {
        LinkParseResult result = LinkFieldParser.Parse(["<a>; rel=\"next"]);

        Assert.Equal(LinkParseOutcome.Malformed, result.Outcome);
    }

    [Fact]
    public void More_values_than_the_ceiling_is_an_over_limit_refusal()
    {
        var field = string.Join(", ", System.Linq.Enumerable.Repeat("<a>; rel=prev", ResponseProjectionLimits.MaxLinkValues + 1));

        LinkParseResult result = LinkFieldParser.Parse([field]);

        Assert.Equal(LinkParseOutcome.OverLimit, result.Outcome);
    }

    [Fact]
    public void Exactly_the_ceiling_is_still_parsed()
    {
        var field = string.Join(", ", System.Linq.Enumerable.Repeat("<a>; rel=prev", ResponseProjectionLimits.MaxLinkValues));

        LinkParseResult result = LinkFieldParser.Parse([field]);

        Assert.Equal(LinkParseOutcome.Parsed, result.Outcome);
        Assert.Equal(ResponseProjectionLimits.MaxLinkValues, result.Values.Count);
    }
}
