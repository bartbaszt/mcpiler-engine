using System.Text.Json.Nodes;
using MCPiler.Engine.Execution.Projection;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Projection;

public sealed class JsonNumberConversionTests
{
    [Theory]
    [InlineData("0")]
    [InlineData("-0")]
    [InlineData("1.2300")]
    [InlineData("1e+3")]
    [InlineData("1e1000000")]
    [InlineData("1e-1000000")]
    [InlineData("9007199254740993")]
    public void Number_lexemes_round_trip_without_binary_rounding(string lexeme)
    {
        var value = JsonNumberConversion.ParseNumber(lexeme);

        Assert.NotNull(value);
        Assert.Equal(lexeme, value.ToJsonString());
    }

    [Theory]
    [InlineData("")]
    [InlineData(" 1")]
    [InlineData("1 ")]
    [InlineData("+1")]
    [InlineData("01")]
    [InlineData(".1")]
    [InlineData("1.")]
    [InlineData("1e")]
    [InlineData("NaN")]
    [InlineData("Infinity")]
    [InlineData("-Infinity")]
    public void Non_json_number_spellings_are_refused(string lexeme)
    {
        Assert.Null(JsonNumberConversion.ParseNumber(lexeme));
        Assert.Null(JsonNumberConversion.ParseInteger(lexeme));
    }

    [Theory]
    [InlineData("0", 0L)]
    [InlineData("-0", 0L)]
    [InlineData("1.0", 1L)]
    [InlineData("1e3", 1000L)]
    [InlineData("1.000e3", 1000L)]
    [InlineData("9223372036854775807", long.MaxValue)]
    [InlineData("-9223372036854775808", long.MinValue)]
    public void Integer_conversion_is_exact(string lexeme, long expected)
    {
        var value = JsonNumberConversion.ParseInteger(lexeme);

        Assert.NotNull(value);
        Assert.Equal(expected, value.GetValue<long>());
    }

    [Theory]
    [InlineData("1.5")]
    [InlineData("1e-1")]
    [InlineData("9223372036854775808")]
    [InlineData("-9223372036854775809")]
    [InlineData("1e1000000")]
    [InlineData("999999999999999999999999999999999999999e-1000000")]
    public void Integer_conversion_refuses_fractional_or_out_of_range_values(string lexeme)
    {
        Assert.Null(JsonNumberConversion.ParseInteger(lexeme));
    }

    [Fact]
    public void Wrapped_json_number_keeps_its_original_token()
    {
        var value = JsonNode.Parse("9007199254740993e+3")!.AsValue();

        Assert.True(JsonNumberConversion.TryGetLexeme(value, out var lexeme));
        Assert.Equal("9007199254740993e+3", lexeme);
        Assert.Equal("9007199254740993e+3", JsonNumberConversion.ParseNumber(lexeme)!.ToJsonString());
    }
}
