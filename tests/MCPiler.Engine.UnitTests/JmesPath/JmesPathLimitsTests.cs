using MCPiler.Engine.Runtime.Projection;

using Xunit;

namespace MCPiler.Engine.UnitTests.JmesPath;

/// <summary>
/// Profile-1 limit arithmetic: what fits, what exceeds, and what narrowing means.
/// </summary>
/// <remarks>
/// The authored defaults are ordinary values, not maximums, and the ceiling is a different
/// record. These tests fix both relationships: the defaults fit inside the ceiling, and a value
/// that crosses any single dimension is named by that dimension.
/// </remarks>
public sealed class JmesPathLimitsTests
{
    [Fact]
    public void Authoring_defaults_fit_inside_the_administrator_ceiling()
    {
        Assert.True(JmesPathLimits.AuthoringDefault.IsPositive);
        Assert.True(JmesPathLimits.AdministratorCeiling.IsPositive);
        Assert.Empty(
            JmesPathLimits.AuthoringDefault.ExceedingDimensions(JmesPathLimits.AdministratorCeiling));
    }

    [Fact]
    public void The_calibrated_authoring_defaults_are_the_measured_ones()
    {
        // The values are part of the profile contract: they are what a new projection starts
        // with and what the operator-facing defaults show. A silent change here would change
        // what every new projection declares.
        JmesPathLimits defaults = JmesPathLimits.AuthoringDefault;

        Assert.Equal(4096, defaults.MaxExpressionBytes);
        Assert.Equal(100_000L, defaults.MaxInputNodes);
        Assert.Equal(64, defaults.MaxInputDepth);
        Assert.Equal(8_192L, defaults.MaxResultNodes);
        Assert.Equal(32, defaults.MaxResultDepth);
        Assert.Equal(256L * 1024, defaults.MaxOutputBytes);
        Assert.Equal(10_000, defaults.MaxEvaluationMilliseconds);
    }

    [Fact]
    public void Exceeding_dimensions_names_exactly_the_dimensions_over_the_ceiling()
    {
        JmesPathLimits ceiling = JmesPathLimits.AuthoringDefault;
        JmesPathLimits wider = ceiling with
        {
            MaxExpressionBytes = ceiling.MaxExpressionBytes + 1,
            MaxEvaluationMilliseconds = ceiling.MaxEvaluationMilliseconds + 1,
        };

        Assert.Equal(
            [nameof(JmesPathLimits.MaxExpressionBytes), nameof(JmesPathLimits.MaxEvaluationMilliseconds)],
            wider.ExceedingDimensions(ceiling));
    }

    [Fact]
    public void A_value_equal_to_the_ceiling_does_not_exceed_it()
    {
        JmesPathLimits ceiling = JmesPathLimits.AdministratorCeiling;

        Assert.Empty(ceiling.ExceedingDimensions(ceiling));
    }

    [Fact]
    public void Clamp_takes_the_dimension_wise_minimum()
    {
        JmesPathLimits narrower = new(
            MaxExpressionBytes: 10,
            MaxInputNodes: 20,
            MaxInputDepth: 30,
            MaxResultNodes: 40,
            MaxResultDepth: 50,
            MaxOutputBytes: 60,
            MaxEvaluationMilliseconds: 70);

        JmesPathLimits wider = new(
            MaxExpressionBytes: 100,
            MaxInputNodes: 200,
            MaxInputDepth: 300,
            MaxResultNodes: 400,
            MaxResultDepth: 500,
            MaxOutputBytes: 600,
            MaxEvaluationMilliseconds: 7000);

        Assert.Equal(narrower, narrower.ClampTo(wider));
        Assert.Equal(narrower, wider.ClampTo(narrower));
    }

    [Theory]
    [InlineData(0, 1, 1, 1, 1, 1, 1)]
    [InlineData(1, 0, 1, 1, 1, 1, 1)]
    [InlineData(1, 1, 0, 1, 1, 1, 1)]
    [InlineData(1, 1, 1, 0, 1, 1, 1)]
    [InlineData(1, 1, 1, 1, 0, 1, 1)]
    [InlineData(1, 1, 1, 1, 1, 0, 1)]
    [InlineData(1, 1, 1, 1, 1, 1, 0)]
    public void A_zero_dimension_is_not_positive(
        int expressionBytes,
        long inputNodes,
        int inputDepth,
        long resultNodes,
        int resultDepth,
        long outputBytes,
        int milliseconds)
    {
        JmesPathLimits limits = new(
            expressionBytes, inputNodes, inputDepth, resultNodes, resultDepth, outputBytes, milliseconds);

        Assert.False(limits.IsPositive);
    }
}
