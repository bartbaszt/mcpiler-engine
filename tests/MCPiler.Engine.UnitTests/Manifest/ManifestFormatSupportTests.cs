using MCPiler.Engine.Manifest;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest;

public sealed class ManifestFormatVersionTests
{
    [Theory]
    [InlineData("0.1", 0, 1)]
    [InlineData("1.0", 1, 0)]
    [InlineData("0.10", 0, 10)]
    [InlineData("12.34", 12, 34)]
    public void TryParse_accepts_strict_major_minor(string value, int major, int minor)
    {
        Assert.True(ManifestFormatVersion.TryParse(value, out var version));
        Assert.Equal(new ManifestFormatVersion(major, minor), version);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("0")]
    [InlineData("0.")]
    [InlineData(".1")]
    [InlineData("0.1.2")]
    [InlineData("v0.1")]
    [InlineData("0.1-alpha")]
    [InlineData(" 0.1")]
    [InlineData("0.1 ")]
    [InlineData("+0.1")]
    [InlineData("-1.0")]
    [InlineData("0.01")]
    [InlineData("00.1")]
    [InlineData("०.१")]
    [InlineData("0.1234567890")]
    public void TryParse_rejects_anything_that_is_not_one_canonical_spelling(string? value)
    {
        Assert.False(ManifestFormatVersion.TryParse(value, out var version));
        Assert.Equal(default, version);
    }

    [Fact]
    public void ToString_round_trips_through_TryParse()
    {
        var original = new ManifestFormatVersion(3, 14);

        Assert.True(ManifestFormatVersion.TryParse(original.ToString(), out var parsed));
        Assert.Equal(original, parsed);
    }

    [Theory]
    [InlineData(0, 1, 0, 1, true)]
    [InlineData(0, 2, 0, 1, true)]
    [InlineData(1, 0, 0, 9, true)]
    [InlineData(0, 1, 0, 2, false)]
    [InlineData(0, 9, 1, 0, false)]
    public void IsAtLeast_orders_by_major_then_minor(int major, int minor, int otherMajor, int otherMinor, bool expected)
        => Assert.Equal(expected, new ManifestFormatVersion(major, minor).IsAtLeast(new ManifestFormatVersion(otherMajor, otherMinor)));

    [Theory]
    [InlineData(0, 1, 0, 1, true)]
    [InlineData(0, 1, 0, 2, true)]
    [InlineData(0, 9, 1, 0, true)]
    [InlineData(0, 2, 0, 1, false)]
    [InlineData(1, 0, 0, 9, false)]
    public void IsAtMost_orders_by_major_then_minor(int major, int minor, int otherMajor, int otherMinor, bool expected)
        => Assert.Equal(expected, new ManifestFormatVersion(major, minor).IsAtMost(new ManifestFormatVersion(otherMajor, otherMinor)));

    [Fact]
    public void Constructor_rejects_negative_components()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ManifestFormatVersion(-1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ManifestFormatVersion(0, -1));
    }
}

public sealed class ManifestFormatSupportTests
{
    [Fact]
    public void Supported_range_is_well_formed()
    {
        Assert.True(ManifestFormatSupport.Maximum.IsAtLeast(ManifestFormatSupport.Minimum));
        Assert.False(string.IsNullOrWhiteSpace(ManifestFormatSupport.SupportedRange));
    }

    [Fact]
    public void Declared_supported_version_is_accepted()
    {
        var evaluation = ManifestFormatSupport.Evaluate(ManifestFormatSupport.Minimum.ToString());

        Assert.True(evaluation.IsSupported);
        Assert.Equal(ManifestFormatCompatibility.Supported, evaluation.Compatibility);
        Assert.Equal(ManifestFormatSupport.Minimum, evaluation.Version);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Missing_version_fails_closed_and_names_the_supported_range(string? declared)
    {
        var evaluation = ManifestFormatSupport.Evaluate(declared);

        Assert.False(evaluation.IsSupported);
        Assert.Equal(ManifestFormatCompatibility.Missing, evaluation.Compatibility);
        Assert.Null(evaluation.Version);
        Assert.Contains(ManifestFormatSupport.SupportedRange, evaluation.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("latest")]
    [InlineData("0.1.0")]
    [InlineData("v1")]
    public void Malformed_version_fails_closed_and_names_the_supported_range(string declared)
    {
        var evaluation = ManifestFormatSupport.Evaluate(declared);

        Assert.False(evaluation.IsSupported);
        Assert.Equal(ManifestFormatCompatibility.Malformed, evaluation.Compatibility);
        Assert.Null(evaluation.Version);
        Assert.Contains(ManifestFormatSupport.SupportedRange, evaluation.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Newer_version_is_refused_and_described_as_newer()
    {
        var newer = new ManifestFormatVersion(ManifestFormatSupport.Maximum.Major + 1, 0);

        var evaluation = ManifestFormatSupport.Evaluate(newer.ToString());

        Assert.False(evaluation.IsSupported);
        Assert.Equal(ManifestFormatCompatibility.Unsupported, evaluation.Compatibility);
        Assert.Equal(newer, evaluation.Version);
        Assert.Contains("newer", evaluation.Message, StringComparison.Ordinal);
        Assert.Contains(ManifestFormatSupport.SupportedRange, evaluation.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Older_version_is_refused_and_described_as_older()
    {
        var older = new ManifestFormatVersion(0, 0);

        var evaluation = ManifestFormatSupport.Evaluate(older.ToString());

        Assert.False(evaluation.IsSupported);
        Assert.Equal(ManifestFormatCompatibility.Unsupported, evaluation.Compatibility);
        Assert.Equal(older, evaluation.Version);
        Assert.Contains("older", evaluation.Message, StringComparison.Ordinal);
        Assert.Contains(ManifestFormatSupport.SupportedRange, evaluation.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refusal_message_does_not_echo_an_unbounded_declared_value()
    {
        var hostile = new string('A', 4096);

        var evaluation = ManifestFormatSupport.Evaluate(hostile);

        Assert.False(evaluation.IsSupported);
        Assert.DoesNotContain(hostile, evaluation.Message, StringComparison.Ordinal);
        Assert.True(evaluation.Message.Length < 256, $"Message was {evaluation.Message.Length} characters long.");
    }
}
