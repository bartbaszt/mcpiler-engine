using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

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

    /// <summary>
    /// The supported range is exactly one version.
    /// </summary>
    /// <remarks>
    /// While the major version is 0 a minor bump may be breaking, so a superseded manifest is
    /// re-exported rather than migrated. Pinning the range in a test keeps that a decision
    /// rather than an accident of whichever constant was edited last.
    /// </remarks>
    [Fact]
    public void The_supported_range_is_the_single_current_version()
    {
        Assert.Equal(new ManifestFormatVersion(0, 2), ManifestFormatSupport.Minimum);
        Assert.Equal(new ManifestFormatVersion(0, 2), ManifestFormatSupport.Maximum);
        Assert.True(ManifestFormatSupport.Evaluate("0.2").IsSupported);
    }

    [Fact]
    public void The_previous_format_version_is_refused_as_older()
    {
        var evaluation = ManifestFormatSupport.Evaluate("0.1");

        Assert.False(evaluation.IsSupported);
        Assert.Equal(ManifestFormatCompatibility.Unsupported, evaluation.Compatibility);
        Assert.Equal(new ManifestFormatVersion(0, 1), evaluation.Version);
        Assert.Contains("older", evaluation.Message, StringComparison.Ordinal);
        Assert.Contains(ManifestFormatSupport.SupportedRange, evaluation.Message, StringComparison.Ordinal);
    }
}

/// <summary>
/// The section versions do not move together.
/// </summary>
/// <remarks>
/// Each section version governs only its own payload, so a change confined to one section
/// bumps that section alone. A single shared constant would have hidden that, which is why
/// the matrix is pinned here rather than inferred.
/// </remarks>
public sealed class SectionFormatVersionMatrixTests
{
    private readonly List<ManifestDiagnostic> _diagnostics = [];

    private static JsonNode Json(string text) => JsonNode.Parse(text)!;

    private IReadOnlyList<string> ErrorCodes
        => [.. _diagnostics.Where(static d => d.IsError).Select(static d => d.Code)];

    [Fact]
    public void The_declared_section_versions_are_the_expected_ones()
    {
        Assert.Equal(1, ServerSection.FormatVersion);
        Assert.Equal(1, PolicySection.FormatVersion);
        Assert.Equal(1, OperationsSection.FormatVersion);
        Assert.Equal(2, AgentSurfaceSection.FormatVersion);
        Assert.Equal(2, CredentialsSection.FormatVersion);
        Assert.Equal(1, ToolsSection.FormatVersion);
        Assert.Equal(1, SearchSection.FormatVersion);
    }

    [Theory]
    [InlineData("server", 1, true)]
    [InlineData("server", 2, false)]
    [InlineData("policy", 1, true)]
    [InlineData("policy", 2, false)]
    [InlineData("operations", 1, true)]
    [InlineData("operations", 2, false)]
    [InlineData("agentSurface", 2, true)]
    [InlineData("agentSurface", 1, false)]
    [InlineData("credentials", 2, true)]
    [InlineData("credentials", 1, false)]
    [InlineData("tools", 1, true)]
    [InlineData("tools", 2, false)]
    [InlineData("search", 1, true)]
    [InlineData("search", 2, false)]
    public void Each_section_accepts_only_its_own_version(string section, int declared, bool accepted)
    {
        Read(section, $"\"formatVersion\": {declared}, ");

        if (accepted)
        {
            Assert.DoesNotContain(
                ManifestDiagnosticCodes.SectionFormatVersionUnsupported,
                ErrorCodes,
                StringComparer.Ordinal);
        }
        else
        {
            Assert.Contains(
                ManifestDiagnosticCodes.SectionFormatVersionUnsupported,
                ErrorCodes,
                StringComparer.Ordinal);
        }
    }

    /// <summary>
    /// An absent section version is accepted whatever the supported value is.
    /// </summary>
    /// <remarks>
    /// A hand-written manifest should not have to state a version it cannot choose, so
    /// omission means "whatever this Engine supports" rather than "version one".
    /// </remarks>
    [Theory]
    [InlineData("server")]
    [InlineData("policy")]
    [InlineData("operations")]
    [InlineData("agentSurface")]
    [InlineData("credentials")]
    [InlineData("tools")]
    [InlineData("search")]
    public void An_absent_section_version_is_accepted(string section)
    {
        Read(section, string.Empty);

        Assert.DoesNotContain(
            ManifestDiagnosticCodes.SectionFormatVersionUnsupported,
            ErrorCodes,
            StringComparer.Ordinal);
    }

    private void Read(string section, string version)
    {
        switch (section)
        {
            case "server":
                SectionReader.ReadServer(Json($"{{ {version}\"name\": \"Example\" }}"), _diagnostics);
                break;
            case "policy":
                SectionReader.ReadPolicy(Json($"{{ {version}\"baseUrl\": \"https://api.example.com\" }}"), _diagnostics);
                break;
            case "operations":
                SectionReader.ReadOperations(Json($"{{ {version}\"operations\": [] }}"), _diagnostics);
                break;
            case "agentSurface":
                SectionReader.ReadAgentSurface(Json($"{{ {version}\"operations\": [] }}"), _diagnostics);
                break;
            case "credentials":
                SectionReader.ReadCredentials(Json($"{{ {version}\"credentials\": [] }}"), _diagnostics);
                break;
            case "tools":
                SectionReader.ReadTools(Json($"{{ {version}\"surfaces\": {{}} }}"), _diagnostics);
                break;
            case "search":
                SectionReader.ReadSearch(Json($"{{ {version}\"operations\": [] }}"), _diagnostics);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(section), section, "Unknown section.");
        }
    }
}
