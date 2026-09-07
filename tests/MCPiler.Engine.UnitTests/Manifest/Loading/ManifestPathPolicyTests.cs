using MCPiler.Engine.Manifest.Loading;
using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Loading;

public sealed class ManifestPathPolicyTests
{
    private static readonly string Bundle = OperatingSystem.IsWindows()
        ? @"C:\bundles\example"
        : "/bundles/example";

    [Theory]
    [InlineData("sections/operations.json")]
    [InlineData("operations.json")]
    [InlineData("a/b/c/d.json")]
    [InlineData("sections/with.dots/file.json")]
    [InlineData("sections/./operations.json")]
    public void Accepts_a_bundle_relative_path(string declared)
    {
        Assert.Equal(
            ManifestPathVerdict.Accepted,
            ManifestPathPolicy.Resolve(declared, Bundle, out var resolved));

        Assert.NotNull(resolved);
        Assert.StartsWith(Path.GetFullPath(Bundle), resolved, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, ManifestPathVerdict.Empty)]
    [InlineData("", ManifestPathVerdict.Empty)]
    [InlineData("   ", ManifestPathVerdict.Empty)]
    [InlineData("/etc/passwd", ManifestPathVerdict.Absolute)]
    [InlineData("../secrets.json", ManifestPathVerdict.ParentSegment)]
    [InlineData("sections/../../secrets.json", ManifestPathVerdict.ParentSegment)]
    [InlineData("sections/..", ManifestPathVerdict.ParentSegment)]
    [InlineData("https://evil.example.com/sections.json", ManifestPathVerdict.Uri)]
    [InlineData("file:///etc/passwd", ManifestPathVerdict.Uri)]
    [InlineData("sections\\operations.json", ManifestPathVerdict.BackslashSeparator)]
    public void Refuses_everything_that_is_not_a_portable_relative_path(
        string? declared,
        ManifestPathVerdict expected)
    {
        Assert.Equal(expected, ManifestPathPolicy.Resolve(declared, Bundle, out var resolved));
        Assert.Null(resolved);
    }

    [Fact]
    public void Refuses_a_parent_segment_even_when_the_result_would_stay_inside_the_bundle()
    {
        // "sections/../operations.json" normalizes back inside the bundle, so a containment
        // check alone would accept it. The segment is refused anyway: a path that has to be
        // normalized before it can be judged safe is a path a reviewer cannot judge by
        // reading it.
        Assert.Equal(
            ManifestPathVerdict.ParentSegment,
            ManifestPathPolicy.Resolve("sections/../operations.json", Bundle, out _));
    }

    [Fact]
    public void Every_verdict_has_an_explanation()
    {
        foreach (var verdict in Enum.GetValues<ManifestPathVerdict>())
        {
            var explanation = ManifestPathPolicy.Explain(verdict);

            Assert.False(string.IsNullOrWhiteSpace(explanation));
            Assert.NotEqual("the path was refused", explanation);
        }
    }

    [Fact]
    public void Requires_a_bundle_directory()
    {
        Assert.Throws<ArgumentException>(() => ManifestPathPolicy.Resolve("x.json", " ", out _));
    }
}
