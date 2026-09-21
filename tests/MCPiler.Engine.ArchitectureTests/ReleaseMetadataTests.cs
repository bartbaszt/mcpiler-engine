using System.Text.RegularExpressions;
using System.Xml;

using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Static release-contract guards for the standalone Engine repository.
/// </summary>
public sealed class ReleaseMetadataTests
{
    private static string Read(string relative)
    {
        var path = EngineRepository.Absolute(relative);
        Assert.True(File.Exists(path), $"Expected release file is missing: {relative}");
        return File.ReadAllText(path);
    }

    private static string HostVersion()
    {
        var xml = new XmlDocument();
        xml.Load(EngineRepository.Absolute("src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj"));
        var value = xml.SelectSingleNode("//PropertyGroup/Version")?.InnerText.Trim();
        Assert.False(string.IsNullOrWhiteSpace(value));
        return value!;
    }

    [Fact]
    public void Host_version_and_first_changelog_header_are_the_same_stable_release()
    {
        var version = HostVersion();
        Assert.Matches(@"^\d+\.\d+\.\d+$", version);

        var changelog = Read("CHANGELOG.md");
        var first = Regex.Match(
            changelog,
            @"(?m)^##\s+(v\d+\.\d+\.\d+)\s*$",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));

        Assert.True(first.Success, "CHANGELOG.md has no stable release header.");
        Assert.Equal($"v{version}", first.Groups[1].Value);
        Assert.Contains("Manifest format", changelog, StringComparison.Ordinal);
        Assert.Contains("Diagnostic codes", changelog, StringComparison.Ordinal);
    }

    [Fact]
    public void Standalone_release_entry_points_and_helpers_exist()
    {
        string[] required =
        [
            "eng/check-release-metadata.sh",
            "eng/check-licenses.sh",
            "eng/test-release-helpers.sh",
            "eng/release.sh",
            "eng/publish-release.sh",
            "eng/verify-container.sh",
            ".github/workflows/release-patch.yml",
            ".github/workflows/release-minor.yml",
            ".github/workflows/release-major.yml",
            ".github/workflows/release.yml",
            ".github/workflows/release-resume.yml",
        ];

        Assert.All(required, relative => Assert.True(EngineRepository.Exists(relative), $"Missing {relative}"));
    }

    [Fact]
    public void Release_workflow_separates_repository_package_and_oidc_write_permissions()
    {
        var workflow = Read(".github/workflows/release.yml");

        Assert.Contains("contents: read", workflow, StringComparison.Ordinal);
        Assert.Contains("contents: write", workflow, StringComparison.Ordinal);
        Assert.Contains("packages: write", workflow, StringComparison.Ordinal);
        Assert.Contains("id-token: write", workflow, StringComparison.Ordinal);
        Assert.Contains("ubuntu-24.04-arm", workflow, StringComparison.Ordinal);
        Assert.Contains("linux/amd64,linux/arm64", workflow, StringComparison.Ordinal);
        Assert.Contains("provenance: false", workflow, StringComparison.Ordinal);
        Assert.Contains("sbom: false", workflow, StringComparison.Ordinal);

        var gitJob = Job(workflow, "git_publish");
        Assert.Contains("contents: write", gitJob, StringComparison.Ordinal);
        Assert.DoesNotContain("packages: write", gitJob, StringComparison.Ordinal);

        var candidateJob = Job(workflow, "candidate_publish");
        Assert.Contains("packages: write", candidateJob, StringComparison.Ordinal);
        Assert.DoesNotContain("contents: write", candidateJob, StringComparison.Ordinal);

        var supplyJob = Job(workflow, "supply_chain");
        Assert.Contains("id-token: write", supplyJob, StringComparison.Ordinal);
        Assert.DoesNotContain("contents: write", supplyJob, StringComparison.Ordinal);
    }

    [Fact]
    public void Latest_is_owned_only_by_the_stable_release_path()
    {
        var ci = Read(".github/workflows/ci.yml");
        Assert.DoesNotContain("mcpiler-engine:latest", ci, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("imagetools create", ci, StringComparison.OrdinalIgnoreCase);

        var release = Read(".github/workflows/release.yml");
        Assert.Contains("LATEST_PROMOTED", release, StringComparison.Ordinal);
        Assert.Contains(":latest", release, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_identity_is_the_documented_dco_bot_identity()
    {
        var release = Read("eng/release.sh");
        Assert.Contains("github-actions[bot]", release, StringComparison.Ordinal);
        Assert.Contains("41898282+github-actions[bot]@users.noreply.github.com", release, StringComparison.Ordinal);
        Assert.Contains("git commit -s", release, StringComparison.Ordinal);
        Assert.Contains("Signed-off-by", release, StringComparison.Ordinal);
    }

    [Fact]
    public void Dockerfile_carries_public_release_metadata_and_redistribution_material()
    {
        var dockerfile = Read("Dockerfile");

        foreach (var label in new[]
                 {
                     "org.opencontainers.image.source",
                     "org.opencontainers.image.revision",
                     "org.opencontainers.image.version",
                     "org.opencontainers.image.licenses",
                     "org.opencontainers.image.title",
                     "org.opencontainers.image.description",
                     "org.opencontainers.image.documentation",
                 })
        {
            Assert.Contains(label, dockerfile, StringComparison.Ordinal);
        }

        Assert.Contains("/licenses/mcpiler-engine/", dockerfile, StringComparison.Ordinal);
        Assert.Contains("LICENSE", dockerfile, StringComparison.Ordinal);
        Assert.Contains("NOTICE", dockerfile, StringComparison.Ordinal);
        Assert.Contains("THIRD-PARTY-NOTICES", dockerfile, StringComparison.Ordinal);
        Assert.Contains("/usr/share/dotnet/LICENSE.txt", dockerfile, StringComparison.Ordinal);
        Assert.Contains("/usr/share/dotnet/ThirdPartyNotices.txt", dockerfile, StringComparison.Ordinal);
    }

    private static string Job(string workflow, string name)
    {
        var match = Regex.Match(
            workflow,
            $@"(?ms)^  {Regex.Escape(name)}:\s*\n(?<body>.*?)(?=^  [a-zA-Z0-9_-]+:\s*\n|\z)",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));
        Assert.True(match.Success, $"Workflow job '{name}' was not found.");
        return match.Groups["body"].Value;
    }
}
