using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Guards the two invariants that make this repository publishable and independently
/// buildable. These are enforced as tests rather than as a shell script so there is one
/// cross-platform implementation that runs identically in CI and on a developer machine.
/// </summary>
public sealed class EngineBoundaryTests
{
    /// <summary>
    /// Private MCPiler Platform development artifacts. Engine is treated as future public
    /// from its first source commit, so none of these may ever exist here.
    /// </summary>
    private static readonly string[] ForbiddenRootEntries =
    [
        ".agents",
        ".opencode",
        "AGENTS.md",
        "LESSONS.md",
        "LESSONS-TRIAGE.md",
        "rules",
        "specs",
        "decisions",
        "work",
        "archive",
    ];

    /// <summary>
    /// Dependency classes Engine must never acquire. Engine consumes a compiled MCPiler
    /// Manifest; it never interprets a source API description, never uses an ORM, and
    /// never ships a user interface.
    /// </summary>
    internal static readonly string[] ForbiddenPackages =
    [
        "Microsoft.OpenApi",
        "YamlDotNet",
        "BinkyLabs.OpenApi.Overlays",
        "Microsoft.EntityFrameworkCore",
        "BlazorBlueprint",
        "BlazorMonaco",
    ];

    /// <summary>
    /// Platform namespaces that must never be referenced from Engine sources.
    /// Manifest-local reference resolution is explicitly NOT covered by this list; the
    /// prohibition is on interpreting source API description formats and on reaching into
    /// Platform persistence, identity, AI, validation and UI.
    /// </summary>
    internal static readonly string[] ForbiddenNamespaces =
    [
        "MCPiler.Storage",
        "MCPiler.Identity",
        "MCPiler.Components",
        "MCPiler.Ai",
        "MCPiler.Validation",
        "MCPiler.Compilation.Parsing",
        "MCPiler.Compilation.Ingestion",
        "MCPiler.Compilation.SourceFormats",
        "MCPiler.Compilation.Repairs",
        "MCPiler.Compilation.Diagnostics",
    ];

    [Fact]
    public void Repository_contains_no_private_platform_artifacts()
    {
        var present = ForbiddenRootEntries
            .Where(EngineRepository.Exists)
            .ToArray();

        Assert.True(
            present.Length == 0,
            $"Private MCPiler Platform artifacts must never exist in the Engine repository: {string.Join(", ", present)}");
    }

    [Fact]
    public void No_build_file_references_a_path_outside_the_repository()
    {
        var offenders = SourceFiles("*.csproj", "*.props", "*.targets", "*.slnx")
            .Where(file => File.ReadAllText(file).Contains("../../../", StringComparison.Ordinal)
                || File.ReadAllText(file).Contains(@"..\..\..\", StringComparison.Ordinal))
            .Select(Relative)
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            $"Engine must build from a standalone checkout; these build files escape the repository root: {string.Join(", ", offenders)}");
    }

    [Fact]
    public void No_forbidden_dependency_is_referenced()
    {
        var offenders = new List<string>();

        foreach (var file in SourceFiles("*.csproj", "*.props"))
        {
            var text = File.ReadAllText(file);
            offenders.AddRange(
                ForbiddenPackages
                    .Where(package => text.Contains('"' + package, StringComparison.Ordinal))
                    .Select(package => $"{Relative(file)} -> {package}"));
        }

        Assert.True(
            offenders.Count == 0,
            $"Forbidden dependency class referenced: {string.Join(", ", offenders)}");
    }

    [Fact]
    public void No_forbidden_platform_namespace_is_referenced()
    {
        var offenders = new List<string>();

        foreach (var file in SourceFiles("*.cs"))
        {
            var text = File.ReadAllText(file);
            offenders.AddRange(
                ForbiddenNamespaces
                    .Where(ns => text.Contains(ns, StringComparison.Ordinal))
                    .Select(ns => $"{Relative(file)} -> {ns}"));
        }

        // This test file names the forbidden namespaces on purpose; it is the guard itself.
        offenders.RemoveAll(entry => entry.StartsWith(Relative(CurrentSourceFile()), StringComparison.Ordinal));

        Assert.True(
            offenders.Count == 0,
            $"Forbidden Platform namespace referenced from Engine source: {string.Join(", ", offenders)}");
    }

    private static IEnumerable<string> SourceFiles(params string[] patterns)
        => EngineRepository.Files(patterns);

    private static string Relative(string path)
        => EngineRepository.Relative(path);

    private static string CurrentSourceFile()
        => EngineRepository.Absolute("tests/MCPiler.Engine.ArchitectureTests/EngineBoundaryTests.cs");
}
