using System.Text.RegularExpressions;

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

    /// <summary>
    /// Path-shaped references to private MCPiler Platform locations, plus the private
    /// Platform repository URL. Matched with a separator or extension rather than as bare
    /// words, because "work", "rules" and "archive" are ordinary English and a guard that
    /// refused them would be turned off rather than obeyed.
    /// </summary>
    private static readonly string[] ForbiddenDocumentationReferences =
    [
        "work/",
        "specs/",
        "decisions/",
        "rules/",
        ".opencode/",
        ".agents/",
        "AGENTS.md",
        "LESSONS.md",
        "LESSONS-TRIAGE.md",
        "github.com/bartbaszt/mcpiler/",
        "github.com/bartbaszt/mcpiler.git",
    ];

    /// <summary>
    /// Prose is published with the source. A document that cites a Platform-private path
    /// or repository is either a broken link for every reader outside this repository or a
    /// disclosure of private development structure, and the two are indistinguishable from
    /// the outside.
    /// </summary>
    /// <remarks>
    /// Build files are scanned too, and that is not thoroughness for its own sake. A
    /// project file is prose as much as it is configuration - it carries the comments that
    /// explain why a flag is set - and it ships in every clone. The scan reached only
    /// <c>*.md</c> and production C# until a project comment was written pointing at a
    /// private decision record, which no assertion noticed. A rule about published content
    /// has to cover the published content, not the file extensions somebody happened to
    /// think of.
    /// </remarks>
    [Fact]
    public void No_document_references_a_private_platform_location()
    {
        var offenders = new List<string>();

        foreach (var file in PublishedText())
        {
            var text = File.ReadAllText(file);
            foreach (var reference in ForbiddenDocumentationReferences)
            {
                if (text.Contains(reference, StringComparison.OrdinalIgnoreCase))
                {
                    offenders.Add($"{EngineRepository.Relative(file)} -> {reference}");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Engine documentation must not reference private MCPiler Platform locations: "
                + string.Join(", ", offenders));
    }

    /// <summary>
    /// Decision records live only in the private Platform repository, so an <c>ADR-NNNN</c>
    /// citation in published Engine content is an identifier no outside reader can resolve.
    /// It is also fragile in a way a broken link is not: the private repository renumbers a
    /// draft when it collides with an accepted record, and this repository would silently
    /// keep pointing at the old number. Engine states its own rules, or points at its own
    /// documentation, and never borrows Platform's numbering.
    /// </summary>
    [Fact]
    public void No_published_content_cites_a_private_decision_record()
    {
        var offenders = PublishedText()
            .Where(file => CitesADecisionRecord(File.ReadAllText(file)))
            .Select(EngineRepository.Relative)
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Engine content must not cite a private Platform decision record by number; "
                + "state the rule or point at Engine's own documentation instead: "
                + string.Join(", ", offenders));
    }

    private static bool CitesADecisionRecord(string text)
    {
        const string Token = "ADR-";
        var index = text.IndexOf(Token, StringComparison.OrdinalIgnoreCase);
        while (index >= 0)
        {
            var digit = index + Token.Length;
            if (digit < text.Length && char.IsAsciiDigit(text[digit]))
            {
                return true;
            }

            if (digit >= text.Length)
            {
                return false;
            }

            index = text.IndexOf(Token, digit, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

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

    /// <summary>
    /// The dependency set is exactly this list, so a package arrives as a decision rather
    /// than as a transitive surprise.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A forbidden-list guard answers "did we take something we already knew was wrong".
    /// It cannot answer "did we take something at all", and that is the question that
    /// matters for a repository whose whole claim is a small, permissively licensed
    /// dependency graph. A package nobody thought to forbid passes the other guard
    /// silently.
    /// </para>
    /// <para>
    /// Every entry is named with the reason it is here. Changing this list is the review:
    /// the diff shows a dependency being added, in a file whose only purpose is to say
    /// which dependencies exist.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_declared_package_set_is_exactly_the_reviewed_list()
    {
        string[] reviewed =
        [
            // Analyzers. Build-time only, nothing ships.
            "Meziantou.Analyzer",
            "Microsoft.CodeAnalysis.BannedApiAnalyzers",
            "Microsoft.VisualStudio.Threading.Analyzers",

            // Runtime. The protocol SDK, the JSON Schema evaluator, and JOSE token
            // security for the configured JWKS validation mode.
            "ModelContextProtocol.AspNetCore",
            "ModelContextProtocol.Core",
            "JsonSchema.Net",
            "Microsoft.IdentityModel.JsonWebTokens",

            // Testing.
            "xunit.v3",
        ];

        var declared = new Regex(
            @"<PackageVersion\s+Include=""(?<id>[^""]+)""",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5))
            .Matches(File.ReadAllText(EngineRepository.Absolute("Directory.Packages.props")))
            .Select(match => match.Groups["id"].Value)
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.Equal([.. reviewed.Order(StringComparer.Ordinal)], declared);
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

    /// <summary>
    /// Everything published with the repository that a human reads: prose, production
    /// source, and the build files whose comments explain the source.
    /// </summary>
    /// <remarks>
    /// Test sources are deliberately absent. A guard names the rule it enforces, and
    /// naming a private decision record is how it says which rule - the citation belongs
    /// there and nowhere the repository publishes as its own explanation of itself.
    /// </remarks>
    private static IEnumerable<string> PublishedText()
        => EngineRepository
            .Files("*.md", "*.csproj", "*.props", "*.targets", "*.slnx")
            .Concat(EngineRepository.ProductionSources())
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);

    private static string Relative(string path)
        => EngineRepository.Relative(path);

    private static string CurrentSourceFile()
        => EngineRepository.Absolute("tests/MCPiler.Engine.ArchitectureTests/EngineBoundaryTests.cs");
}
