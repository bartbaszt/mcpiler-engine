using System.Text.RegularExpressions;

using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Guards the rule that exactly one component decides what a binding executes.
/// </summary>
/// <remarks>
/// <para>
/// A capability gate once resolved an execution key with its own type switch in which a
/// transformed binding fell through to the source key, while invocation ran the transformed
/// binding's base key. The two answers diverged and a file upload passed a gate that forbade
/// files. The defect was not the switch itself; it was that a second switch existed at all.
/// </para>
/// <para>
/// This guard is intentionally textual and slightly blunt. A type-level check could not see
/// the difference between resolving a binding and constructing one, and a reviewer noticing
/// the second switch is exactly what failed last time.
/// </para>
/// </remarks>
public sealed class BindingSeamGuardTests
{
    /// <summary>The only component permitted to discriminate on binding shape.</summary>
    private const string Dispatcher = "src/MCPiler.Engine/Manifest/Model/ManifestBindingDispatcher.cs";

    /// <summary>
    /// Files permitted to name a binding type in a discriminating position.
    /// </summary>
    /// <remarks>
    /// The section reader is exempt because constructing a binding from JSON necessarily
    /// discriminates on the declared type. What the rule forbids is re-deriving, elsewhere,
    /// what an already constructed binding does.
    /// </remarks>
    private static readonly string[] PermittedFiles =
    [
        Dispatcher,
        "src/MCPiler.Engine/Manifest/Loading/AgentSurfaceSectionReader.cs",
    ];

    private static readonly string[] BindingTypes =
    [
        "HttpBinding",
        "TransformedHttpBinding",
        "CompoundBinding",
    ];

    [Fact]
    public void Only_the_dispatcher_discriminates_on_binding_shape()
    {
        var pattern = new Regex(
            @"(\bis\s+(HttpBinding|TransformedHttpBinding|CompoundBinding)\b)"
                + @"|(\bas\s+(HttpBinding|TransformedHttpBinding|CompoundBinding)\b)"
                + @"|(^\s*(HttpBinding|TransformedHttpBinding|CompoundBinding)(\s+\w+)?\s*(=>|when\b))",
            RegexOptions.Multiline | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));

        var offenders = new List<string>();

        foreach (var file in ProductionSources())
        {
            var relative = Relative(file);

            if (PermittedFiles.Contains(relative, StringComparer.Ordinal))
            {
                continue;
            }

            foreach (Match match in pattern.Matches(File.ReadAllText(file)))
            {
                offenders.Add($"{relative}: {match.Value.Trim()}");
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Binding shape must be resolved through ManifestBindingDispatcher so inspection and "
                + $"execution cannot disagree. Offending sites: {string.Join("; ", offenders)}");
    }

    [Fact]
    public void The_dispatcher_exists_where_the_guard_expects_it()
        => Assert.True(
            File.Exists(Path.Combine(RepositoryRoot(), Dispatcher.Replace('/', Path.DirectorySeparatorChar))),
            $"The binding seam is missing from {Dispatcher}, so this guard would silently pass.");

    /// <summary>
    /// Every exemption must name a file that exists, so a rename cannot silently widen the
    /// permitted set.
    /// </summary>
    [Fact]
    public void Every_permitted_file_exists()
    {
        var missing = PermittedFiles
            .Where(entry => !File.Exists(Path.Combine(RepositoryRoot(), entry.Replace('/', Path.DirectorySeparatorChar))))
            .ToList();

        Assert.True(missing.Count == 0, $"Stale binding-seam exemption: {string.Join(", ", missing)}");
    }

    [Fact]
    public void The_guard_recognizes_every_binding_type_in_the_model()
    {
        var declared = File
            .ReadAllText(Path.Combine(
                RepositoryRoot(),
                "src", "MCPiler.Engine", "Manifest", "Model", "ManifestBinding.cs"));

        var missing = new Regex(
                @"public sealed record (\w+Binding)\b",
                RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(5))
            .Matches(declared)
            .Select(match => match.Groups[1].Value)
            .Where(name => !BindingTypes.Contains(name, StringComparer.Ordinal))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"A binding type exists that this guard does not watch: {string.Join(", ", missing)}");
    }

    private static IEnumerable<string> ProductionSources()
        => Directory
            .EnumerateFiles(Path.Combine(RepositoryRoot(), "src"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .OrderBy(path => path, StringComparer.Ordinal);

    private static bool IsBuildOutput(string path)
        => Path
            .GetRelativePath(RepositoryRoot(), path)
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(segment =>
                string.Equals(segment, "bin", StringComparison.OrdinalIgnoreCase)
                || string.Equals(segment, "obj", StringComparison.OrdinalIgnoreCase));

    private static string Relative(string path)
        => Path.GetRelativePath(RepositoryRoot(), path).Replace('\\', '/');

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "MCPiler.Engine.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("Could not locate the Engine repository root.");
    }
}
