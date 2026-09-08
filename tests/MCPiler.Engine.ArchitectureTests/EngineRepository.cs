namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Locates the Engine repository and enumerates its sources for the architecture guards.
/// </summary>
/// <remarks>
/// Architecture guards read the repository as text, so they need a repository root rather
/// than an assembly. Resolution walks up from the test output directory to the solution
/// file, which keeps the guards working from a standalone Engine checkout and from the
/// Platform superproject where Engine is mounted as a submodule.
/// </remarks>
internal static class EngineRepository
{
    private static readonly Lazy<string> LazyRoot = new(Locate, isThreadSafe: true);

    /// <summary>Absolute path of the Engine repository root.</summary>
    public static string Root => LazyRoot.Value;

    /// <summary>Absolute path of a repository-relative entry written with forward slashes.</summary>
    public static string Absolute(string relative)
        => Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));

    /// <summary>Repository-relative path with forward slashes, so guard messages read the same on every host.</summary>
    public static string Relative(string absolute)
        => Path.GetRelativePath(Root, absolute).Replace('\\', '/');

    /// <summary>True when a repository-relative file or directory exists.</summary>
    public static bool Exists(string relative)
    {
        var absolute = Absolute(relative);
        return File.Exists(absolute) || Directory.Exists(absolute);
    }

    /// <summary>Every tracked file matching the patterns, build output excluded, in ordinal path order.</summary>
    public static IEnumerable<string> Files(params string[] patterns)
        => patterns
            .SelectMany(pattern => Directory.EnumerateFiles(Root, pattern, SearchOption.AllDirectories))
            .Where(path => !IsBuildOutput(path))
            .OrderBy(path => path, StringComparer.Ordinal);

    /// <summary>Every C# file under <c>src/</c>, build output excluded, in ordinal path order.</summary>
    public static IEnumerable<string> ProductionSources()
        => Directory
            .EnumerateFiles(Path.Combine(Root, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .OrderBy(path => path, StringComparer.Ordinal);

    private static bool IsBuildOutput(string path)
        => Path
            .GetRelativePath(Root, path)
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(segment =>
                string.Equals(segment, "bin", StringComparison.OrdinalIgnoreCase)
                || string.Equals(segment, "obj", StringComparison.OrdinalIgnoreCase));

    private static string Locate()
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

        throw new InvalidOperationException(
            $"Could not locate the Engine repository root above '{AppContext.BaseDirectory}'.");
    }
}
