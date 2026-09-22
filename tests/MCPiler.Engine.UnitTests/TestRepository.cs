using System.Runtime.CompilerServices;

namespace MCPiler.Engine.UnitTests;

/// <summary>
/// Locates repository-relative test assets without depending on the test host's working directory.
/// </summary>
/// <remarks>
/// The path is normally derived from the compiler-provided path of this source file. Deterministic
/// CI builds can map that path to the virtual <c>/_/</c> root, so the executable output directory
/// is the fallback when the mapped source path is not an accessible checkout.
/// </remarks>
internal static class TestRepository
{
    /// <summary>Absolute path of the Engine repository root.</summary>
    public static string Root { get; } = ResolveRoot();

    /// <summary>Absolute path of a file or directory under <c>engine/tests/fixtures</c>.</summary>
    public static string Fixture(params string[] segments)
        => Path.Combine([Root, "tests", "fixtures", .. segments]);

    /// <summary>Absolute path of a repository-relative path, given with forward slashes.</summary>
    public static string Absolute(string relative)
        => Path.Combine([Root, .. relative.Split('/', StringSplitOptions.RemoveEmptyEntries)]);

    private static string ResolveRoot()
    {
        // <root>/tests/MCPiler.Engine.UnitTests/TestRepository.cs
        var sourceDirectory = Path.GetDirectoryName(SourceFile());
        var sourceRoot = sourceDirectory is null ? null : FindRoot(sourceDirectory);
        if (sourceRoot is not null)
        {
            return sourceRoot;
        }

        var runtimeRoot = FindRoot(AppContext.BaseDirectory);
        if (runtimeRoot is not null)
        {
            return runtimeRoot;
        }

        var sourceDescription = sourceDirectory ?? "the compiler-provided source path";
        throw new InvalidOperationException(
            $"Could not locate MCPiler.Engine.slnx above '{sourceDescription}' or the test output directory '{AppContext.BaseDirectory}'.");
    }

    private static string? FindRoot(string directory)
    {
        var current = new DirectoryInfo(directory);

        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "MCPiler.Engine.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        return null;
    }

    private static string SourceFile([CallerFilePath] string path = "") => path;
}
