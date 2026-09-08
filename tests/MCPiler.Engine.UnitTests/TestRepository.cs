using System.Runtime.CompilerServices;

namespace MCPiler.Engine.UnitTests;

/// <summary>
/// Locates repository-relative test assets without depending on the build output layout.
/// </summary>
/// <remarks>
/// The path is derived from the compiler-provided path of this source file rather than from
/// <c>AppContext.BaseDirectory</c>, so it stays correct regardless of target framework
/// folder, configuration folder, or a test host that changes the working directory.
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
        var directory = Path.GetDirectoryName(SourceFile())
            ?? throw new InvalidOperationException("Could not determine the test source directory.");

        var current = new DirectoryInfo(directory);

        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "MCPiler.Engine.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException(
            $"Could not locate MCPiler.Engine.slnx above '{directory}'.");
    }

    private static string SourceFile([CallerFilePath] string path = "") => path;
}
