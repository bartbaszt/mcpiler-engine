using System.Text;
using System.Text.Json.Nodes;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Serialization;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Reads the shared request-compilation corpus and renders a compiled request in the corpus format.
/// </summary>
/// <remarks>
/// <para>
/// The corpus is the contract, and it has two implementations. One of them produces the operation
/// sections committed under <c>tests/fixtures/http/operations</c> and drives the same case files from
/// its own model; this one drives them from the manifest. Neither side authors the sections by hand,
/// because a contract with one author is indistinguishable from whatever that author happened to
/// write, and neither side owns the case files, because a producer that can edit its own expectation
/// is not being checked by it.
/// </para>
/// <para>
/// The rendered form carries only the method, the exact URL, the headers sorted by name, and the body
/// as lower-case hex. It deliberately excludes the serialization decisions: those are an inspection
/// aid whose wording may differ between implementations without any wire consequence, and pinning them
/// would turn a comment change into a parity failure.
/// </para>
/// </remarks>
internal static class GoldenCorpus
{
    private static readonly Dictionary<string, OperationsSection> Sections = new(StringComparer.Ordinal);

    /// <summary>Absolute path of the corpus directory.</summary>
    public static string Directory => TestRepository.Fixture("http");

    /// <summary>Whether the corpus is present in this checkout.</summary>
    public static bool Available => System.IO.Directory.Exists(Directory);

    /// <summary>Reads a committed case file, trimming only the trailing newline.</summary>
    public static string Case(string name)
        => File.ReadAllText(Path.Combine(Directory, "cases", name)).TrimEnd('\r', '\n');

    /// <summary>Every committed case file name.</summary>
    public static IReadOnlyList<string> CaseNames()
        => [.. System.IO.Directory
            .EnumerateFiles(Path.Combine(Directory, "cases"), "*.txt")
            .Select(Path.GetFileName)
            .Select(static name => name!)
            .OrderBy(static name => name, StringComparer.Ordinal)];

    /// <summary>
    /// Reads the operation section committed for one source document, refusing anything the reader
    /// reports. A fixture the reader cannot read in full is a corpus defect, not a test to relax.
    /// </summary>
    public static OperationsSection Section(string stem)
    {
        lock (Sections)
        {
            if (Sections.TryGetValue(stem, out var cached))
            {
                return cached;
            }

            var path = Path.Combine(Directory, "operations", stem + ".json");
            var text = File.ReadAllText(path);
            var diagnostics = new List<ManifestDiagnostic>();
            var section = SectionReader.ReadOperations(JsonNode.Parse(text), diagnostics);

            Assert.Empty(diagnostics);
            Assert.NotNull(section);

            Sections[stem] = section!;
            return section!;
        }
    }

    /// <summary>Reads one operation by key from the section committed for a source document.</summary>
    public static ManifestOperation Operation(string stem, string key)
    {
        var operation = Section(stem).Operation(key);

        // A missing key means the section no longer describes what the case compiles, which the
        // corpus-completeness test cannot see: it counts files, not keys.
        Assert.NotNull(operation);
        return operation!;
    }

    /// <summary>Compiles one case and renders it in the corpus format.</summary>
    public static string CompileAndRender(
        string stem,
        string key,
        Uri baseUri,
        JsonObject arguments,
        IReadOnlyDictionary<string, byte[]>? files = null,
        IReadOnlyDictionary<string, string>? fileNames = null,
        IReadOnlyDictionary<string, string>? fileMediaTypes = null,
        IBoundaryProvider? boundaryProvider = null)
    {
        var compiled = RequestCompiler.Compile(
            Operation(stem, key),
            baseUri,
            arguments,
            files,
            fileNames,
            fileMediaTypes,
            boundaryProvider);

        return Render(compiled).TrimEnd('\n');
    }

    /// <summary>Renders a compiled request in the corpus format.</summary>
    public static string Render(CompiledRequest compiled)
    {
        ArgumentNullException.ThrowIfNull(compiled);

        var text = new StringBuilder();
        text.Append("METHOD ").Append(compiled.Method).Append('\n');
        text.Append("URL ").Append(compiled.ExactUrl).Append('\n');

        foreach (var header in compiled.Headers.OrderBy(static h => h.Key, StringComparer.Ordinal))
        {
            foreach (var value in header.Value)
            {
                text.Append("H ").Append(header.Key).Append(": ").Append(value).Append('\n');
            }
        }

        if (compiled.Body is { Length: > 0 } body)
        {
            text.Append("BODY ").Append(Convert.ToHexString(body).ToLowerInvariant()).Append('\n');
        }

        return text.ToString();
    }
}
