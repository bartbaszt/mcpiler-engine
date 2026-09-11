using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// What a Manifest's embedding matrix does to a running mount, across the states in which it
/// cannot be used.
/// </summary>
/// <remarks>
/// <para>
/// Two things are being proved, and the second is the one an operator depends on. Discovery
/// keeps working in every state, and the state is legible from the process's ordinary output
/// rather than from a debugger — a matrix that quietly stopped counting would show up as
/// search that is merely worse, which nobody reports as a fault.
/// </para>
/// <para>
/// The pages are compared byte for byte rather than by their contents. "The same fields and
/// the same determinism" is a statement about the serialized answer, and comparing parsed
/// values would pass for a page that gained a field.
/// </para>
/// </remarks>
public sealed class VectorDegradationTests : IDisposable
{
    private readonly List<string> _roots = [];

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_payload_that_is_not_a_matrix_is_named_and_ranking_continues()
        => await DegradesAsync(Encoding.UTF8.GetBytes("this is not a matrix"), null, "vectors/unreadable");

    [Fact]
    public async Task A_payload_the_declared_shape_does_not_fit_is_named_and_ranking_continues()
    {
        // A header describing four vectors of eight values over a payload holding one.
        byte[] payload = Compose(Header(8, ServedManifests.IndexedOperations.Count), Values([1f]));

        await DegradesAsync(payload, null, "vectors/dimension-mismatch");
    }

    [Fact]
    public async Task A_section_index_dimension_contradicting_the_header_is_named_and_ranking_continues()
        => await DegradesAsync(Usable(), 1536, "vectors/dimension-mismatch");

    [Fact]
    public async Task A_matrix_describing_other_operations_is_named_and_ranking_continues()
    {
        // Every slug here exists; none of them is the set this Manifest indexes. A row read
        // under this header would be attributed to whichever operation happened to share its
        // position.
        byte[] payload = Matrix(["add-pet", "list-pets"]);

        await DegradesAsync(payload, null, "vectors/operation-mismatch");
    }

    [Fact]
    public async Task A_matrix_that_fits_starts_without_a_word_about_vectors()
    {
        await using var upstream = await Idle();
        await using var engine = await ServeAsync(upstream.Address, Usable(), dimension: 2);

        Assert.DoesNotContain(engine.Started.Warnings, warning => warning.Code.StartsWith("vectors/", StringComparison.Ordinal));
        Assert.DoesNotContain("vectors/", StartupReport.Render(engine.Started), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Discovery_answers_with_every_outbound_address_refused()
    {
        // The guard refuses every address there is, so any connection this mount tried to
        // open would fail rather than succeed quietly. Discovery still answers, which is what
        // "contacts no provider" means when it is observed instead of asserted about source
        // code: there is no embedding request because there is no request.
        await using var upstream = await Idle();
        await using var engine = await ServeAsync(
            upstream.Address,
            Usable(),
            dimension: 2,
            connections: new OutboundConnectionPolicy(static _ => true));

        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var page = await session.CallAsync("catalogue.discover", """{"query":"pets"}""", 2, Token);

        Assert.Contains("list-pets", page.Payload, StringComparison.Ordinal);
    }

    /// <summary>
    /// A semantic query is answered while every address this process could dial is refused.
    /// </summary>
    /// <remarks>
    /// The vector arrives from the caller and the matrix arrives from the bundle, so the
    /// ranking has both halves and still needs no provider. Observed rather than asserted
    /// about source code: a build that reached for an embedding endpoint would fail here
    /// instead of passing a review.
    /// </remarks>
    [Fact]
    public async Task A_semantic_query_is_answered_with_every_outbound_address_refused()
    {
        await using var upstream = await Idle();
        await using var engine = await ServeAsync(
            upstream.Address,
            Usable(),
            dimension: 2,
            connections: new OutboundConnectionPolicy(static _ => true));

        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var page = await session.CallAsync(
            "catalogue.discover",
            """{"query":"pets","queryVector":[1,0]}""",
            2,
            Token);

        Assert.Contains("list-pets", page.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("\"isError\":true", page.Payload, StringComparison.Ordinal);
    }

    /// <summary>The same semantic query answers with the same bytes on a fresh process.</summary>
    [Fact]
    public async Task A_semantic_page_is_the_same_bytes_on_a_second_mount()
    {
        await using var upstream = await Idle();

        await using var first = await ServeAsync(upstream.Address, Usable(), dimension: 2);
        await using var second = await ServeAsync(upstream.Address, Usable(), dimension: 2);

        Assert.Equal(await PageAsync(first, Semantic), await PageAsync(second, Semantic));
    }

    /// <summary>
    /// A query vector of the wrong length is refused, and the refusal says both lengths.
    /// </summary>
    /// <remarks>
    /// Named rather than ignored. A caller that embedded its query with the wrong model has a
    /// fixable mistake, and a silently lexical answer would present it as a relevance problem.
    /// </remarks>
    [Fact]
    public async Task A_query_vector_of_the_wrong_length_is_refused_over_the_wire()
    {
        await using var upstream = await Idle();
        await using var engine = await ServeAsync(upstream.Address, Usable(), dimension: 2);

        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var refused = await session.CallAsync(
            "catalogue.discover",
            """{"query":"pets","queryVector":[1,0,0]}""",
            2,
            Token);

        string text = JsonNode.Parse(refused.Payload)!["result"]!["content"]![0]!["text"]!.GetValue<string>();

        Assert.Contains("\"isError\":true", refused.Payload, StringComparison.Ordinal);
        Assert.Contains("3", text, StringComparison.Ordinal);
        Assert.Contains("2", text, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        foreach (string root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Mounts the same Manifest with and without <paramref name="payload"/> and requires the
    /// two discovery pages to be the same bytes, with the refusal named on the second.
    /// </summary>
    private async Task DegradesAsync(byte[] payload, int? dimension, string code)
    {
        await using var upstream = await Idle();

        await using var lexical = await ServeAsync(upstream.Address, vectors: null, dimension: null);
        string expected = await PageAsync(lexical);

        await using var degraded = await ServeAsync(upstream.Address, payload, dimension);

        StartupRefusal warning = Assert.Single(
            degraded.Started.Warnings,
            candidate => string.Equals(candidate.Code, code, StringComparison.Ordinal));

        // Named, and named somewhere an operator reads without attaching anything.
        Assert.Contains(code, StartupReport.Render(degraded.Started), StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(warning.Message));

        Assert.Equal(expected, await PageAsync(degraded));
    }

    /// <summary>The query every page comparison here is taken over.</summary>
    private const string Lexical = """{"query":"pets"}""";

    /// <summary>The same query with a caller-supplied vector beside it.</summary>
    private const string Semantic = """{"query":"pets","queryVector":[1,0]}""";

    private Task<string> PageAsync(ServedEngine engine) => PageAsync(engine, Lexical);

    private async Task<string> PageAsync(ServedEngine engine, string arguments)
    {
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var page = await session.CallAsync("catalogue.discover", arguments, 2, Token);

        return page.Body;
    }

    /// <summary>A matrix over exactly the operations this Manifest indexes.</summary>
    private static byte[] Usable() => Matrix(ServedManifests.IndexedOperations);

    /// <summary>One unit-length row per operation; the values never matter, only the shape.</summary>
    private static readonly float[] Row = [1f, 0f];

    private static byte[] Matrix(IReadOnlyList<string> operations)
        => Compose(
            Header(Row.Length, operations.Count, operations),
            Values(Enumerable.Range(0, operations.Count).SelectMany(static _ => Row)));

    private static JsonObject Header(int dimension, int count, IReadOnlyList<string>? operations = null) => new()
    {
        ["formatVersion"] = 1,
        ["dimension"] = dimension,
        ["count"] = count,
        ["elementType"] = "float32",
        ["normalization"] = "l2",
        ["ids"] = new JsonArray(
            [.. (operations ?? ServedManifests.IndexedOperations).Select(static slug => JsonValue.Create(slug))]),
    };

    private static byte[] Values(IEnumerable<float> values)
    {
        using var buffer = new MemoryStream();
        Span<byte> element = stackalloc byte[4];

        foreach (float value in values)
        {
            BinaryPrimitives.WriteSingleLittleEndian(element, value);
            buffer.Write(element);
        }

        return buffer.ToArray();
    }

    private static byte[] Compose(JsonObject header, byte[] payload)
    {
        byte[] encoded = Encoding.UTF8.GetBytes(header.ToJsonString());

        using var buffer = new MemoryStream();
        buffer.Write("MVMX"u8);

        Span<byte> prefix = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, encoded.Length);
        buffer.Write(prefix);

        buffer.Write(encoded);
        buffer.Write(payload);
        return buffer.ToArray();
    }

    private static Task<LoopbackHost> Idle()
        => LoopbackHost.StartAsync(200, "application/json", Encoding.UTF8.GetBytes("{}"), Token);

    private async Task<ServedEngine> ServeAsync(
        Uri upstream,
        byte[]? vectors,
        int? dimension,
        OutboundConnectionPolicy? connections = null)
    {
        string root = Path.Combine(Path.GetTempPath(), "mcpiler-vec-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);

        string manifest = ServedManifests.Upstream(upstream);
        string bundle = vectors is null
            ? ServedManifests.Write(root, "pets", manifest)
            : ServedManifests.Write(root, "pets", manifest, vectors, dimension);

        string files = Directory.CreateDirectory(Path.Combine(root, "files")).FullName;

        return await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", bundle)], files),
            Token,
            connections);
    }
}
