using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Mcp;
using MCPiler.Engine.Mcp.Navigator;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.UnitTests.Search;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>
/// Discovery with a semantic half: what changes, what does not, and what still cannot leak.
/// </summary>
/// <remarks>
/// Nothing here asserts a similarity. What is measured is the order, the bytes of the page,
/// and the exclusions - the three things the format promises to reproduce.
/// </remarks>
public sealed class NavigatorHybridTests
{
    /// <summary>The index order, which is also the order the matrix rows must be written in.</summary>
    private static readonly string[] Indexed = ["alpha-op", "beta-op", "gamma-op", "secret-op"];

    /// <summary>
    /// The semantic half reaches an operation the query never named.
    /// </summary>
    /// <remarks>
    /// Against the lexical answer to the same query rather than against a literal list. A
    /// literal would pass for a build that ignored the vector and happened to be asserted
    /// with the order it already produced.
    /// </remarks>
    [Fact]
    public void A_query_vector_finds_an_operation_no_term_matched()
    {
        MountedManifest mount = Mount(Embedded());

        Assert.Equal(["alpha-op"], Operations(Discover(mount, Arguments("alpha"))));
        Assert.Equal(["alpha-op", "gamma-op"], Operations(Discover(mount, Arguments("alpha", Toward("gamma-op")))));
    }

    /// <summary>
    /// The semantic half decides between two operations the query matched equally.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both carry the queried word in the same field, so lexically they tie and the ordinal
    /// tie-break settles it. The vector moves one of them, which is the reordering the format
    /// promises a usable matrix produces.
    /// </para>
    /// <para>
    /// It does not promise dominance. A perfect cosine is worth ten thousand milli-score and
    /// an exact name match twelve, so the semantic half re-ranks a field of candidates and
    /// never outranks a literal name. That is the declared weighting, and a test that assumed
    /// otherwise would be asserting a different product.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_query_vector_reorders_two_operations_the_query_matched_alike()
    {
        MountedManifest mount = Mount(Embedded());

        Assert.Equal(["alpha-op", "beta-op"], Operations(Discover(mount, Arguments("shared"))));
        Assert.Equal(["beta-op", "alpha-op"], Operations(Discover(mount, Arguments("shared", Toward("beta-op")))));
    }

    /// <summary>
    /// An operation the surface does not expose is absent however well it scores.
    /// </summary>
    /// <remarks>
    /// The index still documents it and the matrix still carries its row, so the vector aims
    /// straight at it. The exposure filter runs at query time for exactly this reason: an
    /// index is an artifact, and an artifact cannot grant reachability it was not given.
    /// </remarks>
    [Fact]
    public void The_best_scoring_row_is_still_excluded_when_the_surface_hides_it()
    {
        JsonObject page = Discover(Mount(Embedded()), Arguments(query: null, Toward("secret-op")));

        Assert.DoesNotContain("secret-op", Operations(page));
        Assert.Equal(["alpha-op", "beta-op", "gamma-op"], Operations(page).Order(StringComparer.Ordinal));
    }

    /// <summary>The same semantic query answers with the same bytes, twice and after a remount.</summary>
    [Fact]
    public void A_semantic_page_repeats_byte_identically()
    {
        JsonObject arguments = Arguments("alpha", Toward("gamma-op"));

        string first = Page(Mount(Embedded()), arguments);
        string again = Page(Mount(Embedded()), arguments);

        Assert.Equal(first, again);
    }

    /// <summary>
    /// A page boundary from a semantic ranking is not a position in the lexical one.
    /// </summary>
    /// <remarks>
    /// The quiet failure this prevents: same query text, same surface, same catalogue, and a
    /// caller resuming into a list that was ordered by something else.
    /// </remarks>
    [Fact]
    public void A_continuation_issued_with_a_vector_is_refused_without_it()
    {
        MountedManifest mount = Mount(Embedded());

        JsonObject first = Discover(mount, Arguments(query: null, Toward("gamma-op"), pageSize: 1));
        string token = first["continuation"]!.GetValue<string>();

        ToolOutcome resumed = NavigatorRuntime.Discover(
            mount,
            Surface(mount),
            Arguments(query: null, vector: null, pageSize: 1, continuation: token));

        Assert.True(resumed.IsError);
        Assert.Equal(NavigatorRuntime.StaleContinuation, resumed.Text);
    }

    /// <summary>A vector of the wrong length is refused rather than quietly dropped.</summary>
    [Fact]
    public void A_vector_that_does_not_fit_the_catalogue_is_refused()
    {
        ToolOutcome outcome = NavigatorRuntime.Discover(
            Mount(Embedded()),
            Surface(Mount(Embedded())),
            Arguments("alpha", [1d, 0d]));

        Assert.True(outcome.IsError);
        Assert.Contains("2", outcome.Text, StringComparison.Ordinal);
        Assert.Contains("4", outcome.Text, StringComparison.Ordinal);
    }

    /// <summary>A vector that is not a list of numbers is refused rather than read as absent.</summary>
    [Fact]
    public void A_vector_that_is_not_a_list_of_numbers_is_refused()
    {
        MountedManifest mount = Mount(Embedded());

        foreach (JsonNode malformed in new JsonNode[] { "not a vector", new JsonArray("alpha"), new JsonObject() })
        {
            ToolOutcome outcome = NavigatorRuntime.Discover(
                mount,
                Surface(mount),
                new JsonObject { ["queryVector"] = malformed });

            Assert.True(outcome.IsError);
            Assert.Equal(NavigatorRuntime.MalformedVector, outcome.Text);
        }
    }

    /// <summary>
    /// A catalogue that cannot use its matrix answers the query, and answers it identically.
    /// </summary>
    /// <remarks>
    /// Both halves at once: degradation does not change the contract, and a vector sent to a
    /// catalogue with no usable matrix is not a caller error. A refusal here would turn a
    /// producer's broken artifact into every caller's failed request.
    /// </remarks>
    [Fact]
    public void A_degraded_catalogue_answers_a_semantic_query_lexically()
    {
        string lexical = Page(Mount(Load(Catalogue)), Arguments("alpha"));
        string degraded = Page(Mount(Broken()), Arguments("alpha", Toward("gamma-op")));

        Assert.Equal(lexical, degraded);
    }

    /// <summary>The Manifest with a usable matrix: one axis per indexed operation.</summary>
    private static ManifestDocument Embedded()
        => Load(Catalogue) with
        {
            VectorPayload = PackedMatrix.Write(Indexed, [.. Indexed.Select((_, row) => Axis(row))]),
        };

    /// <summary>The same Manifest with a payload nothing can read.</summary>
    private static ManifestDocument Broken()
        => Load(Catalogue) with { VectorPayload = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 } };

    private static float[] Axis(int row)
    {
        float[] values = new float[Indexed.Length];
        values[row] = 1f;
        return values;
    }

    /// <summary>A query vector pointing exactly at one indexed operation.</summary>
    private static double[] Toward(string operation)
    {
        double[] values = new double[Indexed.Length];
        values[Array.IndexOf(Indexed, operation)] = 1d;
        return values;
    }

    private static JsonObject Arguments(
        string? query,
        IReadOnlyList<double>? vector = null,
        int? pageSize = null,
        string? continuation = null)
    {
        JsonObject arguments = [];

        if (query is not null)
        {
            arguments["query"] = query;
        }

        if (vector is not null)
        {
            arguments["queryVector"] = new JsonArray([.. vector.Select(value => JsonValue.Create(value))]);
        }

        if (pageSize is { } size)
        {
            arguments["pageSize"] = size;
        }

        if (continuation is not null)
        {
            arguments["continuation"] = continuation;
        }

        return arguments;
    }

    private static JsonObject Discover(MountedManifest mount, JsonObject arguments)
        => (JsonObject)JsonNode.Parse(Page(mount, arguments))!;

    private static string Page(MountedManifest mount, JsonObject arguments)
    {
        ToolOutcome outcome = NavigatorRuntime.Discover(mount, Surface(mount), arguments);

        Assert.False(outcome.IsError);

        return outcome.Text;
    }

    private static IReadOnlyList<string> Operations(JsonObject page)
        => [.. page["items"]!.AsArray().Select(item => item!["operation"]!.GetValue<string>())];

    private static MountedSurface Surface(MountedManifest mount) => mount.Surfaces.Single();

    private static MountedManifest Mount(ManifestDocument manifest)
    {
        List<ManifestDiagnostic> diagnostics = [];

        List<MountedSurface> surfaces =
            [.. manifest.Server.Surfaces.Select(surface => SurfaceCatalogue.Build(manifest, surface, diagnostics))];

        NavigatorIndex index = NavigatorIndex.Resolve(manifest, diagnostics);

        Assert.DoesNotContain(diagnostics, static diagnostic => diagnostic.IsError);

        return new MountedManifest("/api", "bundle", manifest, manifest.Policy, surfaces, index);
    }

    private static ManifestDocument Load(string manifestText)
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(manifestText));
        Assert.True(result.Succeeded);
        return result.Manifest!;
    }

    /// <summary>
    /// Four operations, one of them hidden, over names that share no vocabulary.
    /// </summary>
    /// <remarks>
    /// Distinct names so a lexical query names exactly one of them, which is what makes a
    /// reordering attributable to the semantic half rather than to a coincidence of tokens.
    /// </remarks>
    private const string Catalogue = """
        {
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "surfaces": [
                  {
                    "slug": "full",
                    "isDefault": true,
                    "navigator": { "enabled": true },
                    "operations": [
                      { "operation": "alpha-op" },
                      { "operation": "beta-op" },
                      { "operation": "gamma-op" },
                      { "operation": "secret-op", "exposure": "hidden" }
                    ]
                  }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": {
                "operations": [
                  { "key": "GET /alpha", "method": "GET", "path": "/alpha" },
                  { "key": "GET /beta", "method": "GET", "path": "/beta" },
                  { "key": "GET /gamma", "method": "GET", "path": "/gamma" },
                  { "key": "GET /secret", "method": "GET", "path": "/secret" }
                ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  {
                    "slug": "alpha-op",
                    "name": "Alpha",
                    "summary": "A shared endpoint.",
                    "binding": { "type": "http", "operation": "GET /alpha" }
                  },
                  {
                    "slug": "beta-op",
                    "name": "Beta",
                    "summary": "A shared endpoint.",
                    "binding": { "type": "http", "operation": "GET /beta" }
                  },
                  { "slug": "gamma-op", "name": "Gamma", "binding": { "type": "http", "operation": "GET /gamma" } },
                  { "slug": "secret-op", "name": "Secret", "binding": { "type": "http", "operation": "GET /secret" } }
                ]
              }
            }
          }
        }
        """;
}
