using System.Text.Json.Nodes;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// Guards the Engine-local copy of the shared response-projection corpus.
/// </summary>
/// <remarks>
/// <para>
/// The corpus is authored in the Platform repository and copied here byte-for-byte. This suite
/// pins the exact case set and the declared directive/semantics vocabulary so a case cannot
/// leave the corpus unnoticed, and it reads only the Engine-local copy: Engine must stay
/// buildable and testable from a standalone checkout and must never reach outside this
/// repository for a fixture.
/// </para>
/// <para>
/// Behaviour replay is intentionally absent here. It belongs to the runtime suites and is added
/// together with the projection/pagination implementation, against these same authored
/// expectations.
/// </para>
/// </remarks>
public sealed class ResponseProjectionCorpusTests
{
    /// <summary>The committed cases, by id, in corpus order.</summary>
    private static readonly string[] ExpectedCases =
    [
        "legacy.no-projection-plain-body",
        "metadata.selected-multivalue-unselected-sensitive-status",
        "metadata.missing-selected-header",
        "metadata.header-value-at-16k",
        "metadata.header-value-over-16k",
        "metadata.header-values-at-32",
        "metadata.header-values-over-32",
        "metadata.raw-header-aggregate-over-32k",
        "metadata.serialized-aggregate-over-64k",
        "metadata.sensitive-header-load-refusal",
        "pagination.self-direct-next-arguments",
        "pagination.self-final-page",
        "pagination.body-json-pointer-survives-output-transform",
        "pagination.cross-operation-direct-relative-after-redirect",
        "pagination.cross-operation-navigator-payload",
        "pagination.link-no-next-final-page",
        "pagination.link-malformed-unavailable",
        "pagination.link-duplicate-next-unavailable",
        "pagination.link-anchor-context-mismatch",
        "pagination.cross-origin-url-refused",
        "pagination.target-url-mismatch-refused",
        "pagination.non-success-skips-link-but-keeps-retry-after",
        "pagination.body-transform-does-not-remove-link-next",
        "pagination.body-url-at-16k",
        "pagination.body-url-over-16k",
        "pagination.link-values-at-128",
        "pagination.link-values-over-128",
        "pagination.object-over-32k",
        "pagination.direct-name-collision-continuation",
        "pagination.profile-target-removed-refusal",
    ];

    private static readonly string[] RequiredDirectives = ["$repeatUtf8", "$repeatArray", "$concatUtf8"];

    private static readonly string[] RequiredSemantics =
        ["evaluation", "responseShape", "expectedShape", "aggregateRefusal", "comparison"];

    [Fact]
    public void The_local_corpus_is_exactly_the_declared_contract()
    {
        var corpus = Corpus();

        Assert.Equal(ExpectedCases, CaseIds(corpus));
        Assert.Equal(1, corpus["corpusVersion"]!.GetValue<int>());
    }

    [Fact]
    public void The_local_corpus_declares_its_directives_and_interpretation()
    {
        var corpus = Corpus();

        foreach (var directive in RequiredDirectives)
        {
            Assert.False(
                string.IsNullOrWhiteSpace(corpus["directives"]?[directive]?["meaning"]?.GetValue<string>()),
                $"The corpus must declare the '{directive}' directive.");
        }

        foreach (var semantic in RequiredSemantics)
        {
            Assert.False(
                string.IsNullOrWhiteSpace(corpus["semantics"]?[semantic]?.GetValue<string>()),
                $"The corpus must declare the '{semantic}' semantics.");
        }
    }

    [Fact]
    public void The_corpus_lives_inside_this_repository()
    {
        var path = FixturePath();

        Assert.True(File.Exists(path), $"Missing corpus '{path}'.");
        Assert.DoesNotContain(
            Path.Combine("engine", ".."),
            Path.GetFullPath(path),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string[] CaseIds(JsonObject corpus) =>
    [
        .. corpus["cases"]!
            .AsArray()
            .Select(static node => node!["id"]!.GetValue<string>()),
    ];

    private static JsonObject Corpus() =>
        JsonNode.Parse(File.ReadAllText(FixturePath()))!.AsObject();

    private static string FixturePath() =>
        TestRepository.Fixture("response-projection", "cases.json");
}
