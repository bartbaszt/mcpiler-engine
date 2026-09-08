using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Derivation;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Search;
using MCPiler.Engine.Manifest.Validation;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Derivation;

/// <summary>
/// Lexical index derivation: the field vocabulary, the tokenizer, what a derived index
/// contains, and the reconciliation between a pinned index and the derivation.
/// </summary>
public sealed class LexicalIndexDeriverTests
{
    // ---- field vocabulary --------------------------------------------------------------

    [Fact]
    public void EveryIndexedFieldCarriesAWeight()
    {
        Assert.Equal(15, SearchFieldCatalogue.IndexedFields.Count);

        var missing = SearchFieldCatalogue.IndexedFields
            .Where(field => !SearchFieldCatalogue.DefaultWeights.ContainsKey(field))
            .ToList();

        Assert.Empty(missing);
        Assert.Equal(SearchFieldCatalogue.IndexedFields.Count, SearchFieldCatalogue.DefaultWeights.Count);
    }

    [Fact]
    public void TheMetadataSubsetIsExactlyTheCuratedFields()
    {
        Assert.Equal(
            new[] { SearchFieldCatalogue.Alias, SearchFieldCatalogue.ExampleIntent, SearchFieldCatalogue.Keyword },
            SearchFieldCatalogue.MetadataFields.OrderBy(field => field, StringComparer.Ordinal));
    }

    [Fact]
    public void CuratedMetadataOutweighsIncidentalProse()
    {
        // Aliases and keywords exist because a caller's words rarely match a vendor's prose.
        // If a long description could outrank them the curation would be pointless.
        Assert.True(SearchFieldCatalogue.DefaultWeight(SearchFieldCatalogue.Alias)
            > SearchFieldCatalogue.DefaultWeight(SearchFieldCatalogue.Description));
        Assert.True(SearchFieldCatalogue.DefaultWeight(SearchFieldCatalogue.Keyword)
            > SearchFieldCatalogue.DefaultWeight(SearchFieldCatalogue.Summary));
        Assert.True(SearchFieldCatalogue.DefaultWeight(SearchFieldCatalogue.Name)
            > SearchFieldCatalogue.DefaultWeight(SearchFieldCatalogue.Alias));
    }

    [Fact]
    public void AnUnknownFieldScoresNothingRatherThanBeingRejected()
    {
        // A later builder may record a field this Engine does not model. Ignoring its
        // contribution keeps the index usable; refusing it would make a newer export
        // unreadable for no safety gain.
        Assert.False(SearchFieldCatalogue.IsKnown("inventedField"));
        Assert.False(SearchFieldCatalogue.IsMetadata("inventedField"));
        Assert.Equal(0, SearchFieldCatalogue.DefaultWeight("inventedField"));
    }

    // ---- tokenizer ---------------------------------------------------------------------

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("Ping", "ping")]
    [InlineData("List Pets", "list|pets")]
    [InlineData("GET /pets/{petId}", "get|pets|petid")]
    [InlineData("snake_case-and.dots", "snake|case|and|dots")]
    [InlineData("v2 API", "v2|api")]
    public void TokenizationIsLowerCasedRunsOfAsciiAlphanumerics(string? text, string expected)
        => Assert.Equal(
            expected.Length == 0 ? [] : expected.Split('|'),
            SearchTokenizer.Tokenize(text));

    [Fact]
    public void TokensAreDeduplicatedInFirstSeenOrder()
        => Assert.Equal(["pet", "list", "all"], SearchTokenizer.Tokenize("Pet list PET all pet"));

    [Fact]
    public void AnOverLongRunIsDroppedRatherThanTruncated()
    {
        // A truncated token is a term nobody wrote; it would match a prefix query that has
        // no counterpart in the source text.
        var tokens = SearchTokenizer.Tokenize(new string('a', SearchTokenizer.MaxTokenLength + 1) + " short");

        Assert.Equal(["short"], tokens);
    }

    [Fact]
    public void ARunExactlyAtTheLimitIsKept()
    {
        var token = new string('a', SearchTokenizer.MaxTokenLength);

        Assert.Equal([token], SearchTokenizer.Tokenize(token));
    }

    [Fact]
    public void OnlyTheBoundedPrefixOfTheInputIsExamined()
    {
        var text = new string('a', SearchTokenizer.MaxInputLength) + " tail";

        Assert.DoesNotContain("tail", SearchTokenizer.Tokenize(text), StringComparer.Ordinal);
    }

    [Fact]
    public void NonAsciiLettersSeparateTokensRatherThanBeingCaseFolded()
    {
        // Case folding outside ASCII is culture-sensitive, and a manifest that indexes
        // differently depending on the host locale is not portable.
        Assert.Equal(["i", "x"], SearchTokenizer.Tokenize("I\u0130x"));
        Assert.Equal(["caf", "s"], SearchTokenizer.Tokenize("caf\u00e9s"));
    }

    // ---- derivation content ------------------------------------------------------------

    [Fact]
    public void DerivedEntriesAreOrderedBySlugNotByAuthoredOrder()
    {
        var index = LexicalIndexDeriver.Derive(Load(SearchFixture));

        // The fixture declares ping before alpha on purpose.
        Assert.Equal(["alpha", "ping"], index.Operations.Select(entry => entry.Operation));
    }

    [Fact]
    public void DerivationIsIndependentOfTheAuthoredOperationOrder()
    {
        var manifest = Load(SearchFixture);
        var reversed = manifest with
        {
            AgentSurface = manifest.AgentSurface with
            {
                Operations = [.. manifest.AgentSurface.Operations.Reverse()],
            },
        };

        Assert.Equal(
            LexicalIndexDeriver.Fingerprint(LexicalIndexDeriver.Derive(manifest)),
            LexicalIndexDeriver.Fingerprint(LexicalIndexDeriver.Derive(reversed)));
    }

    [Fact]
    public void TermsCarryTheFieldsTheyOccurredInOrderedByWeight()
    {
        var index = LexicalIndexDeriver.Derive(Load(SearchFixture));
        var alpha = index.Operations.Single(entry => entry.Operation == "alpha");

        Assert.Equal(
            [SearchFieldCatalogue.Name, SearchFieldCatalogue.Summary, SearchFieldCatalogue.HttpPath],
            alpha.Terms["alpha"]);
        Assert.Equal([SearchFieldCatalogue.Alias], alpha.Terms["health"]);
        Assert.Equal([SearchFieldCatalogue.HttpPath], alpha.Terms["post"]);
    }

    [Fact]
    public void TheHttpMethodAndPathOfTheBoundOperationAreIndexed()
    {
        var index = LexicalIndexDeriver.Derive(Load(SearchFixture));
        var ping = index.Operations.Single(entry => entry.Operation == "ping");

        Assert.Contains(SearchFieldCatalogue.HttpPath, ping.Terms["get"]);
        Assert.Contains(SearchFieldCatalogue.HttpPath, ping.Terms["ping"]);
    }

    [Fact]
    public void ADeclaredRiskWinsOverTheMethodFallback()
    {
        var index = LexicalIndexDeriver.Derive(Load(MultiSurface));

        Assert.Equal("readOnly", index.Operations.Single(e => e.Operation == "list-pets").Risk);
        Assert.Equal("destructive,mutating", index.Operations.Single(e => e.Operation == "delete-pet").Risk);
    }

    [Fact]
    public void AnUndeclaredRiskIsDerivedFromTheHttpMethod()
    {
        // A hand-authored manifest that declares no risk must not read as "nothing is
        // risky"; the method is the one signal Engine legitimately has.
        var index = LexicalIndexDeriver.Derive(Load(MultiSurface));

        Assert.Equal("openWorld,readOnly", index.Operations.Single(e => e.Operation == "get-pet").Risk);
    }

    [Theory]
    [InlineData("GET", "openWorld,readOnly")]
    [InlineData("head", "openWorld,readOnly")]
    [InlineData("OPTIONS", "openWorld,readOnly")]
    [InlineData("POST", "mutating,openWorld,requiresConfirmation")]
    [InlineData("PUT", "idempotent,mutating,openWorld,requiresConfirmation")]
    [InlineData("PATCH", "destructive,mutating,openWorld,requiresConfirmation")]
    [InlineData("DELETE", "destructive,idempotent,mutating,openWorld,requiresConfirmation")]
    [InlineData("TRACE", "openWorld")]
    [InlineData(null, "openWorld")]
    public void MethodDerivedRiskIsDeterministicAndOrdinallyOrdered(string? method, string expected)
        => Assert.Equal(expected, RiskWire.FromMethod(method));

    [Fact]
    public void SummariesAreBoundedForResultItems()
    {
        var manifest = Load(WithSummary(new string('x', SearchScoring.MaxSummaryCharacters + 50)));
        var entry = LexicalIndexDeriver.Derive(manifest).Operations.Single();

        Assert.Equal(SearchScoring.MaxSummaryCharacters, entry.Summary.Length);
    }

    [Fact]
    public void InputSchemaPropertyNamesAndDescriptionsAreIndexedSeparately()
    {
        var index = LexicalIndexDeriver.Derive(Load(SchemaFixture));
        var entry = index.Operations.Single();

        Assert.Equal([SearchFieldCatalogue.ParameterName], entry.Terms["cursor"]);
        Assert.Equal([SearchFieldCatalogue.RequestSchema], entry.Terms["nested"]);

        // A top-level property description is both the parameter's description and part of
        // the request schema's prose, so it carries both provenances, weightiest first.
        Assert.Equal(
            [SearchFieldCatalogue.ParameterDescription, SearchFieldCatalogue.RequestSchema],
            entry.Terms["pagination"]);
    }

    [Fact]
    public void AnOutputSchemaIsIndexedOnlyWhenItIsUsedInternally()
    {
        // Advertising a schema is a client-facing decision; feeding it to the index is a
        // relevance decision. Conflating them lets a cosmetic change move rankings.
        var advertised = LexicalIndexDeriver.Derive(Load(OutputSchema(useInternally: false))).Operations.Single();
        var internalUse = LexicalIndexDeriver.Derive(Load(OutputSchema(useInternally: true))).Operations.Single();

        Assert.DoesNotContain("envelope", advertised.Terms.Keys, StringComparer.Ordinal);
        Assert.Equal([SearchFieldCatalogue.ResponseSchema], internalUse.Terms["envelope"]);
    }

    [Fact]
    public void CompoundStepNamesAndSummariesAreIndexed()
    {
        var index = LexicalIndexDeriver.Derive(Load(CompoundFixture));
        var order = index.Operations.Single(entry => entry.Operation == "place-order");

        // A caller searching for a step's wording finds the workflow that performs it, even
        // though the step itself is not separately invocable.
        Assert.Equal([SearchFieldCatalogue.StepName], order.Terms["requested"]);
        Assert.Equal([SearchFieldCatalogue.StepSummary], order.Terms["finalises"]);
        Assert.Contains(SearchFieldCatalogue.StepName, order.Terms["cart"]);
    }

    [Fact]
    public void TheIndexCoversOperationsNoSurfaceExposes()
    {
        // The index is a term store, not a permission list. Excluding hidden operations here
        // would make the index depend on which surface you asked about.
        var manifest = Load(SearchFixture);
        var index = LexicalIndexDeriver.Derive(manifest);
        var restricted = manifest.Server.Surface("restricted")!;

        Assert.Contains(index.Operations, entry => entry.Operation == "ping");
        Assert.False(restricted.InvocationAllowed("ping"));
    }

    // ---- references --------------------------------------------------------------------

    [Fact]
    public void FactoringASchemaIntoAComponentDoesNotChangeTheIndex()
    {
        // Extracting a shared component is a representational choice. If it changed the term
        // set, the choice would silently change which queries can find the operation.
        var inlined = LexicalIndexDeriver.Derive(Load(SchemaFixture));
        var factored = LexicalIndexDeriver.Derive(Load(SchemaFixtureWithComponent));

        Assert.Equal(
            LexicalIndexDeriver.Fingerprint(inlined),
            LexicalIndexDeriver.Fingerprint(factored));
    }

    [Fact]
    public void ARecursiveSchemaTerminatesInsteadOfRecursing()
    {
        var index = LexicalIndexDeriver.Derive(Load(RefsFixture));

        Assert.NotEmpty(index.Operations);
        Assert.All(index.Operations, entry =>
            Assert.True(entry.Terms.Count <= SearchScoring.MaxTermsPerOperation));
    }

    // ---- bounds ------------------------------------------------------------------------

    [Fact]
    public void ThePerOperationTermCapBinds()
    {
        // Tags are tokenized one value at a time, so this is the honest way to exceed the
        // cap: a single text field cannot, because the tokenizer bounds its input first.
        var tags = new JsonArray();
        for (var index = 0; index < SearchScoring.MaxTermsPerOperation + 200; index++)
        {
            tags.Add("t" + index.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        var entry = LexicalIndexDeriver.Derive(Load(WithTags(tags))).Operations.Single();

        Assert.Equal(SearchScoring.MaxTermsPerOperation, entry.Terms.Count);
    }

    [Fact]
    public void TheSchemaWalkIsNodeBounded()
    {
        // Stays inside the per-level property limit so this exercises the walk budget and
        // not the validator's breadth bound. Names are zero padded so ordinal order is
        // numeric order and "the last one" is unambiguous.
        var properties = new JsonObject();
        for (var index = 0; index < 250; index++)
        {
            var name = "p" + index.ToString("D3", System.Globalization.CultureInfo.InvariantCulture);
            properties[name] = new JsonObject
            {
                ["title"] = "title" + name,
                ["properties"] = new JsonObject { ["inner"] = new JsonObject { ["title"] = "inner" + name } },
            };
        }

        var schema = new JsonObject { ["type"] = "object", ["properties"] = properties };
        var entry = LexicalIndexDeriver.Derive(Load(WithInputSchema(schema))).Operations.Single();

        // Property names are collected outside the node budget; the titles beneath them are
        // not, so the walk stops well before the last one.
        Assert.Contains("titlep000", entry.Terms.Keys, StringComparer.Ordinal);
        Assert.DoesNotContain("titlep249", entry.Terms.Keys, StringComparer.Ordinal);
    }

    [Fact]
    public void TheSchemaWalkIsDepthBounded()
    {
        JsonObject leaf = new() { ["title"] = "deepest" };
        var node = leaf;
        for (var depth = 0; depth < SearchScoring.MaxSchemaDepth + 3; depth++)
        {
            node = new JsonObject { ["properties"] = new JsonObject { ["child"] = node } };
        }

        var entry = LexicalIndexDeriver.Derive(Load(WithInputSchema(node))).Operations.Single();

        Assert.DoesNotContain("deepest", entry.Terms.Keys, StringComparer.Ordinal);
    }

    // ---- reconciliation ----------------------------------------------------------------

    [Fact]
    public void AHandWrittenIndexMatchesWhatDerivationProduces()
    {
        // The pinned section in the fixture was written by hand from the documented rules.
        // If either side drifts, this fails — which is the whole point of pinning it.
        var manifest = Load(SearchFixture);

        Assert.NotNull(manifest.Search);
        Assert.Equal(
            LexicalIndexDeriver.Fingerprint(LexicalIndexDeriver.Derive(manifest)),
            LexicalIndexDeriver.Fingerprint(manifest.Search!));
    }

    [Fact]
    public void ResolveReportsNothingWhenAPinnedIndexAgrees()
    {
        var diagnostics = new List<ManifestDiagnostic>();

        LexicalIndexDeriver.Resolve(Load(SearchFixture), diagnostics);

        Assert.Empty(diagnostics);
    }

    [Fact]
    public void ResolveFallsBackToDerivationWhenNoIndexIsPinned()
    {
        var manifest = Load(MultiSurface);
        var diagnostics = new List<ManifestDiagnostic>();

        var resolved = LexicalIndexDeriver.Resolve(manifest, diagnostics);

        Assert.Null(manifest.Search);
        Assert.Empty(diagnostics);
        Assert.Equal(3, resolved.Operations.Count);
    }

    [Fact]
    public void ResolveKeepsAPinnedIndexButReportsTheDisagreement()
    {
        var manifest = Load(SearchFixture);
        var tampered = manifest with
        {
            Search = manifest.Search! with
            {
                Operations =
                [
                    .. manifest.Search!.Operations.Where(entry => entry.Operation != "ping"),
                ],
            },
        };

        var diagnostics = new List<ManifestDiagnostic>();
        var resolved = LexicalIndexDeriver.Resolve(tampered, diagnostics);

        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal(ManifestDiagnosticCodes.SearchDerivationMismatch, diagnostic.Code);
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Single(resolved.Operations);
    }

    [Fact]
    public void DifferentWeightsCountAsADisagreement()
    {
        // Identical terms under different weights rank differently. Treating weights as
        // incidental would let a real relevance change pass as equal.
        var manifest = Load(SearchFixture);
        var scoring = manifest.Search!.EffectiveScoring;
        var weights = scoring.FieldWeights.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        weights[SearchFieldCatalogue.Alias] = 1;

        var diagnostics = new List<ManifestDiagnostic>();
        LexicalIndexDeriver.Resolve(
            manifest with { Search = manifest.Search with { Scoring = scoring with { FieldWeights = weights } } },
            diagnostics);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Code == ManifestDiagnosticCodes.SearchDerivationMismatch);
    }

    [Fact]
    public void AnIndexFromAnUnsupportedBuilderIsRebuiltWithARecoverableWarning()
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(
            SearchFixture.Replace("\"builderVersion\": 1", "\"builderVersion\": 99", StringComparison.Ordinal)));

        Assert.True(result.Succeeded);
        Assert.Null(result.Manifest!.Search);

        var warning = Assert.Single(
            result.Warnings,
            diagnostic => diagnostic.Code == ManifestDiagnosticCodes.SearchBuilderVersionUnsupported);

        // The severity has to follow from the code alone, so the recoverable case gets its
        // own code rather than sharing the mismatch code at a different severity.
        Assert.Equal(DiagnosticSeverity.Warning, warning.Severity);
        Assert.Contains(
            ManifestDiagnosticCodes.SearchBuilderVersionUnsupported,
            ManifestDiagnosticCodes.AlwaysWarning);
        Assert.DoesNotContain(
            ManifestDiagnosticCodes.SearchDerivationMismatch,
            ManifestDiagnosticCodes.AlwaysWarning);
    }

    [Fact]
    public void TheFingerprintDetectsARealDifference()
    {
        // Without this every equality assertion above would also pass if the fingerprint
        // collapsed to a constant.
        var manifest = Load(SearchFixture);
        var derived = LexicalIndexDeriver.Derive(manifest);
        var altered = derived with
        {
            Operations = [derived.Operations[0] with { Risk = RiskWire.None }, derived.Operations[1]],
        };

        Assert.NotEqual(LexicalIndexDeriver.Fingerprint(derived), LexicalIndexDeriver.Fingerprint(altered));
    }

    // ---- ranking -----------------------------------------------------------------------

    [Fact]
    public void APinnedIndexAndADerivedIndexRankIdentically()
    {
        var manifest = Load(SearchFixture);
        var surface = manifest.Server.DefaultSurface!;
        var pinned = new LexicalRanker(manifest.Search!, surface);
        var derived = new LexicalRanker(LexicalIndexDeriver.Derive(manifest), surface);

        foreach (var query in new[] { "health", "ping", "alpha thing", "get", "nothing matches", "", null })
        {
            Assert.Equal(Describe(pinned.Rank(query)), Describe(derived.Rank(query)));
        }
    }

    [Fact]
    public void CuratedAliasesOutrankAProseMatchOnTheSameWord()
    {
        var manifest = Load(SearchFixture);
        var ranker = new LexicalRanker(manifest.Search!, manifest.Server.DefaultSurface!);

        var results = ranker.Rank("health").Results;

        Assert.Equal(["alpha", "ping"], results.Select(result => result.Operation));
        Assert.True(results[0].Score > results[1].Score);
        Assert.Equal([SearchFieldCatalogue.Alias], results[0].MatchedBy);
    }

    [Fact]
    public void AnOperationTheSurfaceHidesIsNotDiscoverableEvenWhenTheIndexCarriesIt()
    {
        // The surface list is the only authority. A stale, hand-edited, or hostile index
        // must not be able to reintroduce an operation the surface withheld.
        var manifest = Load(SearchFixture);
        var restricted = manifest.Server.Surface("restricted")!;

        var outcome = new LexicalRanker(manifest.Search!, restricted).Rank("health");

        Assert.DoesNotContain(outcome.Results, result => result.Operation == "ping");
        Assert.Equal(1, outcome.FilteredCount);
    }

    [Fact]
    public void AnEmptyQueryListsEveryDiscoverableOperation()
    {
        var manifest = Load(SearchFixture);
        var ranker = new LexicalRanker(manifest.Search!, manifest.Server.DefaultSurface!);

        var results = ranker.Rank(null).Results;

        Assert.Equal(["alpha", "ping"], results.Select(result => result.Operation));
        Assert.All(results, result => Assert.Equal(0, result.Score));
    }

    [Fact]
    public void AQueryThatMatchesNothingProducesNoResults()
    {
        var manifest = Load(SearchFixture);
        var ranker = new LexicalRanker(manifest.Search!, manifest.Server.DefaultSurface!);

        Assert.Empty(ranker.Rank("zzzz").Results);
    }

    [Fact]
    public void ExplainabilityIsBoundedAndNamesFieldClassesOnly()
    {
        var manifest = Load(MultiSurface);
        var index = LexicalIndexDeriver.Derive(manifest);
        var ranker = new LexicalRanker(index, manifest.Server.DefaultSurface!);

        var results = ranker.Rank("pets inventory list").Results;

        Assert.NotEmpty(results);
        Assert.All(results, result =>
        {
            Assert.True(result.MatchedBy.Count <= LexicalRanker.MaxMatchedBy);
            Assert.All(result.MatchedBy, field => Assert.True(SearchFieldCatalogue.IsKnown(field)));
        });
    }

    [Fact]
    public void TiesAreBrokenOnTheSlugRatherThanIndexOrder()
    {
        var manifest = Load(SearchFixture);
        var index = LexicalIndexDeriver.Derive(manifest);
        var surface = manifest.Server.DefaultSurface!;

        var forward = new LexicalRanker(index, surface).Rank(null).Results;
        var reversed = new LexicalRanker(
            index with { Operations = [.. index.Operations.Reverse()] },
            surface).Rank(null).Results;

        Assert.Equal(forward.Select(result => result.Operation), reversed.Select(result => result.Operation));
    }

    // ---- helpers -----------------------------------------------------------------------

    private static IReadOnlyList<string> Describe(LexicalRankOutcome outcome)
        => outcome.Results
            .Select(result => string.Join(
                '|',
                result.Operation,
                result.Score.ToString(System.Globalization.CultureInfo.InvariantCulture),
                string.Join(',', result.MatchedBy),
                result.Risk))
            .ToList();

    private static ManifestDocument Load(string manifestText)
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(manifestText));
        Assert.True(result.Succeeded, string.Join("; ", result.Diagnostics.Select(diagnostic => diagnostic.ToString())));
        return result.Manifest!;
    }

    private static string SearchFixture { get; } =
        File.ReadAllText(TestRepository.Fixture("manifests", "search", "manifest.json"), Encoding.UTF8);

    private static string MultiSurface { get; } =
        File.ReadAllText(TestRepository.Fixture("manifests", "multi-surface", "manifest.json"), Encoding.UTF8);

    private static string CompoundFixture { get; } =
        File.ReadAllText(TestRepository.Fixture("manifests", "compound", "manifest.json"), Encoding.UTF8);

    private static string RefsFixture { get; } =
        File.ReadAllText(TestRepository.Fixture("manifests", "refs", "manifest.json"), Encoding.UTF8);

    private static string Single(string operationBody) => $$"""
    {
      "manifestFormatVersion": "0.1",
      "sections": {
        "server": { "inline": { "name": "Single" } },
        "policy": { "inline": { "baseUrl": "https://api.example.com" } },
        "operations": { "inline": { "operations": [ { "key": "GET /thing", "method": "GET", "path": "/thing" } ] } },
        "agentSurface": { "inline": { "operations": [ {{operationBody}} ] } }
      }
    }
    """;

    private static string WithSummary(string summary)
        => Single(new JsonObject
        {
            ["slug"] = "thing",
            ["name"] = "Thing",
            ["summary"] = summary,
            ["binding"] = new JsonObject { ["type"] = "http", ["operation"] = "GET /thing" },
        }.ToJsonString());

    private static string WithTags(JsonArray tags)
        => Single(new JsonObject
        {
            ["slug"] = "thing",
            ["name"] = "Thing",
            ["tags"] = tags,
            ["binding"] = new JsonObject { ["type"] = "http", ["operation"] = "GET /thing" },
        }.ToJsonString());

    private static string WithInputSchema(JsonNode schema)
        => Single(new JsonObject
        {
            ["slug"] = "thing",
            ["name"] = "Thing",
            ["inputSchema"] = schema,
            ["binding"] = new JsonObject { ["type"] = "http", ["operation"] = "GET /thing" },
        }.ToJsonString());

    private static string OutputSchema(bool useInternally)
        => Single(new JsonObject
        {
            ["slug"] = "thing",
            ["name"] = "Thing",
            ["outputSchema"] = new JsonObject { ["title"] = "envelope" },
            ["outputSchemaPolicy"] = new JsonObject
            {
                ["generate"] = true,
                ["advertise"] = "yes",
                ["useInternally"] = useInternally,
            },
            ["binding"] = new JsonObject { ["type"] = "http", ["operation"] = "GET /thing" },
        }.ToJsonString());

    private static readonly JsonObject NestedSchema = new()
    {
        ["type"] = "object",
        ["properties"] = new JsonObject
        {
            ["cursor"] = new JsonObject
            {
                ["type"] = "object",
                ["description"] = "Pagination",
                ["properties"] = new JsonObject
                {
                    ["inner"] = new JsonObject { ["title"] = "nested" },
                },
            },
        },
    };

    private static string SchemaFixture { get; } = WithInputSchema(NestedSchema.DeepClone());

    private static string SchemaFixtureWithComponent { get; } = $$"""
    {
      "manifestFormatVersion": "0.1",
      "sections": {
        "server": { "inline": { "name": "Single" } },
        "policy": { "inline": { "baseUrl": "https://api.example.com" } },
        "operations": { "inline": { "operations": [ { "key": "GET /thing", "method": "GET", "path": "/thing" } ] } },
        "agentSurface": {
          "inline": {
            "components": { "schemas": { "Cursor": {{NestedSchema["properties"]!["cursor"]!.ToJsonString()}} } },
            "operations": [
              {
                "slug": "thing",
                "name": "Thing",
                "inputSchema": {
                  "type": "object",
                  "properties": { "cursor": { "$ref": "#/components/schemas/Cursor" } }
                },
                "binding": { "type": "http", "operation": "GET /thing" }
              }
            ]
          }
        }
      }
    }
    """;
}
