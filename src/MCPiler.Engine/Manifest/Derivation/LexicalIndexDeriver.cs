using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Derivation;

/// <summary>
/// Derives the lexical search index from <c>agentSurface</c> and <c>operations</c>.
/// </summary>
/// <remarks>
/// <para>
/// The index is a term store, not a permission list. It covers every declared agent
/// operation regardless of how any surface exposes it, and discoverability is decided
/// separately by the surface's own operation list. Keeping those two apart is what makes a
/// stale or hand-edited index harmless: it can contain an entry, but it cannot grant one.
/// </para>
/// <para>
/// Derivation is a pure function of the manifest. No clock, no randomness, no hash-order
/// iteration, no network call, and no embedding endpoint: the same manifest always produces
/// the same index, which is the only reason a pinned index and a derived index can be
/// compared at all.
/// </para>
/// </remarks>
public static class LexicalIndexDeriver
{
    /// <summary>
    /// Derives the index over every declared agent operation.
    /// </summary>
    /// <param name="manifest">The loaded manifest.</param>
    public static SearchSection Derive(ManifestDocument manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        var resolver = SchemaResolverFor(manifest);
        var documents = new List<SearchDocumentEntry>(manifest.AgentSurface.Operations.Count);

        foreach (var entry in manifest.AgentSurface.Operations)
        {
            documents.Add(BuildDocument(manifest, entry, resolver));
        }

        // Entry order is the slug ordinal, never the authored order: a reordered
        // agentSurface section must not change the index bytes.
        documents.Sort(static (left, right) => string.CompareOrdinal(left.Operation, right.Operation));

        return new SearchSection(
            documents,
            SearchFieldCatalogue.IndexedFields,
            new SearchScoring(
                SearchScoring.Default.QuantizationStep,
                SearchScoring.Default.MetaMultiplier,
                SearchScoring.Default.VectorScale,
                SearchFieldCatalogue.DefaultWeights),
            SearchScoring.BuilderVersion);
    }

    /// <summary>
    /// Returns the index actually used, reconciling an explicit section with the derivation.
    /// </summary>
    /// <remarks>
    /// The explicit section wins, for the same reason it wins for tools: a producer that
    /// pinned an index meant it. A disagreement is still an error, because an index that no
    /// longer describes the operations it indexes silently degrades discovery — the caller
    /// sees fewer or worse results and has no way to tell that anything is wrong.
    /// </remarks>
    /// <param name="manifest">The loaded manifest.</param>
    /// <param name="diagnostics">Receives any disagreement.</param>
    public static SearchSection Resolve(ManifestDocument manifest, ICollection<ManifestDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(diagnostics);

        var derived = Derive(manifest);

        if (manifest.Search is not { } declared)
        {
            return derived;
        }

        if (!string.Equals(Fingerprint(declared), Fingerprint(derived), StringComparison.Ordinal))
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SearchDerivationMismatch,
                "The declared search index does not match the index derived from the agentSurface and "
                + "operations sections. The declared index is used; re-export the manifest or remove the "
                + "search section so the two cannot diverge.",
                ManifestSectionName.Search));
        }

        return declared;
    }

    /// <summary>
    /// Produces a canonical fingerprint of everything that can change a ranking.
    /// </summary>
    /// <remarks>
    /// Scoring is part of the fingerprint, not just the terms: two indexes with identical
    /// terms and different weights rank differently, so treating weights as incidental would
    /// let a real relevance change pass as equal.
    /// </remarks>
    /// <param name="index">The index to fingerprint.</param>
    public static string Fingerprint(SearchSection index)
    {
        ArgumentNullException.ThrowIfNull(index);

        var scoring = index.EffectiveScoring;
        var weights = new JsonObject();
        foreach (var field in scoring.FieldWeights.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            weights[field.Key] = field.Value;
        }

        var operations = new JsonArray();
        foreach (var document in index.Operations.OrderBy(static entry => entry.Operation, StringComparer.Ordinal))
        {
            var terms = new JsonObject();
            foreach (var (term, provenance) in document.Terms.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
            {
                var fields = new JsonArray();
                foreach (var field in provenance)
                {
                    fields.Add(field);
                }

                terms[term] = fields;
            }

            operations.Add(new JsonObject
            {
                ["operation"] = document.Operation,
                ["summary"] = document.Summary,
                ["risk"] = document.Risk,
                ["terms"] = terms,
            });
        }

        return CanonicalJson.Hash(new JsonObject
        {
            ["builderVersion"] = index.BuilderVersion,
            ["scoring"] = new JsonObject
            {
                ["quantizationStep"] = scoring.QuantizationStep,
                ["metaMultiplier"] = scoring.MetaMultiplier,
                ["vectorScale"] = scoring.VectorScale,
                ["fieldWeights"] = weights,
            },
            ["operations"] = operations,
        });
    }

    private static SearchDocumentEntry BuildDocument(
        ManifestDocument manifest,
        AgentOperationEntry entry,
        SchemaReferenceResolver? resolver)
    {
        var operationKey = ManifestBindingDispatcher.TryResolveOperationKey(entry.Binding);
        var bound = operationKey is not null ? manifest.Operations.Operation(operationKey) : null;
        var method = bound?.Method ?? RiskWire.MethodOfKey(operationKey);

        var terms = new TermAccumulator();

        // Accumulation order decides which terms survive the per-operation cap, so it is
        // fixed here rather than left to whatever order a collection enumerates in.
        terms.Add(SearchFieldCatalogue.Name, entry.Name);
        terms.Add(SearchFieldCatalogue.Summary, entry.Summary);
        terms.Add(SearchFieldCatalogue.Description, entry.Description);
        terms.AddAll(SearchFieldCatalogue.Tags, entry.Tags);
        terms.AddAll(SearchFieldCatalogue.Groups, entry.Groups);

        // The bound operation's own path is preferred; the key's path segment is the
        // fallback for an authored binding with no counterpart in the operations section.
        terms.Add(SearchFieldCatalogue.HttpPath, bound?.Path ?? PathOfKey(operationKey));
        terms.Add(SearchFieldCatalogue.HttpPath, method);

        CollectSchemaTerms(entry.InputSchema, SearchFieldCatalogue.RequestSchema, terms, resolver);

        // An output schema contributes terms only when the manifest says the schema is used
        // internally. Advertising a schema is a client-facing decision; feeding it to the
        // index is a relevance decision, and conflating them would let a purely cosmetic
        // advertisement change rankings.
        if (entry.EffectiveOutputSchemaPolicy.UseInternally)
        {
            CollectSchemaTerms(entry.OutputSchema, SearchFieldCatalogue.ResponseSchema, terms, resolver);
        }

        var search = entry.EffectiveSearch;
        terms.AddAll(SearchFieldCatalogue.Alias, search.Aliases);
        terms.AddAll(SearchFieldCatalogue.Keyword, search.Keywords);
        terms.AddAll(SearchFieldCatalogue.ExampleIntent, search.ExampleIntents);

        if (ManifestBindingDispatcher.TryResolveCompoundSteps(entry.Binding) is { } steps)
        {
            foreach (var step in steps)
            {
                terms.Add(SearchFieldCatalogue.StepName, step.Name);
                terms.Add(SearchFieldCatalogue.StepSummary, step.Summary);
            }
        }

        return new SearchDocumentEntry(
            entry.Slug,
            Truncate(entry.Summary ?? string.Empty, SearchScoring.MaxSummaryCharacters),
            RiskWire.Resolve(entry.Risk, method),
            terms.Build());
    }

    /// <summary>
    /// Walks a schema for indexable text under a shared node budget.
    /// </summary>
    /// <remarks>
    /// References are followed rather than skipped, so a schema factored into shared
    /// components indexes the same terms as the equivalent inlined schema. Without that, the
    /// purely representational choice of extracting a component would silently change which
    /// operations a query can find. The node budget and the depth limit both bound the walk,
    /// so a cyclic reference terminates on the budget instead of recursing.
    /// </remarks>
    private static void CollectSchemaTerms(
        ManifestSchema? schema,
        string field,
        TermAccumulator terms,
        SchemaReferenceResolver? resolver)
    {
        if (Dereference(schema, resolver)?.Object is not { } root)
        {
            return;
        }

        var budget = new WalkBudget();

        // The root's own title, description, and enumerated values are indexed too: a
        // distinctive envelope title stays findable even when it has no properties.
        CollectNodeText(root, field, terms, budget);

        if (root["properties"] is not JsonObject properties)
        {
            return;
        }

        var nameField = field == SearchFieldCatalogue.RequestSchema
            ? SearchFieldCatalogue.ParameterName
            : field;
        var descriptionField = field == SearchFieldCatalogue.RequestSchema
            ? SearchFieldCatalogue.ParameterDescription
            : field;

        foreach (var (name, value) in properties.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            terms.Add(nameField, name);

            if (Dereference(ManifestSchema.FromOrNull(value), resolver)?.Object is not { } property)
            {
                continue;
            }

            terms.Add(descriptionField, Text(property, "description"));
            WalkNested(property, field, terms, depth: 1, budget, resolver);

            if (budget.Exhausted)
            {
                return;
            }
        }
    }

    private static void WalkNested(
        JsonObject node,
        string field,
        TermAccumulator terms,
        int depth,
        WalkBudget budget,
        SchemaReferenceResolver? resolver)
    {
        if (depth > SearchScoring.MaxSchemaDepth || budget.Exhausted)
        {
            return;
        }

        CollectNodeText(node, field, terms, budget);

        if (node["properties"] is not JsonObject properties)
        {
            return;
        }

        foreach (var (_, value) in properties.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            if (Dereference(ManifestSchema.FromOrNull(value), resolver)?.Object is { } child)
            {
                WalkNested(child, field, terms, depth + 1, budget, resolver);
            }

            if (budget.Exhausted)
            {
                return;
            }
        }
    }

    private static void CollectNodeText(JsonObject node, string field, TermAccumulator terms, WalkBudget budget)
    {
        if (!budget.Consume())
        {
            return;
        }

        var title = Text(node, "title");
        var description = Text(node, "description");

        terms.Add(field, title);

        // A description that merely repeats the title contributes nothing and would double
        // its apparent weight in the accumulation order.
        if (!string.Equals(description, title, StringComparison.Ordinal))
        {
            terms.Add(field, description);
        }

        if (node["enum"] is not JsonArray values)
        {
            return;
        }

        foreach (var value in values)
        {
            if (value is JsonValue scalar && scalar.TryGetValue<string>(out var text))
            {
                terms.Add(field, text);
            }
        }
    }

    private static ManifestSchema? Dereference(ManifestSchema? schema, SchemaReferenceResolver? resolver)
    {
        if (schema is null)
        {
            return null;
        }

        return schema.IsReference && resolver is not null && resolver.TryResolve(schema, out var target, out _)
            ? target
            : schema;
    }

    private static string? Text(JsonObject node, string member)
        => node[member] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static string? PathOfKey(string? operationKey)
    {
        if (string.IsNullOrEmpty(operationKey))
        {
            return null;
        }

        var space = operationKey.IndexOf(' ', StringComparison.Ordinal);
        return space >= 0 && space + 1 < operationKey.Length ? operationKey[(space + 1)..] : operationKey;
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];

    private static SchemaReferenceResolver? SchemaResolverFor(ManifestDocument manifest)
        => manifest.AgentSurfaceDocument is { } document
            ? new SchemaReferenceResolver(document, manifest.Policy.EffectiveSchemaBounds)
            : null;

    private sealed class WalkBudget
    {
        private int _remaining = SearchScoring.MaxSchemaNodes;

        public bool Exhausted => _remaining <= 0;

        public bool Consume()
        {
            if (_remaining <= 0)
            {
                return false;
            }

            _remaining--;
            return true;
        }
    }

    /// <summary>
    /// Collects terms with their field provenance under the per-operation term cap.
    /// </summary>
    /// <remarks>
    /// Provenance is a set of fields per term, ordered by weight then name so the ranker and
    /// the explainability list never depend on hash iteration order. The cap admits terms in
    /// accumulation order: once it is reached a genuinely new term is refused, while a term
    /// already present still records the additional field it occurred in.
    /// </remarks>
    private sealed class TermAccumulator
    {
        private readonly Dictionary<string, HashSet<string>> _terms = new(StringComparer.Ordinal);

        public void Add(string field, string? text)
        {
            foreach (var token in SearchTokenizer.Tokenize(text))
            {
                Record(token, field);
            }
        }

        public void AddAll(string field, IEnumerable<string?>? values)
        {
            if (values is null)
            {
                return;
            }

            foreach (var value in values)
            {
                Add(field, value);
            }
        }

        public IReadOnlyDictionary<string, IReadOnlyList<string>> Build()
        {
            var result = new Dictionary<string, IReadOnlyList<string>>(_terms.Count, StringComparer.Ordinal);

            foreach (var (token, fields) in _terms)
            {
                result[token] = fields
                    .OrderByDescending(SearchFieldCatalogue.DefaultWeight)
                    .ThenBy(static field => field, StringComparer.Ordinal)
                    .ToList();
            }

            return result;
        }

        private void Record(string token, string field)
        {
            if (!_terms.TryGetValue(token, out var fields))
            {
                if (_terms.Count >= SearchScoring.MaxTermsPerOperation)
                {
                    return;
                }

                fields = new HashSet<string>(StringComparer.Ordinal);
                _terms[token] = fields;
            }

            fields.Add(field);
        }
    }
}
