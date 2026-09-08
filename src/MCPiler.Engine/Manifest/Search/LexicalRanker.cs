using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Manifest.Search;

/// <summary>One ranked discovery result.</summary>
/// <param name="Operation">The manifest slug of the matched operation.</param>
/// <param name="Score">The quantized merged score in milli-score units.</param>
/// <param name="MatchedBy">
/// The field classes the query matched, highest-weighted first. Class names only: a matched
/// value is never reported, because the metadata fields hold curated text that is
/// deliberately not advertised.
/// </param>
/// <param name="Summary">The bounded summary carried for the result item.</param>
/// <param name="Risk">The resolved risk classification of the operation.</param>
public sealed record LexicalSearchResult(
    string Operation,
    int Score,
    IReadOnlyList<string> MatchedBy,
    string Summary,
    string Risk);

/// <summary>The outcome of one ranking pass.</summary>
/// <param name="Results">The ranked results.</param>
/// <param name="FilteredCount">
/// How many index entries the surface does not expose. An operator diagnostic: a non-zero
/// count on a surface that should expose everything means the index and the surface disagree.
/// </param>
public sealed record LexicalRankOutcome(IReadOnlyList<LexicalSearchResult> Results, int FilteredCount);

/// <summary>
/// Ranks a lexical index for one surface.
/// </summary>
/// <remarks>
/// <para>
/// The surface's operation list is the only authority over what is discoverable. The index is
/// filtered through it on every query, so an index entry for an operation the surface hides —
/// whether stale, hand-edited, or maliciously added — cannot appear in results, counts, or
/// explainability. An index can never grant discoverability it was not given.
/// </para>
/// <para>
/// Ordering is fully determined by the index contents: merged score descending, ties broken
/// on the ordinal comparison of the slug. It never depends on dictionary enumeration order,
/// wall-clock time, randomness, or usage counters, so two Engines ranking the same index for
/// the same query produce the same list.
/// </para>
/// </remarks>
public sealed class LexicalRanker
{
    /// <summary>Maximum reported field classes per result.</summary>
    public const int MaxMatchedBy = 4;

    private readonly SearchSection _index;
    private readonly ManifestSurface _surface;
    private readonly SearchScoring _scoring;
    private readonly int _quantizationStep;

    /// <summary>Creates a ranker over one index and one surface.</summary>
    /// <param name="index">The index to rank.</param>
    /// <param name="surface">The surface whose operation list decides discoverability.</param>
    public LexicalRanker(SearchSection index, ManifestSurface surface)
    {
        ArgumentNullException.ThrowIfNull(index);
        ArgumentNullException.ThrowIfNull(surface);

        _index = index;
        _surface = surface;
        _scoring = index.EffectiveScoring;

        // A non-positive step would divide by zero or invert the ordering. The recorded
        // profile is honoured where it is meaningful and ignored where it is not.
        _quantizationStep = _scoring.QuantizationStep > 0 ? _scoring.QuantizationStep : 1;
    }

    /// <summary>Ranks the index against a query.</summary>
    /// <param name="query">
    /// The query text. Null or empty lists every discoverable operation with a zero score,
    /// which is what a caller browsing a surface expects.
    /// </param>
    public LexicalRankOutcome Rank(string? query)
    {
        var terms = SearchTokenizer.Tokenize(query);
        var results = new List<LexicalSearchResult>(_index.Operations.Count);
        var filtered = 0;

        foreach (var document in _index.Operations)
        {
            if (!_surface.InvocationAllowed(document.Operation))
            {
                filtered++;
                continue;
            }

            var (score, matched) = Score(document, terms);

            // With a query present, an operation that matched nothing is not a result.
            if (terms.Count > 0 && score <= 0)
            {
                continue;
            }

            results.Add(new LexicalSearchResult(
                document.Operation,
                score,
                matched,
                document.Summary,
                document.Risk));
        }

        results.Sort(static (left, right) =>
        {
            var byScore = right.Score.CompareTo(left.Score);
            return byScore != 0 ? byScore : string.CompareOrdinal(left.Operation, right.Operation);
        });

        return new LexicalRankOutcome(results, filtered);
    }

    /// <summary>
    /// Scores one document, merging the lexical and metadata components.
    /// </summary>
    /// <remarks>
    /// A term that occurs in several fields contributes its best field once per component,
    /// not once per occurrence: otherwise repeating a word across many fields would outrank a
    /// precise match on the operation name. The metadata component is multiplied separately
    /// because curated aliases and example intents are strong intent signals even though they
    /// are never advertised.
    /// </remarks>
    private (int Score, IReadOnlyList<string> MatchedBy) Score(
        SearchDocumentEntry document,
        IReadOnlyList<string> terms)
    {
        if (terms.Count == 0)
        {
            return (0, []);
        }

        var lexical = 0;
        var metadata = 0;
        var matched = new HashSet<string>(StringComparer.Ordinal);

        foreach (var term in terms)
        {
            if (!document.Terms.TryGetValue(term, out var provenance) || provenance.Count == 0)
            {
                continue;
            }

            var bestLexical = 0;
            var bestMetadata = 0;

            foreach (var field in provenance)
            {
                matched.Add(field);
                var weight = Weight(field);

                if (SearchFieldCatalogue.IsMetadata(field))
                {
                    bestMetadata = Math.Max(bestMetadata, weight);
                }
                else
                {
                    bestLexical = Math.Max(bestLexical, weight);
                }
            }

            lexical += bestLexical;
            metadata += bestMetadata;
        }

        var merged = lexical + (_scoring.MetaMultiplier * metadata);
        var quantized = merged / _quantizationStep * _quantizationStep;

        var describe = matched
            .OrderByDescending(Weight)
            .ThenBy(static field => field, StringComparer.Ordinal)
            .Take(MaxMatchedBy)
            .ToList();

        return (quantized, describe);
    }

    /// <remarks>
    /// The index's own recorded weights win over the built-in defaults, because a pinned
    /// index states how its scores were produced and re-ranking it under different weights
    /// would silently change relevance.
    /// </remarks>
    private int Weight(string field)
        => _scoring.FieldWeights.TryGetValue(field, out var weight)
            ? weight
            : SearchFieldCatalogue.DefaultWeight(field);
}
