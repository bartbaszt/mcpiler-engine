using System;
using System.Collections.Generic;

using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Search.Hybrid;

using Xunit;

namespace MCPiler.Engine.UnitTests.Search;

/// <summary>
/// What a caller's query vector becomes, and what it is refused for.
/// </summary>
/// <remarks>
/// The similarities themselves are never asserted as floats. The format places the raw value
/// outside what it promises to reproduce, so what is measured here is the contract around it:
/// which vectors are usable, what a refusal says, and that direction alone decides the result.
/// </remarks>
public sealed class HybridRankerTests
{
    private static readonly string[] Operations = ["alpha", "beta", "gamma"];

    [Fact]
    public void A_query_without_a_vector_has_no_semantic_half()
    {
        Assert.True(HybridRanker.TryResolve(Usable(), Index(), query: null, out SemanticTerm? term, out string? refusal));

        Assert.Null(term);
        Assert.Null(refusal);
    }

    /// <summary>
    /// A vector sent to a catalogue that has none is ignored, not refused.
    /// </summary>
    /// <remarks>
    /// Degradation is required to answer the query rather than fail it, and a catalogue with
    /// no matrix has no dimension for the supplied vector to disagree with. There is nothing
    /// true to say, so nothing is said.
    /// </remarks>
    [Fact]
    public void A_catalogue_with_no_usable_matrix_ignores_the_vector()
    {
        foreach (VectorMatrixResult degraded in new[]
                 {
                     VectorMatrixResult.Absent,
                     VectorMatrixResult.Refused(VectorAvailability.Unreadable, "truncated"),
                     VectorMatrixResult.Refused(VectorAvailability.DimensionMismatch, "declared 4"),
                     VectorMatrixResult.Refused(VectorAvailability.OperationMismatch, "reordered"),
                 })
        {
            Assert.True(HybridRanker.TryResolve(degraded, Index(), [1d, 0d], out SemanticTerm? term, out string? refusal));

            Assert.Null(term);
            Assert.Null(refusal);
        }
    }

    /// <summary>A vector of the wrong length is a caller error, and says both numbers.</summary>
    [Fact]
    public void A_vector_of_the_wrong_length_is_refused_with_both_lengths()
    {
        Assert.False(HybridRanker.TryResolve(Usable(), Index(), [1d, 0d, 0d], out SemanticTerm? term, out string? refusal));

        Assert.Null(term);
        Assert.Contains("3", refusal, StringComparison.Ordinal);
        Assert.Contains("2", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void A_vector_carrying_a_value_that_is_not_a_number_is_refused()
    {
        foreach (double broken in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity })
        {
            Assert.False(
                HybridRanker.TryResolve(Usable(), Index(), [broken, 0d], out SemanticTerm? term, out string? refusal));

            Assert.Null(term);
            Assert.Equal(HybridRanker.NonFiniteVector, refusal);
        }
    }

    /// <summary>A vector with no direction cannot be compared with anything.</summary>
    [Fact]
    public void A_vector_of_zeroes_is_refused()
    {
        Assert.False(HybridRanker.TryResolve(Usable(), Index(), [0d, 0d], out SemanticTerm? term, out string? refusal));

        Assert.Null(term);
        Assert.Equal(HybridRanker.EmptyVector, refusal);
    }

    /// <summary>
    /// An exact match scores the full scale, an unrelated one nothing, an opposite one nothing.
    /// </summary>
    /// <remarks>
    /// The opposing row is the interesting third: clamped at zero rather than allowed to
    /// subtract, so an operation the caller named exactly cannot be dropped by an embedding
    /// that happens to point the other way.
    /// </remarks>
    [Fact]
    public void Similarity_contributes_only_where_it_is_positive()
    {
        Assert.True(HybridRanker.TryResolve(Usable(), Index(), [1d, 0d], out SemanticTerm? term, out _));

        IReadOnlyDictionary<string, int> scored = Assert.IsType<SemanticTerm>(term).Contributions;

        Assert.Equal(Index().EffectiveScoring.VectorScale, scored["alpha"]);
        Assert.Equal(0, scored["beta"]);
        Assert.Equal(0, scored["gamma"]);
    }

    /// <summary>Every operation the matrix carries is scored, exposed here or not.</summary>
    [Fact]
    public void Every_row_is_scored()
    {
        Assert.True(HybridRanker.TryResolve(Usable(), Index(), [1d, 1d], out SemanticTerm? term, out _));

        Assert.Equal(Operations.Length, Assert.IsType<SemanticTerm>(term).Contributions.Count);
    }

    /// <summary>
    /// Only direction matters, and two callers who send one direction page interchangeably.
    /// </summary>
    /// <remarks>
    /// Asserted on the identity as well as the scores, because the identity is what a
    /// continuation is bound to. Two requests that rank alike and page differently would be a
    /// caller unable to walk its own results.
    /// </remarks>
    [Fact]
    public void Magnitude_changes_neither_the_scores_nor_the_page_boundaries()
    {
        Assert.True(HybridRanker.TryResolve(Usable(), Index(), [3d, 4d], out SemanticTerm? small, out _));
        Assert.True(HybridRanker.TryResolve(Usable(), Index(), [300d, 400d], out SemanticTerm? large, out _));

        Assert.Equal(
            Assert.IsType<SemanticTerm>(small).Contributions,
            Assert.IsType<SemanticTerm>(large).Contributions);

        Assert.Equal(small!.Identity, large!.Identity);
    }

    [Fact]
    public void Two_directions_identify_two_lists()
    {
        Assert.True(HybridRanker.TryResolve(Usable(), Index(), [1d, 0d], out SemanticTerm? first, out _));
        Assert.True(HybridRanker.TryResolve(Usable(), Index(), [0d, 1d], out SemanticTerm? second, out _));

        Assert.NotEqual(first!.Identity, second!.Identity);
    }

    /// <summary>
    /// Three rows in two dimensions: one along each axis, and one opposing the first.
    /// </summary>
    private static VectorMatrixResult Usable()
        => VectorMatrixReader.Read(
            PackedMatrix.Write(Operations, [[1f, 0f], [0f, 1f], [-1f, 0f]]),
            declared: null,
            Operations);

    private static SearchSection Index() => new([], []);
}
