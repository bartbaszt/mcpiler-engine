using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Search.Hybrid;

/// <summary>
/// The semantic component of one ranking, already reduced to score units.
/// </summary>
/// <remarks>
/// Scaled and truncated here rather than carried as a similarity, so the value the ordering
/// sees is an integer. A float that reached the merge would put the total order at the mercy
/// of how one machine summed a dot product, and the format places the raw similarity outside
/// what it promises to reproduce.
/// </remarks>
internal sealed class SemanticTerm
{
    internal SemanticTerm(IReadOnlyDictionary<string, int> contributions, string identity)
    {
        Contributions = contributions;
        Identity = identity;
    }

    /// <summary>The contribution for each operation the matrix carries, by slug.</summary>
    internal IReadOnlyDictionary<string, int> Contributions { get; }

    /// <summary>
    /// A digest of the query vector this term was computed from.
    /// </summary>
    /// <remarks>
    /// Continuation depends on it. A page boundary computed against a vector-assisted list
    /// addresses positions in that list; resuming it against a list ranked from a different
    /// vector, or from none, would skip operations and repeat others with nothing to say so.
    /// </remarks>
    internal string Identity { get; }
}

/// <summary>
/// Turns a caller's query vector into the semantic half of a ranking.
/// </summary>
/// <remarks>
/// <para>
/// The vector arrives already computed. This library issues no embedding request and contacts
/// no provider, so the only way a semantic signal can exist here is for the caller to bring
/// one produced with the model the catalogue declares. A catalogue with no usable matrix
/// simply has no semantic half; that is degradation, not a fault, and it is answered by
/// ranking lexically rather than by refusing.
/// </para>
/// <para>
/// Similarity is accumulated by a plain loop over a fixed order rather than by a vectorized
/// dot product. A widened reduction sums in an order that depends on the register width of
/// whichever machine ran it, which would let two deployments of one Manifest rank one query
/// two ways. The dimensions in play are small enough that the arithmetic is not the cost.
/// </para>
/// </remarks>
internal static class HybridRanker
{
    /// <summary>How much of a digest identifies one query vector.</summary>
    private const int IdentityLength = 16;

    internal const string NonFiniteVector =
        "The query vector contains a value that is not a finite number.";

    internal const string EmptyVector =
        "The query vector has no direction and cannot be compared with anything.";

    /// <summary>Explains a query vector that does not fit the catalogue it was sent to.</summary>
    internal static string DimensionRefusal(int supplied, int expected)
        => string.Create(
            CultureInfo.InvariantCulture,
            $"The query vector carries {supplied} values and this catalogue was embedded with {expected}. Embed the query with the model the catalogue declares.");

    /// <summary>
    /// Resolves the semantic term for one query, or explains why the vector cannot be used.
    /// </summary>
    /// <param name="vectors">What the mount could make of the Manifest's vector matrix.</param>
    /// <param name="index">The lexical index, which records the scale scores are kept in.</param>
    /// <param name="query">The caller's vector, or <c>null</c> when none was supplied.</param>
    /// <param name="term">The resolved term, or <c>null</c> when the ranking has no semantic half.</param>
    /// <param name="refusal">Why the supplied vector was rejected, when it was.</param>
    /// <returns><c>false</c> only when the caller must be told something.</returns>
    internal static bool TryResolve(
        VectorMatrixResult vectors,
        SearchSection index,
        IReadOnlyList<double>? query,
        out SemanticTerm? term,
        [NotNullWhen(false)] out string? refusal)
    {
        ArgumentNullException.ThrowIfNull(vectors);
        ArgumentNullException.ThrowIfNull(index);

        term = null;
        refusal = null;

        if (query is null)
        {
            return true;
        }

        if (vectors.State is not VectorAvailability.Usable || vectors.Matrix is not { } matrix)
        {
            // Nothing to compare against, and nothing to complain about: with no matrix there
            // is no dimension for the supplied vector to disagree with. Refusing here would
            // make a degraded catalogue answer a query it is required to answer lexically.
            return true;
        }

        if (query.Count != matrix.Dimension)
        {
            refusal = DimensionRefusal(query.Count, matrix.Dimension);
            return false;
        }

        if (!TryNormalize(query, out double[] unit, out refusal))
        {
            return false;
        }

        term = new SemanticTerm(Score(matrix, unit, index.EffectiveScoring.VectorScale), Identify(unit));
        return true;
    }

    /// <summary>
    /// Scales the query onto the unit sphere the stored rows already sit on.
    /// </summary>
    /// <remarks>
    /// Normalized here rather than demanded of the caller. A cosine between a stored unit row
    /// and an unnormalized query is the cosine multiplied by the query's magnitude, which
    /// leaves the order among semantic candidates intact and silently changes how much the
    /// semantic half weighs against the lexical one. Asking a caller to normalize instead
    /// would make relevance depend on a step nothing can verify.
    /// </remarks>
    private static bool TryNormalize(
        IReadOnlyList<double> query,
        out double[] unit,
        [NotNullWhen(false)] out string? refusal)
    {
        unit = new double[query.Count];
        refusal = null;
        double magnitude = 0;

        for (int index = 0; index < query.Count; index++)
        {
            double value = query[index];

            if (!double.IsFinite(value))
            {
                refusal = NonFiniteVector;
                return false;
            }

            unit[index] = value;
            magnitude += value * value;
        }

        magnitude = Math.Sqrt(magnitude);

        if (magnitude <= 0)
        {
            refusal = EmptyVector;
            return false;
        }

        for (int index = 0; index < unit.Length; index++)
        {
            unit[index] /= magnitude;
        }

        return true;
    }

    /// <summary>
    /// Scores every row against the query.
    /// </summary>
    /// <remarks>
    /// A similarity at or below zero contributes nothing rather than subtracting. The
    /// semantic half is evidence for an operation, and the absence of semantic resemblance is
    /// not evidence against a name the caller typed exactly; letting it subtract would drop a
    /// literal match because an unrelated embedding pointed the other way.
    /// </remarks>
    private static Dictionary<string, int> Score(VectorMatrix matrix, double[] unit, int scale)
    {
        Dictionary<string, int> contributions = new(matrix.Count, StringComparer.Ordinal);

        for (int row = 0; row < matrix.Count; row++)
        {
            double similarity = Dot(matrix.Row(row), unit);

            contributions[matrix.Operations[row]] = double.IsFinite(similarity) && similarity > 0
                ? (int)Math.Truncate(similarity * scale)
                : 0;
        }

        return contributions;
    }

    private static double Dot(ReadOnlySpan<float> stored, double[] unit)
    {
        double total = 0;

        for (int index = 0; index < unit.Length; index++)
        {
            total += stored[index] * unit[index];
        }

        return total;
    }

    /// <summary>Digests the normalized query so a continuation can be bound to it.</summary>
    /// <remarks>
    /// Over the normalized values, not the supplied ones: two callers who send the same
    /// direction at different magnitudes get the same ranking, so they must get interchangeable
    /// page boundaries as well.
    /// </remarks>
    private static string Identify(double[] unit)
    {
        byte[] bytes = new byte[unit.Length * sizeof(double)];

        for (int index = 0; index < unit.Length; index++)
        {
            BinaryPrimitives.WriteDoubleLittleEndian(bytes.AsSpan(index * sizeof(double)), unit[index]);
        }

        return CanonicalJson.ComputeHash(bytes)[..IdentityLength];
    }
}
