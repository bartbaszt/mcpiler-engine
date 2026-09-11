namespace MCPiler.Engine.Search.Hybrid;

/// <summary>
/// An embedding matrix read from a Manifest: one unit-length row per operation, in the
/// order the matrix header lists.
/// </summary>
/// <remarks>
/// <para>
/// Rows live in one flat array because the payload is row-major on the wire and scoring
/// walks it in that order. Materializing an array per operation would copy the whole matrix
/// to gain nothing, and a matrix is the one artifact in a Manifest large enough for that to
/// matter.
/// </para>
/// <para>
/// The type carries no query and computes no score. It is the parsed form of bytes the
/// Manifest supplied, and nothing here decides whether those bytes are the right ones for
/// the operation set being served; <see cref="VectorMatrixReader"/> owns that judgement.
/// </para>
/// </remarks>
internal sealed class VectorMatrix
{
    private readonly float[] _values;

    internal VectorMatrix(int dimension, IReadOnlyList<string> operations, float[] values)
    {
        Dimension = dimension;
        Operations = operations;
        _values = values;
    }

    /// <summary>Values per row.</summary>
    internal int Dimension { get; }

    /// <summary>Operation slugs in payload-row order.</summary>
    internal IReadOnlyList<string> Operations { get; }

    /// <summary>Rows, which is also the number of operations the matrix describes.</summary>
    internal int Count => Operations.Count;

    /// <summary>The row belonging to the operation at this position.</summary>
    internal ReadOnlySpan<float> Row(int index) => _values.AsSpan(index * Dimension, Dimension);
}
