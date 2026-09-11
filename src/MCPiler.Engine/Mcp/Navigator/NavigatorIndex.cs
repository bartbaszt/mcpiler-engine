using System.Globalization;
using MCPiler.Engine.Manifest.Derivation;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Search.Hybrid;

namespace MCPiler.Engine.Mcp.Navigator;

/// <summary>
/// The lexical index a mount ranks from, resolved once while the process is starting.
/// </summary>
/// <remarks>
/// <para>
/// Resolved at mount rather than per query for two reasons, and the second is the one that
/// matters. Deriving an index on every call would repeat a bounded but real walk over every
/// operation; worse, the disagreement between a declared index and the operations it claims
/// to describe would be discovered by whichever caller happened to query first, and reported
/// to them as a fault in their request.
/// </para>
/// <para>
/// The fingerprint is taken here and kept, because it is what a continuation token is bound
/// to. Recomputing it per page would hash the whole index to answer one question about one
/// token.
/// </para>
/// </remarks>
internal sealed class NavigatorIndex
{
    private NavigatorIndex(SearchSection section, string fingerprint, VectorMatrixResult vectors)
    {
        Section = section;
        Fingerprint = fingerprint;
        Vectors = vectors;
    }

    /// <summary>The index actually ranked: the declared one, or the format's derivation.</summary>
    internal SearchSection Section { get; }

    /// <summary>A canonical digest of everything in the index that can change a ranking.</summary>
    internal string Fingerprint { get; }

    /// <summary>
    /// What reading the Manifest's embedding matrix produced, including the four states in
    /// which there is nothing to score.
    /// </summary>
    /// <remarks>
    /// Carried beside the lexical section rather than somewhere else, because a mount ranks
    /// from both and the question "what does this Manifest rank from" has one answer.
    /// </remarks>
    internal VectorMatrixResult Vectors { get; }

    /// <summary>
    /// Resolves the index for one Manifest.
    /// </summary>
    /// <param name="manifest">The loaded Manifest.</param>
    /// <param name="diagnostics">
    /// Receives a disagreement between a declared index and the operations, and the warning
    /// for a vector payload that cannot be used.
    /// </param>
    internal static NavigatorIndex Resolve(ManifestDocument manifest, ICollection<ManifestDiagnostic> diagnostics)
    {
        SearchSection section = LexicalIndexDeriver.Resolve(manifest, diagnostics);

        // Against the lexical index's operation order, not the Manifest's declaration order:
        // the matrix rows are addressed by position, and the index is the list every ranking
        // walks. Comparing against anything else would accept a matrix that is right about a
        // list nobody ranks.
        VectorMatrixResult vectors = VectorMatrixReader.Read(
            manifest.VectorPayload,
            manifest.Vectors,
            [.. section.Operations.Select(static entry => entry.Operation)]);

        if (Code(vectors.State) is { } code && vectors.Detail is { } detail)
        {
            diagnostics.Add(ManifestDiagnostic.Warning(
                code,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The vector matrix cannot be used and ranking stays lexical. {detail}"),
                section: ManifestSectionName.Vectors));
        }

        return new NavigatorIndex(section, LexicalIndexDeriver.Fingerprint(section), vectors);
    }

    /// <summary>The diagnostic code for a refusal, or <c>null</c> when there is nothing to report.</summary>
    /// <remarks>
    /// An absent payload is silent on purpose. A Manifest compiled without embeddings is a
    /// supported configuration, and warning about it every time a process starts would train
    /// an operator to ignore the line where the real ones appear.
    /// </remarks>
    private static string? Code(VectorAvailability state) => state switch
    {
        VectorAvailability.Unreadable => ManifestDiagnosticCodes.VectorsUnreadable,
        VectorAvailability.DimensionMismatch => ManifestDiagnosticCodes.VectorsDimensionMismatch,
        VectorAvailability.OperationMismatch => ManifestDiagnosticCodes.VectorsOperationMismatch,
        _ => null,
    };
}
