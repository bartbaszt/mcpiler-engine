using MCPiler.Engine.Manifest.Derivation;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

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
    private NavigatorIndex(SearchSection section, string fingerprint)
    {
        Section = section;
        Fingerprint = fingerprint;
    }

    /// <summary>The index actually ranked: the declared one, or the format's derivation.</summary>
    internal SearchSection Section { get; }

    /// <summary>A canonical digest of everything in the index that can change a ranking.</summary>
    internal string Fingerprint { get; }

    /// <summary>
    /// Resolves the index for one Manifest.
    /// </summary>
    /// <param name="manifest">The loaded Manifest.</param>
    /// <param name="diagnostics">Receives a disagreement between a declared index and the operations.</param>
    internal static NavigatorIndex Resolve(ManifestDocument manifest, ICollection<ManifestDiagnostic> diagnostics)
    {
        SearchSection section = LexicalIndexDeriver.Resolve(manifest, diagnostics);

        return new NavigatorIndex(section, LexicalIndexDeriver.Fingerprint(section));
    }
}
