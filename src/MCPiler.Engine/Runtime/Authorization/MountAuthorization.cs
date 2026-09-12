namespace MCPiler.Engine.Runtime;

/// <summary>
/// The authorization requirements of one mounted Manifest, decided by the library.
/// </summary>
/// <remarks>
/// <para>
/// A mount requires authorization exactly when one of its enabled surfaces declares a
/// non-empty <c>requiredScopes</c> list. Scopes are the only authorization signal the
/// Manifest format carries, so they are the whole decision: a deployment that wants a
/// scope-free mount protected has a Manifest question, not a configuration question, and the
/// format is the place it will be answered.
/// </para>
/// <para>
/// The requirement is per mount rather than per surface deliberately. A token authorizes a
/// process boundary crossing, and the audience it must carry names a surface address; a
/// mount that protected one surface and left its sibling open would let a client with one
/// token for the open surface learn the protected sibling's tool names from a listing of the
/// mount it was already allowed to read. Every surface of a requiring mount therefore
/// requires a token, and the scopes a surface declares are enforced on top of that.
/// </para>
/// <para>
/// The decision lives in the library, on the seam, because it reads Manifest state. A host
/// that read <c>requiredScopes</c> and decided for itself would be the deployable deciding
/// what a Manifest means, which is the one thing the containment guard exists to prevent.
/// </para>
/// </remarks>
public static class MountAuthorization
{
    /// <summary>Whether this mount's surfaces require a bearer token on every request.</summary>
    public static bool RequiresAuthorization(this MountedManifest mount)
    {
        ArgumentNullException.ThrowIfNull(mount);

        foreach (MountedSurface surface in mount.Surfaces)
        {
            if (surface.RequiredScopes.Count > 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The canonical resource identifier of an addressed surface: the exact absolute address
    /// the client connected to, including the mount prefix and the surface slug, with any
    /// trailing characters the request carried.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The raw request path is authoritative. Reconstructing it from route values would
    /// silently normalize away a trailing slash, and a trailing slash is a byte the audience
    /// compares against: <c>https://host/mcp/api</c> and <c>https://host/mcp/api/</c> are two
    /// names for one place and one resource each, and a token for one must not open the other.
    /// </para>
    /// <para>
    /// The default surface is reachable at two addresses and they are two protected
    /// resources that happen to serve the same tools. Building the identifier from the
    /// address keeps that property: the identifier of <c>{mount}</c> differs from the
    /// identifier of <c>{mount}/{slug}</c> by construction, and no equivalence between them
    /// is ever offered.
    /// </para>
    /// </remarks>
    /// <param name="scheme">The request scheme, lowercased by the server.</param>
    /// <param name="host">The request host, exactly as the server received it.</param>
    /// <param name="path">The raw request path, including any trailing slash.</param>
    public static string CanonicalResource(string scheme, string host, string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(scheme);
        ArgumentException.ThrowIfNullOrEmpty(host);
        ArgumentException.ThrowIfNullOrEmpty(path);

        return $"{scheme}://{host}{path}";
    }

    /// <summary>
    /// Whether a presented audience names the addressed resource, compared byte for byte.
    /// </summary>
    /// <remarks>
    /// Every relaxed comparison is a refused one: case-insensitive matching would accept a
    /// token for <c>HTTPS://HOST/...</c> at <c>https://host/...</c>, trailing-slash
    /// equivalence would accept a token for the bare mount at the slug-qualified address,
    /// and prefix matching would accept a token for one surface at every surface below it.
    /// The refused set is the requirement, not an implementation nicety.
    /// </remarks>
    public static bool AudienceNames(string audience, string canonicalResource)
        => string.Equals(audience, canonicalResource, StringComparison.Ordinal);
}