namespace MCPiler.Engine.Runtime;

/// <summary>
/// The authorization requirements of one mounted Manifest, decided by the library.
/// </summary>
/// <remarks>
/// <para>
/// A mount requires authorization exactly when its <c>server.authenticationRequired</c> member
/// is true, which is also the meaning of the member being absent. The decision is the
/// Manifest's, not the configuration's and not a surface's.
/// </para>
/// <para>
/// The decision used to be read from <c>requiredScopes</c>: a mount was protected when any of
/// its surfaces declared a scope. That made protection an implication of a member whose defined
/// meaning is additive — scopes required <i>in addition to</i> the audience binding — so a
/// manifest that required a token while declaring no specific scope could not say so, and every
/// Platform export, which deliberately states no scope, was served publicly. Reading
/// <c>RequiredScopes</c> as a protection signal is the defect this replaces; the mount member is
/// the one spelling of the decision.
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
/// that read the member and decided for itself would be the deployable deciding what a
/// Manifest means, which is the one thing the containment guard exists to prevent.
/// </para>
/// </remarks>
public static class MountAuthorization
{
    /// <summary>Whether this mount's surfaces require a bearer token on every request.</summary>
    public static bool RequiresAuthorization(this MountedManifest mount)
    {
        ArgumentNullException.ThrowIfNull(mount);

        return mount.RequiresAuthorization;
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