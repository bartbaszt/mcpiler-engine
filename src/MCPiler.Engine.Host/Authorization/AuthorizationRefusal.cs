using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Files;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using ModelContextProtocol.Authentication;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// The startup refusal for a mount that requires authorization and a process that trusts no
/// issuer.
/// </summary>
/// <remarks>
/// Refusing to start is the point. A resource server with no configured issuer can only
/// reject every token, which is indistinguishable at the client from a misconfigured client,
/// and an operator would debug the wrong end of the connection. The refusal names the mount,
/// so the operator's own configuration is the first place they look.
/// </remarks>
internal static class AuthorizationRefusal
{
    internal static StartupRefusal? Find(
        IReadOnlyList<MountedManifest> mounts,
        HostAuthorizationOptions? authorization)
    {
        ArgumentNullException.ThrowIfNull(mounts);

        if (authorization is not null)
        {
            return null;
        }

        foreach (MountedManifest mount in mounts)
        {
            if (mount.RequiresAuthorization())
            {
                return new StartupRefusal(
                    mount.Prefix,
                    "auth/issuer-missing",
                    $"Mount '{mount.Prefix}' requires authorization, so every request to it must carry a token, and no issuer is configured to validate one against. Set 'issuer' and 'token-validation'.")
                {
                    Manifest = mount.Path,
                };
            }
        }

        return null;
    }
}

/// <summary>
/// Builds the RFC 9728 protected-resource metadata of an addressed surface.
/// </summary>
/// <remarks>
/// The resource is the exact address the client connected to, rebuilt the same way the
/// canonical identifier is: the request's own scheme, host and raw path, byte for byte. The
/// well-known location the SDK serves it at mirrors that path, so a client that followed the
/// challenge finds a document whose <c>resource</c> names the resource it addressed.
/// </remarks>
internal static class SurfaceMetadata
{
    /// <summary>The well-known prefix the SDK's handler mirrors the resource path under.</summary>
    private const string WellKnownPrefix = "/.well-known/oauth-protected-resource";

    /// <summary>
    /// Whether the mount an addressed resource belongs to requires a token, or <c>null</c> when
    /// no mount serves the address this request named.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the same decision the mount middleware makes, taken from the same generation lease,
    /// so the document a client fetches and the response it later receives cannot disagree about
    /// whether the resource is protected. Reading protection from anywhere else here would
    /// reintroduce exactly the divergence this change exists to remove.
    /// </para>
    /// <para>
    /// A null is not a permission to serve metadata. An address no mount serves gets the same
    /// answer an unprotected mount gets — no document — because publishing a document for an
    /// address that names nothing would confirm the address exists.
    /// </para>
    /// </remarks>
    internal static bool? MountRequiresAuthorization(
        HttpContext context,
        EngineGenerationManager generations)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(generations);

        string resource = DecodedResourceOf(context);
        string address = string.IsNullOrEmpty(resource) ? "/" : resource;

        // A transfer child is not a protected resource of its own: it inherits the mount that
        // owns the surface it hangs off, which is the same resolution the middleware performs.
        if (TransferPath.TryParse(address, out TransferPath transfer))
        {
            address = transfer.ParentAddress;
        }

        if (generations.LeaseSource() is not { } lease)
        {
            return null;
        }

        string resolutionAddress = RequestAddress.NormalizeResolutionAddress(address);

        using (lease)
        {
            return lease.Generation.TryResolve(resolutionAddress, out SurfaceResolution? resolved)
                && resolved is not null
                ? resolved.Mount.RequiresAuthorization()
                : null;
        }
    }

    /// <summary>
    /// The decoded resource path used only to resolve whether a mounted surface exists.
    /// </summary>
    private static string DecodedResourceOf(HttpContext context)
    {
        string path = context.Request.Path.Value ?? "/";

        return path.StartsWith(WellKnownPrefix, StringComparison.Ordinal)
            ? path[WellKnownPrefix.Length..]
            : path;
    }

    /// <summary>
    /// The request-target spelling mirrored into RFC 9728 metadata.
    /// </summary>
    private static string RawResourceOf(HttpContext context)
    {
        string path = RequestAddress.RawPath(context);

        return path.StartsWith(WellKnownPrefix, StringComparison.Ordinal)
            ? path[WellKnownPrefix.Length..]
            : path;
    }

    internal static ProtectedResourceMetadata Build(
        HttpContext context,
        HostAuthorizationOptions options)
    {
        string resource = RawResourceOf(context);

        string canonical = MountAuthorization.CanonicalResource(
            context.Request.Scheme,
            context.Request.Host.Value ?? string.Empty,
            string.IsNullOrEmpty(resource) ? "/" : resource);

        return new ProtectedResourceMetadata
        {
            Resource = canonical,
            AuthorizationServers = [options.Issuer],
            BearerMethodsSupported = ["header"],
        };
    }
}