using MCPiler.Engine.Host.Configuration;
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
                    $"Mount '{mount.Prefix}' declares a surface that requires a scope, so every request to it must carry a token, and no issuer is configured to validate one against. Set 'issuer' and 'token-validation'.")
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

    internal static ProtectedResourceMetadata Build(
        HttpContext context,
        HostAuthorizationOptions options)
    {
        // The metadata request carries the well-known prefix ahead of the resource path it
        // mirrors; the canonical identifier is the resource itself, prefix stripped.
        string path = context.Request.Path.Value ?? "/";
        string resource = path.StartsWith(WellKnownPrefix, StringComparison.Ordinal)
            ? path[WellKnownPrefix.Length..]
            : path;

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