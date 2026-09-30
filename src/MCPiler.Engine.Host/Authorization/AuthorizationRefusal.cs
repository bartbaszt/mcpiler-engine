using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Files;
using MCPiler.Engine.Host.Hosting;
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
    /// Builds metadata from one immutable generation lease, or returns null when the addressed
    /// surface is absent or open.
    /// </summary>
    internal static ProtectedResourceMetadata? Build(
        HttpContext context,
        HostAuthorizationOptions options,
        EngineGenerationManager generations)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(generations);

        string resource = ResourceOf(context);
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

        using (lease)
        {
            if (!lease.Generation.TryResolve(address, out SurfaceResolution? resolved)
                || resolved is null
                || !resolved.Mount.RequiresAuthorization())
            {
                return null;
            }

            string direct = MountAuthorization.CanonicalResource(
                context.Request.Scheme,
                context.Request.Host.Value ?? string.Empty,
                address);
            string resourceIdentity = lease.Generation.EffectiveResourceIdentity(resolved, direct);

            return new ProtectedResourceMetadata
            {
                Resource = resourceIdentity,
                AuthorizationServers = [options.Issuer],
                BearerMethodsSupported = ["header"],
            };
        }
    }

    /// <summary>
    /// The resource path a metadata request mirrors, with the well-known prefix removed.
    /// </summary>
    private static string ResourceOf(HttpContext context)
    {
        string path = context.Request.Path.Value ?? "/";

        return path.StartsWith(WellKnownPrefix, StringComparison.Ordinal)
            ? path[WellKnownPrefix.Length..]
            : path;
    }

    /// <summary>
    /// RFC 9728 metadata address for one exact protected-resource identity.
    /// </summary>
    /// <remarks>
    /// The resource string is split rather than round-tripped through <see cref="Uri"/> so an
    /// external identity is not normalized while constructing the discovery location.
    /// </remarks>
    internal static string MetadataAddress(string resourceIdentity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceIdentity);

        int scheme = resourceIdentity.IndexOf("://", StringComparison.Ordinal);
        int path = scheme < 0
            ? -1
            : resourceIdentity.IndexOf('/', scheme + 3);

        if (scheme <= 0)
        {
            throw new InvalidOperationException("A protected-resource identity must be an absolute URI.");
        }

        return path < 0
            ? resourceIdentity + WellKnownPrefix
            : resourceIdentity[..path] + WellKnownPrefix + resourceIdentity[path..];
    }
}
