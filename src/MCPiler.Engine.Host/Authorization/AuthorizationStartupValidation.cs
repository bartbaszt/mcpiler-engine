using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// Validates host-side authorization startup configuration without building a listener.
/// </summary>
/// <remarks>
/// This is shared by `serve` and `inspect` so a deployment preflight cannot report success for
/// an authorization configuration the serving path will refuse before opening the listener.
/// It performs only startup-safe checks: configuration pairing, local secret-file readability and
/// issuer endpoint discovery/policy. It never validates a caller token.
/// </remarks>
internal static class AuthorizationStartupValidation
{
    internal static async Task<StartupRefusal?> FindAsync(
        IReadOnlyList<MountedManifest> mounts,
        HostAuthorizationOptions? authorization,
        HostTransport transport,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mounts);

        if (transport is HostTransport.Http
            && AuthorizationRefusal.Find(mounts, authorization) is { } mountRefusal)
        {
            return mountRefusal;
        }

        return await FindConfigurationAsync(authorization, transport, cancellationToken)
            .ConfigureAwait(false);
    }

    internal static async Task<StartupRefusal?> FindConfigurationAsync(
        HostAuthorizationOptions? authorization,
        HostTransport transport,
        CancellationToken cancellationToken)
    {
        if (authorization is not { } options)
        {
            return null;
        }

        // Stdio does not construct an HTTP resource server, so its bearer-validator credential
        // is not part of the active security boundary. Keep endpoint-policy parity with serving
        // for explicitly configured authorization, but do not invent an HTTP secret-file
        // requirement for a transport that never instantiates the validator.
        if (transport is HostTransport.Http
            && MountAuthorizationSetup.FindStartupRefusal(options) is { } localRefusal)
        {
            return localRefusal;
        }

        return await AuthorizationEndpointCheck
            .FindAsync(options, cancellationToken)
            .ConfigureAwait(false);
    }
}
