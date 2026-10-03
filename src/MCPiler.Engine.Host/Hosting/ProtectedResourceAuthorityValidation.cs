using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// The listener-authority requirement that a protected surface's resource identity creates.
/// </summary>
/// <remarks>
/// <para>
/// A protected surface whose resource identity is deployment-owned - that is, one carrying an
/// explicit external resource - needs no listener boundary, because its audience is already a
/// fixed string the token must carry. A protected surface with no external resource derives its
/// identity from the request authority instead, so the process must know which authority it is
/// willing to serve before it can admit a request at all.
/// </para>
/// <para>
/// The deployment's answer is one concrete authority, from <c>--allowed-host</c> or from a listen
/// address that is not a wildcard. A wildcard listen deliberately yields nothing: <c>*</c>,
/// <c>+</c>, <c>0.0.0.0</c> and <c>::</c> all name every interface, so treating one of them as an
/// authority would accept any Host header and reduce the protected resource to whatever the
/// caller asked for.
/// </para>
/// <para>
/// This is one seam for three call sites that previously each carried their own copy of the
/// boolean test and their own copy of the message. A duplicated test is where a rule silently
/// stops being enforced in one deployment mode, and a duplicated message is where the diagnostic
/// an operator reads stops naming the thing they must change.
/// </para>
/// </remarks>
internal static class ProtectedResourceAuthorityValidation
{
    internal const string Code = "auth/allowed-host-missing";

    /// <summary>
    /// The refusal when the deployment cannot bound protected request-derived identities, or
    /// <c>null</c> when it can, when nothing is protected, or when the surfaces all have an
    /// external resource.
    /// </summary>
internal static StartupRefusal? Find(
        MountSet mounts,
        IReadOnlyDictionary<string, string> externalResources,
        IReadOnlyList<string> AllowedHosts,
        bool requiresAuthorization)
    {
        ArgumentNullException.ThrowIfNull(mounts);
        ArgumentNullException.ThrowIfNull(externalResources);
        ArgumentNullException.ThrowIfNull(AllowedHosts);

        if (!requiresAuthorization || AllowedHosts.Count > 0)
        {
            return null;
        }

        IReadOnlyList<string> unbound = RequestDerivedProtectedSurfaceRoutes(mounts, externalResources);
        if (unbound.Count == 0)
        {
            return null;
        }

        return new StartupRefusal(
            unbound[0],
            Code,
            $"Protected HTTP serving requires at least one '{HostConfiguration.AllowedHostKey}' "
            + $"when '{HostConfiguration.ListenKey}' does not name one concrete authority. "
            + $"These protected surfaces have no external resource, so their resource identity is "
            + $"derived from the request authority: {string.Join(", ", unbound)}.")
        {
            Setting = HostConfiguration.AllowedHostKey,
        };
    }

    /// <summary>
    /// The mounted routes of every protected surface with no deployment-owned resource identity,
    /// in mount order.
    /// </summary>
    internal static IReadOnlyList<string> RequestDerivedProtectedSurfaceRoutes(
        MountSet mounts,
        IReadOnlyDictionary<string, string> externalResources)
    {
        ArgumentNullException.ThrowIfNull(mounts);
        ArgumentNullException.ThrowIfNull(externalResources);

        List<string> unbound = [];

        foreach (MountedManifest mount in mounts.Mounts)
        {
            if (!mount.RequiresAuthorization())
            {
                continue;
            }

            foreach (MountedSurface surface in mount.Surfaces)
            {
                if (!externalResources.ContainsKey(mount.Prefix + "/" + surface.Slug))
                {
                    unbound.Add(mount.Prefix + "/" + surface.Slug);
                }
            }
        }

        return unbound;
    }
}