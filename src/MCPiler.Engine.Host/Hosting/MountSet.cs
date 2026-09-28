using MCPiler.Engine.Host.Files;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>The complete address topology of one started HTTP host.</summary>
/// <remarks>
/// <para>
/// A mount set is derived only from a runtime that already accepted every Manifest. It does not
/// merge catalogues or invent names: every entry retains the exact <see cref="MountedManifest"/>
/// and <see cref="MountedSurface"/> the runtime derived.
/// </para>
/// <para>
/// There is deliberately no process-root entry. A default surface is addressable at its mount
/// prefix, but a process with one mount is no more entitled to serve <c>/</c> than a process with
/// ten. Adding another mount therefore cannot change the meaning of an existing address.
/// </para>
/// </remarks>
internal sealed class MountSet
{
    private MountSet(
        IReadOnlyList<MountedManifest> mounts,
        IReadOnlyList<MountedSurfaceAddress> addresses)
    {
        Mounts = mounts;
        Addresses = addresses;
    }

    /// <summary>The independent Manifests this process serves.</summary>
    public IReadOnlyList<MountedManifest> Mounts { get; }

    /// <summary>Every explicit MCP address the host maps, with no process-level default.</summary>
    public IReadOnlyList<MountedSurfaceAddress> Addresses { get; }

    /// <summary>Builds the immutable host topology from a fully-started runtime.</summary>
    public static MountSet From(RuntimeStartResult started)
    {
        ArgumentNullException.ThrowIfNull(started);

        if (!started.Started)
        {
            throw new InvalidOperationException(
                "A refused runtime has no mount set. Nothing partially mounts, so a caller that "
                + "reached here has already ignored a refusal.");
        }

        return From(started.Mounts);
    }

    /// <summary>
    /// Builds the immutable host topology from an already-loaded mount set.
    /// </summary>
    /// <remarks>
    /// A managed generation arrives as loaded mounts rather than as a started runtime, because the
    /// loader that produced them is on the library side of the seam. Deriving addresses from the
    /// mounts themselves keeps one topology rule for both modes: a managed activation cannot map
    /// an address the file-mode host would not have mapped for the same Manifests.
    /// </remarks>
    public static MountSet From(IReadOnlyList<MountedManifest> mounts)
    {
        ArgumentNullException.ThrowIfNull(mounts);

        List<MountedSurfaceAddress> addresses = [];

        foreach (MountedManifest mount in mounts)
        {
            foreach (MountedSurface surface in mount.Surfaces)
            {
                addresses.Add(new MountedSurfaceAddress(
                    mount,
                    surface,
                    mount.Prefix + "/" + surface.Slug));

                if (surface.IsDefault)
                {
                    addresses.Add(new MountedSurfaceAddress(mount, surface, mount.Prefix));
                }
            }
        }

        return new MountSet(mounts, addresses);
    }
}

/// <summary>One explicit HTTP address and the independent mount/surface it resolves to.</summary>
internal sealed record MountedSurfaceAddress(
    MountedManifest Mount,
    MountedSurface Surface,
    string Path);


/// <summary>
/// Validates the final HTTP route topology owned by one Engine generation.
/// </summary>
/// <remarks>
/// Validation is deliberately performed on final mounted addresses, not only on manifest slugs.
/// A harmless-looking slug may become a host-owned or protocol-owned route only after it is
/// combined with its mount prefix, and managed generations must obey the same rule as file mode.
/// </remarks>
internal static class HostRouteTopologyValidation
{
    private const string ProtectedResourceMetadataPrefix = "/.well-known/oauth-protected-resource";
    private const string HealthPrefix = "/health";
    private const string OperatorPrefix = "/.engine";

    internal static IReadOnlyList<StartupRefusal> Find(MountSet mounts)
    {
        ArgumentNullException.ThrowIfNull(mounts);

        List<StartupRefusal> refusals = [];
        Dictionary<string, MountedSurfaceAddress> exact = new(StringComparer.Ordinal);
        Dictionary<string, MountedSurfaceAddress> routed = new(StringComparer.OrdinalIgnoreCase);

        foreach (MountedSurfaceAddress address in mounts.Addresses)
        {
            if (!IsCanonicalLiteralPath(address.Path))
            {
                refusals.Add(Refusal(
                    address,
                    "host/surface-address-noncanonical",
                    $"Mounted surface address '{address.Path}' is not a canonical literal HTTP path."));
                continue;
            }

            if (IsReservedHostPath(address.Path))
            {
                refusals.Add(Refusal(
                    address,
                    "host/surface-address-reserved",
                    $"Mounted surface address '{address.Path}' collides with an Engine-owned host/protocol namespace."));
                continue;
            }

            if (TransferPath.TryParse(address.Path, out _))
            {
                refusals.Add(Refusal(
                    address,
                    "host/surface-address-transfer-collision",
                    $"Mounted surface address '{address.Path}' collides with the Engine-owned file-transfer child namespace."));
                continue;
            }

            if (exact.TryGetValue(address.Path, out MountedSurfaceAddress? same))
            {
                refusals.Add(Refusal(
                    address,
                    "host/surface-address-duplicate",
                    $"Mounted surface address '{address.Path}' duplicates the address produced by mount '{same.Mount.Prefix}' surface '{same.Surface.Slug}'."));
                continue;
            }

            exact[address.Path] = address;

            // ASP.NET literal routing is case-insensitive even though Engine resource identity and
            // generation lookup are ordinal. Mapping two addresses that differ only by case would
            // therefore create an ambiguous endpoint before Engine can apply its ordinal check.
            if (routed.TryGetValue(address.Path, out MountedSurfaceAddress? alias))
            {
                refusals.Add(Refusal(
                    address,
                    "host/surface-address-route-alias",
                    $"Mounted surface address '{address.Path}' aliases '{alias.Path}' under ASP.NET literal routing."));
                continue;
            }

            routed[address.Path] = address;
        }

        return refusals;
    }

    internal static bool IsCanonicalMountPrefix(string prefix)
        => IsCanonicalLiteralPath(prefix);

    private static bool IsCanonicalLiteralPath(string path)
    {
        if (string.IsNullOrEmpty(path)
            || path[0] != '/'
            || path.Length == 1
            || path.EndsWith('/', StringComparison.Ordinal)
            || path.Contains("//", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (char value in path)
        {
            if (char.IsControl(value)
                || char.IsWhiteSpace(value)
                || value is '{' or '}' or '?' or '#' or '\\' or '%' or '*')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsReservedHostPath(string path)
        => IsNamespace(path, HealthPrefix)
            || IsNamespace(path, OperatorPrefix)
            || IsNamespace(path, ProtectedResourceMetadataPrefix);

    private static bool IsNamespace(string path, string prefix)
        => string.Equals(path, prefix, StringComparison.Ordinal)
            || path.StartsWith(prefix + "/", StringComparison.Ordinal);

    private static StartupRefusal Refusal(
        MountedSurfaceAddress address,
        string code,
        string message)
        => new(address.Mount.Prefix, code, message)
        {
            Manifest = address.Mount.Path,
        };
}
