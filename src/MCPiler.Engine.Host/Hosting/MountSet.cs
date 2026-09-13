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

        List<MountedSurfaceAddress> addresses = [];

        foreach (MountedManifest mount in started.Mounts)
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

        return new MountSet(started.Mounts, addresses);
    }
}

/// <summary>One explicit HTTP address and the independent mount/surface it resolves to.</summary>
internal sealed record MountedSurfaceAddress(
    MountedManifest Mount,
    MountedSurface Surface,
    string Path);
