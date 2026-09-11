using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Mcp;

/// <summary>How a call reached the invoker.</summary>
/// <remarks>
/// Two ways in, and they are not equivalent. One names a tool the surface published; the other
/// names an operation the caller chose. An operation's exposure says which of the two it
/// answers to, so the way in is part of the question rather than context the answer can ignore.
/// </remarks>
internal enum InvocationPath
{
    /// <summary>A <c>tools/call</c> naming a tool from the advertised listing.</summary>
    Direct,

    /// <summary>The Navigator's invoke tool, naming an operation the caller supplied.</summary>
    Navigator,
}

/// <summary>
/// Whether a surface admits an operation by the path a call arrived on.
/// </summary>
/// <remarks>
/// <para>
/// Advertisement and invocation are two lists. Deriving the second from the first is safe only
/// while nothing else can reach the invoker, and something else can: the Navigator takes an
/// operation name from the caller and invokes it without consulting the advertised listing.
/// This is the second list, read from the surface's own exposure table rather than from
/// anything derived, so the two paths cannot disagree about what a surface excludes.
/// </para>
/// <para>
/// Fail-closed at every unknown. An operation the table does not list is refused, a surface
/// that cannot be resolved refuses everything, and an exposure this build does not recognise is
/// refused rather than admitted. A gate whose default is "allow" only protects what someone
/// remembered to enumerate.
/// </para>
/// </remarks>
internal static class ExposureGate
{
    /// <summary>
    /// Whether <paramref name="operation"/> may run on <paramref name="surface"/> when reached
    /// by <paramref name="path"/>.
    /// </summary>
    /// <remarks>
    /// Resolves the mounted surface back to the declaration it was built from. The mounted
    /// value is a projection of what the surface advertises, and asking a projection of the
    /// advertised list what the excluded list contains would be asking the first list the
    /// question the second one exists to answer.
    /// </remarks>
    internal static bool Permits(
        MountedManifest mount,
        MountedSurface surface,
        string operation,
        InvocationPath path)
    {
        ArgumentNullException.ThrowIfNull(mount);
        ArgumentNullException.ThrowIfNull(surface);

        return mount.Document.Server.Surface(surface.Slug) is { } declared
            && Permits(declared, operation, path);
    }

    /// <summary>The exposure table itself, over one declared surface.</summary>
    /// <remarks>
    /// <c>Direct</c> answers on both paths: an operation the surface publishes is not made
    /// unreachable by a caller choosing to name it through the Navigator. <c>Navigator</c>
    /// answers on one, which is what makes it absent from the listing rather than merely
    /// undocumented in it. <c>Hidden</c> answers on neither, and neither does an operation this
    /// surface does not list at all — the two are one refusal because a caller must not be able
    /// to tell them apart.
    /// </remarks>
    internal static bool Permits(ManifestSurface surface, string operation, InvocationPath path)
    {
        ArgumentNullException.ThrowIfNull(surface);

        return surface.ExposureOf(operation) switch
        {
            OperationExposure.Direct => true,
            OperationExposure.Navigator => path is InvocationPath.Navigator,
            OperationExposure.Hidden => false,
            _ => false,
        };
    }
}
