using MCPiler.Engine.Manifest.Derivation;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Mcp;

/// <summary>
/// Builds one surface's catalogue: what it advertises, and the digest of what it advertises.
/// </summary>
/// <remarks>
/// <para>
/// Called once per surface while the process is starting, before anything listens. Both
/// transports then read the value rather than each computing one, which is what makes a
/// byte-identical listing across transports a property of the design instead of a
/// coincidence a test happens to observe. A transport that computed its own would be free to
/// drift, and the drift would show up as one client seeing a tool another client does not.
/// </para>
/// <para>
/// The fingerprint travels with the tools deliberately. It is taken over the derived set,
/// so an operator comparing two deployments compares one string instead of two listings, and
/// an inspection verb can prove agreement with what would be served without rendering a
/// protocol payload to do it.
/// </para>
/// </remarks>
public static class SurfaceCatalogue
{
    /// <summary>
    /// Derives, projects and fingerprints one enabled surface.
    /// </summary>
    /// <param name="manifest">The loaded Manifest.</param>
    /// <param name="surface">The surface to advertise.</param>
    /// <param name="diagnostics">Receives any derivation disagreement.</param>
    public static MountedSurface Build(
        ManifestDocument manifest,
        ManifestSurface surface,
        ICollection<ManifestDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(surface);
        ArgumentNullException.ThrowIfNull(diagnostics);

        SurfaceToolSet tools = ToolSetDeriver.Resolve(manifest, surface, diagnostics);

        return new MountedSurface(
            surface.Slug,
            surface.DisplayName,
            surface.IsDefault,
            surface.RequiredScopes,
            ToolSetProjection.Project(tools),
            ToolSetDeriver.Fingerprint(tools))
        {
            // What the Navigator may reach, derived here for the same reason the listing is:
            // a surface that cannot resolve an identifier should fail to start rather than
            // fail the first caller that asks for one.
            Navigable = ToolSetProjection.Project(ToolSetDeriver.DeriveNavigable(manifest, surface)),

            // The declared identity, resolved once here so no transport has to decide what to
            // say when the Manifest leaves a field out.
            Identity = new ServerIdentity(
                manifest.Server.Name,
                manifest.Server.Version ?? string.Empty,
                surface.Name,
                manifest.Server.Description),
        };
    }
}
