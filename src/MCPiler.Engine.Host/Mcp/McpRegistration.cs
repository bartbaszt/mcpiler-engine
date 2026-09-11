using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace MCPiler.Engine.Host.Mcp;

/// <summary>
/// One addressable surface, with its protocol definitions already built.
/// </summary>
/// <remarks>
/// <para>
/// Attached to the route as endpoint metadata, which is how a request finds the surface it
/// addressed. The alternative — reading the path back apart into a mount and a slug — would
/// make routing decide once and then decide again differently, and the second decision is the
/// one that would accept a path a router had already normalized.
/// </para>
/// <para>
/// Definitions are built here, at mapping time, so a listing enumerates objects that already
/// exist. Building them per session would make repeated enumeration a repeated rendering, and
/// byte-identity across enumerations would then rest on the renderer rather than on there
/// being one set of objects.
/// </para>
/// </remarks>
internal sealed class SurfaceEndpoint
{
    internal SurfaceEndpoint(MountedManifest mount, MountedSurface surface)
    {
        Mount = mount;
        Surface = surface;
        Definitions = SdkTranslation.Define(surface);
    }

    /// <summary>The mount this surface belongs to.</summary>
    public MountedManifest Mount { get; }

    /// <summary>The surface addressed.</summary>
    public MountedSurface Surface { get; }

    /// <summary>The surface's protocol definitions, in advertisement order.</summary>
    public IReadOnlyList<Tool> Definitions { get; }
}

/// <summary>
/// Registers the protocol server and maps every mounted surface onto a route.
/// </summary>
/// <remarks>
/// <para>
/// Routes are mapped from the mount set, one per surface, plus the bare mount prefix for the
/// surface the Manifest declared default. The default is served by the same endpoint rather
/// than by a redirect, because the two addresses are two protected resources and a redirect
/// would move a client from the one its token names to the one it does not.
/// </para>
/// <para>
/// Nothing is mapped at the process root. A request that names no mount therefore matches no
/// route, and matching no route is what "there is no default mount" has to mean: resolving it
/// to the only Manifest loaded would silently move a working client the day a second one is
/// added.
/// </para>
/// <para>
/// Mapping every address explicitly is also why an unknown mount and an unknown slug need no
/// refusal of their own. Neither reaches a handler, so neither can disclose a mount name, a
/// surface list or a tool.
/// </para>
/// </remarks>
internal static class McpRegistration
{
    /// <summary>Registers the protocol server and its HTTP transport.</summary>
    public static void AddEngineMcp(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services
            .AddMcpServer()
            .WithHttpTransport(transport =>
            {
                // The same session mode the Studio serves under. A protocol behaviour that
                // differs between the two implementations should be a difference in our code,
                // not in how the two configured one SDK.
                transport.SessionMode = HttpServerSessionMode.StatefulForInitializeClients;
                transport.ConfigureSessionOptions = ConfigureSessionAsync;
            });
    }

    /// <summary>Maps every surface of every mount, and nothing else.</summary>
    public static void MapMounts(WebApplication app, IReadOnlyList<MountedManifest> mounts)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(mounts);

        foreach (MountedManifest mount in mounts)
        {
            foreach (MountedSurface surface in mount.Surfaces)
            {
                SurfaceEndpoint addressed = new(mount, surface);

                app.MapMcp(mount.Prefix + "/" + surface.Slug).WithMetadata(addressed);

                if (surface.IsDefault)
                {
                    app.MapMcp(mount.Prefix).WithMetadata(addressed);
                }
            }
        }
    }

    /// <summary>
    /// Gives a session exactly the tools of the surface its request addressed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Handlers rather than the SDK's tool collection. The collection is keyed by name and
    /// enumerates in dictionary order, which would replace the surface's exposure order — the
    /// single ordering authority — with an order no Manifest describes and no fingerprint
    /// covers. A handler serves the list it was given.
    /// </para>
    /// <para>
    /// A request that matched no surface leaves the session with no tool capability at all,
    /// rather than with an empty tool list. An empty list reads as a server that legitimately
    /// exposes nothing, which is the disclosure this avoids making.
    /// </para>
    /// <para>
    /// The identity handed back at handshake is the addressed surface's, copied field for
    /// field. The default is this assembly's own name and version, which would tell a client
    /// connected to one Manifest exactly what a client connected to another is told.
    /// </para>
    /// </remarks>
    private static Task ConfigureSessionAsync(
        HttpContext context,
        McpServerOptions options,
        CancellationToken cancellationToken)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<SurfaceEndpoint>() is not { } addressed)
        {
            return Task.CompletedTask;
        }

        ServerIdentity identity = addressed.Surface.Identity;

        options.ServerInfo = new Implementation
        {
            Name = identity.Name,
            Version = identity.Version,
            Title = identity.Title,
            Description = identity.Description,
        };

        options.Capabilities ??= new ServerCapabilities();
        options.Capabilities.Tools = new ToolsCapability();

        EngineExecution execution = context.RequestServices.GetRequiredService<EngineExecution>();

        options.Handlers.ListToolsHandler = (_, _)
            => ValueTask.FromResult(new ListToolsResult { Tools = [.. addressed.Definitions] });

        options.Handlers.CallToolHandler = (request, token)
            => ToolBridge.InvokeAsync(addressed, execution, request, token);

        return Task.CompletedTask;
    }
}
