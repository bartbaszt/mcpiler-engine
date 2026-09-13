using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace MCPiler.Engine.Host.Mcp;

/// <summary>
/// One addressable surface, with its protocol definitions cached by negotiated revision.
/// </summary>
/// <remarks>
/// <para>
/// Attached to the route as endpoint metadata, which is how a request finds the surface it
/// addressed. The alternative — reading the path back apart into a mount and a slug — would
/// make routing decide once and then decide again differently, and the second decision is the
/// one that would accept a path a router had already normalized.
/// </para>
/// <para>
/// Definitions are built once for each revision this route actually negotiates. A listing
/// therefore enumerates objects that already exist, while the revision-dependent advertisement
/// decision remains request-scoped. Rebuilding on every listing would make byte-identity rest
/// on repeated rendering rather than on there being one set of objects.
/// </para>
/// </remarks>
internal sealed class SurfaceEndpoint
{
    private readonly Dictionary<string, IReadOnlyList<Tool>> _definitions =
        new(StringComparer.Ordinal);
    private readonly object _definitionsGate = new();

    internal SurfaceEndpoint(
        MountedManifest mount,
        MountedSurface surface,
        string resourceIdentity,
        string? authorizationResourcePath = null)
    {
        Mount = mount;
        Surface = surface;
        ResourceIdentity = resourceIdentity;
        AuthorizationResourcePath = authorizationResourcePath;
    }

    /// <summary>The mount this surface belongs to.</summary>
    public MountedManifest Mount { get; }

    /// <summary>The surface addressed.</summary>
    public MountedSurface Surface { get; }

    /// <summary>The exact protected-resource identity this route represents.</summary>
    public string ResourceIdentity { get; }

    /// <summary>
    /// A parent resource path inherited by a child endpoint, or null when the request path itself
    /// is the protected resource. MCP routes leave this null; transfer child routes set it.
    /// </summary>
    public string? AuthorizationResourcePath { get; }

    /// <summary>Maps the compiled catalogue for one negotiated protocol revision.</summary>
    public IReadOnlyList<Tool> Definitions(string? negotiatedProtocolRevision)
    {
        string key = negotiatedProtocolRevision ?? string.Empty;

        lock (_definitionsGate)
        {
            if (!_definitions.TryGetValue(key, out IReadOnlyList<Tool>? definitions))
            {
                definitions = SdkTranslation.Define(Surface, negotiatedProtocolRevision);
                _definitions.Add(key, definitions);
            }

            return definitions;
        }
    }
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
                string qualifiedPath = mount.Prefix + "/" + surface.Slug;
                app.MapMcp(qualifiedPath).WithMetadata(
                    new SurfaceEndpoint(mount, surface, ResourceIdentity(app, qualifiedPath)));

                if (surface.IsDefault)
                {
                    app.MapMcp(mount.Prefix).WithMetadata(
                        new SurfaceEndpoint(mount, surface, ResourceIdentity(app, mount.Prefix)));
                }
            }
        }
    }

    private static string ResourceIdentity(WebApplication app, string path)
    {
        // The listener may bind port zero and learn its concrete authority only after start,
        // so route registration cannot freeze scheme/host here. The path is the part routing
        // decides. ConfigureSession replaces this provisional value with the request's exact
        // canonical identity before a handler is installed.
        return path;
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
        if (context.GetEndpoint()?.Metadata.GetMetadata<SurfaceEndpoint>() is not { } route)
        {
            return Task.CompletedTask;
        }

        SurfaceEndpoint addressed = new(
            route.Mount,
            route.Surface,
            MountAuthorization.CanonicalResource(
                context.Request.Scheme,
                context.Request.Host.Value ?? string.Empty,
                context.Request.Path.Value ?? "/"));

        EngineExecution execution = context.RequestServices.GetRequiredService<EngineExecution>();
        ConfigureSurface(options, addressed, execution);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Configures one protocol session from one already-derived surface.
    /// </summary>
    /// <remarks>
    /// Both transports call this method. Keeping identity, listing and invocation handlers here
    /// makes transport parity structural: HTTP and stdio differ in framing and reachability, while
    /// the surface they expose is the same object with the same handlers.
    /// </remarks>
    internal static void ConfigureSurface(
        McpServerOptions options,
        SurfaceEndpoint addressed,
        EngineExecution execution)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(addressed);
        ArgumentNullException.ThrowIfNull(execution);

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

        options.Handlers.ListToolsHandler = (request, _)
            => ValueTask.FromResult(new ListToolsResult
            {
                Tools = [.. addressed.Definitions(request.Server?.NegotiatedProtocolVersion)],
            });

        options.Handlers.CallToolHandler = (request, token)
            => ToolBridge.InvokeAsync(addressed, execution, request, token);
    }
}
