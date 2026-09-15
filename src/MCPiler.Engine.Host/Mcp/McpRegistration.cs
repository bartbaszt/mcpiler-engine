using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace MCPiler.Engine.Host.Mcp;

/// <summary>
/// The address a route represents, without the surface that address resolves to.
/// </summary>
/// <remarks>
/// <para>
/// Endpoint metadata must stay valid for the life of the listener, while the surface an address
/// resolves to belongs to one immutable generation. Carrying the surface here would freeze the
/// generation into the route table, so a request admitted after an activation would route under
/// the new generation and execute against the old surface. The address is therefore the only
/// thing a route states, and resolution happens through a lease taken for the admission.
/// </para>
/// <para>
/// <see cref="Address"/> is null for a managed template route, where the map is wide enough to
/// carry any mount; the request path is then the address. It is non-null for a file-mode route,
/// where the address is exactly what was mapped.
/// </para>
/// </remarks>
internal sealed class SurfaceEndpoint
{
    internal SurfaceEndpoint(string? address, string? authorizationResourcePath = null)
    {
        Address = address;
        AuthorizationResourcePath = authorizationResourcePath;
    }

    /// <summary>The mapped address, or null when the request path is the address.</summary>
    public string? Address { get; }

    /// <summary>
    /// A parent resource path inherited by a child endpoint, or null when the request path itself
    /// is the protected resource. MCP routes leave this null; transfer child routes set it.
    /// </summary>
    public string? AuthorizationResourcePath { get; }

    /// <summary>The address this request actually used.</summary>
    /// <remarks>
    /// A trailing slash is not part of an address. ASP.NET Core routing treats it as absent when
    /// matching a literal pattern, and the mapped address never carries one, so it is removed here
    /// before the address is compared.
    /// </remarks>
    public string ResolveAddress(HttpContext context)
    {
        if (Address is { } mapped)
        {
            return mapped;
        }

        string path = context.Request.Path.Value ?? "/";

        return path.Length > 1 && path.EndsWith('/') ? path[..^1] : path;
    }
}

/// <summary>
/// The address a request reached, once a transfer child is folded back onto its parent.
/// </summary>
/// <remarks>
/// A managed listener maps one template, which also matches the transfer children. Those children
/// are not protected resources of their own: they inherit the parent surface's identity and mount,
/// so an authorization or dispatch decision must resolve them to the parent address rather than to
/// the whole path.
/// </remarks>
internal static class RequestAddress
{
    /// <summary>Resolves the request to the surface address that governs it.</summary>
    internal static string Resolve(HttpContext context, SurfaceEndpoint route)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(route);

        if (route.Address is not null)
        {
            return route.Address;
        }

        string path = route.ResolveAddress(context);

        return Files.TransferPath.TryParse(path, out Files.TransferPath transfer)
            ? transfer.ParentAddress
            : path;
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
    /// <summary>The template a managed listener maps once and resolves per request.</summary>
    /// <remarks>
    /// One template rather than one route per address: a managed activation may introduce a mount
    /// the process has never seen, and a route added after the listener started would need the
    /// endpoint table to grow. The address is what the lease resolves, so the map can stay wide.
    /// </remarks>
    public const string ManagedTemplate = "/{**path}";

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
    public static void MapMounts(WebApplication app, MountSet mounts)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(mounts);

        foreach (MountedSurfaceAddress address in mounts.Addresses)
        {
            app.MapMcp(address.Path).WithMetadata(new SurfaceEndpoint(address.Path));
        }
    }

    /// <summary>Maps the managed template an activation resolves through.</summary>
    public static void MapManagedTemplate(WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.MapMcp(ManagedTemplate).WithMetadata(new SurfaceEndpoint(address: null));
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
    /// <para>
    /// The session is not pinned to the generation it started in. Each listing and each call
    /// takes a fresh lease and resolves its address again, so a surface an activation removed
    /// cannot be reached through a session that predates the activation.
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

        EngineGenerationManager generations =
            context.RequestServices.GetRequiredService<EngineGenerationManager>();

        string address = RequestAddress.Resolve(context, route);
        string identity = MountAuthorization.CanonicalResource(
            context.Request.Scheme,
            context.Request.Host.Value ?? string.Empty,
            route.AuthorizationResourcePath ?? address);

        DrainCoordinator drain = context.RequestServices.GetRequiredService<DrainCoordinator>();

        ConfigureSurface(options, address, identity, generations.LeaseSource, drain);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Configures one protocol session from one already-derived address.
    /// </summary>
    /// <remarks>
    /// Both transports call this method. Keeping identity, listing and invocation handlers here
    /// makes transport parity structural: HTTP and stdio differ in framing and reachability, while
    /// the surface they expose is the same object with the same handlers.
    /// </remarks>
    internal static void ConfigureSurface(
        McpServerOptions options,
        string address,
        string resourceIdentity,
        GenerationLeaseSource leases,
        DrainCoordinator drain)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceIdentity);
        ArgumentNullException.ThrowIfNull(leases);
        ArgumentNullException.ThrowIfNull(drain);

        if (leases() is not { } lease)
        {
            return;
        }

        using (lease)
        {
            if (!lease.Generation.TryResolve(address, out SurfaceResolution? resolved) || resolved is null)
            {
                return;
            }

            ServerIdentity identity = resolved.Surface.Identity;

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
                => ListToolsAsync(address, leases, request.Server?.NegotiatedProtocolVersion);

            options.Handlers.CallToolHandler = (request, token)
                => ToolBridge.InvokeAsync(address, resourceIdentity, leases, drain, request, token);
        }
    }

    private static ValueTask<ListToolsResult> ListToolsAsync(
        string address,
        GenerationLeaseSource leases,
        string? negotiatedProtocolRevision)
    {
        if (leases() is not { } lease)
        {
            return ValueTask.FromResult(new ListToolsResult { Tools = [] });
        }

        using (lease)
        {
            if (!lease.Generation.TryResolve(address, out SurfaceResolution? resolved) || resolved is null)
            {
                // The surface this session started against is no longer served. An empty list is
                // the answer a route that never existed would give.
                return ValueTask.FromResult(new ListToolsResult { Tools = [] });
            }

            return ValueTask.FromResult(new ListToolsResult
            {
                Tools = [.. lease.Generation.Definitions(address, resolved.Surface, negotiatedProtocolRevision)],
            });
        }
    }
}
