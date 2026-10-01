using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Files;
using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using System.Net;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// Turns a started runtime into a listening process.
/// </summary>
/// <remarks>
/// <para>
/// Takes a <see cref="RuntimeStartResult"/> that already started, so a listener cannot exist
/// for a mount set that was refused. The order is the substance: loading, validating,
/// narrowing and deriving all happen before this file runs, which is what moves a deployment
/// fault from the first request to the start of the process.
/// </para>
/// <para>
/// The serving verb and the tests that observe a real connection both build through here, so
/// what a test starts is the process an operator starts.
/// </para>
/// </remarks>
public static class EngineWebHost
{
    /// <summary>Builds the listening application for a started runtime.</summary>
    /// <remarks>
    /// <para>
    /// The execution machinery is supplied rather than constructed here. It owns an outbound
    /// connection pool, and a pool whose disposal is decided by a container's teardown
    /// ordering would close connections at a moment no drain accounted for; the caller that
    /// started the process is the one that can say when.
    /// </para>
    /// <para>
    /// The whole bound configuration is taken rather than the listener half, because the
    /// authorization configuration is a deployment fact: the startup refusal for a
    /// scope-declaring mount with no issuer has to happen before the listener exists, and a
    /// caller that passed only the listener could forget to check.
    /// </para>
    /// </remarks>
    /// <param name="started">A runtime whose every mount is ready.</param>
    /// <param name="binding">Everything the command line resolved to.</param>
    /// <param name="execution">How a call reaches an upstream.</param>
    public static WebApplication Build(
        RuntimeStartResult started,
        HostBinding binding,
        EngineExecution execution)
        => Build(started, binding, execution, new DrainCoordinator());

    /// <summary>Builds the listener with the lifecycle coordinator owned by the command runner.</summary>
    internal static WebApplication Build(
        RuntimeStartResult started,
        HostBinding binding,
        EngineExecution execution,
        DrainCoordinator drain)
    {
        ArgumentNullException.ThrowIfNull(started);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(drain);

        if (!started.Started)
        {
            throw new InvalidOperationException(
                "A refused runtime has no listener. Nothing partially mounts, so a caller that "
                + "reached here has already ignored a refusal.");
        }

        MountSet mounts = MountSet.From(started);

        // File mode serves exactly the mounts startup loaded, and nothing ever replaces them.
        // The generation wraps the execution graph the command runner owns, so disposing it does
        // not dispose what it does not own.
        EngineGenerationManager generations = new(HostMode.File);
        _ = generations.Activate(new EngineGeneration(
            number: 0,
            mounts,
            execution,
            ownsExecution: false,
            externalResources: binding.ExternalResources));

        return BuildCore(
            binding,
            execution,
            drain,
            generations,
            managed: false);
    }

    /// <summary>Builds a listener whose served mounts an activation may replace.</summary>
    /// <remarks>
    /// Managed mode maps one template and resolves the addressed surface from the generation
    /// leased for the request. The manager must already hold the generation built from the initial
    /// synchronization; a listener without one would serve nothing while claiming to be ready.
    /// </remarks>
    internal static WebApplication BuildManaged(
        HostBinding binding,
        DrainCoordinator drain,
        EngineGenerationManager generations)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(drain);
        ArgumentNullException.ThrowIfNull(generations);

        if (generations.Mode != HostMode.Managed)
        {
            throw new InvalidOperationException(
                "A managed listener requires a managed generation manager; the supplied manager "
                + "serves a fixed mount set.");
        }

        if (generations.Current is not { } active)
        {
            throw new InvalidOperationException(
                "A managed listener requires one initial generation. The process must finish its "
                + "bounded initial synchronization before the listener opens; otherwise it would "
                + "serve an empty surface and claim to be ready.");
        }

        return BuildCore(
            binding,
            active.Execution,
            drain,
            generations,
            managed: true);
    }

    private static WebApplication BuildCore(
        HostBinding binding,
        EngineExecution execution,
        DrainCoordinator drain,
        EngineGenerationManager generations,
        bool managed)
    {
        if (generations.Current is not { } activeGeneration)
        {
            throw new InvalidOperationException("The listener has no active Engine generation.");
        }

        if (HostRouteTopologyValidation.Find(activeGeneration.Mounts) is { Count: > 0 } topologyRefusals)
        {
            StartupRefusal first = topologyRefusals[0];
            generations.Dispose();
            throw new InvalidOperationException(
                $"refused {first.Mount} [{first.Code}]: {first.Message}");
        }

        if (binding.Authorization is not null
            && activeGeneration.RequiresAllowedHostForProtectedResources
            && binding.AllowedHosts.Count == 0)
        {
            generations.Dispose();
            throw new InvalidOperationException(
                $"refused [auth/allowed-host-missing]: protected HTTP serving requires at least one '{HostConfiguration.AllowedHostKey}'.");
        }

        // The authorization pairing is a startup fact, not a request-time surprise. A mount
        // that requires a token exists and the process trusts no issuer: refusing here
        // names the mount, and an operator debugs their deployment rather than a client
        // that can only ever see a 401.
        StartupRefusal? unconfigured = AuthorizationRefusal.Find(
            generations.Current?.Mounts.Mounts ?? [],
            binding.Authorization);

        if (unconfigured is not null)
        {
            generations.Dispose();
            throw new InvalidOperationException(
                "refused " + unconfigured.Mount + ": " + unconfigured.Message);
        }

        // The content root is pinned to the executable's own directory rather than inherited
        // from the working directory, so the same command line means the same thing wherever
        // it was run from. Nothing is served off disk; an unresolvable root fails startup.
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            ContentRootPath = AppContext.BaseDirectory,
        });

        // The stock hosting diagnostics log the raw request URL. File download URLs contain a
        // bearer capability, so emitting those messages would copy the capability into a wider
        // operator log. Endpoint routing still logs the route template (with {capability}), and
        // warnings/errors remain available without reproducing the presented value.
        builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);

        builder.WebHost.UseUrls(binding.Listener.Listen);

        // Forwarded headers are honoured only from the addresses the operator named. Without
        // this, a process behind a TLS-terminating proxy would observe http, and every
        // protected-resource metadata document and audience comparison would name a scheme and
        // authority no client used. Trusting nobody by default is what keeps a client from
        // claiming the scheme for itself.
        if (binding.TrustedProxies.Count > 0)
        {
            builder.Services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

                foreach (string proxy in binding.TrustedProxies)
                {
                    if (IPAddress.TryParse(proxy, out IPAddress? address))
                    {
                        options.KnownProxies.Add(address);
                    }
                }
            });
        }

        builder.Services.AddSingleton(binding);
        builder.Services.AddSingleton(execution);
        builder.Services.AddSingleton(drain);
        builder.Services.AddSingleton(generations);
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddSingleton<EngineRequestGenerationAdmissionAccessor>();

        McpRegistration.AddEngineMcp(builder.Services);

        if (MountAuthorizationSetup.IsConfigured(binding.Authorization))
        {
            // An instance, not a type: the key is generated exactly once for the process, and a
            // type activation would let a later resolution produce a second key under which the
            // same callers would derive different partitions.
            builder.Services.AddSingleton(new CallerPartitionKey());
            builder.Services.AddSingleton(MountAuthorizationSetup.Validator(binding.Authorization!));

            builder.Services
                .AddAuthentication(MountAuthorizationSetup.BearerScheme)
                .AddScheme<AuthenticationSchemeOptions, BearerSchemeHandler>(
                    MountAuthorizationSetup.BearerScheme,
                    _ => { })
                .AddMcp(options =>
                {
                    // Per-surface metadata resolves through one generation lease so protection
                    // and the generation-owned effective resource identity are one decision.
                    options.Events.OnResourceMetadataRequest = context =>
                    {
                        var metadata = SurfaceMetadata.Build(
                            context.HttpContext,
                            binding.Authorization!,
                            generations,
                            binding.AllowedHosts);

                        if (metadata is null)
                        {
                            context.SkipHandler();
                            return Task.CompletedTask;
                        }

                        context.ResourceMetadata = metadata;
                        return Task.CompletedTask;
                    };
                });
        }

        WebApplication app = builder.Build();

        // The middleware must run before anything reads the request's scheme or client address.
        // It is installed only when proxies were configured, mirroring the registration above.
        if (binding.TrustedProxies.Count > 0)
        {
            app.UseForwardedHeaders();
        }

        // Spec 11 requires the MCP endpoint to validate the Origin header when it is present and
        // reject an unexpected origin. Only a browser sends that header, so the decision is "may
        // this browser origin call the MCP addresses"; a non-browser client that sends none is
        // served normally. It runs before admission so a refused origin costs no work.
        app.Use(async (context, next) =>
        {
            if (context.Request.Headers.Origin is { Count: > 0 } origins
                && !IsOriginAllowed(context, origins, binding.AllowedOrigins))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }

            await next(context).ConfigureAwait(false);
        });

        // Closing admission is distinct from closing the socket. During the drain window health
        // remains observable, while every new product request is refused immediately instead of
        // entering behind work that was already admitted.
        app.Use(async (context, next) =>
        {
            if (drain.IsDraining && !HealthEndpoints.IsHealthPath(context.Request.Path))
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                return;
            }

            await next(context).ConfigureAwait(false);
        });

        // Every Engine surface request, including an open surface and a transfer child, owns one
        // generation lease from this point through response completion. Authorization, transfer
        // dispatch and MCP handlers consume the non-owning admission feature instead of taking a
        // second lease from the manager.
        app.UseMiddleware<EngineRequestGenerationAdmissionMiddleware>();

        if (MountAuthorizationSetup.IsConfigured(binding.Authorization))
        {
            app.UseAuthentication();
            app.UseMiddleware<MountAuthorizationMiddleware>();
        }

        // Transfer children are recognised in middleware for both deployment modes. This keeps
        // file mode capable of serving slash-terminated parent resources whose exact child URL
        // contains a deliberate double slash, which ASP.NET route templates cannot express.
        // Admission and authorization have already bound the request to the exact parent resource.
        app.Use(async (context, next) =>
        {
            if (await FileTransferEndpoints.TryServeAsync(context).ConfigureAwait(false))
            {
                return;
            }

            await next(context).ConfigureAwait(false);
        });

        if (managed)
        {
            // One template for every MCP address, because an activation may introduce a mount the
            // process has never seen.
            McpRegistration.MapManagedTemplate(app);
        }
        else
        {
            McpRegistration.MapMounts(app, generations.Current!.Mounts);
        }

        HealthEndpoints.Map(app, binding.Runtime.FileStoreRoot, drain);

        // The operator channel is mapped last and only when a dedicated secret was configured.
        // Its routes are not MCP addresses, so neither the origin check nor generation admission
        // above applies to them; the endpoints authenticate and lease a generation themselves.
        ResponseCacheOperatorEndpoints.Map(app, binding);

        return app;
    }

    /// <summary>
    /// Whether a presented browser origin may call the MCP address this request reached.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Applies only to a served MCP address: health and the protected-resource metadata are read
    /// by tooling that is not a browser page, and refusing them on an origin would make a
    /// browser-based client unable to discover the resource it is allowed to call.
    /// </para>
    /// <para>
    /// The address is recognised from the endpoint's own metadata rather than from a hard-coded
    /// path prefix. A deployment may mount a Manifest at any prefix, so "is this an MCP address"
    /// is a property of the routing table, not of a string literal; in managed mode the same
    /// catch-all template also matches non-MCP paths, which must keep being served. The
    /// comparison is ordinal-ignore-case on the whole origin, with a trailing slash ignored
    /// because a browser never sends one and an operator may write one.
    /// </remarks>
    private static bool IsOriginAllowed(
        HttpContext context,
        IReadOnlyList<string> presented,
        IReadOnlyList<string> allowed)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<SurfaceEndpoint>() is null
            && !TransferPath.TryParse(context.Request.Path.Value, out _))
        {
            return true;
        }

        foreach (string origin in presented)
        {
            string candidate = origin.TrimEnd('/');

            if (allowed.Any(configured =>
                string.Equals(configured, candidate, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }
}
