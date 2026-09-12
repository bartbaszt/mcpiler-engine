using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

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
    {
        ArgumentNullException.ThrowIfNull(started);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(execution);

        if (!started.Started)
        {
            throw new InvalidOperationException(
                "A refused runtime has no listener. Nothing partially mounts, so a caller that "
                + "reached here has already ignored a refusal.");
        }

        // The authorization pairing is a startup fact, not a request-time surprise. A mount
        // that requires a token exists and the process trusts no issuer: refusing here
        // names the mount, and an operator debugs their deployment rather than a client
        // that can only ever see a 401.
        StartupRefusal? unconfigured = AuthorizationRefusal.Find(started.Mounts, binding.Authorization);

        if (unconfigured is not null)
        {
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

        builder.WebHost.UseUrls(binding.Listener.Listen);

        builder.Services.AddSingleton(execution);

        McpRegistration.AddEngineMcp(builder.Services);

        if (MountAuthorizationSetup.IsConfigured(binding.Authorization))
        {
            builder.Services.AddSingleton(MountAuthorizationSetup.Validator(binding.Authorization!));

            builder.Services
                .AddAuthentication(MountAuthorizationSetup.BearerScheme)
                .AddScheme<AuthenticationSchemeOptions, BearerSchemeHandler>(
                    MountAuthorizationSetup.BearerScheme,
                    _ => { })
                .AddMcp(options =>
                {
                    // Per-surface metadata is derived from the addressed path by the event:
                    // the canonical resource identifier is the exact address the client
                    // connected to, which only the request knows.
                    options.Events.OnResourceMetadataRequest = context =>
                    {
                        context.ResourceMetadata = SurfaceMetadata.Build(
                            context.HttpContext,
                            binding.Authorization!);
                        return Task.CompletedTask;
                    };
                });
        }

        WebApplication app = builder.Build();

        if (MountAuthorizationSetup.IsConfigured(binding.Authorization))
        {
            app.UseAuthentication();
            app.UseMiddleware<MountAuthorizationMiddleware>();
        }

        McpRegistration.MapMounts(app, started.Mounts);

        return app;
    }
}
