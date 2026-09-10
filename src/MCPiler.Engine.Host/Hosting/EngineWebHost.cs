using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;

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
    /// The execution machinery is supplied rather than constructed here. It owns an outbound
    /// connection pool, and a pool whose disposal is decided by a container's teardown
    /// ordering would close connections at a moment no drain accounted for; the caller that
    /// started the process is the one that can say when.
    /// </remarks>
    /// <param name="started">A runtime whose every mount is ready.</param>
    /// <param name="listener">Where to listen and how.</param>
    /// <param name="execution">How a call reaches an upstream.</param>
    public static WebApplication Build(
        RuntimeStartResult started,
        HostListenOptions listener,
        EngineExecution execution)
    {
        ArgumentNullException.ThrowIfNull(started);
        ArgumentNullException.ThrowIfNull(listener);
        ArgumentNullException.ThrowIfNull(execution);

        if (!started.Started)
        {
            throw new InvalidOperationException(
                "A refused runtime has no listener. Nothing partially mounts, so a caller that "
                + "reached here has already ignored a refusal.");
        }

        // The content root is pinned to the executable's own directory rather than inherited
        // from the working directory, so the same command line means the same thing wherever
        // it was run from. Nothing is served off disk; an unresolvable root fails startup.
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            ContentRootPath = AppContext.BaseDirectory,
        });

        builder.WebHost.UseUrls(listener.Listen);

        builder.Services.AddSingleton(execution);

        McpRegistration.AddEngineMcp(builder.Services);

        WebApplication app = builder.Build();

        McpRegistration.MapMounts(app, started.Mounts);

        return app;
    }
}
