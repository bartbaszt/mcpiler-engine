using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>Runs one mounted surface as one local MCP session over standard streams.</summary>
/// <remarks>
/// <para>
/// Stdio is deliberately single-surface. It has no request address from which a client could
/// select a mount or surface, so accepting an ambiguous runtime would make configuration order
/// decide what the client reached.
/// </para>
/// <para>
/// This transport opens no network listener and performs no bearer-token authorization. The
/// operating-system process boundary authorizes the local caller. Consequently inbound host
/// restriction, trusted-proxy processing and network rate limiting have no inbound request to
/// apply to; that security requirement is satisfied vacuously rather than left unevaluated.
/// </para>
/// <para>
/// Framing, negotiation and session lifetime belong to the MCP SDK. This type only chooses the
/// already-derived surface and supplies the same handlers the HTTP transport uses.
/// </para>
/// </remarks>
internal static class StdioTransport
{
    /// <summary>The operator-visible statement of stdio's authorization and network boundary.</summary>
    internal const string SecurityBoundaryStatement =
        "stdio: no network listener; the process boundary authorizes the local caller, so bearer authorization, host restriction, trusted-proxy processing and network rate limiting do not apply.";

    /// <summary>Runs the production transport on stdin/stdout until the SDK session ends.</summary>
    internal static Task RunAsync(
        RuntimeStartResult started,
        EngineExecution execution,
        CancellationToken cancellationToken)
        => RunCoreAsync(started, execution, input: null, output: null, cancellationToken);

    /// <summary>Runs the same SDK transport on explicit streams for wire-level tests.</summary>
    internal static Task RunAsync(
        RuntimeStartResult started,
        EngineExecution execution,
        Stream input,
        Stream output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);

        return RunCoreAsync(started, execution, input, output, cancellationToken);
    }

    /// <summary>Selects the only surface stdio can address.</summary>
    internal static bool TrySelectSurface(
        RuntimeStartResult started,
        out SurfaceEndpoint? endpoint,
        out string? refusal)
    {
        ArgumentNullException.ThrowIfNull(started);

        if (!started.Started)
        {
            endpoint = null;
            refusal = "stdio cannot serve a runtime that startup refused.";
            return false;
        }

        if (started.Mounts.Count != 1)
        {
            endpoint = null;
            refusal = $"stdio requires exactly one mounted Manifest because it has no address with which to select one; found {started.Mounts.Count}.";
            return false;
        }

        MountedManifest mount = started.Mounts[0];

        if (mount.Surfaces.Count != 1)
        {
            endpoint = null;
            refusal = $"stdio requires exactly one surface because it has no address with which to select one; mount '{mount.Prefix}' exposes {mount.Surfaces.Count}.";
            return false;
        }

        // The scope deliberately is not an HTTP URI. There is no protected network resource
        // on stdio, and a fresh process-local value prevents a local handle scope from being
        // mistaken for a stable remote audience.
        string resourceScope = "stdio-process-" + Guid.NewGuid().ToString("N");
        endpoint = new SurfaceEndpoint(mount, mount.Surfaces[0], resourceScope);
        refusal = null;
        return true;
    }

    private static async Task RunCoreAsync(
        RuntimeStartResult started,
        EngineExecution execution,
        Stream? input,
        Stream? output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(started);
        ArgumentNullException.ThrowIfNull(execution);

        if (!TrySelectSurface(started, out SurfaceEndpoint? endpoint, out string? refusal))
        {
            throw new InvalidOperationException(refusal);
        }

        HostApplicationBuilder builder = Microsoft.Extensions.Hosting.Host.CreateApplicationBuilder();

        // Console logging would share stdout with protocol frames. Startup/operator text is
        // emitted by the command runner on stderr, so the hosted SDK session needs no provider.
        builder.Logging.ClearProviders();

        IMcpServerBuilder server = builder.Services
            .AddMcpServer(options => McpRegistration.ConfigureSurface(options, endpoint!, execution));

        if (input is null)
        {
            server.WithStdioServerTransport();
        }
        else
        {
            server.WithStreamServerTransport(input, output!);
        }

        using IHost host = builder.Build();
        await host.RunAsync(cancellationToken).ConfigureAwait(false);
    }
}
