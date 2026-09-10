using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// A running Engine, started the way the serving verb starts one.
/// </summary>
/// <remarks>
/// <para>
/// Built through <see cref="EngineWebHost"/> rather than through a hand-assembled
/// application, because a harness that composed its own listener would be asserting the
/// harness. Everything below the address is the product: the same registration, the same
/// route mapping, the same session hook.
/// </para>
/// <para>
/// Owned by the test that starts it and stopped when that test disposes it. Port zero asks
/// the operating system for a free port, so two suites cannot collide and a port number still
/// identifies which test is being served.
/// </para>
/// </remarks>
internal sealed class ServedEngine : IAsyncDisposable
{
    /// <summary>How long shutdown may take before it is abandoned.</summary>
    /// <remarks>
    /// Bounded deliberately. An unbounded stop inside disposal would hang the suite if a
    /// connection never drained, and the hang would be reported against whichever test
    /// happened to be running rather than against the teardown.
    /// </remarks>
    private static readonly TimeSpan ShutdownBudget = TimeSpan.FromSeconds(5);

    private readonly WebApplication _app;
    private readonly EngineExecution _execution;

    private ServedEngine(WebApplication app, Uri address, RuntimeStartResult started, EngineExecution execution)
    {
        _app = app;
        Address = address;
        Started = started;
        _execution = execution;
    }

    /// <summary>The address the listener bound.</summary>
    public Uri Address { get; }

    /// <summary>What startup produced, so a test can compare a listing against it.</summary>
    public RuntimeStartResult Started { get; }

    /// <summary>
    /// An outbound policy that judges no address.
    /// </summary>
    /// <remarks>
    /// The default for a served engine, because a served engine exists in these tests to be
    /// called and every upstream a test can start lives on loopback, which the shipped policy
    /// refuses. A test that wants to observe that refusal passes the real policy instead.
    /// </remarks>
    public static OutboundConnectionPolicy Permissive() => new(static _ => false);

    /// <summary>Starts a host for <paramref name="options"/>, which must not be refused.</summary>
    public static async Task<ServedEngine> StartAsync(
        RuntimeOptions options,
        CancellationToken cancellationToken,
        OutboundConnectionPolicy? connections = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        RuntimeStartResult started = EngineRuntime.Start(options);

        if (!started.Started)
        {
            throw new InvalidOperationException(
                "The runtime refused to start, so there is nothing to serve: "
                + string.Join("; ", started.Refusals.Select(refusal => refusal.Code + " " + refusal.Message)));
        }

        EngineExecution execution = EngineExecution.Create(started, connections ?? Permissive());

        WebApplication app = EngineWebHost.Build(
            started,
            new HostListenOptions("http://127.0.0.1:0", HostTransport.Http),
            execution);

        try
        {
            await app.StartAsync(cancellationToken);
        }
        catch
        {
            execution.Dispose();
            await app.DisposeAsync();
            throw;
        }

        try
        {
            string bound = app.Urls.Count == 1
                ? app.Urls.Single()
                : throw new InvalidOperationException(
                    $"Expected exactly one bound address, found {app.Urls.Count}: {string.Join(", ", app.Urls)}.");

            return new ServedEngine(app, new Uri(bound, UriKind.Absolute), started, execution);
        }
        catch
        {
            execution.Dispose();
            await StopQuietlyAsync(app);
            throw;
        }
    }

    /// <summary>The absolute address of one route under this host.</summary>
    public Uri At(string route) => new(Address, route);

    public async ValueTask DisposeAsync()
    {
        // The listener stops before the outbound pool closes. Closing the pool first would
        // abort a call that was still in flight and report it as a transport fault.
        await StopQuietlyAsync(_app);
        _execution.Dispose();
    }

    private static async Task StopQuietlyAsync(WebApplication app)
    {
        using var shutdown = new CancellationTokenSource(ShutdownBudget);

        try
        {
            await app.StopAsync(shutdown.Token);
        }
        finally
        {
            await app.DisposeAsync();
        }
    }
}
