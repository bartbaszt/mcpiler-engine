using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace MCPiler.Engine.IntegrationTests;

/// <summary>
/// An in-process HTTP server bound to an ephemeral loopback port, used by the tests that
/// have to observe a real connection rather than a substituted message handler.
/// </summary>
/// <remarks>
/// <para>
/// The host is owned by the test that starts it and stops when that test disposes it. It is
/// not a fixture shared across a class: a suite that leaves a listener running between tests
/// makes a later failure depend on an earlier test's handler, and the port number stops
/// identifying which test is being served.
/// </para>
/// <para>
/// Two addresses are exposed because they are not interchangeable. <see cref="Address"/> is
/// the literal address the listener is bound to, and is what an address policy sees.
/// <see cref="LocalhostAddress"/> names the same endpoint through a hostname, which is what
/// an origin comparison sees. A test that wants to exercise host-shaped origin handling must
/// use the second; a test that wants to exercise address-shaped policy must use the first.
/// </para>
/// <para>
/// A test that sends through the production outbound policy will be refused, because loopback
/// is a denied range and refusing it is the policy working. Those tests assert the refusal.
/// A test that needs the request to arrive supplies a permissive policy through the outbound
/// port instead of weakening the real one — which is the reason that port exists.
/// </para>
/// </remarks>
internal sealed class LoopbackHost : IAsyncDisposable
{
    /// <summary>
    /// How long shutdown may take before it is abandoned. Bounded on purpose: an unbounded
    /// <c>StopAsync</c> inside <see cref="DisposeAsync"/> would hang the whole suite if a
    /// connection never drained, and a hung teardown reports as a timeout in whichever test
    /// happens to be running rather than as a defect here.
    /// </summary>
    private static readonly TimeSpan ShutdownBudget = TimeSpan.FromSeconds(5);

    private readonly WebApplication _app;

    private LoopbackHost(WebApplication app, Uri address)
    {
        _app = app;
        Address = address;
    }

    /// <summary>The bound address, always on the literal loopback host.</summary>
    public Uri Address { get; }

    /// <summary>The same endpoint addressed by hostname rather than by literal address.</summary>
    public Uri LocalhostAddress => new UriBuilder(Address) { Host = "localhost" }.Uri;

    /// <summary>Starts a server that answers every request with <paramref name="handler"/>.</summary>
    public static async Task<LoopbackHost> StartAsync(RequestDelegate handler, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);

        // The content root is pinned to the test binary's directory rather than inherited from
        // the working directory, so a runner that starts elsewhere cannot change what this host
        // resolves. Nothing is served from disk, but an unresolvable content root fails startup.
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = AppContext.BaseDirectory,
            EnvironmentName = "Testing",
        });

        // Port 0 asks the operating system for a free port, so concurrent suites cannot collide
        // on a hard-coded one.
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();

        var app = builder.Build();
        app.Run(handler);

        try
        {
            await app.StartAsync(cancellationToken);
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }

        try
        {
            var bound = app.Urls.Count == 1
                ? app.Urls.Single()
                : throw new InvalidOperationException(
                    $"Expected exactly one bound address, found {app.Urls.Count}: {string.Join(", ", app.Urls)}.");

            return new LoopbackHost(app, new Uri(bound, UriKind.Absolute));
        }
        catch
        {
            await StopQuietlyAsync(app);
            throw;
        }
    }

    /// <summary>Starts a server that answers every request with one fixed response.</summary>
    public static Task<LoopbackHost> StartAsync(
        int statusCode,
        string mediaType,
        byte[] body,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mediaType);
        ArgumentNullException.ThrowIfNull(body);

        return StartAsync(
            async context =>
            {
                context.Response.StatusCode = statusCode;
                context.Response.ContentType = mediaType;
                context.Response.ContentLength = body.Length;
                await context.Response.Body.WriteAsync(body, context.RequestAborted);
            },
            cancellationToken);
    }

    public async ValueTask DisposeAsync() => await StopQuietlyAsync(_app);

    /// <summary>
    /// Stops and disposes the host under a bounded budget. Stop precedes dispose so the listener
    /// is closed deliberately rather than as a side effect of teardown; a disposed-but-listening
    /// host would hand the next test a port that answers with the previous test's handler.
    /// </summary>
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
