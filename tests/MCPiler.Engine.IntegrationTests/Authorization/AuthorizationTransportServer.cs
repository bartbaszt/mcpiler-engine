using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Authorization;

/// <summary>
/// Owns a real loopback HTTP listener for authorization redirect tests.
/// </summary>
/// <remarks>
/// The production authorization clients, including their <see cref="HttpClientHandler"/>, are
/// used to reach this server. The helper records requests at the second hop so a test can prove
/// that a redirect response did not forward a credential-bearing request.
/// </remarks>
internal sealed class AuthorizationTransportServer : IAsyncDisposable
{
    private static readonly TimeSpan ShutdownBudget = TimeSpan.FromSeconds(5);

    private readonly WebApplication _app;
    private readonly Func<HttpContext, Task> _handler;
    private readonly List<string> _requestPaths = [];
    private int _requestCount;
    private string? _lastAuthorization;
    private string? _lastBody;

    private AuthorizationTransportServer(WebApplication app, Func<HttpContext, Task> handler)
    {
        _app = app;
        _handler = handler;
    }

    public Uri Address { get; private set; } = null!;

    public int RequestCount => Volatile.Read(ref _requestCount);

    /// <summary>Every request path this server has answered, in arrival order.</summary>
    /// <remarks>
    /// A count alone cannot prove which well-known an authorization client actually asked for, and
    /// the discovery tests need exactly that: the issuer-derived OIDC path must be absent from the
    /// list when no fallback is permitted.
    /// </remarks>
    public IReadOnlyList<string> RequestedPaths
    {
        get
        {
            lock (_requestPaths)
            {
                return [.. _requestPaths];
            }
        }
    }

    public string? LastAuthorization => Volatile.Read(ref _lastAuthorization);

    public string? LastBody => Volatile.Read(ref _lastBody);

    public static async Task<AuthorizationTransportServer> StartAsync(
        Func<HttpContext, Task> handler)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        WebApplication app = builder.Build();

        AuthorizationTransportServer server = new(app, handler);
        app.Run(server.HandleAsync);
        await app.StartAsync(TestContext.Current.CancellationToken);

        server.Address = new Uri(app.Urls.Single(), UriKind.Absolute);
        return server;
    }

    private async Task HandleAsync(HttpContext context)
    {
        Interlocked.Increment(ref _requestCount);
        _lastAuthorization = context.Request.Headers.Authorization.ToString();

        lock (_requestPaths)
        {
            _requestPaths.Add(context.Request.Path.Value ?? string.Empty);
        }

        context.Request.EnableBuffering();
        using (StreamReader reader = new(context.Request.Body, Encoding.UTF8, leaveOpen: true))
        {
            _lastBody = await reader.ReadToEndAsync(context.RequestAborted);
        }

        context.Request.Body.Position = 0;
        await _handler(context);
    }

    public async ValueTask DisposeAsync()
    {
        using CancellationTokenSource shutdown = new(ShutdownBudget);

        try
        {
            await _app.StopAsync(shutdown.Token);
        }
        catch (OperationCanceledException)
        {
            // A fake that will not stop cannot fail the test it served.
        }
        finally
        {
            await _app.DisposeAsync();
        }
    }
}

/// <summary>
/// Sends every destination to one real proxy listener. The production proxy policy decides whether
/// this proxy is consulted; the listener's request count is the non-vacuous evidence.
/// </summary>
internal sealed class FixedWebProxy(Uri proxyAddress) : IWebProxy
{
    public ICredentials? Credentials { get; set; }

    public Uri GetProxy(Uri destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        return proxyAddress;
    }

    public bool IsBypassed(Uri host)
    {
        ArgumentNullException.ThrowIfNull(host);
        return false;
    }
}
