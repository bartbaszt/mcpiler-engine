using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace MCPiler.Engine.Host.Cli;

/// <summary>
/// A short-lived, loopback-only callback listener owned by one <c>auth authorize</c> invocation.
/// </summary>
/// <remarks>
/// <para>
/// The listener binds exactly the loopback host and port of the operator's configured callback URI
/// and answers exactly its path. It captures the raw query string of the first matching request and
/// hands it to the attempt unchanged; it never parses, logs or echoes a callback value.
/// </para>
/// <para>
/// The callback query can carry a short-lived authorization code and the attempt's state, so the
/// host's default request logging is removed entirely: it prints the request line, including the
/// query. The confirmation page echoes nothing back to the browser.
/// </para>
/// </remarks>
internal sealed class OAuthLoopbackCallbackListener : IAsyncDisposable
{
    private readonly string _bindHost;
    private readonly int _port;
    private readonly string _path;
    private readonly TaskCompletionSource<string?> _callback = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private WebApplication? _app;

    private OAuthLoopbackCallbackListener(Uri redirect)
    {
        _bindHost = BindHost(redirect.Host);
        _port = redirect.Port;
        _path = redirect.AbsolutePath;
    }

    /// <summary>Creates the listener for the exact callback URI an attempt was registered for.</summary>
    internal static OAuthLoopbackCallbackListener For(Uri redirect) => new(redirect);

    /// <summary>Binds the listener. A failure here is a configuration refusal, not a crash.</summary>
    internal async Task StartAsync(CancellationToken cancellationToken)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls($"http://{_bindHost}:{_port.ToString(System.Globalization.CultureInfo.InvariantCulture)}");

        // Removed deliberately: ASP.NET's default request logging prints the request line, and the
        // callback query string it contains carries a short-lived authorization code and the state.
        builder.Logging.ClearProviders();

        WebApplication app = builder.Build();

        app.MapGet(_path, (HttpContext context) =>
        {
            _callback.TrySetResult(context.Request.QueryString.Value ?? string.Empty);
            return WriteConfirmationAsync(context);
        });

        await app.StartAsync(cancellationToken).ConfigureAwait(false);
        _app = app;
    }

    /// <summary>
    /// Waits for the first callback, returning its raw query string; null when the attempt expired
    /// or the command was cancelled before one arrived.
    /// </summary>
    internal async Task<string?> WaitAsync(DateTimeOffset expiresAtUtc, CancellationToken cancellationToken)
    {
        TimeSpan remaining = expiresAtUtc - DateTimeOffset.UtcNow;

        if (remaining <= TimeSpan.Zero)
        {
            return null;
        }

        try
        {
            return await _callback.Task.WaitAsync(remaining, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            return null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            // The listener was disposed while the command was still waiting.
            return null;
        }
    }

    private static async Task WriteConfirmationAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.WriteAsync(
            "<!doctype html><html><head><title>Authorization complete</title></head>"
            + "<body><p>You may close this window and return to the terminal.</p></body></html>",
            context.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>Wraps a literal IPv6 loopback so the listen URL is well formed.</summary>
    private static string BindHost(string host)
        => host.Contains(':', StringComparison.Ordinal) ? "[" + host + "]" : host;

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_app is not { } app)
        {
            // Disposed before the listener bound: nothing is accepting, so only release any waiter.
            _callback.TrySetCanceled(CancellationToken.None);
            return;
        }

        // Release any pending wait, then stop accepting. The port is closed before the command
        // returns, so a later invocation can rebind the same callback URI.
        _callback.TrySetCanceled(app.Lifetime.ApplicationStopping);

        try
        {
            await app.StopAsync(app.Lifetime.ApplicationStopping).ConfigureAwait(false);
        }
        finally
        {
            await app.DisposeAsync().ConfigureAwait(false);
        }
    }
}
