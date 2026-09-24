using System.Net;

using MCPiler.Engine.Execution;

namespace MCPiler.Engine.Execution.Outbound;

/// <summary>
/// Builds the transport stack a set of limits calls for.
/// </summary>
/// <remarks>
/// Substituting this is how the redirect, header and replay semantics are exercised without a
/// socket. It is not a way to reconfigure the shipped stack: production uses
/// <see cref="UpstreamClientFactory.CreateSocketsHandler"/>, whose configuration is asserted
/// directly rather than inferred from an exchange.
/// </remarks>
/// <param name="limits">The governing transport limits.</param>
public delegate HttpMessageHandler UpstreamHandlerFactory(OutboundLimits limits);

/// <summary>
/// Builds and reuses the clients an upstream exchange is sent through, one per distinct set of
/// transport limits.
/// </summary>
/// <remarks>
/// <para>
/// The cache key is the limits value itself, not a connector name. A name is an identity that
/// can stay the same while the values behind it change, which is exactly the case where a
/// cached client is wrong: a limit edit would take effect on the next restart rather than on
/// the next execution. Keying on the value means a changed policy is a different key, and the
/// client built from the superseded values can be released.
/// </para>
/// <para>
/// The per-client timeout is infinite by construction. The deadline for an exchange is the
/// caller's token: a client-level timeout would be a second mechanism for one cause, and two
/// mechanisms produce two classifications — a slow single request would report as a transport
/// cancellation on one path and a budget expiry on the other.
/// </para>
/// </remarks>
public sealed class UpstreamClientFactory : IDisposable
{
    /// <summary>The user agent every Engine-originated request announces.</summary>
    public const string UserAgent = UpstreamRequestDefaults.UserAgent;

    private readonly UpstreamHandlerFactory _handlers;
    private readonly bool _cookieStateObservable;
    private readonly Lock _gate = new();
    private readonly Dictionary<OutboundLimits, HttpClient> _clients = [];
    private bool _disposed;

    /// <summary>Creates a factory whose sockets are opened by the shipped outbound policy.</summary>
    public UpstreamClientFactory()
        : this(new OutboundConnectionPolicy())
    {
    }

    /// <summary>Creates a factory whose sockets are opened by <paramref name="connections"/>.</summary>
    public UpstreamClientFactory(OutboundConnectionPolicy connections)
    {
        ArgumentNullException.ThrowIfNull(connections);
        _handlers = limits => CreateSocketsHandler(limits, connections);
        _cookieStateObservable = true;
    }

    /// <summary>Creates a factory over a substituted transport stack.</summary>
    public UpstreamClientFactory(UpstreamHandlerFactory handlers)
    {
        ArgumentNullException.ThrowIfNull(handlers);
        _handlers = handlers;
        _cookieStateObservable = false;
    }

    /// <summary>Whether the stock handler has no hidden, externally pre-seeded cookie state.</summary>
    internal bool CookieStateObservable => _cookieStateObservable;

    /// <summary>The number of distinct policies currently holding a client.</summary>
    public int CachedClientCount
    {
        get
        {
            lock (_gate)
            {
                return _clients.Count;
            }
        }
    }

    /// <summary>
    /// The shipped transport stack for <paramref name="limits"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Automatic redirect following is off, because the perimeter has to be re-checked at every
    /// hop and a handler that follows redirects itself would already have connected before
    /// anything could refuse the destination.
    /// </para>
    /// <para>
    /// Decompression is on, because the response ceiling counts decoded bytes: a payload that
    /// only fits while compressed is not within the ceiling, and leaving the body compressed
    /// would move the decision about how large it is to whoever expands it later.
    /// </para>
    /// <para>
    /// The connect timeout stays on the handler and stays per-connection. It bounds
    /// establishing a socket rather than awaiting a response, and a redirect chain legitimately
    /// opens a new connection for each origin it visits.
    /// </para>
    /// </remarks>
    public static SocketsHttpHandler CreateSocketsHandler(OutboundLimits limits, OutboundConnectionPolicy connections)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentNullException.ThrowIfNull(connections);

        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = limits.ConnectTimeout,
            MaxConnectionsPerServer = limits.MaxConnectionsPerServer,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            ConnectCallback = (context, cancellationToken) =>
                connections.ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, cancellationToken),
        };
    }

    /// <summary>Returns the client governed by <paramref name="limits"/>, building it once.</summary>
    public HttpClient Client(OutboundLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ObjectDisposedException.ThrowIf(_disposed, this);

        lock (_gate)
        {
            if (_clients.TryGetValue(limits, out var existing))
            {
                return existing;
            }

            var created = new HttpClient(_handlers(limits), disposeHandler: true)
            {
                Timeout = Timeout.InfiniteTimeSpan,
            };

            created.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);

            _clients[limits] = created;
            return created;
        }
    }

    /// <summary>Releases every client built for a policy other than <paramref name="current"/>.</summary>
    /// <returns>The number of clients released.</returns>
    /// <remarks>
    /// A superseded client is not merely unused: it holds open connections configured by values
    /// an operator has already changed, so an upstream would keep being reached under the
    /// previous connect timeout and connection ceiling for as long as those sockets live.
    /// </remarks>
    public int ReleaseOtherThan(OutboundLimits current)
    {
        ArgumentNullException.ThrowIfNull(current);

        lock (_gate)
        {
            var superseded = _clients.Where(entry => entry.Key != current).ToList();

            foreach (var (limits, client) in superseded)
            {
                client.Dispose();
                _clients.Remove(limits);
            }

            return superseded.Count;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        lock (_gate)
        {
            foreach (var client in _clients.Values)
            {
                client.Dispose();
            }

            _clients.Clear();
        }
    }
}
