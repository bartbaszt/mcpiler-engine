namespace MCPiler.Engine.Execution;

/// <summary>
/// One outbound exchange, described without naming a transport.
/// </summary>
/// <remarks>
/// A compiled request is bytes plus metadata; this type is the same information expressed as
/// something an adapter can send. It exists so the execution decisions — which destination is
/// admissible, which credential applies, when a budget is exhausted, how a response is
/// classified — stay in a component that reaches nothing, and so the whole path is exercisable
/// against a substitute that opens no socket.
/// </remarks>
public sealed record UpstreamRequest
{
    /// <summary>The upper-case HTTP method.</summary>
    public required string Method { get; init; }

    /// <summary>The absolute destination.</summary>
    public required Uri Uri { get; init; }

    /// <summary>Headers to send, compared case-insensitively by name.</summary>
    public IReadOnlyDictionary<string, string[]> Headers { get; init; } =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The body bytes, or null when the request carries none.</summary>
    public byte[]? Body { get; init; }

    /// <summary>A replayable streaming body, mutually exclusive with <see cref="Body"/>.</summary>
    public ReplayableBodySource? BodySource { get; init; }

    /// <summary>The complete media type of the body, parameters included.</summary>
    public string? BodyMediaType { get; init; }

    /// <summary>
    /// Header names carrying credential material, which a redirect to another origin must not
    /// replay.
    /// </summary>
    /// <remarks>
    /// The set is supplied rather than derived from the names, because a contract may place a
    /// secret in any header it likes. The well-known names are sensitive unconditionally; this
    /// collection is what makes a configured one sensitive too.
    /// </remarks>
    public IReadOnlyCollection<string> SensitiveHeaders { get; init; } = [];

    /// <summary>
    /// Query parameter names carrying credential or signature material. Transport diagnostics
    /// redact these values while preserving ordinary request structure.
    /// </summary>
    public IReadOnlyCollection<string> SensitiveQueryParameters { get; init; } = [];

    /// <summary>
    /// Optional header values for keyed identity after credential values have been replaced by
    /// stable authority markers. Never passed to the transport.
    /// </summary>
    internal IReadOnlyDictionary<string, string[]>? CacheIdentityHeaders { get; init; }

    /// <summary>Header names whose cache-identity values are wholly represented by authority.</summary>
    internal IReadOnlyCollection<string> AuthorityRepresentedSensitiveHeaders { get; init; } = [];

    /// <summary>The credential-normalized URI used only for opaque cache identity derivation.</summary>
    internal Uri? CacheIdentityUri { get; init; }
}

/// <summary>The governing outbound policy for one exchange.</summary>
/// <param name="AllowedOrigins">
/// The perimeter. Re-evaluated before the first request and before every redirect hop.
/// </param>
/// <param name="Limits">
/// The transport limits the client is built from: connect timeout, hop limit, concurrency.
/// The total time budget is NOT here — it is the caller's cancellation token, because a budget
/// that the transport re-derived per call could not span a chain the caller is measuring.
/// </param>
/// <param name="SignRequest">
/// An optional per-hop rewrite applied to the request immediately before each hop is sent.
/// </param>
/// <remarks>
/// The hook exists because a request signature covers the exact bytes, destination and headers of
/// one hop: a redirect target is a different request, and a signature carried to it would either
/// be rejected or, worse, accepted for a destination it never covered. Signing is therefore
/// re-evaluated per hop rather than once per exchange.
///
/// It is a delegate over <see cref="UpstreamRequest"/> rather than over a signer type so the
/// transport stays unaware of what signing is; the execution layer builds the closure. The hook
/// returns the request to send, and a hop's returned request is what the next hop's redirect rules
/// are applied to.
/// </remarks>
public sealed record UpstreamSendPolicy(
    OriginAllowList AllowedOrigins,
    OutboundLimits Limits,
    Func<UpstreamRequest, int, CancellationToken, ValueTask<UpstreamRequest>>? SignRequest = null);

/// <summary>
/// A response whose metadata has already been captured and whose body is still streaming.
/// </summary>
/// <remarks>
/// Status, headers and media type are values by the time this exists, so nothing downstream can
/// depend on reading them from a released transport object. The body is a stream because the
/// size ceiling is enforced over decoded bytes while they arrive; buffering first would spend
/// exactly the memory the ceiling protects.
/// </remarks>
public sealed class UpstreamResponse : IAsyncDisposable
{
    private readonly IAsyncDisposable? _owner;

    /// <summary>Creates a captured response.</summary>
    /// <param name="statusCode">The observed status code.</param>
    /// <param name="headers">Response headers and content headers together.</param>
    /// <param name="mediaType">The observed media type without parameters, when one was stated.</param>
    /// <param name="body">The undecoded-length body stream.</param>
    /// <param name="owner">
    /// The transport resource whose lifetime the stream depends on, released by
    /// <see cref="DisposeAsync"/>.
    /// </param>
    public UpstreamResponse(
        int statusCode,
        IReadOnlyDictionary<string, string[]> headers,
        string? mediaType,
        Stream body,
        IAsyncDisposable? owner = null,
        bool wasRedirected = false)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(body);

        StatusCode = statusCode;
        Headers = headers;
        MediaType = mediaType;
        Body = body;
        _owner = owner;
        WasRedirected = wasRedirected;
    }

    /// <summary>The observed status code.</summary>
    public int StatusCode { get; }

    /// <summary>Response headers and content headers together.</summary>
    public IReadOnlyDictionary<string, string[]> Headers { get; }

    /// <summary>The observed media type without parameters, or null when none was stated.</summary>
    public string? MediaType { get; }

    /// <summary>The body stream. Bounded reading is the caller's obligation.</summary>
    public Stream Body { get; }

    /// <summary>Whether the transport followed one or more redirects before this response.</summary>
    public bool WasRedirected { get; }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_owner is not null)
        {
            await _owner.DisposeAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>
/// The one way execution reaches an upstream.
/// </summary>
/// <remarks>
/// Implementations own the socket, the redirect replay and the header stripping. They own no
/// decision the product depends on: what a redirect means and which headers are sensitive are
/// stated in <see cref="RedirectRules"/>, which has no transport to reach.
/// </remarks>
public interface IUpstreamTransport
{
    /// <summary>
    /// Sends <paramref name="request"/> under <paramref name="policy"/> and returns the final
    /// response of the chain.
    /// </summary>
    /// <remarks>
    /// <paramref name="cancellationToken"/> is the whole-exchange deadline. An implementation
    /// MUST NOT add a competing per-request timeout: two mechanisms for one cause produce two
    /// classifications for one fault.
    /// </remarks>
    Task<UpstreamResponse> SendAsync(
        UpstreamRequest request,
        UpstreamSendPolicy policy,
        CancellationToken cancellationToken);
}
