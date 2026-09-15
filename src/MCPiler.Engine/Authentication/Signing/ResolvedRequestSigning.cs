using MCPiler.Engine.Execution;

namespace MCPiler.Engine.Authentication.Signing;

/// <summary>
/// A request signer bound to its material and destination scope, ready to sign hops.
/// </summary>
/// <remarks>
/// The destination scope is re-checked on every signature rather than only where the plan was
/// built, because a redirect can move a request to a destination the plan never saw. Signing a
/// request that has left its scope would hand the upstream a valid signature for a destination
/// the operator did not authorize, which is exactly what the scope exists to prevent.
/// </remarks>
public sealed class ResolvedRequestSigning
{
    private readonly IRequestSigner _signer;
    private readonly RequestSigningMaterial _material;
    private readonly OriginAllowList _destinations;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a signing seam over a resolved signer.</summary>
    public ResolvedRequestSigning(
        IRequestSigner signer,
        RequestSigningMaterial material,
        OriginAllowList destinations,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(destinations);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _signer = signer;
        _material = material;
        _destinations = destinations;
        _timeProvider = timeProvider;
    }

    /// <summary>The reviewed signer kind in effect.</summary>
    public string StrategyId => _signer.StrategyId;

    /// <summary>Header names the signer writes that a cross-origin redirect must not replay.</summary>
    public IReadOnlySet<string> SensitiveHeaders => _signer.SensitiveHeaders;

    /// <summary>Query parameter names the signature covers.</summary>
    public IReadOnlySet<string> SensitiveQueryParameters => _signer.SensitiveQueryParameters;

    /// <summary>Creates a fresh attempt from the supplied clock and a new nonce.</summary>
    public RequestSigningAttempt CreateAttempt() => RequestSigningAttempt.Create(_timeProvider);

    /// <summary>Signs one hop after re-checking that its destination is inside the scope.</summary>
    public ValueTask SignAsync(
        SignableRequest request,
        RequestSigningAttempt attempt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(attempt);

        if (!_destinations.IsAllowed(request.Uri))
        {
            throw new CredentialUnavailableException(
                _material.AccessKeyId,
                "Request signing was refused because the final destination is outside the stored "
                    + "authentication scope.");
        }

        return _signer.SignAsync(request, _material, attempt, cancellationToken);
    }

    /// <summary>
    /// Applies the signature to a transport request by rewriting it through a signable view.
    /// </summary>
    /// <remarks>
    /// The view carries the same headers and body source as the transport request, so the
    /// signature covers exactly the bytes the transport will send and a body-preserving redirect
    /// re-reads the same payload for its own signature.
    /// </remarks>
    public async ValueTask<UpstreamRequest> SignAsync(
        UpstreamRequest request,
        RequestSigningAttempt attempt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var signable = new SignableRequest(request.Method, request.Uri, request.Headers)
        {
            ReadBodyAsync = BodyReader(request),
        };

        await SignAsync(signable, attempt, cancellationToken).ConfigureAwait(false);

        return request with
        {
            Uri = signable.Uri,
            Headers = new Dictionary<string, string[]>(signable.Headers, StringComparer.OrdinalIgnoreCase),
        };
    }

    private static Func<CancellationToken, ValueTask<byte[]>>? BodyReader(UpstreamRequest request)
    {
        if (request.Body is { } bytes)
        {
            return _ => ValueTask.FromResult(bytes);
        }

        if (request.BodySource is { } source)
        {
            return async token =>
            {
                using var buffer = new MemoryStream();
                await source.CopyToAsync(buffer, token).ConfigureAwait(false);
                return buffer.ToArray();
            };
        }

        return null;
    }
}

/// <summary>
/// The closed registry of reviewed request signers.
/// </summary>
/// <remarks>
/// Product identity is deliberately absent: a manifest profile names one reviewed generic signing
/// strategy and supplies only its key id and secret, so the same build serves any connector that
/// speaks one of the reviewed protocols. An unknown strategy id is refused at resolution rather
/// than at signing time, because a request that reaches a socket unsigned is worse than a
/// request that was never built.
/// </remarks>
public sealed class RequestSignerRegistry
{
    private readonly IReadOnlyDictionary<string, IRequestSigner> _signers;

    /// <summary>Creates a registry over the installed signers.</summary>
    public RequestSignerRegistry(IEnumerable<IRequestSigner> signers)
    {
        ArgumentNullException.ThrowIfNull(signers);

        _signers = signers.ToDictionary(
            signer => signer.StrategyId,
            StringComparer.Ordinal);
    }

    /// <summary>The installed signer kinds, ordinally ordered.</summary>
    public IReadOnlyList<string> StrategyIds =>
        [.. _signers.Keys.Order(StringComparer.Ordinal)];

    /// <summary>True when <paramref name="strategyId"/> names an installed signer.</summary>
    public bool Contains(string strategyId) => _signers.ContainsKey(strategyId);

    /// <summary>Resolves a signer for a request-signing profile.</summary>
    /// <param name="profileId">The manifest-local profile id, for diagnostics only.</param>
    /// <param name="strategyId">The reviewed signer kind named by the configuration.</param>
    /// <param name="accessKeyId">The public key identifier.</param>
    /// <param name="signingSecret">The resolved signing secret.</param>
    /// <param name="destinationOrigins">The profile's destination scope.</param>
    /// <param name="timeProvider">The clock an attempt binds into its signature.</param>
    public ResolvedRequestSigning Resolve(
        string profileId,
        string strategyId,
        string accessKeyId,
        string signingSecret,
        IReadOnlyList<string> destinationOrigins,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(strategyId);
        ArgumentNullException.ThrowIfNull(destinationOrigins);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if (!_signers.TryGetValue(strategyId, out var signer))
        {
            throw new UnsupportedAuthenticationStrategyException(
                $"Request-signing strategy '{strategyId}' is not installed in this Engine build. "
                    + $"Installed: {string.Join(", ", StrategyIds)}.");
        }

        return new ResolvedRequestSigning(
            signer,
            new RequestSigningMaterial(strategyId, accessKeyId, signingSecret),
            new OriginAllowList(destinationOrigins),
            timeProvider);
    }
}
