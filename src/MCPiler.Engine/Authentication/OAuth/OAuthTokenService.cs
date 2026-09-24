using MCPiler.Engine.Authentication.Caching;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.OAuth;

/// <summary>The bearer credential an OAuth strategy acquired, ready to apply to a request.</summary>
/// <param name="Credentials">The credential set to apply, exactly one bearer.</param>
/// <param name="AuthorityEpoch">The epoch the acquisition ran under, for reconciliation.</param>
/// <param name="RuntimeRevision">The revision the acquisition observed.</param>
/// <param name="ExpiresAtUtc">
/// When the acquired access token stops being usable. A response obtained under this authority
/// must not be cached past it, so the expiry is reported rather than kept inside the cache.
/// </param>
public sealed record OAuthAcquisition(
    IReadOnlyList<ResolvedCredential> Credentials,
    long AuthorityEpoch,
    long RuntimeRevision,
    DateTimeOffset ExpiresAtUtc);

/// <summary>
/// Acquires the bearer access token an OAuth profile authenticates a request with.
/// </summary>
/// <remarks>
/// <para>
/// The Engine counterpart of the Platform's token service, with two deliberate differences. It
/// has no database: profile identity is manifest-local and the only durable state it touches is
/// the narrow mutable-slot port. And it does not know about authoring status: an authorization
/// code profile is usable when a refresh token is resolvable, and a missing refresh token is the
/// reauthorization signal rather than a status string.
/// </para>
/// <para>
/// A provider that rotates its refresh token makes ordering load-bearing. The replacement is
/// committed to the mutable-slot store BEFORE the access token it produced is cached or returned,
/// so a failure between the two leaves the deployment holding the old refresh token — which the
/// provider may already have retired — rather than an access token whose refresh credential was
/// never recorded. The failure is fail-closed and may require reauthorization; no ordering can
/// restore provider validity.
/// </para>
/// <para>
/// Concurrent callers coalesce through single-flight. A rotating provider would otherwise see one
/// refresh token presented several times, retire the replacement produced by whichever call won,
/// and leave every later caller holding a value the provider had already invalidated.
/// </para>
/// </remarks>
public sealed class OAuthTokenService
{
    /// <summary>The mutable slot an authorization-code profile rotates.</summary>
    public const string RefreshTokenSlot = "refreshToken";

    private readonly OAuthTokenEndpointClient _endpoint;
    private readonly AccessTokenCache _cache;
    private readonly AccessTokenSingleFlight _singleFlight;
    private readonly IMutableSlotStore _slots;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates the service over its ports.</summary>
    /// <param name="endpoint">The token endpoint client.</param>
    /// <param name="cache">The bounded access-token cache.</param>
    /// <param name="singleFlight">The per-profile acquisition gate.</param>
    /// <param name="slots">Where a rotated refresh token becomes authoritative.</param>
    /// <param name="timeProvider">The clock, so expiry is testable.</param>
    /// <param name="onRefreshTokenRotated">
    /// Invoked after a rotation is durably committed, so a host can queue reconciliation. It is
    /// called after the commit and never before: a notification about a rotation that could still
    /// roll back would let a host report state the deployment does not hold.
    /// </param>
    public OAuthTokenService(
        OAuthTokenEndpointClient endpoint,
        AccessTokenCache cache,
        AccessTokenSingleFlight singleFlight,
        IMutableSlotStore slots,
        TimeProvider timeProvider,
        Func<RotatedRefreshToken, CancellationToken, ValueTask>? onRefreshTokenRotated = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(singleFlight);
        ArgumentNullException.ThrowIfNull(slots);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _endpoint = endpoint;
        _cache = cache;
        _singleFlight = singleFlight;
        _slots = slots;
        _timeProvider = timeProvider;
        OnRefreshTokenRotated = onRefreshTokenRotated;
    }

    /// <summary>Receives every durably committed refresh-token rotation.</summary>
    public Func<RotatedRefreshToken, CancellationToken, ValueTask>? OnRefreshTokenRotated { get; }

    /// <summary>
    /// Acquires a bearer token for <paramref name="profile"/>.
    /// </summary>
    /// <param name="profile">The OAuth profile. Its kind must be an OAuth kind.</param>
    /// <param name="credentials">
    /// The profile's already-resolved credentials. For client credentials that is the client
    /// secret; for the authorization-code kind it is the client secret and the initial refresh
    /// token, either of which may be absent when the deployment supplies the value another way.
    /// </param>
    /// <param name="cancellationToken">The caller's deadline.</param>
    /// <exception cref="CredentialUnavailableException">
    /// The grant cannot be completed: a required credential is absent, the provider rejected the
    /// grant, or the response was unusable. The message never carries a value.
    /// </exception>
    public async ValueTask<OAuthAcquisition> AcquireAsync(
        AuthenticationProfile profile,
        IReadOnlyList<ResolvedCredential> credentials,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(credentials);

        var authorizationCode = profile.Kind == AuthenticationKind.OAuth2AuthorizationCodePkceRefresh;

        if (profile.Kind is not (AuthenticationKind.OAuth2ClientCredentials
            or AuthenticationKind.OAuth2AuthorizationCodePkceRefresh))
        {
            throw new UnsupportedAuthenticationStrategyException(
                "The OAuth token service acquires tokens only for the OAuth strategy kinds.");
        }

        var configuration = OAuthStrategyConfiguration.FromConfiguration(
            profile.Configuration,
            authorizationCode);

        var slot = profile.Slots.FirstOrDefault(candidate =>
            string.Equals(candidate.Slot, RefreshTokenSlot, StringComparison.Ordinal));

        // Cache identity comes from the profile's own declared authority state, preferring the
        // rotating slot. A client-credentials profile has no refresh slot but may still declare a
        // mutable client secret, and a change to either epoch or revision must not resolve a token
        // acquired under the previous deployment state.
        var identitySlot = slot ?? (profile.Slots.Count > 0 ? profile.Slots[0] : null);

        var authorityEpoch = identitySlot?.AuthorityEpoch ?? 0;
        var runtimeRevision = identitySlot?.RuntimeRevision ?? 0;

        var refreshToken = authorizationCode
            ? await ResolveRefreshTokenAsync(profile, credentials, slot, cancellationToken)
                .ConfigureAwait(false)
            : null;

        var key = new AccessTokenKey(
            profile.Id,
            authorityEpoch,
            runtimeRevision,
            configuration.ScopeResourceKey);

        if (_cache.TryGet(key, configuration.AccessTokenSafetySkew, _timeProvider.GetUtcNow(), out var cached))
        {
            return new OAuthAcquisition(Bearer(cached.Value), authorityEpoch, runtimeRevision, cached.ExpiresAtUtc);
        }

        var acquired = await _singleFlight.RunAsync(
            profile.Id,
            async token =>
            {
                // Re-checked inside the gate: a token acquired while this caller waited must be
                // returned rather than re-fetched, or a burst at expiry would present the same
                // rotating refresh credential several times.
                if (_cache.TryGet(key, configuration.AccessTokenSafetySkew, _timeProvider.GetUtcNow(), out var winner))
                {
                    return new AcquiredToken(winner.Value, winner.ExpiresAtUtc, RefreshToken: null, authorityEpoch, runtimeRevision);
                }

                var result = authorizationCode
                    ? await RefreshAsync(profile, configuration, credentials, refreshToken!, token).ConfigureAwait(false)
                    : await ClientCredentialsAsync(profile, configuration, credentials, authorityEpoch, runtimeRevision, token)
                        .ConfigureAwait(false);

                // A rotated refresh credential is committed to durable state BEFORE the access
                // token it produced is published, and both happen inside the gate so no later
                // caller can observe the access token without the credential that renews it.
                // A commit that fails here propagates, so the failed transition's access token is
                // never cached and never returned.
                if (result.RefreshToken is { } rotated && slot is not null)
                {
                    var record = new MutableSlotRecord(
                        profile.Id,
                        slot.Slot,
                        profile.ScopeFingerprint,
                        slot.AuthorityEpoch,
                        slot.RuntimeRevision + 1,
                        rotated);

                    await _slots.ReplaceAsync(record, token).ConfigureAwait(false);
                }

                _cache.Set(key, new CachedAccessToken(result.AccessToken, result.ExpiresAtUtc));
                return result;
            },
            cancellationToken).ConfigureAwait(false);

        if (acquired.RefreshToken is not null && slot is not null)
        {
            // The commit already happened; this only reports it. A notification about a rotation
            // that could still roll back would let a host report state the deployment does not hold.
            if (OnRefreshTokenRotated is { } notify)
            {
                await notify(
                    new RotatedRefreshToken(
                        profile.Id,
                        slot.Slot,
                        slot.AuthorityEpoch,
                        slot.RuntimeRevision,
                        slot.RuntimeRevision + 1),
                    cancellationToken).ConfigureAwait(false);
            }

            return new OAuthAcquisition(
                Bearer(acquired.AccessToken),
                slot.AuthorityEpoch,
                slot.RuntimeRevision + 1,
                acquired.ExpiresAtUtc);
        }

        return new OAuthAcquisition(
            Bearer(acquired.AccessToken),
            authorityEpoch,
            runtimeRevision,
            acquired.ExpiresAtUtc);
    }

    /// <summary>
    /// Resolves the refresh credential: the locally rotated record when it matches the deployed
    /// authority state and is at least as new as the generation input, the declared credential
    /// otherwise.
    /// </summary>
    private async ValueTask<string?> ResolveRefreshTokenAsync(
        AuthenticationProfile profile,
        IReadOnlyList<ResolvedCredential> credentials,
        AuthenticationSlot? slot,
        CancellationToken cancellationToken)
    {
        if (slot is { } declared)
        {
            var record = await _slots.LoadAsync(profile.Id, declared.Slot, cancellationToken).ConfigureAwait(false);

            if (record is not null
                && record.AuthorityEpoch == declared.AuthorityEpoch
                && string.Equals(record.ScopeFingerprint, profile.ScopeFingerprint, StringComparison.Ordinal)
                && record.RuntimeRevision >= declared.RuntimeRevision
                && record.Value.Length > 0)
            {
                return record.Value;
            }
        }

        var declaredCredential = credentials.FirstOrDefault(credential =>
            credential.Declaration.Scheme == CredentialScheme.OAuth2AuthorizationCode
            && string.Equals(credential.Declaration.Slot, RefreshTokenSlot, StringComparison.Ordinal));

        if (declaredCredential is null || declaredCredential.Value.Length == 0)
        {
            throw new CredentialUnavailableException(
                "oauth",
                "The authorization-code profile has no refresh token, so it must be authorized again before it can execute.");
        }

        return declaredCredential.Value;
    }

    private static IReadOnlyList<ResolvedCredential> Bearer(string accessToken)
        => [new(
            new ManifestCredential(
                "oauth-access-token",
                CredentialScheme.Bearer,

                // The slot names the header a bearer credential writes. Engine reads the slot as
                // the header name rather than as a fixed 'token' marker, so an acquired token
                // addressed to anything else would be sent on a header the upstream never reads.
                ManifestCredential.AuthorizationHeader,

                // The declaration is a carrier for the acquired value; its reference is never
                // resolved or reported, so the placeholder is a shape rather than a source.
                CredentialReference.Literal("oauth-access-token")),
            accessToken)];

    private async ValueTask<AcquiredToken> ClientCredentialsAsync(
        AuthenticationProfile profile,
        OAuthStrategyConfiguration configuration,
        IReadOnlyList<ResolvedCredential> credentials,
        long authorityEpoch,
        long runtimeRevision,
        CancellationToken cancellationToken)
    {
        var clientSecret = credentials.FirstOrDefault(credential =>
            credential.Declaration.Scheme == CredentialScheme.OAuth2ClientCredentials
            && string.Equals(credential.Declaration.Slot, "clientSecret", StringComparison.Ordinal));

        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "client_credentials",
        };

        AddScopeResourceAudience(form, configuration);

        var result = await _endpoint
            .ExchangeAsync(
                configuration,
                profile.AuthenticationOrigins,
                form,
                clientSecret?.Value,
                cancellationToken)
            .ConfigureAwait(false);

        return new AcquiredToken(
            result.AccessToken,
            result.ExpiresAtUtc,
            result.RefreshToken,
            authorityEpoch,
            runtimeRevision);
    }

    private async ValueTask<AcquiredToken> RefreshAsync(
        AuthenticationProfile profile,
        OAuthStrategyConfiguration configuration,
        IReadOnlyList<ResolvedCredential> credentials,
        string refreshToken,
        CancellationToken cancellationToken)
    {
        var clientSecret = credentials.FirstOrDefault(credential =>
            credential.Declaration.Scheme == CredentialScheme.OAuth2AuthorizationCode
            && string.Equals(credential.Declaration.Slot, "clientSecret", StringComparison.Ordinal));

        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
        };

        AddScopeResourceAudience(form, configuration);

        OAuthTokenEndpointResult result;
        try
        {
            result = await _endpoint
                .ExchangeAsync(
                    configuration,
                    profile.AuthenticationOrigins,
                    form,
                    clientSecret?.Value,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OAuthTokenEndpointException ex) when (string.Equals(ex.ErrorCode, "invalid_grant", StringComparison.Ordinal))
        {
            // The provider refused the refresh credential. That is a reauthorization requirement,
            // not a transient fault: retrying would present a value the provider has retired.
            throw new CredentialUnavailableException(
                "oauth",
                "The provider rejected the refresh credential, so the connector must be authorized again.");
        }

        return new AcquiredToken(
            result.AccessToken,
            result.ExpiresAtUtc,
            result.RefreshToken,
            AuthorityEpoch: 0,
            RuntimeRevision: 0);
    }

    private static void AddScopeResourceAudience(
        Dictionary<string, string> form,
        OAuthStrategyConfiguration configuration)
    {
        if (configuration.Scopes.Count > 0)
        {
            form["scope"] = string.Join(' ', configuration.Scopes);
        }

        if (configuration.Resource is { Length: > 0 } resource)
        {
            form["resource"] = resource;
        }

        if (configuration.Audience is { Length: > 0 } audience)
        {
            form["audience"] = audience;
        }
    }

    private sealed record AcquiredToken(
        string AccessToken,
        DateTimeOffset ExpiresAtUtc,
        string? RefreshToken,
        long AuthorityEpoch,
        long RuntimeRevision);
}

/// <summary>
/// A refresh-token rotation that has already been committed locally, reported so a host can
/// reconcile it. Carries only non-secret identities and the new revision; never the value.
/// </summary>
/// <param name="ProfileId">The profile that owns the slot.</param>
/// <param name="Slot">The rotated slot.</param>
/// <param name="AuthorityEpoch">The epoch the rotation happened under.</param>
/// <param name="PreviousRuntimeRevision">The revision before the rotation.</param>
/// <param name="RuntimeRevision">The revision the rotation established.</param>
public sealed record RotatedRefreshToken(
    string ProfileId,
    string Slot,
    long AuthorityEpoch,
    long PreviousRuntimeRevision,
    long RuntimeRevision);
