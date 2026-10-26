using MCPiler.Engine.Authentication.Caching;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.OAuth;

/// <summary>The bearer credential an OAuth strategy acquired, ready to apply to a request.</summary>
/// <param name="Credentials">The credential set to apply, exactly one bearer.</param>
/// <param name="AuthorityEpoch">The effective epoch the acquisition ran under, for reconciliation.</param>
/// <param name="RuntimeRevision">The effective revision the acquisition observed.</param>
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
/// The Engine counterpart of the Platform's token service, with three deliberate differences. It
/// has no database: profile identity is manifest-local and the only durable state it touches is
/// the narrow mutable-slot port. It does not know about authoring status: an authorization code
/// profile is usable when a refresh token is resolvable, and a missing refresh token is the
/// reauthorization signal rather than a status string. And it resolves the <em>effective</em>
/// authority: a committed local decision (a successor the operator authorized, or a clear) takes
/// precedence over the Manifest's declared source, while a deployment with no local decision keeps
/// the original declaration-epoch resolution unchanged.
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
/// Concurrent callers coalesce through a slot-scoped gate shared with explicit authority
/// transitions. A rotating provider would otherwise see one refresh token presented several
/// times, retire the replacement produced by whichever call won, and leave every later caller
/// holding a value the provider had already invalidated. The gate also lets a transition and an
/// acquisition serialize, and the shared generation fence lets an acquisition discard a result
/// whose authority moved while it was in flight.
/// </para>
/// </remarks>
public sealed class OAuthTokenService
{
    /// <summary>The mutable slot an authorization-code profile rotates.</summary>
    public const string RefreshTokenSlot = "refreshToken";

    private readonly OAuthTokenEndpointClient _endpoint;
    private readonly AccessTokenCache _cache;
    private readonly IMutableSlotStore _slots;
    private readonly TimeProvider _timeProvider;
    private readonly AuthorityCoordinator _authority;

    /// <summary>Creates the service over its ports.</summary>
    /// <param name="endpoint">The token endpoint client.</param>
    /// <param name="cache">The bounded access-token cache.</param>
    /// <param name="singleFlight">The per-slot acquisition gate the authority coordinator shares.</param>
    /// <param name="slots">Where a rotated refresh token becomes authoritative.</param>
    /// <param name="timeProvider">The clock, so expiry is testable.</param>
    /// <param name="onRefreshTokenRotated">
    /// Invoked after a rotation is durably committed, so a host can queue reconciliation. It is
    /// called after the commit and never before: a notification about a rotation that could still
    /// roll back would let a host report state the deployment does not hold. A failure in the
    /// notification is not a failed rotation — the durable commit already happened — so it is
    /// recorded as an auxiliary failure rather than reported as a refused acquisition.
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
        _slots = slots;
        _timeProvider = timeProvider;
        _authority = new AuthorityCoordinator(singleFlight);
        OnRefreshTokenRotated = onRefreshTokenRotated;
    }

    /// <summary>Receives every durably committed refresh-token rotation.</summary>
    public Func<RotatedRefreshToken, CancellationToken, ValueTask>? OnRefreshTokenRotated { get; }

    /// <summary>
    /// The slot-scoped coordination gate and authority-generation fence. An explicit authority
    /// transition (authorize, reauthorize or clear) runs its commit and calls
    /// <see cref="NotifyAuthorityChanged"/> while holding
    /// <see cref="AuthorityCoordinator.RunExclusiveAsync"/>.
    /// </summary>
    public AuthorityCoordinator Authority => _authority;

    /// <summary>
    /// Reports that an explicit authority transition for one slot has committed, so in-flight
    /// acquisitions derived from the displaced authority refuse to publish and already-cached
    /// tokens for the profile are dropped.
    /// </summary>
    /// <param name="profileId">The profile whose slot authority changed.</param>
    /// <param name="slot">The slot identity whose authority changed.</param>
    public void NotifyAuthorityChanged(string profileId, string slot)
    {
        ArgumentException.ThrowIfNullOrEmpty(profileId);
        ArgumentNullException.ThrowIfNull(slot);

        _authority.Advance(profileId, slot);
        _cache.InvalidateProfile(profileId);
    }

    /// <summary>
    /// Clears the local authority of one profile's rotating slot.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the in-host half of an explicit operator clear: it runs the whole read-decide-commit
    /// under the same slot gate an acquisition uses, so a clear and a refresh cannot interleave, and
    /// it commits through the same store instance the mount serves with, so the fence it sets is the
    /// fence the serving path observes.
    /// </para>
    /// <para>
    /// The commit point is the compare-and-commit of the tombstone. Everything before it may refuse
    /// and change nothing; everything after it — the cache drop, the generation advance, the
    /// best-effort revocation the caller performs — cannot undo it or report it as failed.
    /// </para>
    /// </remarks>
    /// <param name="profile">The authorization-code profile to clear.</param>
    /// <param name="declaredRefreshPresent">
    /// Whether the profile's declared source still resolves to a usable refresh value. A slot with
    /// no local decision and no declared value has nothing to clear, and saying so is more useful
    /// than committing a floor over an already-unusable profile.
    /// </param>
    /// <param name="cancellationToken">The caller's deadline.</param>
    internal async ValueTask<OAuthAuthorityClear> ClearAuthorityAsync(
        AuthenticationProfile profile,
        bool declaredRefreshPresent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);

        AuthenticationSlot? declared = profile.Slots.FirstOrDefault(candidate =>
            string.Equals(candidate.Slot, RefreshTokenSlot, StringComparison.Ordinal));

        if (declared is null)
        {
            return new OAuthAuthorityClear(
                false,
                "oauth/no-runtime-slot",
                "The profile declares no rotating refresh slot, so there is no local authority to clear.",
                0,
                0,
                null);
        }

        OAuthStrategyConfiguration configuration = OAuthStrategyConfiguration.FromConfiguration(
            profile.Configuration,
            authorizationCodeRequired: true);

        OAuthAuthorityClear cleared = await _authority.RunExclusiveAsync(
            profile.Id,
            declared.Slot,
            async token =>
            {
                MutableSlotDecision? prior;

                try
                {
                    prior = await _slots.LoadDecisionAsync(profile.Id, declared.Slot, token).ConfigureAwait(false);
                }
                catch (RuntimeStateStoreException)
                {
                    return new OAuthAuthorityClear(
                        false,
                        "oauth/authority-unreadable",
                        "The stored authority for this slot could not be read, so nothing was cleared. "
                        + "An unreadable record is not an absent one; recover it with the acknowledged reset.",
                        0,
                        0,
                        null);
                }

                if (prior is { IsLegacy: false, Kind: MutableSlotDecisionKind.Cleared })
                {
                    return new OAuthAuthorityClear(
                        false,
                        "oauth/already-cleared",
                        "The slot already carries a cleared floor, so a second clear would only advance the same decision.",
                        prior.AuthorityEpoch,
                        prior.RuntimeRevision,
                        null);
                }

                if (prior is null && !declaredRefreshPresent)
                {
                    return new OAuthAuthorityClear(
                        false,
                        "oauth/nothing-to-clear",
                        "The slot has no local authority and no declared refresh source, so there is nothing to clear.",
                        declared.AuthorityEpoch,
                        declared.RuntimeRevision,
                        null);
                }

                long baseEpoch = Math.Max(
                    declared.AuthorityEpoch,
                    prior?.AuthorityEpoch ?? declared.AuthorityEpoch);

                if (baseEpoch == long.MaxValue)
                {
                    return new OAuthAuthorityClear(
                        false,
                        "oauth/persistence-failed",
                        "The local authority epoch is exhausted, so a new cleared floor cannot be established.",
                        0,
                        0,
                        null);
                }

                MutableSlotDecision tombstone = new(
                    profile.Id,
                    declared.Slot,
                    profile.ScopeFingerprint,
                    AuthorityBinding.Declaration(profile),
                    AuthorityBinding.Configuration(configuration),
                    baseEpoch + 1,
                    0,
                    MutableSlotDecisionKind.Cleared,
                    RefreshToken: null);

                MutableSlotDecision committed;

                try
                {
                    committed = await _slots
                        .CompareAndCommitAsync(tombstone, prior?.Version, declared.AuthorityEpoch, token)
                        .ConfigureAwait(false);
                }
                catch (RuntimeStateStoreException)
                {
                    return new OAuthAuthorityClear(
                        false,
                        "oauth/persistence-failed",
                        "The cleared floor could not be written, so nothing was cleared and the previous authority is unchanged.",
                        0,
                        0,
                        null);
                }

                // Publish the fence while still owning the slot gate. Otherwise a waiting
                // acquisition can reuse the displaced cached token between gate release and
                // the notification.
                NotifyAuthorityChanged(profile.Id, declared.Slot);
                return new OAuthAuthorityClear(
                    true,
                    "oauth/cleared",
                    "The local authority for this slot was cleared.",
                    committed.AuthorityEpoch,
                    committed.RuntimeRevision,
                    prior?.RefreshToken);
            },
            cancellationToken).ConfigureAwait(false);

        return cleared;
    }

    /// <summary>
    /// Commits the refresh credential one completed authorization attempt obtained.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the in-host half of an explicit operator authorization. The attempt itself is
    /// memory-only and host-neutral; this is what makes its result durable, and it is deliberately
    /// the mirror image of <see cref="ClearAuthorityAsync"/>: it runs the whole read-decide-commit
    /// under the same slot gate an acquisition uses, commits through the same store instance the
    /// mount serves with, and advances the same generation fence afterwards.
    /// </para>
    /// <para>
    /// The commit point is the compare-and-commit of the authorized successor. Everything before it
    /// may refuse and change nothing; everything after it — the cache fill, the generation advance —
    /// cannot undo it or report it as failed.
    /// </para>
    /// <para>
    /// The attempt's captured fingerprints are re-checked against the profile as it is now. A
    /// Manifest that changed while the attempt was open would otherwise commit a credential the
    /// provider minted for the previous declaration, so that is refused rather than repaired.
    /// </para>
    /// </remarks>
    /// <param name="profile">The authorization-code profile to authorize.</param>
    /// <param name="result">What the completed attempt obtained, including the binding it captured.</param>
    /// <param name="cancellationToken">The caller's deadline.</param>
    internal async ValueTask<OAuthAuthorityAuthorization> CompleteAuthorizationAsync(
        AuthenticationProfile profile,
        OAuthAuthorizationResult result,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(result);

        AuthenticationSlot? declared = profile.Slots.FirstOrDefault(candidate =>
            string.Equals(candidate.Slot, RefreshTokenSlot, StringComparison.Ordinal));

        if (declared is null)
        {
            return new OAuthAuthorityAuthorization(
                false,
                "oauth/no-runtime-slot",
                "The profile declares no rotating refresh slot, so there is nowhere to commit the acquired credential.",
                0,
                0);
        }

        OAuthStrategyConfiguration configuration = OAuthStrategyConfiguration.FromConfiguration(
            profile.Configuration,
            authorizationCodeRequired: true);

        string declarationFingerprint = AuthorityBinding.Declaration(profile);
        string configurationFingerprint = AuthorityBinding.Configuration(configuration);

        OAuthAuthorityAuthorization authorized = await _authority.RunExclusiveAsync(
            profile.Id,
            declared.Slot,
            async token =>
            {
                if (!string.Equals(result.Binding.DeclarationFingerprint, declarationFingerprint, StringComparison.Ordinal)
                    || !string.Equals(result.Binding.ConfigurationFingerprint, configurationFingerprint, StringComparison.Ordinal))
                {
                    return new OAuthAuthorityAuthorization(
                        false,
                        "oauth/declaration-changed",
                        "The profile's declaration or configuration changed while the authorization attempt was open, so the acquired credential was not committed. Authorize again against the current Manifest.",
                        0,
                        0);
                }

                MutableSlotDecision? prior;

                try
                {
                    prior = await _slots.LoadDecisionAsync(profile.Id, declared.Slot, token).ConfigureAwait(false);
                }
                catch (RuntimeStateStoreException)
                {
                    return new OAuthAuthorityAuthorization(
                        false,
                        "oauth/authority-unreadable",
                        "The stored authority for this slot could not be read, so the acquired credential was not committed. "
                        + "An unreadable record is not an absent one; recover it with the acknowledged reset.",
                        0,
                        0);
                }

                // An explicit authorization opens a new epoch beyond everything committed before it,
                // including a cleared floor: that is what makes 'authorize again' the documented way
                // back from a clear, and why it is never a revision of the previous decision.
                long baseEpoch = Math.Max(
                    declared.AuthorityEpoch,
                    prior?.AuthorityEpoch ?? declared.AuthorityEpoch);

                if (baseEpoch == long.MaxValue)
                {
                    return new OAuthAuthorityAuthorization(
                        false,
                        "oauth/persistence-failed",
                        "The local authority epoch is exhausted, so a new authorized decision cannot be established.",
                        0,
                        0);
                }

                MutableSlotDecision successor = new(
                    profile.Id,
                    declared.Slot,
                    profile.ScopeFingerprint,
                    declarationFingerprint,
                    configurationFingerprint,
                    baseEpoch + 1,
                    0,
                    MutableSlotDecisionKind.Authorized,
                    result.RefreshToken);

                MutableSlotDecision committed;

                try
                {
                    committed = await _slots
                        .CompareAndCommitAsync(successor, prior?.Version, declared.AuthorityEpoch, token)
                        .ConfigureAwait(false);
                }
                catch (RuntimeStateStoreException)
                {
                    return new OAuthAuthorityAuthorization(
                        false,
                        "oauth/persistence-failed",
                        "The provider issued a refresh credential but it could not be durably committed, so the profile is not authorized. Make the runtime-state store writable and authorize again.",
                        0,
                        0);
                }

                // The generation and the access token from this authorization must become
                // visible before the next slot participant can proceed. A later clear must
                // never race with publishing the newly authorized token.
                NotifyAuthorityChanged(profile.Id, declared.Slot);
                _cache.Set(
                    new AccessTokenKey(profile.Id, committed.AuthorityEpoch, committed.RuntimeRevision, configuration.ScopeResourceKey),
                    new CachedAccessToken(result.AccessToken, result.ExpiresAtUtc));

                return new OAuthAuthorityAuthorization(
                    true,
                    "oauth/authorized",
                    "The profile is now authorized; the provider-issued refresh credential was committed to the durable runtime store.",
                    committed.AuthorityEpoch,
                    committed.RuntimeRevision);
            },
            cancellationToken).ConfigureAwait(false);

        return authorized;
    }

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
    /// grant, the local authority was cleared or rebound, or the response was unusable. The
    /// message never carries a value.
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
        var slotName = slot?.Slot ?? string.Empty;

        if (!authorizationCode)
        {
            var authorityEpoch = identitySlot?.AuthorityEpoch ?? 0;
            var runtimeRevision = identitySlot?.RuntimeRevision ?? 0;
            var clientKey = new AccessTokenKey(
                profile.Id, authorityEpoch, runtimeRevision, configuration.ScopeResourceKey);

            if (_cache.TryGet(clientKey, configuration.AccessTokenSafetySkew, _timeProvider.GetUtcNow(), out var cachedClient))
            {
                return new OAuthAcquisition(Bearer(cachedClient.Value), authorityEpoch, runtimeRevision, cachedClient.ExpiresAtUtc);
            }

            var clientAcquired = await _authority.RunExclusiveAsync(
                profile.Id,
                slotName,
                async token =>
                {
                    if (_cache.TryGet(clientKey, configuration.AccessTokenSafetySkew, _timeProvider.GetUtcNow(), out var winner))
                    {
                        return new AcquiredToken(winner.Value, winner.ExpiresAtUtc, RefreshToken: null, authorityEpoch, runtimeRevision);
                    }

                    var result = await ClientCredentialsAsync(profile, configuration, credentials, authorityEpoch, runtimeRevision, token)
                        .ConfigureAwait(false);

                    _cache.Set(clientKey, new CachedAccessToken(result.AccessToken, result.ExpiresAtUtc));
                    return result;
                },
                cancellationToken).ConfigureAwait(false);

            return new OAuthAcquisition(
                Bearer(clientAcquired.AccessToken),
                clientAcquired.AuthorityEpoch,
                clientAcquired.RuntimeRevision,
                clientAcquired.ExpiresAtUtc);
        }

        // This generation guards the optimistic cache read. The gated refresh takes a fresh
        // generation after entering the slot gate, since a transition may finish while queued.
        var generation = _authority.Generation(profile.Id, slotName);
        var authority = await ResolveAuthorityAsync(profile, configuration, credentials, slot, cancellationToken)
            .ConfigureAwait(false);

        var key = new AccessTokenKey(
            profile.Id, authority.AuthorityEpoch, authority.RuntimeRevision, configuration.ScopeResourceKey);

        if (_authority.Generation(profile.Id, slotName) == generation
            && _cache.TryGet(key, configuration.AccessTokenSafetySkew, _timeProvider.GetUtcNow(), out var cached))
        {
            return new OAuthAcquisition(
                Bearer(cached.Value), authority.AuthorityEpoch, authority.RuntimeRevision, cached.ExpiresAtUtc);
        }

        var acquired = await _authority.RunExclusiveAsync(
            profile.Id,
            slotName,
            async token =>
            {
                // Only changes occurring after gate entry can invalidate this acquisition.
                // An explicit transition that completed while queued is already authoritative.
                var acquisitionGeneration = _authority.Generation(profile.Id, slotName);
                // A waiting participant re-reads authority after the gate: an explicit transition
                // may have committed while this caller waited, so the value read before the gate is
                // not authority to acquire under.
                var current = await ResolveAuthorityAsync(profile, configuration, credentials, slot, token)
                    .ConfigureAwait(false);
                var currentKey = new AccessTokenKey(
                    profile.Id, current.AuthorityEpoch, current.RuntimeRevision, configuration.ScopeResourceKey);

                // Re-checked inside the gate: a token acquired while this caller waited must be
                // returned rather than re-fetched, or a burst at expiry would present the same
                // rotating refresh credential several times.
                if (_cache.TryGet(currentKey, configuration.AccessTokenSafetySkew, _timeProvider.GetUtcNow(), out var winner))
                {
                    return new AcquiredToken(winner.Value, winner.ExpiresAtUtc, RefreshToken: null,
                        current.AuthorityEpoch, current.RuntimeRevision);
                }

                var result = await RefreshAsync(profile, configuration, credentials, current.RefreshToken!, token)
                    .ConfigureAwait(false);

                // A rotated refresh credential is committed to durable state BEFORE the access
                // token it produced is published, and both happen inside the gate so no later
                // caller can observe the access token without the credential that renews it.
                // A commit that fails here propagates, so the failed transition's access token is
                // never cached and never returned.
                var rotated = result.RefreshToken is not null && slot is not null;
                if (rotated)
                {
                    await CommitRotationAsync(profile, slot!, current, result.RefreshToken!, token)
                        .ConfigureAwait(false);
                }

                // Fence: an older completion must not serve or cache a token once its authority was
                // displaced. A transition cannot run inside this gate concurrently, but an
                // out-of-band change (a direct store commit, a test) must still be detected.
                if (_authority.Generation(profile.Id, slotName) != acquisitionGeneration)
                {
                    throw new CredentialUnavailableException(
                        "oauth",
                        "The local authority changed while the token was being acquired, so the result was discarded and the token must be requested again.");
                }

                // A bound v2 rotation commits revision N+1 before publishing its access
                // token. Cache against that new authority identity. Legacy v1 authority
                // keeps the declaration's revision as its cache identity, even when the
                // stored refresh token rotates (ResolveAuthorityAsync follows that rule).
                var committedRevision = rotated ? current.RuntimeRevision + 1 : current.RuntimeRevision;
                var cacheRevision = rotated && current.Decision is not null
                    ? committedRevision
                    : current.RuntimeRevision;
                _cache.Set(
                    new AccessTokenKey(profile.Id, current.AuthorityEpoch, cacheRevision, configuration.ScopeResourceKey),
                    new CachedAccessToken(result.AccessToken, result.ExpiresAtUtc));
                return new AcquiredToken(
                    result.AccessToken,
                    result.ExpiresAtUtc,
                    result.RefreshToken,
                    current.AuthorityEpoch,
                    committedRevision);
            },
            cancellationToken).ConfigureAwait(false);

        if (acquired.RefreshToken is not null && slot is not null)
        {
            // The commit already happened; this only reports it. A notification about a rotation
            // that could still roll back would let a host report state the deployment does not hold.
            await NotifyRotationAsync(
                profile.Id,
                slot.Slot,
                acquired.AuthorityEpoch,
                acquired.RuntimeRevision - 1,
                acquired.RuntimeRevision,
                cancellationToken).ConfigureAwait(false);
        }

        return new OAuthAcquisition(
            Bearer(acquired.AccessToken),
            acquired.AuthorityEpoch,
            acquired.RuntimeRevision,
            acquired.ExpiresAtUtc);
    }

    /// <summary>
    /// Resolves the authority an acquisition runs under: a committed local decision when present,
    /// otherwise the original declared-source resolution.
    /// </summary>
    /// <remarks>
    /// A cleared decision fails closed and masks every declared source, including one that a newer
    /// Manifest epoch or configuration would otherwise expose. A v2 authorized decision whose scope
    /// or configuration binding no longer matches the deployment fails closed rather than silently
    /// falling back, because the credential was minted for a different declaration. Only a legacy
    /// v1 record, or no record, uses the deployment's declared refresh source.
    /// </remarks>
    private async ValueTask<EffectiveAuthority> ResolveAuthorityAsync(
        AuthenticationProfile profile,
        OAuthStrategyConfiguration configuration,
        IReadOnlyList<ResolvedCredential> credentials,
        AuthenticationSlot? slot,
        CancellationToken cancellationToken)
    {
        if (slot is { } declared)
        {
            var decision = await _slots.LoadDecisionAsync(profile.Id, declared.Slot, cancellationToken)
                .ConfigureAwait(false);

            if (decision is not null && !decision.IsLegacy)
            {
                if (decision.Kind == MutableSlotDecisionKind.Cleared)
                {
                    throw new CredentialUnavailableException(
                        "oauth",
                        "The profile was explicitly cleared, so it must be authorized again before it can execute.");
                }

                if (!string.Equals(decision.ScopeFingerprint, profile.ScopeFingerprint, StringComparison.Ordinal)
                    || !string.Equals(decision.DeclarationFingerprint, AuthorityBinding.Declaration(profile), StringComparison.Ordinal)
                    || !string.Equals(decision.ConfigurationFingerprint, AuthorityBinding.Configuration(configuration), StringComparison.Ordinal))
                {
                    throw new CredentialUnavailableException(
                        "oauth",
                        "The stored authority was established for a different scope or configuration, so the profile must be authorized again.");
                }

                if (string.IsNullOrEmpty(decision.RefreshToken))
                {
                    throw new CredentialUnavailableException(
                        "oauth",
                        "The stored authority has no usable refresh token, so the profile must be authorized again.");
                }

                return new EffectiveAuthority(
                    decision.RefreshToken, decision.AuthorityEpoch, decision.RuntimeRevision, decision);
            }

            if (decision is { IsLegacy: true, RefreshToken: { Length: > 0 } legacy }
                && decision.AuthorityEpoch == declared.AuthorityEpoch
                && string.Equals(decision.ScopeFingerprint, profile.ScopeFingerprint, StringComparison.Ordinal)
                && decision.RuntimeRevision >= declared.RuntimeRevision)
            {
                return new EffectiveAuthority(
                    legacy, declared.AuthorityEpoch, declared.RuntimeRevision, Decision: null);
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

        return new EffectiveAuthority(
            declaredCredential.Value,
            slot?.AuthorityEpoch ?? 0,
            slot?.RuntimeRevision ?? 0,
            Decision: null);
    }

    /// <summary>
    /// Commits a rotated refresh credential under the current effective authority: a
    /// compare-and-commit of the next revision in the same epoch for a local authorized decision,
    /// or the original declared-revision advance for a legacy/absent slot.
    /// </summary>
    /// <remarks>
    /// The revision is always derived from the observed effective authority, never from the
    /// declared slot, so a rotation can never regress behind a locally advanced revision. The
    /// compare-and-commit refuses a write whose observed version changed, so a competing clear or
    /// reauthorization between the provider call and this commit refuses rather than overwritten.
    /// </remarks>
    private async ValueTask CommitRotationAsync(
        AuthenticationProfile profile,
        AuthenticationSlot declared,
        EffectiveAuthority current,
        string rotated,
        CancellationToken cancellationToken)
    {
        if (current.Decision is { } prior)
        {
            var successor = prior with
            {
                RuntimeRevision = prior.RuntimeRevision + 1,
                RefreshToken = rotated,
            };

            await _slots.CompareAndCommitAsync(successor, prior.Version, declared.AuthorityEpoch, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var record = new MutableSlotRecord(
            profile.Id,
            declared.Slot,
            profile.ScopeFingerprint,
            declared.AuthorityEpoch,
            declared.RuntimeRevision + 1,
            rotated);

        await _slots.ReplaceAsync(record, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reports a committed rotation best-effort. The durable commit already happened, so a
    /// notification failure is an auxiliary outcome and is never reported as a failed rotation.
    /// </summary>
    private async ValueTask NotifyRotationAsync(
        string profileId,
        string slot,
        long authorityEpoch,
        long previousRuntimeRevision,
        long runtimeRevision,
        CancellationToken cancellationToken)
    {
        if (OnRefreshTokenRotated is not { } notify)
        {
            return;
        }

        try
        {
            await notify(
                new RotatedRefreshToken(profileId, slot, authorityEpoch, previousRuntimeRevision, runtimeRevision),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The rotation is durable. Reconciliation regenerates its report from the committed
            // record, so a failure here must not turn a committed rotation into a refused call.
        }
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

    /// <summary>The effective authority an acquisition runs under: the resolved refresh value and
    /// the epoch/revision that identify it, plus the local decision when one supplied the value.</summary>
    private sealed record EffectiveAuthority(
        string RefreshToken,
        long AuthorityEpoch,
        long RuntimeRevision,
        MutableSlotDecision? Decision);

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

/// <summary>
/// The outcome of clearing one profile's local authority.
/// </summary>
/// <remarks>
/// Carries the code an operator reads and the epoch/revision the clear established. The previous
/// refresh value travels only so the caller can attempt a bounded revocation with it, and is never
/// rendered, logged or persisted by this type or by any report built from it.
/// </remarks>
/// <param name="Cleared">True once a new cleared floor was committed.</param>
/// <param name="Code">A stable, non-secret outcome code.</param>
/// <param name="Message">A non-secret explanation naming what happened and what to do next.</param>
/// <param name="AuthorityEpoch">The cleared epoch, or the observed epoch for a no-op.</param>
/// <param name="RuntimeRevision">The revision the clear established, or the observed one for a no-op.</param>
/// <param name="PriorRefreshToken">
/// The refresh value the superseded authority held, in memory only, or null when there was none.
/// </param>
internal sealed record OAuthAuthorityClear(
    bool Cleared,
    string Code,
    string Message,
    long AuthorityEpoch,
    long RuntimeRevision,
    string? PriorRefreshToken);

/// <summary>
/// The outcome of committing one profile's completed authorization attempt.
/// </summary>
/// <remarks>
/// Carries the code an operator reads and the epoch/revision the authorization established. It never
/// carries the access token, the refresh token or any provider body; those live only in the values
/// the caller passed in and in the durable record.
/// </remarks>
/// <param name="Authorized">True once a new authorized decision was committed.</param>
/// <param name="Code">A stable, non-secret outcome code.</param>
/// <param name="Message">A non-secret explanation naming what happened and what to do next.</param>
/// <param name="AuthorityEpoch">The committed epoch, or zero when nothing was committed.</param>
/// <param name="RuntimeRevision">The committed revision, or zero when nothing was committed.</param>
internal sealed record OAuthAuthorityAuthorization(
    bool Authorized,
    string Code,
    string Message,
    long AuthorityEpoch,
    long RuntimeRevision);
