using System.Net;
using System.Text.Json;

using MCPiler.Engine.Host.Configuration;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// Validates tokens by verifying the issuer's signature and lifetime locally, against a bounded
/// process-local cache of the keys the issuer publishes as JWKS.
/// </summary>
/// <remarks>
/// <para>
/// JWKS validation is chosen when the issuer's availability must not gate every request. A valid
/// key set is reused for a bounded interval, refreshed periodically and refreshed early when a
/// token names an unknown <c>kid</c>. A short stale window keeps already-known keys usable through
/// a transient issuer outage without turning the cache into an indefinite trust source.
/// </para>
/// <para>
/// The <c>aud</c> claim is read but never validated by the token library: the audience decision is
/// byte-exact against the addressed surface and is made by the authorization middleware. Exactly
/// one audience name is carried forward; a multi-valued audience names no single protected
/// resource and is refused in the same way as introspection mode.
/// </para>
/// <para>
/// Fail-closed everywhere: an unreadable or malformed key set, a malformed token, a signature that
/// does not verify, or an expired timestamp yields an inactive token, never an exception.
/// </para>
/// </remarks>
internal sealed class JwksTokenValidator : ITokenValidator
{
    private static readonly TimeSpan KeyRefreshInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaximumKeyAge = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan RefreshAttemptCooldown = TimeSpan.FromSeconds(30);

    private readonly HttpClient _client;
    private readonly string _issuer;
    private readonly string? _jwksOverride;
    private readonly TokenValidationParameters _parameters;
    private readonly TimeProvider _clock;
    private readonly object _keyGate = new();

    private string? _jwksUri;
    private JsonWebKeySet? _cachedKeys;
    private DateTimeOffset _keysFetchedAt;
    private DateTimeOffset _lastRegularRefreshAttemptAt;
    private DateTimeOffset _lastForcedRefreshAttemptAt;
    private Task<JsonWebKeySet?>? _refreshTask;

    internal JwksTokenValidator(
        HttpClient client,
        string issuer,
        string? jwksOverride,
        TimeProvider? clock = null)
    {
        _client = client;
        _issuer = issuer;
        _jwksOverride = jwksOverride;
        _clock = clock ?? TimeProvider.System;
        _parameters = new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
        };
    }

    public async Task<TokenVerification> ValidateAsync(string token, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        JsonWebKeySet? keys = await ResolveKeysAsync(forceRefresh: false, cancellationToken).ConfigureAwait(false);

        if (keys is null)
        {
            return TokenVerification.Inactive;
        }

        TokenVerification verification = await ValidateWithKeysAsync(token, keys).ConfigureAwait(false);

        if (verification.Active)
        {
            return verification;
        }

        string? kid = TokenKeyId(token);
        if (kid is null || ContainsKey(keys, kid))
        {
            return verification;
        }

        JsonWebKeySet? refreshed = await ResolveKeysAsync(forceRefresh: true, cancellationToken).ConfigureAwait(false);
        return refreshed is null
            ? TokenVerification.Inactive
            : await ValidateWithKeysAsync(token, refreshed).ConfigureAwait(false);
    }

    private async Task<TokenVerification> ValidateWithKeysAsync(string token, JsonWebKeySet keys)
    {
        if (!TrySigningKeys(keys, out IReadOnlyList<SecurityKey> signingKeys)
            || signingKeys.Count == 0)
        {
            return TokenVerification.Inactive;
        }

        TokenValidationParameters parameters = _parameters.Clone();
        parameters.IssuerSigningKeys = signingKeys;

        try
        {
            JsonWebTokenHandler handler = new();
            TokenValidationResult result = await handler.ValidateTokenAsync(token, parameters).ConfigureAwait(false);

            if (!result.IsValid || result.SecurityToken is not JsonWebToken verified)
            {
                return TokenVerification.Inactive;
            }

            string[] audiences = verified.Audiences?.Take(2).ToArray() ?? [];
            string? audience = audiences.Length == 1 ? audiences[0] : null;

            return new TokenVerification(
                Active: true,
                Audience: audience,
                Scopes: ScopeClaim(verified));
        }
        catch (Exception failure)
            when (failure is ArgumentException or JsonException or SecurityTokenException)
        {
            return TokenVerification.Inactive;
        }
    }

    private Task<JsonWebKeySet?> ResolveKeysAsync(
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        Task<JsonWebKeySet?> refresh;

        lock (_keyGate)
        {
            DateTimeOffset now = _clock.GetUtcNow();

            if (!forceRefresh && FreshKeysUnsafe(now) is { } fresh)
            {
                return Task.FromResult<JsonWebKeySet?>(fresh);
            }

            if (_refreshTask is null || _refreshTask.IsCompleted)
            {
                DateTimeOffset lastAttempt = forceRefresh
                    ? _lastForcedRefreshAttemptAt
                    : _lastRegularRefreshAttemptAt;

                if (lastAttempt != default && now - lastAttempt < RefreshAttemptCooldown)
                {
                    return Task.FromResult(StaleKeysUnsafe(now));
                }

                if (forceRefresh)
                {
                    _lastForcedRefreshAttemptAt = now;
                }
                else
                {
                    _lastRegularRefreshAttemptAt = now;
                }

                _refreshTask = RefreshKeysAsync();
            }

            refresh = _refreshTask;
        }

        return refresh.WaitAsync(cancellationToken);
    }

    private async Task<JsonWebKeySet?> RefreshKeysAsync()
    {
        string? jwksUri = await ResolveJwksUriAsync(CancellationToken.None).ConfigureAwait(false);
        JsonWebKeySet? fetched = jwksUri is null
            ? null
            : await FetchKeysAsync(jwksUri, CancellationToken.None).ConfigureAwait(false);

        lock (_keyGate)
        {
            DateTimeOffset now = _clock.GetUtcNow();

            if (fetched is not null
                && TrySigningKeys(fetched, out IReadOnlyList<SecurityKey> signingKeys)
                && signingKeys.Count > 0)
            {
                _cachedKeys = fetched;
                _keysFetchedAt = now;
                return fetched;
            }

            return StaleKeysUnsafe(now);
        }
    }

    private JsonWebKeySet? FreshKeysUnsafe(DateTimeOffset now)
        => _cachedKeys is not null && now - _keysFetchedAt <= KeyRefreshInterval
            ? _cachedKeys
            : null;

    private JsonWebKeySet? StaleKeysUnsafe(DateTimeOffset now)
        => _cachedKeys is not null && now - _keysFetchedAt <= MaximumKeyAge
            ? _cachedKeys
            : null;

    private static bool ContainsKey(JsonWebKeySet keys, string kid)
        => TrySigningKeys(keys, out IReadOnlyList<SecurityKey> signingKeys)
            && signingKeys.Any(key => string.Equals(key.KeyId, kid, StringComparison.Ordinal));

    private static bool TrySigningKeys(
        JsonWebKeySet keys,
        out IReadOnlyList<SecurityKey> signingKeys)
    {
        try
        {
            signingKeys = [.. keys.GetSigningKeys()];
            return true;
        }
        catch (Exception failure)
            when (failure is ArgumentException or JsonException or SecurityTokenException)
        {
            signingKeys = [];
            return false;
        }
    }

    private static string? TokenKeyId(string token)
    {
        try
        {
            return new JsonWebToken(token).Kid;
        }
        catch (Exception failure) when (failure is ArgumentException or SecurityTokenMalformedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Resolves the JWKS URI once from validated RFC 8414 metadata, unless configuration overrode
    /// it. The URI is cached separately from the bounded key-set cache.
    /// </summary>
    private async Task<string?> ResolveJwksUriAsync(CancellationToken cancellationToken)
    {
        if (_jwksUri is not null)
        {
            return _jwksUri;
        }

        if (_jwksOverride is { } overrideUri)
        {
            return Uri.TryCreate(overrideUri, UriKind.Absolute, out Uri? configured)
                && AuthorizationEndpointPolicy.IsAllowed(configured)
                ? overrideUri
                : null;
        }

        IssuerMetadataDiscovery metadata;

        try
        {
            metadata = await IssuerMetadata.DiscoverAsync(
                _client,
                _issuer,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            return null;
        }

        if (metadata.InvalidReason is not null
            || metadata.Document is not { } discovered
            || !discovered.TryGetProperty("jwks_uri", out JsonElement declared)
            || declared.ValueKind is not JsonValueKind.String
            || declared.GetString() is not { } address
            || !Uri.TryCreate(address, UriKind.Absolute, out Uri? resolved)
            || resolved.Scheme is not ("http" or "https")
            || !AuthorizationEndpointPolicy.IsAllowed(resolved))
        {
            return null;
        }

        return _jwksUri = address;
    }

    private async Task<JsonWebKeySet?> FetchKeysAsync(string jwksUri, CancellationToken cancellationToken)
    {
        try
        {
            using HttpResponseMessage response = await _client
                .GetAsync(jwksUri, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode is not HttpStatusCode.OK)
            {
                return null;
            }

            string json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return JsonWebKeySet.Create(json);
        }
        catch (Exception failure)
            when (failure is HttpRequestException or JsonException or ArgumentException)
        {
            return null;
        }
    }

    private static IReadOnlyList<string> ScopeClaim(JsonWebToken token)
    {
        if (token.Claims.FirstOrDefault(claim => string.Equals(claim.Type, "scope", StringComparison.Ordinal))?.Value
            is not { } declared)
        {
            return [];
        }

        return [.. declared.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
    }
}
