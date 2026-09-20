using System.Net;
using System.Text.Json;

using MCPiler.Engine.Host.Configuration;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// Validates tokens by verifying the issuer's signature and lifetime locally, against the
/// keys the issuer publishes as JWKS.
/// </summary>
/// <remarks>
/// <para>
/// JWKS validation is chosen when the issuer's availability must not gate every request: a
/// verified signature and an unexpired timestamp are checked without a round trip, which is
/// what "offline-capable" costs — revocation and early inactivation are invisible here. The
/// configuration chooses this approximation knowingly; the introspection mode is the one
/// that answers "is this token still active" as a fact.
/// </para>
/// <para>
/// The <c>aud</c> claim is read but never validated by the token library: the audience
/// decision is byte-exact against the addressed surface and is made by the authorization
/// middleware, once, where the canonical identifier is known. Letting the validator accept a
/// list of configured audiences would reintroduce exactly the relaxed matching the
/// protected-resource requirement forbids.
/// </para>
/// <para>
/// Fail-closed everywhere: an unreadable key set, a malformed token, a signature that does
/// not verify, an expired timestamp — each is an inactive token, never an exception.
/// </para>
/// </remarks>
internal sealed class JwksTokenValidator : ITokenValidator
{
    private readonly HttpClient _client;
    private readonly string _issuer;
    private readonly string? _jwksOverride;
    private readonly TokenValidationParameters _parameters;

    private string? _jwksUri;

    internal JwksTokenValidator(HttpClient client, string issuer, string? jwksOverride)
    {
        _client = client;
        _issuer = issuer;
        _jwksOverride = jwksOverride;
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
        string? jwksUri = await ResolveJwksUriAsync(cancellationToken).ConfigureAwait(false);

        if (jwksUri is null)
        {
            return TokenVerification.Inactive;
        }

        JsonWebKeySet? keys = await FetchKeysAsync(jwksUri, cancellationToken).ConfigureAwait(false);

        if (keys is null || keys.GetSigningKeys().Count == 0)
        {
            return TokenVerification.Inactive;
        }

        TokenValidationParameters parameters = _parameters.Clone();
        parameters.IssuerSigningKeys = [.. keys.GetSigningKeys()];

        try
        {
            JsonWebTokenHandler handler = new();
            TokenValidationResult result = await handler.ValidateTokenAsync(token, parameters).ConfigureAwait(false);

            if (!result.IsValid || result.SecurityToken is not JsonWebToken verified)
            {
                return TokenVerification.Inactive;
            }

            string? audience = verified.Audiences?.FirstOrDefault();
            return new TokenVerification(
                Active: true,
                Audience: audience,
                Scopes: ScopeClaim(verified));
        }
        catch (Exception failure)
            when (failure is ArgumentException or SecurityTokenMalformedException or SecurityTokenInvalidSignatureException)
        {
            return TokenVerification.Inactive;
        }
    }

    /// <summary>
    /// Resolves the JWKS URI once from the issuer's RFC 8414 metadata, unless configuration
    /// overrode it. Re-discovering per request would make every invocation depend on the
    /// issuer's metadata endpoint, which is the dependency the JWKS mode exists to avoid.
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

        JsonElement? metadata;

        try
        {
            metadata = await IssuerMetadata.DiscoverAsync(
                _client,
                _issuer,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is HttpRequestException or TaskCanceledException)
        {
            return null;
        }

        if (metadata is not { } discovered
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
        catch (Exception failure) when (failure is HttpRequestException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads the scope claim, treating the multi-audience case as naming no single resource.
    /// </summary>
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
