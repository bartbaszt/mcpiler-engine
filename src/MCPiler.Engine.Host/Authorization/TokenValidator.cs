using System.Net;
using System.Text.Json;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// The outcome of validating one presented bearer token.
/// </summary>
/// <param name="Active">Whether the token is valid, live, and issued by the trusted issuer.</param>
/// <param name="Audience">The audience claim, when the token is active.</param>
/// <param name="Scopes">The scope claim split on spaces, when the token is active.</param>
/// <param name="ExpiresAt">The issuer-reported expiration, when the validation mode provided one.</param>
public sealed record TokenVerification(
    bool Active,
    string? Audience,
    IReadOnlyList<string> Scopes,
    DateTimeOffset? ExpiresAt = null)
{
    /// <summary>The verdict for a token that failed validation for any reason.</summary>
    public static TokenVerification Inactive { get; } = new(false, null, []);

    /// <summary>
    /// Whether an inactive result came from a successfully parsed RFC 7662 <c>active:false</c>
    /// response and may therefore be negatively cached.
    /// </summary>
    public bool IsAuthoritativeInactive { get; init; }
}

/// <summary>
/// Validates a presented bearer token against the one issuer this process trusts.
/// </summary>
/// <remarks>
/// <para>
/// The seam is deliberately narrow: a token and a deadline go in, an active flag, an
/// audience and scopes come out. What "active" means — a remote introspection response or a
/// verified signature and lifetime — is the implementation's whole identity, and no caller
/// can observe which one answered.
/// </para>
/// <para>
/// Every implementation fails closed. An unreachable introspection endpoint, an
/// uninterpretable key set, a malformed token: each is an inactive token, never an
/// exception, because the alternative is a request whose failure mode depends on which half
/// of the authorization configuration broke.
/// </para>
/// </remarks>
public interface ITokenValidator
{
    /// <summary>Validates one presented token against the trusted issuer.</summary>
    Task<TokenVerification> ValidateAsync(string token, CancellationToken cancellationToken);
}

/// <summary>
/// Discovers the RFC 8414 authorization-server metadata of the trusted issuer.
/// </summary>
/// <remarks>
/// Both validation modes need it: introspection reads its endpoint from
/// <c>introspection_endpoint</c>, JWKS reads its keys from <c>jwks_uri</c>. Discovery is
/// shared rather than duplicated so the two modes cannot disagree about where an issuer's
/// metadata lives.
/// </remarks>
internal readonly record struct IssuerMetadataDiscovery(
    JsonElement? Document,
    string? InvalidReason);

internal static class IssuerMetadata
{
    internal static Uri DiscoveryUri(string issuer)
    {
        Uri configured = new(issuer, UriKind.Absolute);
        string issuerPath = configured
            .GetComponents(UriComponents.Path, UriFormat.UriEscaped)
            .TrimStart('/');

        string path = "/.well-known/oauth-authorization-server";
        if (issuerPath.Length > 0)
        {
            path += "/" + issuerPath;
        }

        return new Uri(configured.GetLeftPart(UriPartial.Authority) + path, UriKind.Absolute);
    }

    internal static async Task<IssuerMetadataDiscovery> DiscoverAsync(
        HttpClient client,
        string issuer,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await client.GetAsync(
            DiscoveryUri(issuer),
            cancellationToken).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.OK)
        {
            return new IssuerMetadataDiscovery(null, null);
        }

        try
        {
            using JsonDocument document = await JsonDocument.ParseAsync(
                await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false),
                cancellationToken: cancellationToken).ConfigureAwait(false);

            JsonElement root = document.RootElement;

            if (root.ValueKind is not JsonValueKind.Object)
            {
                return new IssuerMetadataDiscovery(null, "The authorization-server metadata is not a JSON object.");
            }

            if (!root.TryGetProperty("issuer", out JsonElement declared)
                || declared.ValueKind is not JsonValueKind.String
                || declared.GetString() is not { Length: > 0 } metadataIssuer)
            {
                return new IssuerMetadataDiscovery(null, "The authorization-server metadata omits the required 'issuer' member.");
            }

            if (!string.Equals(metadataIssuer, issuer, StringComparison.Ordinal))
            {
                return new IssuerMetadataDiscovery(
                    null,
                    $"The authorization-server metadata issuer '{metadataIssuer}' does not exactly match configured issuer '{issuer}'.");
            }

            return new IssuerMetadataDiscovery(root.Clone(), null);
        }
        catch (JsonException)
        {
            return new IssuerMetadataDiscovery(null, "The authorization-server metadata is not valid JSON.");
        }
    }
}
