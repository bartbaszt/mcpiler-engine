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
/// Which well-known metadata route produced a discovery outcome.
/// </summary>
internal enum IssuerMetadataRoute
{
    /// <summary>The RFC 8414 <c>/.well-known/oauth-authorization-server</c> route.</summary>
    Rfc8414 = 0,

    /// <summary>
    /// The issuer-derived OIDC <c>openid-configuration</c> route, reachable only after the RFC 8414
    /// resource answered a definitive 404/410 and only when the host explicitly enabled fallback.
    /// </summary>
    OidcFallback = 1,
}

/// <summary>Why an HTTP 200 metadata document was refused, as one structured category.</summary>
/// <remarks>
/// A consumer that renders a refusal to an operator selects its own fixed diagnostic from this
/// category instead of echoing <see cref="IssuerMetadataDiscovery.InvalidReason"/>: the reason text
/// may embed the configured issuer, its derived metadata URL or members of the untrusted document.
/// </remarks>
internal enum IssuerMetadataInvalidKind
{
    /// <summary>No invalid-document refusal was produced.</summary>
    None,

    /// <summary>The body was not valid JSON or not a JSON object.</summary>
    Malformed,

    /// <summary>The required <c>issuer</c> member is absent or not a non-empty string.</summary>
    MissingIssuer,

    /// <summary>The <c>issuer</c> member appears more than once, so no single identity exists.</summary>
    DuplicateIssuer,

    /// <summary>The declared issuer is not byte-identical to the configured issuer.</summary>
    IssuerMismatch,

    /// <summary>The configured issuer derives a URL the origin policy refuses before any request.</summary>
    OriginRefused,
}

/// <summary>
/// Discovers the RFC 8414 authorization-server metadata of the trusted issuer, with the restricted
/// opt-in OIDC fallback.
/// </summary>
/// <remarks>
/// <para>
/// Both validation modes and the startup preflight use this one resolver, so they cannot disagree
/// about which metadata route answers, what counts as a definitive absence, or how a returned
/// document is trusted. Introspection reads its endpoint from <c>introspection_endpoint</c>, JWKS
/// reads its keys from <c>jwks_uri</c>; discovery is shared rather than duplicated.
/// </para>
/// <para>
/// Fallback is deliberately narrow. It fires only when the primary RFC 8414 resource answered
/// exactly 404 or 410, the operator enabled it, and the alternate URL was derived from the
/// configured issuer. A malformed or wrong-issuer document, a redirect, any other status and every
/// transport failure end the resolution without a second origin ever being asked: a document is
/// never reinterpreted as absence.
/// </para>
/// </remarks>
/// <param name="Document">The validated metadata document, when discovery succeeded.</param>
/// <param name="InvalidReason">
/// Why an HTTP 200 document was refused, when one was returned. The text may embed the configured
/// issuer, its derived metadata URL or members of the untrusted document, so it is diagnostic detail
/// for internal consumers, not operator-facing output; consumers that print a refusal select their
/// own fixed message from <see cref="InvalidKind"/> instead.
/// </param>
/// <param name="StatusCode">The HTTP status that ended the resolution, when one was received.</param>
/// <param name="Route">Which well-known route produced this outcome.</param>
internal readonly record struct IssuerMetadataDiscovery(
    JsonElement? Document,
    string? InvalidReason,
    HttpStatusCode? StatusCode = null,
    IssuerMetadataRoute Route = IssuerMetadataRoute.Rfc8414)
{
    /// <summary>
    /// Whether the request produced no HTTP status at all: DNS, TLS, timeout or a comparable
    /// transport failure. A transport failure is an outage, never a definitive absence.
    /// </summary>
    internal bool IsTransportFailure => Document is null && InvalidReason is null && StatusCode is null;

    /// <summary>The structured category of an invalid-document refusal, when one was produced.</summary>
    internal IssuerMetadataInvalidKind InvalidKind { get; init; }
}

internal static class IssuerMetadata
{
    /// <summary>The RFC 8414 well-known path.</summary>
    internal const string Rfc8414WellKnownPath = "/.well-known/oauth-authorization-server";

    /// <summary>The OIDC Discovery well-known path.</summary>
    internal const string OidcWellKnownPath = "/.well-known/openid-configuration";

    internal static Uri DiscoveryUri(string issuer)
    {
        Uri configured = new(issuer, UriKind.Absolute);
        string issuerPath = configured
            .GetComponents(UriComponents.Path, UriFormat.UriEscaped)
            .TrimStart('/');

        string path = Rfc8414WellKnownPath;
        if (issuerPath.Length > 0)
        {
            path += "/" + issuerPath;
        }

        return new Uri(configured.GetLeftPart(UriPartial.Authority) + path, UriKind.Absolute);
    }

    /// <summary>
    /// The OIDC Discovery 1.0 metadata URL for a configured issuer.
    /// </summary>
    /// <remarks>
    /// The well-known path is appended to the issuer path, which is the one standards-compliant
    /// construction for OIDC Discovery and differs from RFC 8414's insert-before-path rule. The URL
    /// is derived from the configured issuer alone: no slug inference, no arbitrary override, and
    /// no widening of the issuer's origin.
    /// </remarks>
    internal static Uri OidcDiscoveryUri(string issuer)
    {
        Uri configured = new(issuer, UriKind.Absolute);
        string issuerPath = configured
            .GetComponents(UriComponents.Path, UriFormat.UriEscaped)
            .Trim('/');

        string path = issuerPath.Length == 0
            ? OidcWellKnownPath
            : "/" + issuerPath + OidcWellKnownPath;

        return new Uri(configured.GetLeftPart(UriPartial.Authority) + path, UriKind.Absolute);
    }

    /// <summary>
    /// Resolves the trusted issuer's metadata through the shared primary-then-fallback policy.
    /// </summary>
    internal static async Task<IssuerMetadataDiscovery> ResolveAsync(
        HttpClient client,
        string issuer,
        bool allowOidcFallback,
        CancellationToken cancellationToken)
    {
        Uri primary;

        try
        {
            primary = DiscoveryUri(issuer);
        }
        catch (UriFormatException)
        {
            return new IssuerMetadataDiscovery(null, null);
        }

        if (!AuthorizationEndpointPolicy.IsAllowed(primary))
        {
            // The configured issuer itself must already satisfy the trust-endpoint policy at bind
            // time; re-checking here keeps the resolver self-contained, because no request may be
            // sent to an address the policy would refuse when the URL is derived rather than spelled.
            return new IssuerMetadataDiscovery(
                null,
                $"The configured issuer '{issuer}' derives metadata URL '{primary}', which is remote plain http. "
                + "Authorization trust endpoints must use https unless they resolve to loopback.")
            {
                InvalidKind = IssuerMetadataInvalidKind.OriginRefused,
            };
        }

        IssuerMetadataDiscovery resolved = await FetchAsync(
            client,
            primary,
            issuer,
            IssuerMetadataRoute.Rfc8414,
            cancellationToken).ConfigureAwait(false);

        // Fallback requires a definitive absence from the exact RFC 8414 resource: an HTTP status,
        // not a transport failure, and exactly 404 or 410. Any document — valid or not — and every
        // other status ends the resolution here, because answering them with a different
        // well-known would turn a trust-configuration error into a different trust authority.
        if (!allowOidcFallback
            || resolved.Document is not null
            || resolved.InvalidReason is not null
            || resolved.IsTransportFailure
            || resolved.StatusCode is not (HttpStatusCode.NotFound or HttpStatusCode.Gone))
        {
            return resolved;
        }

        Uri fallback;
        try
        {
            fallback = OidcDiscoveryUri(issuer);
        }
        catch (UriFormatException)
        {
            return resolved;
        }

        return await FetchAsync(
            client,
            fallback,
            issuer,
            IssuerMetadataRoute.OidcFallback,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one member and reports whether the document declares it more than once.
    /// </summary>
    /// <remarks>
    /// Duplicate security-relevant members are ambiguity, not a normalization problem: a document
    /// that names two different issuers or two different endpoints must be refused rather than
    /// resolved by whichever occurrence the JSON reader happens to return first.
    /// </remarks>
    internal static bool TryReadUniqueMember(
        JsonElement root,
        string member,
        out JsonElement value,
        out bool duplicated)
    {
        value = default;
        duplicated = false;
        bool found = false;

        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (!string.Equals(property.Name, member, StringComparison.Ordinal))
            {
                continue;
            }

            if (found)
            {
                duplicated = true;
            }
            else
            {
                value = property.Value;
                found = true;
            }
        }

        return found;
    }

    /// <summary>
    /// Reads one endpoint member a discovery consumer may trust.
    /// </summary>
    /// <remarks>
    /// A missing, non-string, empty or duplicated member is unusable. The duplicate case must not
    /// be normalized to a single occurrence, and every runtime consumer must treat any of these
    /// shapes exactly as fail-closed as an unreachable endpoint.
    /// </remarks>
    internal static bool TryReadEndpoint(JsonElement document, string member, out string address)
    {
        address = string.Empty;

        if (!TryReadUniqueMember(document, member, out JsonElement value, out bool duplicated)
            || duplicated
            || value.ValueKind is not JsonValueKind.String
            || value.GetString() is not { Length: > 0 } declared)
        {
            return false;
        }

        address = declared;
        return true;
    }

    private static async Task<IssuerMetadataDiscovery> FetchAsync(
        HttpClient client,
        Uri uri,
        string issuer,
        IssuerMetadataRoute route,
        CancellationToken cancellationToken)
    {
        HttpResponseMessage response;

        try
        {
            response = await client.GetAsync(uri, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            // DNS, TLS, timeout: an outage on this route. The caller must never treat it as a
            // definitive absence, so no alternate well-known is attempted.
            return new IssuerMetadataDiscovery(null, null, null, route);
        }

        using (response)
        {
            return response.StatusCode != HttpStatusCode.OK
                ? new IssuerMetadataDiscovery(null, null, response.StatusCode, route)
                : await ValidateAsync(response, issuer, route, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<IssuerMetadataDiscovery> ValidateAsync(
        HttpResponseMessage response,
        string issuer,
        IssuerMetadataRoute route,
        CancellationToken cancellationToken)
    {
        string label = route is IssuerMetadataRoute.OidcFallback
            ? "The OIDC discovery fallback metadata"
            : "The authorization-server metadata";

        try
        {
            using JsonDocument document = await JsonDocument.ParseAsync(
                await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false),
                cancellationToken: cancellationToken).ConfigureAwait(false);

            JsonElement root = document.RootElement;

            if (root.ValueKind is not JsonValueKind.Object)
            {
                return new IssuerMetadataDiscovery(null, $"{label} is not a JSON object.", response.StatusCode, route)
                {
                    InvalidKind = IssuerMetadataInvalidKind.Malformed,
                };
            }

            if (!TryReadUniqueMember(root, "issuer", out JsonElement declared, out bool duplicated))
            {
                return new IssuerMetadataDiscovery(null, $"{label} omits the required 'issuer' member.", response.StatusCode, route)
                {
                    InvalidKind = IssuerMetadataInvalidKind.MissingIssuer,
                };
            }

            if (duplicated)
            {
                return new IssuerMetadataDiscovery(
                    null,
                    $"{label} declares the 'issuer' member more than once, so no single issuer identity can be trusted.",
                    response.StatusCode,
                    route)
                {
                    InvalidKind = IssuerMetadataInvalidKind.DuplicateIssuer,
                };
            }

            if (declared.ValueKind is not JsonValueKind.String
                || declared.GetString() is not { Length: > 0 } metadataIssuer)
            {
                return new IssuerMetadataDiscovery(null, $"{label} omits the required 'issuer' member.", response.StatusCode, route)
                {
                    InvalidKind = IssuerMetadataInvalidKind.MissingIssuer,
                };
            }

            if (!string.Equals(metadataIssuer, issuer, StringComparison.Ordinal))
            {
                return new IssuerMetadataDiscovery(
                    null,
                    $"{label} issuer '{metadataIssuer}' does not exactly match configured issuer '{issuer}'.",
                    response.StatusCode,
                    route)
                {
                    InvalidKind = IssuerMetadataInvalidKind.IssuerMismatch,
                };
            }

            return new IssuerMetadataDiscovery(root.Clone(), null, response.StatusCode, route);
        }
        catch (JsonException)
        {
            return new IssuerMetadataDiscovery(null, $"{label} is not valid JSON.", response.StatusCode, route)
            {
                InvalidKind = IssuerMetadataInvalidKind.Malformed,
            };
        }
    }
}
