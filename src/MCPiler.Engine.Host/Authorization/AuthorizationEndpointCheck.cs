using System.Text.Json;
using System.Net;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// Performs startup preflight for the endpoint the configured authorization mode trusts.
/// </summary>
/// <remarks>
/// A valid discovery document that omits or unusably names the endpoint is a configuration
/// refusal. A discovery request that cannot complete is an issuer outage and is deliberately not
/// converted into a false configuration claim. No credential-bearing endpoint request is made by
/// this check.
/// </remarks>
internal static class AuthorizationEndpointCheck
{
    private static readonly TimeSpan DiscoveryTimeout = TimeSpan.FromSeconds(5);

    internal static async Task<StartupRefusal?> FindAsync(
        HostAuthorizationOptions? authorization,
        CancellationToken cancellationToken)
        => await FindAsync(authorization, proxy: null, cancellationToken).ConfigureAwait(false);

    internal static async Task<StartupRefusal?> FindAsync(
        HostAuthorizationOptions? authorization,
        IWebProxy? proxy,
        CancellationToken cancellationToken)
    {
        if (authorization is not { } options)
        {
            return null;
        }

        return options.Validation switch
        {
            HostTokenValidation.Introspection => await FindIntrospectionAsync(options, proxy, cancellationToken).ConfigureAwait(false),
            HostTokenValidation.Jwks => await FindJwksAsync(options, proxy, cancellationToken).ConfigureAwait(false),
            _ => null,
        };
    }

    private static async Task<StartupRefusal?> FindIntrospectionAsync(
        HostAuthorizationOptions options,
        IWebProxy? proxy,
        CancellationToken cancellationToken)
    {
        if (options.IntrospectionEndpoint is { } explicitEndpoint)
        {
            return ValidateExplicit(options, explicitEndpoint, HostConfiguration.IntrospectionEndpointKey, "introspection");
        }

        IssuerMetadataDiscovery metadata = await DiscoverAsync(options, proxy, cancellationToken).ConfigureAwait(false);
        if (metadata.InvalidReason is { } invalid)
        {
            return InvalidMetadataRefusal(options, metadata, invalid);
        }

        if (DiscoveryStatusRefusal(metadata, options) is { } statusRefusal)
        {
            return statusRefusal;
        }

        return metadata.Document is { } document
            ? ValidateDiscovered(document, options, "introspection_endpoint", HostConfiguration.IntrospectionEndpointKey, "introspection")
            : null;
    }

    private static async Task<StartupRefusal?> FindJwksAsync(
        HostAuthorizationOptions options,
        IWebProxy? proxy,
        CancellationToken cancellationToken)
    {
        if (options.JwksUri is { } explicitUri)
        {
            return ValidateExplicit(options, explicitUri, HostConfiguration.JwksUriKey, "JWKS");
        }

        IssuerMetadataDiscovery metadata = await DiscoverAsync(options, proxy, cancellationToken).ConfigureAwait(false);
        if (metadata.InvalidReason is { } invalid)
        {
            return InvalidMetadataRefusal(options, metadata, invalid);
        }

        if (DiscoveryStatusRefusal(metadata, options) is { } statusRefusal)
        {
            return statusRefusal;
        }

        return metadata.Document is { } document
            ? ValidateDiscovered(document, options, "jwks_uri", HostConfiguration.JwksUriKey, "JWKS")
            : null;
    }

    private static StartupRefusal? ValidateExplicit(
        HostAuthorizationOptions options,
        string address,
        string setting,
        string kind)
    {
        if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? endpoint)
            || !AuthorizationEndpointPolicy.IsAllowed(endpoint))
        {
            return InsecureRefusal(options, setting, kind, address);
        }

        return null;
    }

    private static StartupRefusal? ValidateDiscovered(
        JsonElement metadata,
        HostAuthorizationOptions options,
        string member,
        string setting,
        string kind)
    {
        if (metadata.ValueKind is not JsonValueKind.Object)
        {
            return MissingRefusal(options, setting, kind);
        }

        if (IssuerMetadata.TryReadUniqueMember(metadata, member, out _, out bool duplicated) && duplicated)
        {
            return AmbiguousRefusal(options, setting, kind);
        }

        if (!IssuerMetadata.TryReadEndpoint(metadata, member, out string address)
            || !Uri.TryCreate(address, UriKind.Absolute, out Uri? endpoint)
            || (!string.Equals(endpoint.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                && !string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            return MissingRefusal(options, setting, kind);
        }

        return AuthorizationEndpointPolicy.IsAllowed(endpoint)
            ? null
            : InsecureRefusal(options, setting, kind, address);
    }

    private static async Task<IssuerMetadataDiscovery> DiscoverAsync(
        HostAuthorizationOptions options,
        IWebProxy? proxy,
        CancellationToken cancellationToken)
    {
        using HttpClient client = AuthorizationHttpClientFactory.Create(DiscoveryTimeout, proxy);

        // The one shared resolver: startup, JWKS and introspection all read the same route policy,
        // so no half of the process can fall back when the other half would not.
        return await IssuerMetadata.ResolveAsync(
            client,
            options.Issuer,
            options.OidcDiscoveryFallbackEnabled,
            cancellationToken).ConfigureAwait(false);
    }

    private static StartupRefusal? DiscoveryStatusRefusal(
        IssuerMetadataDiscovery metadata,
        HostAuthorizationOptions options)
    {
        if (metadata.StatusCode is not { } status || status is HttpStatusCode.OK)
        {
            return null;
        }

        int code = (int)status;
        if (status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests
            || code >= 500)
        {
            // A server-side or throttling response may recover without an operator change.
            return null;
        }

        string attempt = metadata.Route is IssuerMetadataRoute.OidcFallback
            ? "RFC 8414 discovery was definitively absent and the enabled OIDC discovery fallback returned"
            : "RFC 8414 discovery returned";

        return new StartupRefusal(
            string.Empty,
            "auth/issuer-discovery-unusable",
            $"'{HostConfiguration.IssuerKey}' is '{options.Issuer}', but {attempt} HTTP {code} ({status}). "
            + "The configured issuer endpoint is definitively unusable by this Engine configuration.")
        {
            Setting = HostConfiguration.IssuerKey,
        };
    }

    private static StartupRefusal InvalidMetadataRefusal(
        HostAuthorizationOptions options,
        IssuerMetadataDiscovery metadata,
        string reason)
    {
        string attempt = metadata.Route is IssuerMetadataRoute.OidcFallback
            ? "RFC 8414 discovery was definitively absent and the enabled OIDC discovery fallback returned metadata that cannot be trusted. "
            : "RFC 8414 discovery returned metadata that cannot be trusted. ";

        return new(
            string.Empty,
            "auth/issuer-metadata-invalid",
            $"'{HostConfiguration.IssuerKey}' is '{options.Issuer}', but {attempt}{reason}")
        {
            Setting = HostConfiguration.IssuerKey,
        };
    }

    private static StartupRefusal MissingRefusal(
        HostAuthorizationOptions options,
        string setting,
        string kind)
        => new(
            string.Empty,
            $"auth/{(kind is "JWKS" ? "jwks-uri" : "introspection-endpoint")}-missing",
            $"'{HostConfiguration.TokenValidationKey}' is configured for {kind} validation and "
            + $"'{HostConfiguration.IssuerKey}' is '{options.Issuer}', but the issuer publishes no "
            + $"usable '{(kind is "JWKS" ? "jwks_uri" : "introspection_endpoint")}'. Configure "
            + $"'{setting}' explicitly, or point '{HostConfiguration.IssuerKey}' at an authorization server "
            + "that publishes the endpoint.")
        {
            Setting = setting,
        };

    private static StartupRefusal AmbiguousRefusal(
        HostAuthorizationOptions options,
        string setting,
        string kind)
        => new(
            string.Empty,
            $"auth/{(kind is "JWKS" ? "jwks-uri" : "introspection-endpoint")}-ambiguous",
            $"'{HostConfiguration.TokenValidationKey}' is configured for {kind} validation and "
            + $"'{HostConfiguration.IssuerKey}' is '{options.Issuer}', but the discovered metadata declares "
            + $"'{(kind is "JWKS" ? "jwks_uri" : "introspection_endpoint")}' more than once. A duplicated "
            + "endpoint member is ambiguous and is not trusted; publish exactly one, or configure "
            + $"'{setting}' explicitly.")
        {
            Setting = setting,
        };

    private static StartupRefusal InsecureRefusal(
        HostAuthorizationOptions options,
        string setting,
        string kind,
        string address)
        => new(
            string.Empty,
            $"auth/{(kind is "JWKS" ? "jwks-uri" : "introspection-endpoint")}-insecure",
            $"'{HostConfiguration.TokenValidationKey}' is configured for {kind} validation and "
            + $"'{setting}' resolved to '{address}', which is remote plain http. Authorization trust "
            + "endpoints must use https unless they resolve to loopback; no credential or key request "
            + $"was sent to it for issuer '{options.Issuer}'.")
        {
            Setting = setting,
        };
}
