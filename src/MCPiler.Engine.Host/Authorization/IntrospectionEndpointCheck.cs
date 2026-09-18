using System.Net;
using System.Text.Json;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// The startup refusal for an introspection deployment whose issuer publishes no introspection
/// endpoint.
/// </summary>
/// <remarks>
/// <para>
/// A resource server configured for introspection can only ever answer "this token is not known
/// to be active" when the endpoint it needs does not exist. Every protected request then fails
/// with the one answer a client cannot tell apart from its own misconfiguration, and the
/// operator debugs the wrong end of the connection. Refusing to start names the setting instead.
/// </para>
/// <para>
/// The check is about the issuer's published metadata, deliberately not about the issuer's
/// availability. A check that required the issuer to answer would make this process's startup
/// depend on another service being reachable, and an orchestrator that restarts a refused
/// process would turn an authorization-server outage into a restart loop. An unreachable issuer
/// is therefore not a refusal: the per-request path already fails closed in exactly that case,
/// and an outage is a condition that ends by itself.
/// </para>
/// </remarks>
internal static class IntrospectionEndpointCheck
{
    /// <summary>The bound on the single discovery request this check makes.</summary>
    /// <remarks>
    /// Short because startup is where the whole process waits. A slow enough answer to exceed
    /// this budget is treated as an unreachable issuer rather than as a missing endpoint,
    /// because "did not answer in time" is not evidence about what an issuer publishes.
    /// </remarks>
    private static readonly TimeSpan DiscoveryTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The refusal when the configured mode needs an introspection endpoint the issuer does not
    /// publish, or <c>null</c> when the configuration is usable or the issuer could not be asked.
    /// </summary>
    internal static async Task<StartupRefusal?> FindAsync(
        HostAuthorizationOptions? authorization,
        CancellationToken cancellationToken)
    {
        if (authorization is not { } options
            || options.Validation is not HostTokenValidation.Introspection
            || options.IntrospectionEndpoint is not null)
        {
            // A configured endpoint is the operator stating where to introspect, and a mode that
            // never introspects has nothing to discover. Only the discovered case can be checked.
            return null;
        }

        bool? published = await PublishesIntrospectionEndpointAsync(options.Issuer, cancellationToken)
            .ConfigureAwait(false);

        // True is a usable deployment; null is an issuer that could not be asked, which is not a
        // configuration fault and not this check's decision.
        if (published is not false)
        {
            return null;
        }

        return new StartupRefusal(
            string.Empty,
            "auth/introspection-endpoint-missing",
            $"'{HostConfiguration.TokenValidationKey}' is '{HostConfiguration.IntrospectionModeName}' and "
            + $"'{HostConfiguration.IssuerKey}' is '{options.Issuer}', but that issuer publishes no "
            + "introspection endpoint, so no token could ever be validated against it. Configure "
            + $"'{HostConfiguration.IntrospectionEndpointKey}' to state the endpoint directly, or point "
            + $"'{HostConfiguration.IssuerKey}' at the authorization server that issues these tokens.")
        {
            Setting = HostConfiguration.IntrospectionEndpointKey,
        };
    }

    /// <summary>
    /// Whether the issuer's RFC 8414 metadata names an introspection endpoint, or <c>null</c> when
    /// the metadata could not be read.
    /// </summary>
    private static async Task<bool?> PublishesIntrospectionEndpointAsync(
        string issuer,
        CancellationToken cancellationToken)
    {
        using HttpClient client = new() { Timeout = DiscoveryTimeout };

        JsonElement? metadata;

        try
        {
            metadata = await IssuerMetadata.DiscoverAsync(client, issuer, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            // The issuer could not be asked. That is an outage, not a configuration fault.
            return null;
        }

        if (metadata is not { } discovered
            || !discovered.TryGetProperty("introspection_endpoint", out JsonElement endpoint)
            || endpoint.ValueKind is not JsonValueKind.String
            || endpoint.GetString() is not { Length: > 0 } address
            || !Uri.TryCreate(address, UriKind.Absolute, out Uri? resolved)
            || resolved.Scheme is not ("http" or "https"))
        {
            return false;
        }

        return true;
    }
}
