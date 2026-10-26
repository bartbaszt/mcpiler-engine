using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;

using Microsoft.IdentityModel.Tokens;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>How one explicit issuer readiness probe ended.</summary>
internal enum IssuerReadinessCategory
{
    /// <summary>Every check the probe can make without an issued token passed.</summary>
    Ready,

    /// <summary>No issuer or no validation mode is configured, so there is nothing to probe.</summary>
    Unconfigured,

    /// <summary>The bound trust mode has no readiness probe in this build.</summary>
    UnsupportedMode,

    /// <summary>A locally configured credential the probe would need is absent or unusable.</summary>
    CredentialUnusable,

    /// <summary>A metadata document arrived and is not usable as written.</summary>
    InvalidMetadata,

    /// <summary>The issuer's metadata resource produced no usable answer (outage, timeout or status).</summary>
    IssuerUnavailable,

    /// <summary>The effective trust URL must not be contacted (remote plain http, or a TLS trust failure).</summary>
    OriginRefused,

    /// <summary>The JWKS or introspection endpoint produced no usable answer.</summary>
    EndpointUnreachable,

    /// <summary>The introspection endpoint refused this resource server's authentication.</summary>
    EndpointUnauthorized,

    /// <summary>The endpoint answered with something that cannot establish readiness.</summary>
    EndpointUnusable,
}

/// <summary>One probe's sanitized, non-secret result.</summary>
/// <param name="Category">How the probe ended.</param>
/// <param name="Mode">
/// The probed trust mode's configuration spelling (<c>jwks</c> or <c>introspection</c>), or empty
/// when no mode was known.
/// </param>
/// <param name="Issuer">
/// The configured issuer string as configured, kept for byte-exact comparisons. Rendering shows
/// only its origin, because the configured value may itself carry credentials in a URL.
/// </param>
internal sealed record IssuerReadinessReport(
    IssuerReadinessCategory Category,
    string Mode,
    string Issuer)
{
    /// <summary>What the metadata step did, when the effective configuration consulted metadata.</summary>
    internal string? MetadataStep { get; init; }

    /// <summary>What the JWKS or introspection step observed, when one was reached.</summary>
    internal string? EndpointStep { get; init; }

    /// <summary>A bounded, sanitized explanation of a not-ready outcome. Never holds a secret.</summary>
    internal string? Detail { get; init; }
}

/// <summary>
/// The explicit, operator-only networked issuer readiness probe (OAUTH-IDP-2).
/// </summary>
/// <remarks>
/// <para>
/// This is deliberately a separate operation from <c>inspect</c>. Inspection answers "what would be
/// served and would startup refuse"; readiness answers "can the configured issuer be trusted right
/// now, over the network". Running one never implies the other, and neither rewrites the other's
/// answer.
/// </para>
/// <para>
/// The probe contacts only what the serving configuration would contact: the shared metadata resolver
/// (RFC 8414 first, and the issuer-derived OIDC well-known only when the operator enabled fallback
/// and RFC 8414 answered exactly 404/410), and then the effective JWKS URI or introspection
/// endpoint. An explicit <c>--jwks-uri</c>/<c>--introspection-endpoint</c> replaces discovery for the
/// serving validators, so it replaces it here too.
/// </para>
/// <para>
/// The probe manufactures no token. It never builds, signs or presents a bearer for any protected
/// resource, and it accepts no token on the command line. The introspection check authenticates as
/// the configured resource-server client and sends one invented, clearly non-issued probe value so
/// the endpoint can be exercised without pretending a caller token exists. That probe value is
/// memory-only and never rendered.
/// </para>
/// <para>
/// Nothing here mutates anything: no listener, no store lease, no cache, no authorization policy.
/// A successful result still states that issued-token audience, scope and revocation behavior are
/// not proven without a real provider-issued token.
/// </para>
/// <para>
/// Every address this report renders is either operator-configured or published by an untrusted
/// issuer document, and either may carry a credential in its userinfo, path, query or fragment.
/// Addresses therefore reach the operator through <see cref="SafeUriDisplay.Origin(string)"/>,
/// which prints only the origin and names the withheld component categories; diagnostic prose is
/// fixed text. No URL spelling, exception message or document member is echoed raw.
/// </para>
/// </remarks>
internal static class IssuerReadiness
{
    /// <summary>How long the metadata step may take, matching the startup preflight's bound.</summary>
    internal static readonly TimeSpan DiscoveryTimeout = TimeSpan.FromSeconds(5);

    /// <summary>How long the JWKS or introspection step may take, matching the validator's bound.</summary>
    internal static readonly TimeSpan EndpointTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The most characters of any remotely influenced value this report renders. An issuer document
    /// is untrusted input: it may carry an arbitrarily long string, so every echoed value is bounded
    /// and stripped of control characters before an operator's terminal or log sees it.
    /// </summary>
    private const int MaximumRenderedCharacters = 400;

    /// <summary>The process exit code a result calls for.</summary>
    /// <remarks>
    /// Ready is success. A transient inability to reach the issuer or endpoint is the generic failure
    /// code, because retrying is the right response and a deployment change is not. Everything else is
    /// the configuration code: the operator must change a setting, a document or a credential.
    /// </remarks>
    internal static int ExitCode(IssuerReadinessCategory category) => category switch
    {
        IssuerReadinessCategory.Ready => ExitCodes.Success,
        IssuerReadinessCategory.IssuerUnavailable or IssuerReadinessCategory.EndpointUnreachable => ExitCodes.Failure,
        _ => ExitCodes.Configuration,
    };

    /// <summary>Probes the bound issuer configuration with the production trust clients.</summary>
    internal static async Task<IssuerReadinessReport> ProbeAsync(
        HostAuthorizationOptions? authorization,
        CancellationToken cancellationToken)
    {
        if (authorization is not { } options)
        {
            return Unconfigured();
        }

        using HttpClient discoveryClient = AuthorizationHttpClientFactory.Create(DiscoveryTimeout);
        using HttpClient endpointClient = AuthorizationHttpClientFactory.Create(EndpointTimeout);

        return await ProbeAsync(options, discoveryClient, endpointClient, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Probes one bound configuration through caller-supplied clients. The two-client shape is the
    /// test seam: production always builds the factory clients above, whose redirect, proxy and
    /// response-size policies are the ones the serving path uses.
    /// </summary>
    internal static async Task<IssuerReadinessReport> ProbeAsync(
        HostAuthorizationOptions options,
        HttpClient metadataClient,
        HttpClient endpointClient,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(metadataClient);
        ArgumentNullException.ThrowIfNull(endpointClient);

        string mode = options.Validation switch
        {
            HostTokenValidation.Introspection => HostConfiguration.IntrospectionModeName,
            HostTokenValidation.Jwks => HostConfiguration.JwksModeName,
            _ => string.Empty,
        };

        if (options.Issuer.Length == 0)
        {
            return new IssuerReadinessReport(IssuerReadinessCategory.Unconfigured, mode, options.Issuer)
            {
                Detail = $"No issuer is configured, so there is no trust endpoint to probe. Name "
                    + $"'{HostConfiguration.IssuerKey}' and '{HostConfiguration.TokenValidationKey}' "
                    + "on the same deployment settings the serving process uses.",
            };
        }

        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out Uri? configured)
            || configured.Scheme is not ("http" or "https"))
        {
            return new IssuerReadinessReport(IssuerReadinessCategory.Unconfigured, mode, options.Issuer)
            {
                Detail = $"The configured issuer {SafeUriDisplay.Origin(options.Issuer)} is not an "
                    + "absolute http(s) URI, so there is no trust endpoint to probe.",
            };
        }

        if (mode.Length == 0)
        {
            return new IssuerReadinessReport(IssuerReadinessCategory.UnsupportedMode, mode, options.Issuer)
            {
                Detail = $"This build has no readiness probe for the bound trust mode. Configure "
                    + $"'{HostConfiguration.TokenValidationKey}' as "
                    + $"'{HostConfiguration.IntrospectionModeName}' or '{HostConfiguration.JwksModeName}'.",
            };
        }

        if (!TryDeriveMetadataUri(options.Issuer, out Uri? metadataUri))
        {
            return new IssuerReadinessReport(IssuerReadinessCategory.Unconfigured, mode, options.Issuer)
            {
                Detail = $"The configured issuer {SafeUriDisplay.Origin(options.Issuer)} derives no "
                    + "usable metadata URL.",
            };
        }

        if (!AuthorizationEndpointPolicy.IsAllowed(metadataUri!))
        {
            // The serving path refuses this issuer at bind time; the seam reports it here for callers
            // that built options directly. No request is sent anywhere, because the first URL the
            // probe would ask is already refused. The resolver re-checks the same deterministic
            // derivation internally, so its own origin refusal is unreachable through this probe;
            // DiscoveryFailure nevertheless maps the structured kind instead of the resolver's reason
            // text, so a future resolver change cannot leak a spelling through this report.
            return new IssuerReadinessReport(IssuerReadinessCategory.OriginRefused, mode, options.Issuer)
            {
                Detail = $"The configured issuer {SafeUriDisplay.Origin(options.Issuer)} derives metadata "
                    + $"URL {SafeUriDisplay.Origin(metadataUri!)}, which is remote plain http. Authorization "
                    + "trust endpoints must use https unless they resolve to loopback, so no request "
                    + "was sent to it.",
            };
        }

        if (options.Validation is HostTokenValidation.Introspection)
        {
            if (!TryReadIntrospectionCredential(options, out string? clientSecret, out string? credentialDetail))
            {
                return new IssuerReadinessReport(IssuerReadinessCategory.CredentialUnusable, mode, options.Issuer)
                {
                    Detail = credentialDetail,
                };
            }

            return await ProbeIntrospectionAsync(options, metadataClient, endpointClient, clientSecret, cancellationToken)
                .ConfigureAwait(false);
        }

        return await ProbeJwksAsync(options, metadataClient, endpointClient, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Renders one result as the operator's plain-text report.</summary>
    internal static string Render(IssuerReadinessReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        StringBuilder text = new();

        text.AppendLine(report.Category is IssuerReadinessCategory.Ready
            ? "issuer readiness: ready"
            : $"issuer readiness: not ready [issuer/{Code(report.Category)}]");

        if (report.Mode.Length > 0)
        {
            text.AppendLine($"mode: {report.Mode}");
        }

        if (report.Issuer.Length > 0)
        {
            text.AppendLine($"issuer: {SafeUriDisplay.Origin(report.Issuer)} (configured)");
        }

        if (report.MetadataStep is { Length: > 0 } metadata)
        {
            text.AppendLine($"metadata: {Bounded(metadata)}");
        }

        if (report.EndpointStep is { Length: > 0 } endpoint)
        {
            string label = report.Mode.Length > 0 ? report.Mode : "endpoint";
            text.AppendLine($"{label}: {Bounded(endpoint)}");
        }

        if (report.Detail is { Length: > 0 } detail)
        {
            text.AppendLine($"detail: {Bounded(detail)}");
        }

        if (report.Category is IssuerReadinessCategory.Ready)
        {
            text.AppendLine(
                "caveat: readiness proves metadata, exact issuer identity, endpoint reachability and, "
                + "for introspection, resource-server client authentication only. Issued-token audience, "
                + "scope and revocation behavior are not proven without a real provider-issued token "
                + "accepted by the protected MCP resource.");
            text.AppendLine(
                "This command opened no listener and changed no authorization policy; it took no "
                + "store-root lease.");
        }

        return text.ToString();
    }

    /// <summary>The stable outcome token a result's category renders as.</summary>
    internal static string Code(IssuerReadinessCategory category) => category switch
    {
        IssuerReadinessCategory.Ready => "ready",
        IssuerReadinessCategory.Unconfigured => "unconfigured",
        IssuerReadinessCategory.UnsupportedMode => "unsupported-mode",
        IssuerReadinessCategory.CredentialUnusable => "credential-unusable",
        IssuerReadinessCategory.InvalidMetadata => "invalid-metadata",
        IssuerReadinessCategory.IssuerUnavailable => "issuer-unavailable",
        IssuerReadinessCategory.OriginRefused => "origin-refused",
        IssuerReadinessCategory.EndpointUnreachable => "endpoint-unreachable",
        IssuerReadinessCategory.EndpointUnauthorized => "endpoint-unauthorized",
        IssuerReadinessCategory.EndpointUnusable => "endpoint-unusable",
        _ => throw new InvalidOperationException("Unknown readiness category."),
    };

    private static IssuerReadinessReport Unconfigured()
        => new(IssuerReadinessCategory.Unconfigured, string.Empty, string.Empty)
        {
            Detail = $"No authorization trust configuration is bound, so there is no issuer to probe. "
                + $"Name '{HostConfiguration.IssuerKey}' and '{HostConfiguration.TokenValidationKey}'.",
        };

    private static bool TryDeriveMetadataUri(string issuer, out Uri? metadata)
    {
        metadata = null;

        try
        {
            metadata = IssuerMetadata.DiscoveryUri(issuer);
            return true;
        }
        catch (UriFormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Reads the introspection client's secret before any network traffic, exactly like the serving
    /// validator's construction order: an unusable local credential is a local refusal, not a reason
    /// to ask a remote endpoint anything.
    /// </summary>
    private static bool TryReadIntrospectionCredential(
        HostAuthorizationOptions options,
        out string? clientSecret,
        out string? detail)
    {
        clientSecret = null;
        detail = null;

        string? clientId = options.IntrospectionClientId;
        string? secretFile = options.IntrospectionClientSecretFile;

        if (clientId is null && secretFile is null)
        {
            // A resource server without its own client identity still probes the endpoint; the
            // endpoint's answer decides whether that configuration is usable.
            return true;
        }

        if (clientId is null || secretFile is null)
        {
            detail = $"'{HostConfiguration.IntrospectionClientIdKey}' and "
                + $"'{HostConfiguration.IntrospectionClientSecretFileKey}' are a pair: name both or "
                + "neither. An endpoint request would otherwise authenticate as half a client.";
            return false;
        }

        if (!IntrospectionClientSecret.TryRead(secretFile, out string secret, out string? refusal))
        {
            detail = $"{refusal} The introspection endpoint was not contacted, because the local "
                + "credential is unusable.";
            return false;
        }

        clientSecret = secret;
        return true;
    }

    private static async Task<IssuerReadinessReport> ProbeJwksAsync(
        HostAuthorizationOptions options,
        HttpClient metadataClient,
        HttpClient endpointClient,
        CancellationToken cancellationToken)
    {
        string mode = HostConfiguration.JwksModeName;
        string? metadataStep;
        string address;

        if (options.JwksUri is { } explicitUri)
        {
            metadataStep = $"not consulted ('{HostConfiguration.JwksUriKey}' names the endpoint explicitly)";
            address = explicitUri;
        }
        else
        {
            IssuerMetadataDiscovery discovery = await DiscoverAsync(metadataClient, options, cancellationToken)
                .ConfigureAwait(false);

            if (DiscoveryFailure(mode, options.Issuer, discovery) is { } failure)
            {
                return failure;
            }

            metadataStep = $"{RouteLabel(discovery)} (HTTP 200), issuer match exact";

            if (!IssuerMetadata.TryReadEndpoint(discovery.Document!.Value, "jwks_uri", out address))
            {
                return new IssuerReadinessReport(IssuerReadinessCategory.InvalidMetadata, mode, options.Issuer)
                {
                    MetadataStep = metadataStep,
                    Detail = "The authorization-server metadata publishes no usable 'jwks_uri'. The "
                        + "document is valid, but it names no key set for this Engine to trust; "
                        + $"configure '{HostConfiguration.JwksUriKey}' explicitly or fix the issuer "
                        + "document.",
                };
            }
        }

        if (!TryResolveEndpoint(address, "JWKS", out Uri? endpoint, out IssuerReadinessCategory endpointCategory, out string? endpointDetail))
        {
            return new IssuerReadinessReport(endpointCategory, mode, options.Issuer)
            {
                MetadataStep = metadataStep,
                Detail = endpointDetail,
            };
        }

        (IssuerReadinessCategory category, string? step, string? detail) = await FetchJwksAsync(
            endpointClient,
            endpoint!,
            cancellationToken).ConfigureAwait(false);

        return new IssuerReadinessReport(category, mode, options.Issuer)
        {
            MetadataStep = metadataStep,
            EndpointStep = category is IssuerReadinessCategory.Ready ? step : null,
            Detail = detail,
        };
    }

    private static async Task<IssuerReadinessReport> ProbeIntrospectionAsync(
        HostAuthorizationOptions options,
        HttpClient metadataClient,
        HttpClient endpointClient,
        string? clientSecret,
        CancellationToken cancellationToken)
    {
        string mode = HostConfiguration.IntrospectionModeName;
        string? metadataStep;
        string address;

        if (options.IntrospectionEndpoint is { } explicitEndpoint)
        {
            metadataStep = $"not consulted ('{HostConfiguration.IntrospectionEndpointKey}' names the endpoint explicitly)";
            address = explicitEndpoint;
        }
        else
        {
            IssuerMetadataDiscovery discovery = await DiscoverAsync(metadataClient, options, cancellationToken)
                .ConfigureAwait(false);

            if (DiscoveryFailure(mode, options.Issuer, discovery) is { } refused)
            {
                return refused;
            }

            metadataStep = $"{RouteLabel(discovery)} (HTTP 200), issuer match exact";

            if (!IssuerMetadata.TryReadEndpoint(discovery.Document!.Value, "introspection_endpoint", out address))
            {
                return new IssuerReadinessReport(IssuerReadinessCategory.InvalidMetadata, mode, options.Issuer)
                {
                    MetadataStep = metadataStep,
                    Detail = "The authorization-server metadata publishes no usable "
                        + "'introspection_endpoint'. The document is valid, but it names no endpoint "
                        + $"for this Engine to call; configure "
                        + $"'{HostConfiguration.IntrospectionEndpointKey}' explicitly or fix the issuer "
                        + "document.",
                };
            }
        }

        if (!TryResolveEndpoint(address, "introspection", out Uri? endpoint, out IssuerReadinessCategory endpointCategory, out string? endpointDetail))
        {
            return new IssuerReadinessReport(endpointCategory, mode, options.Issuer)
            {
                MetadataStep = metadataStep,
                Detail = endpointDetail,
            };
        }

        (IssuerReadinessCategory category, string? step, string? detail) = await FetchIntrospectionAsync(
            endpointClient,
            endpoint!,
            options.IntrospectionClientId,
            clientSecret,
            cancellationToken).ConfigureAwait(false);

        return new IssuerReadinessReport(category, mode, options.Issuer)
        {
            MetadataStep = metadataStep,
            EndpointStep = category is IssuerReadinessCategory.Ready ? step : null,
            Detail = detail,
        };
    }

    private static async Task<IssuerMetadataDiscovery> DiscoverAsync(
        HttpClient client,
        HostAuthorizationOptions options,
        CancellationToken cancellationToken)
        => await IssuerMetadata.ResolveAsync(
            client,
            options.Issuer,
            options.OidcDiscoveryFallbackEnabled,
            cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Turns a non-successful metadata resolution into a report, or returns null when the resolver
    /// produced a validated document.
    /// </summary>
    /// <remarks>
    /// Internal rather than private so the adversarial rendering case can hand it a hostile
    /// <see cref="IssuerMetadataDiscovery"/>: readiness must stay safe by construction even if the
    /// shared resolver's text changes, because its invalid reason may embed the configured issuer,
    /// the derived metadata URL or an untrusted document member.
    /// </remarks>
    internal static IssuerReadinessReport? DiscoveryFailure(
        string mode,
        string issuer,
        IssuerMetadataDiscovery discovery)
    {
        if (discovery.IsTransportFailure)
        {
            return new IssuerReadinessReport(IssuerReadinessCategory.IssuerUnavailable, mode, issuer)
            {
                MetadataStep = $"{RouteLabel(discovery)} (no answer)",
                Detail = "The metadata resource did not answer: a network, DNS, TLS trust or timeout "
                    + "failure. This is an outage, not a definitive absence, and retrying may succeed.",
            };
        }

        if (discovery.InvalidKind is not IssuerMetadataInvalidKind.None
            || discovery.InvalidReason is not null)
        {
            // The resolver's own reason string is deliberately not rendered: it may embed the
            // configured issuer spelling, the derived metadata URL or an untrusted document member.
            // Readiness names its own fixed diagnostic from the structured kind instead. An origin
            // refusal inside the resolver is unreachable through this probe - ProbeAsync refuses the
            // same deterministic derivation first - but if it ever becomes reachable it must still
            // report the origin category, its own step and its own fixed detail.
            bool originRefused = discovery.InvalidKind is IssuerMetadataInvalidKind.OriginRefused;

            return new IssuerReadinessReport(
                originRefused ? IssuerReadinessCategory.OriginRefused : IssuerReadinessCategory.InvalidMetadata,
                mode,
                issuer)
            {
                MetadataStep = originRefused
                    ? $"{RouteLabel(discovery)} (refused before any request)"
                    : $"{RouteLabel(discovery)} (HTTP 200)",
                Detail = $"{InvalidMetadataDetail(discovery.InvalidKind)} No key or introspection request "
                    + "was sent.",
            };
        }

        if (discovery.StatusCode is { } status && status is not HttpStatusCode.OK)
        {
            return new IssuerReadinessReport(IssuerReadinessCategory.IssuerUnavailable, mode, issuer)
            {
                MetadataStep = $"{RouteLabel(discovery)} (HTTP {(int)status})",
                Detail = StatusDetail(status, "metadata resource"),
            };
        }

        return null;
    }

    /// <summary>
    /// Readiness's own fixed explanation of an invalid metadata document, selected from the
    /// resolver's structured category and never built from the resolver's reason text.
    /// </summary>
    private static string InvalidMetadataDetail(IssuerMetadataInvalidKind kind) => kind switch
    {
        IssuerMetadataInvalidKind.Malformed
            => "The issuer's metadata document is not valid JSON or not a JSON object.",
        IssuerMetadataInvalidKind.MissingIssuer
            => "The issuer's metadata document omits the required 'issuer' member.",
        IssuerMetadataInvalidKind.DuplicateIssuer
            => "The issuer's metadata document declares the 'issuer' member more than once, so no "
                + "single issuer identity can be trusted.",
        IssuerMetadataInvalidKind.IssuerMismatch
            => "The issuer's metadata document does not exactly match the configured issuer, so its "
                + "identity is not the configured trust anchor.",
        IssuerMetadataInvalidKind.OriginRefused
            => "The configured issuer derives a metadata URL that is remote plain http and is refused "
                + "rather than contacted.",
        _ => "The issuer's metadata document cannot be trusted as written.",
    };

    /// <summary>
    /// Validates one effective endpoint address against parse and origin policy before any request is
    /// built. This is the same rule the serving validators apply to a discovered or explicit endpoint;
    /// a refusal here guarantees the address is never contacted.
    /// </summary>
    private static bool TryResolveEndpoint(
        string address,
        string kind,
        out Uri? endpoint,
        out IssuerReadinessCategory category,
        out string? detail)
    {
        endpoint = null;
        category = IssuerReadinessCategory.InvalidMetadata;
        detail = null;

        if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? parsed))
        {
            // The untrusted spelling is not echoed at all: an unparsable value cannot be reduced to
            // an origin, and printing it as-is could leak any component.
            detail = $"The effective {kind} endpoint is not an absolute http(s) URL, so it cannot be "
                + "contacted.";
            return false;
        }

        if (parsed.Scheme is not ("http" or "https"))
        {
            detail = $"The effective {kind} endpoint {SafeUriDisplay.Origin(parsed)} does not use http "
                + "or https, so it cannot be contacted.";
            return false;
        }

        if (!AuthorizationEndpointPolicy.IsAllowed(parsed))
        {
            category = IssuerReadinessCategory.OriginRefused;
            detail = $"The effective {kind} endpoint {SafeUriDisplay.Origin(parsed)} is remote plain http. "
                + "Authorization trust endpoints must use https unless they resolve to loopback, so "
                + "no request was sent to it.";
            return false;
        }

        endpoint = parsed;
        return true;
    }

    private static async Task<(IssuerReadinessCategory Category, string? Step, string? Detail)> FetchJwksAsync(
        HttpClient client,
        Uri endpoint,
        CancellationToken cancellationToken)
    {
        HttpResponseMessage response;

        try
        {
            response = await client.GetAsync(endpoint, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception failure) when (IsTransportFailure(failure))
        {
            return TransportOutcome(failure, "JWKS endpoint");
        }

        using (response)
        {
            if (response.StatusCode is not HttpStatusCode.OK)
            {
                return EndpointStatusOutcome(response.StatusCode, "JWKS");
            }

            string document;

            try
            {
                document = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception failure) when (IsTransportFailure(failure))
            {
                return (
                    IssuerReadinessCategory.EndpointUnreachable,
                    null,
                    $"The JWKS endpoint {SafeUriDisplay.Origin(endpoint)} answered HTTP 200 but its body "
                    + "could not be read within the probe's response bound.");
            }

            try
            {
                JsonWebKeySet keys = JsonWebKeySet.Create(document);
                int signing = keys.GetSigningKeys().Count;

                if (signing == 0)
                {
                    return (
                        IssuerReadinessCategory.EndpointUnusable,
                        null,
                        $"The JWKS endpoint {SafeUriDisplay.Origin(endpoint)} answered HTTP 200 but "
                        + "publishes no usable signing keys, so no token could ever be verified through it.");
                }

                return (
                    IssuerReadinessCategory.Ready,
                    $"{SafeUriDisplay.Origin(endpoint)} (HTTP 200), {signing} usable signing "
                        + (signing == 1 ? "key" : "keys"),
                    null);
            }
            catch (Exception failure) when (failure is JsonException or ArgumentException or SecurityTokenException)
            {
                return (
                    IssuerReadinessCategory.EndpointUnusable,
                    null,
                    $"The JWKS endpoint {SafeUriDisplay.Origin(endpoint)} answered HTTP 200 with a "
                    + "document that is not a usable key set.");
            }
        }
    }

    private static async Task<(IssuerReadinessCategory Category, string? Step, string? Detail)> FetchIntrospectionAsync(
        HttpClient client,
        Uri endpoint,
        string? clientId,
        string? clientSecret,
        CancellationToken cancellationToken)
    {
        // The probe value is generated here, is clearly not an issued token, is never a valid MCP
        // bearer, and never reaches any output: it exists so the endpoint can be exercised without a
        // caller token and without manufacturing one.
        string probe = "mcpiler-issuer-readiness-probe-"
            + Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        using HttpRequestMessage request = new(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = probe,
            }),
        };

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        if (clientId is { } id && clientSecret is { } secret)
        {
            // client_secret_basic, encoded exactly as the serving validator encodes it: both halves
            // are form-urlencoded before the base64, because either may contain characters that are
            // not valid in an HTTP header value.
            string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{Uri.EscapeDataString(id)}:{Uri.EscapeDataString(secret)}"));

            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        }

        HttpResponseMessage response;

        try
        {
            response = await client
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception failure) when (IsTransportFailure(failure))
        {
            return TransportOutcome(failure, "introspection endpoint");
        }

        using (response)
        {
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                return (
                    IssuerReadinessCategory.EndpointUnauthorized,
                    null,
                    clientId is null
                        ? $"The introspection endpoint answered HTTP {(int)response.StatusCode} "
                            + $"({response.StatusCode}) and no resource-server client identity is "
                            + $"configured. Configure '{HostConfiguration.IntrospectionClientIdKey}' and "
                            + $"'{HostConfiguration.IntrospectionClientSecretFileKey}' so this resource "
                            + "server can authenticate itself."
                        : $"The introspection endpoint answered HTTP {(int)response.StatusCode} "
                            + $"({response.StatusCode}) for the configured resource-server client. The "
                            + "endpoint is reachable; the client identity or its secret is refused, or "
                            + "the issuer does not allow this resource server to introspect.");
            }

            if (response.StatusCode is not HttpStatusCode.OK)
            {
                return EndpointStatusOutcome(response.StatusCode, "introspection");
            }

            string body;

            try
            {
                body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception failure) when (IsTransportFailure(failure))
            {
                return (
                    IssuerReadinessCategory.EndpointUnreachable,
                    null,
                    $"The introspection endpoint {SafeUriDisplay.Origin(endpoint)} answered HTTP 200 but "
                    + "its body could not be read within the probe's response bound.");
            }

            try
            {
                using JsonDocument document = JsonDocument.Parse(body);
                JsonElement root = document.RootElement;

                if (root.ValueKind is not JsonValueKind.Object
                    || !root.TryGetProperty("active", out JsonElement active)
                    || active.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    return (
                        IssuerReadinessCategory.EndpointUnusable,
                        null,
                        $"The introspection endpoint {SafeUriDisplay.Origin(endpoint)} answered HTTP 200 "
                        + "without the RFC 7662 boolean 'active' member, so its answers cannot be trusted "
                        + "for any token.");
                }

                if (active.ValueKind is JsonValueKind.True)
                {
                    return (
                        IssuerReadinessCategory.EndpointUnusable,
                        null,
                        $"The introspection endpoint {SafeUriDisplay.Origin(endpoint)} reported an "
                        + "invented, never-issued probe value as active. RFC 7662 requires an unknown "
                        + "token to be inactive, and no authorization decision may trust an endpoint "
                        + "that answers active for a value that was never issued. No caller token was "
                        + "sent or manufactured by this probe.");
                }

                return (
                    IssuerReadinessCategory.Ready,
                    $"{SafeUriDisplay.Origin(endpoint)} (HTTP 200), invented probe value standing inactive",
                    null);
            }
            catch (JsonException)
            {
                return (
                    IssuerReadinessCategory.EndpointUnusable,
                    null,
                    $"The introspection endpoint {SafeUriDisplay.Origin(endpoint)} answered HTTP 200 with "
                    + "a body that is not valid JSON.");
            }
        }
    }

    private static (IssuerReadinessCategory Category, string? Step, string? Detail) EndpointStatusOutcome(
        HttpStatusCode status,
        string kind)
    {
        int code = (int)status;

        string detail = status switch
        {
            _ when code is >= 300 and < 400
                => $"The {kind} answered HTTP {code} ({status}). Authorization trust clients never "
                    + "follow redirects, so the target was not contacted.",
            _ when code >= 500 || status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests
                => $"The {kind} answered HTTP {code} ({status}). This is a transient answer; retrying "
                    + "readiness later may succeed.",
            _ => $"The {kind} answered HTTP {code} ({status}) instead of a usable answer.",
        };

        IssuerReadinessCategory category = status switch
        {
            _ when code is >= 300 and < 400 => IssuerReadinessCategory.EndpointUnreachable,
            _ when code >= 500 || status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests
                => IssuerReadinessCategory.EndpointUnreachable,
            _ => IssuerReadinessCategory.EndpointUnusable,
        };

        return (category, $"HTTP {code}", detail);
    }

    private static (IssuerReadinessCategory Category, string? Step, string? Detail) TransportOutcome(
        Exception failure,
        string kind)
    {
        if (TlsFailure(failure))
        {
            return (
                IssuerReadinessCategory.OriginRefused,
                null,
                $"The {kind} could not establish a trusted TLS connection. The address is refused "
                + "rather than contacted insecurely; check the certificate chain and trust store of "
                + "the configured issuer.");
        }

        return (
            IssuerReadinessCategory.EndpointUnreachable,
            null,
            $"The {kind} did not answer: a network, DNS or timeout failure. This is an outage, and "
            + "retrying may succeed.");
    }

    private static bool IsTransportFailure(Exception failure)
        => failure is HttpRequestException or TaskCanceledException or OperationCanceledException;

    private static bool TlsFailure(Exception failure)
    {
        for (Exception? current = failure; current is not null; current = current.InnerException)
        {
            if (current is HttpRequestException { HttpRequestError: HttpRequestError.SecureConnectionError }
                || current is System.Security.Authentication.AuthenticationException)
            {
                return true;
            }
        }

        return false;
    }

    private static string StatusDetail(HttpStatusCode status, string kind)
    {
        int code = (int)status;

        return status switch
        {
            _ when code is >= 300 and < 400
                => $"The {kind} answered HTTP {code} ({status}). Authorization trust clients never "
                    + "follow redirects, so the target was not contacted.",
            _ when code >= 500 || status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests
                => $"The {kind} answered HTTP {code} ({status}). This is a transient answer; retrying "
                    + "readiness later may succeed.",
            HttpStatusCode.NotFound or HttpStatusCode.Gone
                => $"The {kind} answered HTTP {code} ({status}): the issuer publishes no metadata at the "
                    + "configured URL. Correct the issuer address, or enable the restricted OIDC "
                    + "discovery fallback if the provider serves discovery on the OIDC path.",
            _ => $"The {kind} answered HTTP {code} ({status}) instead of a metadata document.",
        };
    }

    private static string RouteLabel(IssuerMetadataDiscovery discovery)
        => discovery.Route is IssuerMetadataRoute.OidcFallback
            ? $"OIDC discovery fallback {IssuerMetadata.OidcWellKnownPath}"
            : $"RFC 8414 {IssuerMetadata.Rfc8414WellKnownPath}";

    /// <summary>
    /// Bounds and de-controls one value before it reaches an operator's terminal. Every string this
    /// report renders may be operator-configured or issuer-published, and an issuer document is
    /// untrusted input; control characters could rewrite a terminal line and an unbounded string
    /// could flood a log. Address-shaped values are routed through
    /// <see cref="SafeUriDisplay.Origin(string)"/> first; this bound covers the whole rendered step
    /// or detail, not one address.
    /// </summary>
    private static string Bounded(string value)
    {
        if (value.Length == 0)
        {
            return value;
        }

        StringBuilder text = new(Math.Min(value.Length, MaximumRenderedCharacters));

        foreach (char character in value)
        {
            if (text.Length >= MaximumRenderedCharacters)
            {
                text.Append('…');
                break;
            }

            text.Append(char.IsControl(character) ? ' ' : character);
        }

        return text.ToString();
    }
}
