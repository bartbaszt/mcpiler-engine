using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Cli;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.IntegrationTests.Cli;

using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Authorization;

/// <summary>
/// The explicit, networked issuer readiness probe (OAUTH-IDP-2, E12): what it asks, which
/// categories refuse, and what it refuses to claim.
/// </summary>
/// <remarks>
/// <para>
/// Every refusal case here also asserts what the network observed, not only which category came
/// back: "fails closed" means no request reached the address in question, so a probe that asked a
/// second origin and then reported a refusal cannot pass.
/// </para>
/// <para>
/// The probe value is the adversarial half of the introspection cases. The tests read the value
/// back out of the fixture's recorded request body and then assert that neither the rendered
/// report nor the CLI output ever contains it, so "no fabricated bearer" is checked as an
/// observable property rather than a comment.
/// </para>
/// </remarks>
public sealed class IssuerReadinessTests : IDisposable
{
    private const string Rfc8414Path = "/.well-known/oauth-authorization-server";
    private const string OidcPath = "/.well-known/openid-configuration";
    private const string UnusedRefreshVariable = "MCPILER_READINESS_UNSET_REFRESH";

    // Distinct canaries, one per URL component a report could echo. None of these values may ever
    // reach an operator-visible stream; they are shaped so a leaked component is unambiguous.
    private const string CredentialCanary = "CANARY-issuer-credential-7f31";
    private const string PathCanary = "CANARY-secret-path-9d4e";
    private const string QueryCanary = "CANARY-query-param-a2c9";
    private const string FragmentCanary = "CANARY-fragment-31b7";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-readiness-" + Guid.NewGuid().ToString("N"));

    public IssuerReadinessTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    // ---------------------------------------------------------------- pre-network refusals

    /// <summary>Nothing configured is a definitive answer, and it asks nobody anything.</summary>
    [Fact]
    public async Task An_absent_authorization_configuration_is_unconfigured_without_a_request()
    {
        StubHandler stub = StubHandler.Refusing();
        using HttpClient client = new(stub);

        IssuerReadinessReport absent = await IssuerReadiness.ProbeAsync(null, TestContext.Current.CancellationToken);
        IssuerReadinessReport none = await IssuerReadiness
            .ProbeAsync(HostAuthorizationOptions.None, client, client, TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.Unconfigured, absent.Category);
        Assert.Equal(IssuerReadinessCategory.Unconfigured, none.Category);
        Assert.Equal(0, stub.Requests);
        Assert.Contains("issuer", IssuerReadiness.Render(none), StringComparison.Ordinal);
    }

    /// <summary>A trust mode this build has no probe for refuses before any address is derived.</summary>
    [Fact]
    public async Task An_unknown_trust_mode_is_unsupported_without_a_request()
    {
        StubHandler stub = StubHandler.Refusing();
        using HttpClient client = new(stub);

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            new HostAuthorizationOptions("https://issuer.example", (HostTokenValidation)7),
            client,
            client,
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.UnsupportedMode, report.Category);
        Assert.Equal(0, stub.Requests);
        Assert.Contains("issuer/unsupported-mode", IssuerReadiness.Render(report), StringComparison.Ordinal);
    }

    /// <summary>
    /// A remote plain-http issuer derives a metadata URL the policy refuses, so the first request
    /// is never sent. The serving binder refuses the same issuer earlier; this covers the seam.
    /// </summary>
    [Fact]
    public async Task A_remote_plain_http_issuer_is_origin_refused_without_a_request()
    {
        StubHandler stub = StubHandler.Refusing();
        using HttpClient client = new(stub);

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            new HostAuthorizationOptions("http://198.51.100.10", HostTokenValidation.Jwks),
            client,
            client,
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.OriginRefused, report.Category);
        Assert.Equal(0, stub.Requests);
        Assert.Contains("remote plain http", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>An explicit key-set override is subject to the same origin rule as a discovered one.</summary>
    [Fact]
    public async Task An_explicit_remote_plain_http_key_endpoint_is_origin_refused_without_a_request()
    {
        StubHandler stub = StubHandler.Refusing();
        using HttpClient client = new(stub);

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            new HostAuthorizationOptions("https://issuer.example", HostTokenValidation.Jwks)
            {
                JwksUri = "http://198.51.100.10/jwks",
            },
            client,
            client,
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.OriginRefused, report.Category);
        Assert.Equal(0, stub.Requests);
    }

    /// <summary>The same origin rule applies to an explicit introspection override.</summary>
    [Fact]
    public async Task An_explicit_remote_plain_http_introspection_endpoint_is_origin_refused_without_a_request()
    {
        StubHandler stub = StubHandler.Refusing();
        using HttpClient client = new(stub);

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            new HostAuthorizationOptions("https://issuer.example", HostTokenValidation.Introspection)
            {
                IntrospectionEndpoint = "http://198.51.100.10/introspect",
            },
            client,
            client,
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.OriginRefused, report.Category);
        Assert.Equal(0, stub.Requests);
    }

    // ---------------------------------------------------------------- JWKS discovery and keys

    /// <summary>
    /// The positive path: one RFC 8414 document with an exact issuer, then one key set with usable
    /// signing material. The report states where each fact came from and what it does not prove.
    /// </summary>
    [Fact]
    public async Task A_valid_rfc8414_document_and_key_set_reach_readiness()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    await WriteJsonAsync(context, JwksMetadata(IssuerOf(context)));
                    return;
                }

                await WriteJsonAsync(context, JwksJson(keyCount: 2));
            });

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.Ready, report.Category);
        Assert.Equal([Rfc8414Path, "/jwks"], server.RequestedPaths);
        Assert.Contains("RFC 8414", report.MetadataStep, StringComparison.Ordinal);
        Assert.Contains("issuer match exact", report.MetadataStep, StringComparison.Ordinal);
        Assert.Contains("2 usable signing keys", report.EndpointStep, StringComparison.Ordinal);
        Assert.Contains("issuer readiness: ready", rendered, StringComparison.Ordinal);
        Assert.Contains("caveat:", rendered, StringComparison.Ordinal);
        Assert.Contains("Issued-token audience, scope and revocation behavior are not proven", rendered, StringComparison.Ordinal);
        Assert.Contains("opened no listener", rendered, StringComparison.Ordinal);
    }

    /// <summary>A document naming another issuer is a trust mismatch, not a key-fetch reason.</summary>
    [Fact]
    public async Task A_wrong_issuer_document_is_invalid_metadata_and_never_fetches_keys()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(
                context,
                $"{{\"issuer\":\"https://other.example\",\"jwks_uri\":\"{AddressOf(context)}/jwks\"}}"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.InvalidMetadata, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
        Assert.Contains("does not exactly match", report.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_malformed_document_is_invalid_metadata()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(context, "not-json"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.InvalidMetadata, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
        Assert.Contains("not valid JSON", report.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_document_without_a_key_set_member_is_invalid_metadata()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(context, $"{{\"issuer\":\"{IssuerOf(context)}\"}}"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.InvalidMetadata, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
        Assert.Contains("jwks_uri", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>A document declaring the key-set member twice is ambiguity and is refused whole.</summary>
    [Fact]
    public async Task A_duplicate_key_set_member_is_invalid_metadata()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(
                context,
                $"{{\"issuer\":\"{IssuerOf(context)}\",\"jwks_uri\":\"{AddressOf(context)}/jwks\","
                + $"\"jwks_uri\":\"{AddressOf(context)}/other\"}}"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.InvalidMetadata, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
    }

    [Fact]
    public async Task A_key_set_member_that_is_not_an_absolute_url_is_invalid_metadata()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(
                context,
                $"{{\"issuer\":\"{IssuerOf(context)}\",\"jwks_uri\":\"not-a-url\"}}"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.InvalidMetadata, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
        Assert.Contains("not an absolute http(s) URL", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A discovered endpoint outside the HTTPS-unless-loopback policy is refused before it is
    /// contacted; the out-of-policy host is never asked anything.
    /// </summary>
    [Fact]
    public async Task An_out_of_policy_advertised_key_endpoint_is_origin_refused_and_never_contacted()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(
                context,
                $"{{\"issuer\":\"{IssuerOf(context)}\",\"jwks_uri\":\"http://198.51.100.10/jwks\"}}"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.OriginRefused, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
        Assert.Contains("remote plain http", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A definitive absence is an unavailable issuer under the default configuration, and the
    /// issuer-derived OIDC route stays untouched because fallback is opt-in.
    /// </summary>
    [Fact]
    public async Task A_definitive_absence_is_issuer_unavailable_and_the_oidc_route_stays_untouched()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return Task.CompletedTask;
            });

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.IssuerUnavailable, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
        Assert.Contains("404", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>The opt-in fallback reaches readiness through the same restricted route policy.</summary>
    [Fact]
    public async Task An_enabled_fallback_uses_the_oidc_route_and_reaches_readiness()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                if (context.Request.Path.Value == OidcPath)
                {
                    await WriteJsonAsync(context, JwksMetadata(IssuerOf(context)));
                    return;
                }

                await WriteJsonAsync(context, JwksJson());
            });

        IssuerReadinessReport report = await ProbeAsync(
            Jwks(server.Address, fallback: true),
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.Ready, report.Category);
        Assert.Equal([Rfc8414Path, OidcPath, "/jwks"], server.RequestedPaths);
        Assert.Contains("OIDC discovery fallback", report.MetadataStep, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_metadata_transport_failure_is_issuer_unavailable()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Abort();
                return Task.CompletedTask;
            });

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.IssuerUnavailable, report.Category);
        Assert.Contains("no answer", report.MetadataStep, StringComparison.Ordinal);
        Assert.Contains("outage", report.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_metadata_5xx_is_issuer_unavailable()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                return Task.CompletedTask;
            });

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.IssuerUnavailable, report.Category);
        Assert.Contains("503", report.MetadataStep, StringComparison.Ordinal);
        Assert.Contains("transient", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>A redirect is reported as such and its target is never contacted.</summary>
    [Fact]
    public async Task A_metadata_redirect_is_never_followed()
    {
        await using AuthorizationTransportServer target = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                return Task.CompletedTask;
            });
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status302Found;
                context.Response.Headers.Location = new Uri(target.Address, "/metadata-target").ToString();
                return Task.CompletedTask;
            });

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.IssuerUnavailable, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
        Assert.Equal(0, target.RequestCount);
        Assert.Contains("302", report.MetadataStep, StringComparison.Ordinal);
    }

    /// <summary>A bound, controlled timeout is an outage, not a definitive absence.</summary>
    [Fact]
    public async Task A_metadata_timeout_is_issuer_unavailable()
    {
        using HttpClient client = new(new DelayingHandler())
        {
            Timeout = TimeSpan.FromMilliseconds(250),
        };

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            Jwks(new Uri("http://127.0.0.1:5099/")),
            client,
            client,
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.IssuerUnavailable, report.Category);
        Assert.Contains("no answer", report.MetadataStep, StringComparison.Ordinal);
    }

    /// <summary>
    /// An explicit key-set setting replaces discovery exactly as it replaces it for the serving
    /// validators: the metadata route must stay unasked.
    /// </summary>
    [Fact]
    public async Task An_explicit_key_set_skips_metadata_discovery()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(context, JwksJson()));

        IssuerReadinessReport report = await ProbeAsync(
            Jwks(server.Address) with { JwksUri = new Uri(server.Address, "/jwks").AbsoluteUri },
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.Ready, report.Category);
        Assert.Equal(["/jwks"], server.RequestedPaths);
        Assert.Contains("not consulted", report.MetadataStep, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- JWKS endpoint outcomes

    [Fact]
    public async Task An_unparseable_key_set_is_endpoint_unusable()
    {
        await using AuthorizationTransportServer server = await JwksServerAsync(async context =>
            await WriteJsonAsync(context, "not-json"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.EndpointUnusable, report.Category);
        Assert.Contains("not a usable key set", report.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_empty_key_set_is_endpoint_unusable()
    {
        await using AuthorizationTransportServer server = await JwksServerAsync(async context =>
            await WriteJsonAsync(context, "{\"keys\":[]}"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.EndpointUnusable, report.Category);
        Assert.Contains("no usable signing keys", report.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_key_set_endpoint_5xx_is_endpoint_unreachable()
    {
        await using AuthorizationTransportServer server = await JwksServerAsync(context =>
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return Task.CompletedTask;
        });

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.EndpointUnreachable, report.Category);
        Assert.Contains("503", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>A key-endpoint redirect is refused and its target is never contacted.</summary>
    [Fact]
    public async Task A_key_set_endpoint_redirect_is_not_followed()
    {
        await using AuthorizationTransportServer target = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                return Task.CompletedTask;
            });
        await using AuthorizationTransportServer server = await JwksServerAsync(context =>
        {
            context.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
            context.Response.Headers.Location = new Uri(target.Address, "/keys-target").ToString();
            return Task.CompletedTask;
        });

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.EndpointUnreachable, report.Category);
        Assert.Equal(0, target.RequestCount);
        Assert.Contains("redirects", report.Detail, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A TLS trust failure at the key endpoint is an origin refusal: the probe does not fall back
    /// to plain http and does not treat an untrusted transport as a key problem.
    /// </summary>
    [Fact]
    public async Task A_tls_failure_at_the_key_endpoint_is_origin_refused()
    {
        using HttpClient client = new(new ThrowingHandler(
            new HttpRequestException(
                HttpRequestError.SecureConnectionError,
                "The TLS connection could not be established.",
                new AuthenticationException("untrusted certificate"))));

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            Jwks(new Uri("https://issuer.example/")) with { JwksUri = "https://issuer.example/jwks" },
            client,
            client,
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.OriginRefused, report.Category);
        Assert.Contains("TLS", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>A key-endpoint timeout is an endpoint outage.</summary>
    [Fact]
    public async Task A_key_set_endpoint_timeout_is_endpoint_unreachable()
    {
        using HttpClient client = new(new DelayingHandler())
        {
            Timeout = TimeSpan.FromMilliseconds(250),
        };

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            Jwks(new Uri("http://127.0.0.1:5099/")) with { JwksUri = "http://127.0.0.1:5099/jwks" },
            client,
            client,
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.EndpointUnreachable, report.Category);
        Assert.Contains("did not answer", report.Detail, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- introspection

    /// <summary>
    /// The authenticated introspection path: the configured client authenticates exactly as the
    /// serving validator authenticates, one invented probe value is sent, the endpoint's RFC 7662
    /// answer is read, and neither the secret nor the probe value ever reaches the report.
    /// </summary>
    [Fact]
    public async Task An_authenticated_introspection_probe_reaches_readiness_without_echoing_its_probe_or_secret()
    {
        const string clientId = "engine-prüfgerät";
        const string clientSecret = "canary-sęcret-Ω-9f3a";
        string expectedBasic = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret)}"));

        string? presented = null;

        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    await WriteJsonAsync(
                        context,
                        $"{{\"issuer\":\"{IssuerOf(context)}\","
                        + $"\"introspection_endpoint\":\"{AddressOf(context)}/introspect\"}}");
                    return;
                }

                presented = context.Request.Headers.Authorization.ToString();
                await WriteJsonAsync(context, "{\"active\":false}");
            });

        string secretFile = Path.Combine(_root, "introspection.secret");
        await File.WriteAllTextAsync(secretFile, clientSecret, TestContext.Current.CancellationToken);

        HostAuthorizationOptions options = new(server.Address.AbsoluteUri, HostTokenValidation.Introspection)
        {
            IntrospectionClientId = clientId,
            IntrospectionClientSecretFile = secretFile,
        };

        IssuerReadinessReport report = await ProbeAsync(options, TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.Ready, report.Category);
        Assert.Equal([Rfc8414Path, "/introspect"], server.RequestedPaths);
        Assert.Contains("probe value standing inactive", report.EndpointStep, StringComparison.Ordinal);

        // The endpoint authenticated the resource server exactly as the serving path would.
        Assert.Equal(expectedBasic, presented);

        // The invented probe value is not a token and never appears anywhere an operator can see.
        string probe = ProbeValueFrom(server.LastBody!);
        Assert.StartsWith("mcpiler-issuer-readiness-probe-", probe, StringComparison.Ordinal);
        Assert.DoesNotContain("eyJ", probe, StringComparison.Ordinal);
        Assert.DoesNotContain(probe, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(clientSecret, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("canary", rendered, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A refused resource-server client is reported by name, never by secret.</summary>
    [Fact]
    public async Task A_refused_introspection_client_is_endpoint_unauthorized()
    {
        const string clientId = "engine-readiness";
        const string correctSecret = "right-secret-9a";
        string secretFile = Path.Combine(_root, "wrong.secret");
        await File.WriteAllTextAsync(secretFile, "wrong-secret-4b", TestContext.Current.CancellationToken);

        await using AuthorizationTransportServer server = await IntrospectionServerAsync(expectedSecret: correctSecret);

        HostAuthorizationOptions options = new(server.Address.AbsoluteUri, HostTokenValidation.Introspection)
        {
            IntrospectionClientId = clientId,
            IntrospectionClientSecretFile = secretFile,
        };

        IssuerReadinessReport report = await ProbeAsync(options, TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.EndpointUnauthorized, report.Category);
        Assert.Contains("resource-server client", report.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("wrong-secret-4b", rendered, StringComparison.Ordinal);
    }

    /// <summary>Without a client identity, a 401 is attributed to the missing configuration.</summary>
    [Fact]
    public async Task An_introspection_refusal_without_a_client_identity_names_the_missing_configuration()
    {
        await using AuthorizationTransportServer server = await IntrospectionServerAsync(refuseAnonymous: true);

        HostAuthorizationOptions options = new(server.Address.AbsoluteUri, HostTokenValidation.Introspection);

        IssuerReadinessReport report = await ProbeAsync(options, TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.EndpointUnauthorized, report.Category);
        Assert.Contains("no resource-server client identity is configured", report.Detail, StringComparison.Ordinal);
        Assert.Contains("introspection-client-id", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// An endpoint that reports an invented, never-issued probe value as active violates RFC 7662
    /// and cannot be trusted, so readiness refuses rather than blessing it.
    /// </summary>
    [Fact]
    public async Task An_invented_probe_value_reported_active_is_endpoint_unusable()
    {
        await using AuthorizationTransportServer server = await IntrospectionServerAsync(
            body: "{\"active\":true}");

        IssuerReadinessReport report = await ProbeAsync(
            new HostAuthorizationOptions(server.Address.AbsoluteUri, HostTokenValidation.Introspection),
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.EndpointUnusable, report.Category);
        Assert.Contains("invented", report.Detail, StringComparison.Ordinal);
        Assert.Contains("never-issued", report.Detail, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>An answer without the RFC 7662 `active` member cannot be trusted for any token.</summary>
    [Fact]
    public async Task An_answer_without_the_active_member_is_endpoint_unusable()
    {
        await using AuthorizationTransportServer server = await IntrospectionServerAsync(
            body: "{\"scope\":\"tools.invoke\"}");

        IssuerReadinessReport report = await ProbeAsync(
            new HostAuthorizationOptions(server.Address.AbsoluteUri, HostTokenValidation.Introspection),
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.EndpointUnusable, report.Category);
        Assert.Contains("'active' member", report.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_introspection_endpoint_outage_is_endpoint_unreachable()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    return WriteJsonAsync(
                        context,
                        $"{{\"issuer\":\"{IssuerOf(context)}\","
                        + $"\"introspection_endpoint\":\"{AddressOf(context)}/introspect\"}}");
                }

                context.Abort();
                return Task.CompletedTask;
            });

        IssuerReadinessReport report = await ProbeAsync(
            new HostAuthorizationOptions(server.Address.AbsoluteUri, HostTokenValidation.Introspection),
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.EndpointUnreachable, report.Category);
        Assert.Contains("did not answer", report.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unusable local client secret refuses before any network traffic, exactly like the serving
    /// validator's construction order.
    /// </summary>
    [Fact]
    public async Task An_unusable_introspection_secret_never_asks_the_issuer()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(context, JwksMetadata(IssuerOf(context))));

        string emptySecret = Path.Combine(_root, "empty.secret");
        await File.WriteAllTextAsync(emptySecret, string.Empty, TestContext.Current.CancellationToken);

        IssuerReadinessReport report = await ProbeAsync(
            new HostAuthorizationOptions(server.Address.AbsoluteUri, HostTokenValidation.Introspection)
            {
                IntrospectionClientId = "engine-readiness",
                IntrospectionClientSecretFile = emptySecret,
            },
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.CredentialUnusable, report.Category);
        Assert.Equal(0, server.RequestCount);
        Assert.Contains(emptySecret, report.Detail, StringComparison.Ordinal);
    }

    /// <summary>An explicit introspection setting replaces discovery for the probe as well.</summary>
    [Fact]
    public async Task An_explicit_introspection_endpoint_skips_metadata_discovery()
    {
        await using AuthorizationTransportServer server = await IntrospectionServerAsync(expectedSecret: null);

        IssuerReadinessReport report = await ProbeAsync(
            new HostAuthorizationOptions("http://127.0.0.1:5099/", HostTokenValidation.Introspection)
            {
                IntrospectionEndpoint = new Uri(server.Address, "/introspect").AbsoluteUri,
            },
            TestContext.Current.CancellationToken);

        Assert.Equal(IssuerReadinessCategory.Ready, report.Category);
        Assert.Equal(["/introspect"], server.RequestedPaths);
        Assert.Contains("not consulted", report.MetadataStep, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- sanitized address rendering

    /*
     * Every address in a report is rendered as its origin. The configured issuer, the metadata URL
     * derived from it, a discovered or explicit endpoint and an untrusted document member can each
     * carry a credential in userinfo, path, query or fragment; the cases below plant a distinct
     * canary in every one of those components and assert that no outcome - ready or refused - prints
     * any of them, while the category, step and origin diagnostics stay actionable.
     */

    /// <summary>
    /// Ready is still a sanitized result: the configured issuer and the effective endpoint may both
    /// carry credentials, and the report names only origins plus the withheld component categories.
    /// </summary>
    [Fact]
    public async Task A_ready_report_renders_only_origins_and_never_a_credential_canary()
    {
        StubHandler stub = StubHandler.Answering(_ => Json(JwksJson()));
        using HttpClient client = new(stub);

        string issuer = CanaryIssuer("https", "issuer.example");
        HostAuthorizationOptions options = new(issuer, HostTokenValidation.Jwks)
        {
            JwksUri = CanaryEndpoint("https", "keys.example:8443", "/jwks"),
        };

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            options,
            client,
            client,
            TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.Ready, report.Category);
        Assert.Equal(1, stub.Requests);

        // The configured spelling is kept for byte-exact matching; only its rendering is reduced.
        Assert.Equal(issuer, report.Issuer);
        Assert.Contains(
            "https://keys.example:8443 [credentials, path, query, fragment withheld] (HTTP 200)",
            report.EndpointStep,
            StringComparison.Ordinal);
        Assert.Contains(
            "issuer: https://issuer.example [credentials, path, query, fragment withheld] (configured)",
            rendered,
            StringComparison.Ordinal);
        AssertNoReadinessCanary(rendered);
    }

    /// <summary>The introspection success step is origin-only for the same reason.</summary>
    [Fact]
    public async Task A_ready_introspection_report_renders_only_the_endpoint_origin()
    {
        StubHandler stub = StubHandler.Answering(_ => Json("{\"active\":false}"));
        using HttpClient client = new(stub);

        HostAuthorizationOptions options = new(
            CanaryIssuer("https", "issuer.example"),
            HostTokenValidation.Introspection)
        {
            IntrospectionEndpoint = CanaryEndpoint("https", "introspection.example", "/introspect"),
        };

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            options,
            client,
            client,
            TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.Ready, report.Category);
        Assert.Contains(
            "https://introspection.example [credentials, path, query, fragment withheld] (HTTP 200)",
            report.EndpointStep,
            StringComparison.Ordinal);
        Assert.Contains("probe value standing inactive", report.EndpointStep, StringComparison.Ordinal);
        AssertNoReadinessCanary(rendered);
    }

    /// <summary>A refusal detail that names the endpoint still never echoes its spelling.</summary>
    [Fact]
    public async Task A_refused_introspection_answer_renders_only_the_endpoint_origin()
    {
        StubHandler stub = StubHandler.Answering(_ => Json("{\"scope\":\"tools.invoke\"}"));
        using HttpClient client = new(stub);

        HostAuthorizationOptions options = new(
            CanaryIssuer("https", "issuer.example"),
            HostTokenValidation.Introspection)
        {
            IntrospectionEndpoint = CanaryEndpoint("https", "introspection.example", "/introspect"),
        };

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            options,
            client,
            client,
            TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.EndpointUnusable, report.Category);
        Assert.Contains(
            "https://introspection.example [credentials, path, query, fragment withheld]",
            report.Detail,
            StringComparison.Ordinal);
        Assert.Contains("'active' member", report.Detail, StringComparison.Ordinal);
        AssertNoReadinessCanary(rendered);
    }

    /// <summary>
    /// A discovered endpoint value that is not an absolute URL is refused without being echoed:
    /// nothing about the untrusted spelling, canary included, reaches the report.
    /// </summary>
    [Fact]
    public async Task An_invalid_advertised_endpoint_value_is_refused_without_echoing_it()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(
                context,
                $"{{\"issuer\":\"{IssuerOf(context)}\","
                + $"\"jwks_uri\":\"{PathCanary} path/{PathCanary}?access_token={QueryCanary}#{FragmentCanary}\"}}"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.InvalidMetadata, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
        Assert.Contains("not an absolute http(s) URL", report.Detail, StringComparison.Ordinal);
        AssertNoReadinessCanary(rendered);
    }

    /// <summary>
    /// A document naming another issuer is refused by category; its declared spelling is untrusted
    /// and may carry a canary, so the readiness report selects its own fixed diagnostic from the
    /// resolver's structured category and never reflects the resolver's reason text.
    /// </summary>
    [Fact]
    public async Task A_wrong_issuer_document_does_not_reflect_its_declared_issuer()
    {
        string declared = CanaryIssuer("https", "other.example");

        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(
                context,
                $"{{\"issuer\":\"{declared}\",\"jwks_uri\":\"{AddressOf(context)}/jwks\"}}"));

        IssuerReadinessReport report = await ProbeAsync(Jwks(server.Address), TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.InvalidMetadata, report.Category);
        Assert.Equal([Rfc8414Path], server.RequestedPaths);
        Assert.Contains("does not exactly match", report.Detail, StringComparison.Ordinal);
        AssertNoReadinessCanary(rendered);
    }

    /// <summary>
    /// The readiness report never renders the resolver's own refusal text. A hostile - or merely
    /// future - <see cref="IssuerMetadataDiscovery"/> reason may embed the configured issuer, the
    /// derived metadata URL or an untrusted document member, so the readiness-owned diagnostic is
    /// selected from the structured kind and the reason string cannot reach an operator, even if the
    /// shared resolver's wording changes.
    /// </summary>
    [Theory]
    [InlineData((int)IssuerMetadataInvalidKind.Malformed)]
    [InlineData((int)IssuerMetadataInvalidKind.MissingIssuer)]
    [InlineData((int)IssuerMetadataInvalidKind.DuplicateIssuer)]
    [InlineData((int)IssuerMetadataInvalidKind.IssuerMismatch)]
    [InlineData((int)IssuerMetadataInvalidKind.OriginRefused)]
    [InlineData((int)IssuerMetadataInvalidKind.None)]
    public void A_hostile_resolver_reason_cannot_reach_the_readiness_report(int kindValue)
    {
        IssuerMetadataInvalidKind kind = (IssuerMetadataInvalidKind)kindValue;
        bool originRefused = kind is IssuerMetadataInvalidKind.OriginRefused;
        string reason = $"A refusal that embeds https://user:{CredentialCanary}@198.51.100.10/"
            + $"{PathCanary}/?access_token={QueryCanary}#{FragmentCanary} and a document member.";

        IssuerMetadataDiscovery discovery = new(
            null,
            reason,
            HttpStatusCode.OK,
            IssuerMetadataRoute.Rfc8414)
        {
            InvalidKind = kind,
        };

        IssuerReadinessReport? report = IssuerReadiness.DiscoveryFailure(
            "jwks",
            "https://issuer.example/",
            discovery);

        Assert.NotNull(report);
        Assert.Equal(
            originRefused ? IssuerReadinessCategory.OriginRefused : IssuerReadinessCategory.InvalidMetadata,
            report!.Category);
        Assert.Contains("RFC 8414", report.MetadataStep, StringComparison.Ordinal);
        Assert.Contains(
            originRefused ? "refused before any request" : "(HTTP 200)",
            report.MetadataStep,
            StringComparison.Ordinal);
        Assert.DoesNotContain(reason, report.Detail, StringComparison.Ordinal);
        AssertNoReadinessCanary(IssuerReadiness.Render(report));
    }

    /// <summary>
    /// A refused metadata derivation names origins only: neither the configured spelling nor the
    /// URL derived from it is ever echoed, and no request is sent anywhere.
    /// </summary>
    [Fact]
    public async Task An_out_of_policy_issuer_derivation_renders_only_origins()
    {
        StubHandler stub = StubHandler.Refusing();
        using HttpClient client = new(stub);

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            new HostAuthorizationOptions(CanaryIssuer("http", "198.51.100.10"), HostTokenValidation.Jwks),
            client,
            client,
            TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.OriginRefused, report.Category);
        Assert.Equal(0, stub.Requests);
        Assert.Contains(
            "http://198.51.100.10 [credentials, path, query, fragment withheld]",
            report.Detail,
            StringComparison.Ordinal);
        Assert.Contains(
            "http://198.51.100.10 [credentials, path withheld]",
            report.Detail,
            StringComparison.Ordinal);
        Assert.Contains("remote plain http", report.Detail, StringComparison.Ordinal);
        AssertNoReadinessCanary(rendered);
    }

    /// <summary>
    /// A configured issuer that is not an absolute URL is reported without being echoed: a fixed
    /// phrase names the problem, and the canary-bearing spelling stays out of the report.
    /// </summary>
    [Fact]
    public async Task An_unparsable_configured_issuer_is_reported_without_echoing_it()
    {
        StubHandler stub = StubHandler.Refusing();
        using HttpClient client = new(stub);

        string issuer = $"{PathCanary} path/{PathCanary}?access_token={QueryCanary}#{FragmentCanary}";

        IssuerReadinessReport report = await IssuerReadiness.ProbeAsync(
            new HostAuthorizationOptions(issuer, HostTokenValidation.Jwks),
            client,
            client,
            TestContext.Current.CancellationToken);
        string rendered = IssuerReadiness.Render(report);

        Assert.Equal(IssuerReadinessCategory.Unconfigured, report.Category);
        Assert.Equal(0, stub.Requests);
        Assert.Contains("not an absolute http(s) URI", report.Detail, StringComparison.Ordinal);
        Assert.Contains(SafeUriDisplay.UnparsableAddress, report.Detail, StringComparison.Ordinal);
        AssertNoReadinessCanary(rendered);
    }

    // ---------------------------------------------------------------- CLI surface

    /// <summary>
    /// The verb without an issuer answers definitively rather than guessing what to probe.
    /// </summary>
    [Fact]
    public async Task The_readiness_verb_reports_unconfigured_without_an_issuer()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            ["issuer", "readiness", "--file-store-root", Store()],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("issuer readiness: not ready [issuer/unconfigured]", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("issuer", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// The whole verb through the real command entry point: bind, probe, render, exit zero, and
    /// state the caveat the acceptance criteria require.
    /// </summary>
    [Fact]
    public async Task The_readiness_verb_probes_a_real_issuer_and_states_the_caveat()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    await WriteJsonAsync(context, JwksMetadata(IssuerOf(context)));
                    return;
                }

                await WriteJsonAsync(context, JwksJson());
            });

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "issuer", "readiness",
                "--file-store-root", Store(),
                "--issuer", $"http://127.0.0.1:{server.Address.Port}/",
                "--token-validation", "jwks",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("issuer readiness: ready", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("usable signing key", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("caveat:", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("opened no listener", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>A currently unreachable issuer is the retryable outcome, not a configuration claim.</summary>
    [Fact]
    public async Task The_readiness_verb_reports_an_unreachable_issuer_with_the_failure_code()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "issuer", "readiness",
                "--file-store-root", Store(),
                "--issuer", "http://127.0.0.1:1",
                "--token-validation", "jwks",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Failure, outcome.ExitCode);
        Assert.Contains("issuer readiness: not ready [issuer/issuer-unavailable]", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>The binder keeps its own policy refusal for a remote plain-http issuer.</summary>
    [Fact]
    public async Task The_readiness_verb_refuses_a_remote_plain_http_issuer_at_bind_time()
    {
        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "issuer", "readiness",
                "--file-store-root", Store(),
                "--issuer", "http://198.51.100.10",
                "--token-validation", "jwks",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("remote plain http", outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// The verb echoes a credential-bearing configured issuer as an origin: a canary in its
    /// userinfo, path, query or fragment never reaches the operator's stream.
    /// </summary>
    [Fact]
    public async Task The_readiness_verb_never_echoes_a_credential_bearing_configured_issuer()
    {
        string issuer = CanaryIssuer("http", "127.0.0.1:1");

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "issuer", "readiness",
                "--file-store-root", Store(),
                "--issuer", issuer,
                "--token-validation", "jwks",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Failure, outcome.ExitCode);
        Assert.Contains("issuer/issuer-unavailable", outcome.Output, StringComparison.Ordinal);
        Assert.Contains(
            "http://127.0.0.1:1 [credentials, path, query, fragment withheld]",
            outcome.Output,
            StringComparison.Ordinal);
        AssertNoReadinessCanary(outcome.Output);
    }

    /// <summary>
    /// The whole verb against a document that echoes the canary-bearing configured issuer and
    /// advertises a canary-bearing key-set endpoint: ready, actionable, and canary-free.
    /// </summary>
    [Fact]
    public async Task The_readiness_verb_never_echoes_canaries_from_the_issuer_document()
    {
        await using AuthorizationTransportServer server = await CanaryDocumentServerAsync();

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "issuer", "readiness",
                "--file-store-root", Store(),
                "--issuer", CanaryIssuer("http", server.Address.Authority),
                "--token-validation", "jwks",
            ],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("issuer readiness: ready", outcome.Output, StringComparison.Ordinal);
        Assert.Contains("usable signing key", outcome.Output, StringComparison.Ordinal);
        Assert.Contains(
            "[credentials, path, query, fragment withheld] (configured)",
            outcome.Output,
            StringComparison.Ordinal);
        AssertNoReadinessCanary(outcome.Output);
    }

    // ---------------------------------------------------------------- real subprocess evidence

    /// <summary>
    /// The verb through a real operating-system process: the entry point routes it, the report
    /// reaches stdout and the exit code distinguishes ready from not-ready.
    /// </summary>
    [Fact]
    public async Task A_subprocess_readiness_probe_reaches_a_real_issuer()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    await WriteJsonAsync(context, JwksMetadata(IssuerOf(context)));
                    return;
                }

                await WriteJsonAsync(context, JwksJson());
            });

        EngineCliOutcome outcome = await EngineCliProcess.RunAsync(
            TestContext.Current.CancellationToken,
            "issuer", "readiness",
            "--file-store-root", Store(),
            "--issuer", $"http://127.0.0.1:{server.Address.Port}/",
            "--token-validation", "jwks");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("issuer readiness: ready", outcome.Stdout, StringComparison.Ordinal);
    }

    /// <summary>
    /// The canary-bearing configuration through a real operating-system process: the verb is ready
    /// and both captured streams stay free of every credential canary.
    /// </summary>
    [Fact]
    public async Task A_subprocess_readiness_report_never_prints_a_credential_canary()
    {
        await using AuthorizationTransportServer server = await CanaryDocumentServerAsync();

        EngineCliOutcome outcome = await EngineCliProcess.RunAsync(
            TestContext.Current.CancellationToken,
            "issuer", "readiness",
            "--file-store-root", Store(),
            "--issuer", CanaryIssuer("http", server.Address.Authority),
            "--token-validation", "jwks");

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("issuer readiness: ready", outcome.Stdout, StringComparison.Ordinal);
        AssertNoReadinessCanary(outcome.Stdout);
        AssertNoReadinessCanary(outcome.Stderr);
    }

    /// <summary>
    /// E12's inspect half: an unreachable issuer plus an unresolvable introspection secret keeps
    /// `inspect` a configuration refusal with no listener, and the reachable-recorder variant proves
    /// the issuer was never asked. The Manifest's declared credential is unset on purpose: inspect
    /// must describe the mount without resolving it.
    /// </summary>
    [Fact]
    public async Task A_subprocess_inspect_with_an_unreachable_issuer_and_an_unresolvable_secret_makes_no_request()
    {
        string manifest = WriteCredentialManifest();
        string missingSecret = Path.Combine(_root, "missing-introspection-secret");
        (string stateRoot, string stateKey) = RuntimeState();

        EngineCliOutcome unreachable = await EngineCliProcess.RunAsync(
            TestContext.Current.CancellationToken,
            "inspect",
            "--mount", "/api=" + manifest,
            "--file-store-root", Store(),
            "--runtime-state-root", stateRoot,
            "--runtime-state-key-file", stateKey,
            "--issuer", "http://127.0.0.1:1",
            "--token-validation", "introspection",
            "--introspection-client-id", "engine-readiness",
            "--introspection-client-secret-file", missingSecret);

        Assert.Equal(ExitCodes.Configuration, unreachable.ExitCode);
        Assert.Contains("auth/introspection-client-secret-unusable", unreachable.Stdout, StringComparison.Ordinal);
        Assert.Contains("fingerprint=", unreachable.Stdout, StringComparison.Ordinal);
        Assert.Contains("opened no listener", unreachable.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(UnusedRefreshVariable, unreachable.Stdout, StringComparison.Ordinal);

        // The same refusal against a reachable issuer proves zero egress on the wire.
        await using AuthorizationTransportServer recorder = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJsonAsync(context, "{}"));

        EngineCliOutcome recorded = await EngineCliProcess.RunAsync(
            TestContext.Current.CancellationToken,
            "inspect",
            "--mount", "/api=" + manifest,
            "--file-store-root", Store(),
            "--runtime-state-root", stateRoot,
            "--runtime-state-key-file", stateKey,
            "--issuer", recorder.Address.AbsoluteUri,
            "--token-validation", "introspection",
            "--introspection-client-id", "engine-readiness",
            "--introspection-client-secret-file", missingSecret);

        Assert.Equal(ExitCodes.Configuration, recorded.ExitCode);
        Assert.Equal(0, recorder.RequestCount);
    }

    // ---------------------------------------------------------------- helpers

    private const string Identity = "mcpiler-engine test (issuer readiness)";

    private static async Task<IssuerReadinessReport> ProbeAsync(
        HostAuthorizationOptions options,
        CancellationToken cancellationToken)
    {
        using HttpClient discovery = AuthorizationHttpClientFactory.Create(IssuerReadiness.DiscoveryTimeout);
        using HttpClient endpoint = AuthorizationHttpClientFactory.Create(IssuerReadiness.EndpointTimeout);

        return await IssuerReadiness.ProbeAsync(options, discovery, endpoint, cancellationToken);
    }

    private static HostAuthorizationOptions Jwks(Uri issuer, bool fallback = false)
        => new(issuer.AbsoluteUri, HostTokenValidation.Jwks)
        {
            OidcDiscoveryFallbackEnabled = fallback,
        };

    /// <summary>One issuer spelling with a canary in every component a URL can carry.</summary>
    private static string CanaryIssuer(string scheme, string authority)
        => $"{scheme}://user:{CredentialCanary}@{authority}/{PathCanary}/?access_token={QueryCanary}#{FragmentCanary}";

    /// <summary>One endpoint spelling with a canary in every component a URL can carry.</summary>
    private static string CanaryEndpoint(string scheme, string authority, string path)
        => $"{scheme}://user:{CredentialCanary}@{authority}/{PathCanary}{path}?access_token={QueryCanary}#{FragmentCanary}";

    /// <summary>Asserts that no canary-bearing URL component reached one operator-visible string.</summary>
    private static void AssertNoReadinessCanary(string text)
    {
        Assert.DoesNotContain(CredentialCanary, text, StringComparison.Ordinal);
        Assert.DoesNotContain(PathCanary, text, StringComparison.Ordinal);
        Assert.DoesNotContain(QueryCanary, text, StringComparison.Ordinal);
        Assert.DoesNotContain(FragmentCanary, text, StringComparison.Ordinal);
    }

    /// <summary>One JSON answer for the stub clients.</summary>
    private static HttpResponseMessage Json(string body)
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

    /// <summary>
    /// A loopback issuer whose document echoes the exact canary-bearing configured issuer and
    /// advertises a canary-bearing key-set endpoint. The issuer string is reconstructed in the same
    /// shape the test configures, so the exact-match rule is exercised rather than bypassed.
    /// </summary>
    private static async Task<AuthorizationTransportServer> CanaryDocumentServerAsync()
        => await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value is { } path
                    && path.StartsWith("/.well-known", StringComparison.Ordinal))
                {
                    string authority = context.Request.Host.Value
                        ?? throw new InvalidOperationException("The fixture request carried no Host header.");
                    string configuredIssuer = CanaryIssuer("http", authority);
                    string keySetEndpoint = CanaryEndpoint("http", authority, "/jwks");

                    await WriteJsonAsync(
                        context,
                        $"{{\"issuer\":\"{configuredIssuer}\",\"jwks_uri\":\"{keySetEndpoint}\"}}");
                    return;
                }

                await WriteJsonAsync(context, JwksJson());
            });

    private static string AddressOf(HttpContext context)
        => $"http://{context.Request.Host.Value}";

    /// <summary>
    /// The issuer spelling the seam tests configure: <see cref="Uri.AbsoluteUri"/> always carries a
    /// trailing slash for an authority without a path, and the metadata must match byte for byte.
    /// </summary>
    private static string IssuerOf(HttpContext context) => AddressOf(context) + "/";

    private static string JwksMetadata(string issuer)
        => $"{{\"issuer\":\"{issuer}\",\"jwks_uri\":\"{issuer.TrimEnd('/')}/jwks\"}}";

    /// <summary>One metadata document and one key-set document, both valid.</summary>
    private static async Task<AuthorizationTransportServer> JwksServerAsync(Func<HttpContext, Task> jwks)
        => await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    await WriteJsonAsync(context, JwksMetadata(IssuerOf(context)));
                    return;
                }

                await jwks(context);
            });

    /// <summary>
    /// An introspection deployment: metadata advertises the endpoint, and the endpoint authenticates
    /// the resource server (when a secret is expected, or when anonymous callers must be refused)
    /// before answering with the configured body.
    /// </summary>
    private static async Task<AuthorizationTransportServer> IntrospectionServerAsync(
        string? expectedSecret = null,
        string body = "{\"active\":false}",
        bool refuseAnonymous = false)
        => await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    await WriteJsonAsync(
                        context,
                        $"{{\"issuer\":\"{IssuerOf(context)}\","
                        + $"\"introspection_endpoint\":\"{AddressOf(context)}/introspect\"}}");
                    return;
                }

                if (expectedSecret is not null)
                {
                    string expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(
                        $"engine-readiness:{Uri.EscapeDataString(expectedSecret)}"));

                    if (!string.Equals(context.Request.Headers.Authorization.ToString(), expected, StringComparison.Ordinal))
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        return;
                    }
                }
                else if (refuseAnonymous && !context.Request.Headers.ContainsKey("Authorization"))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }

                await WriteJsonAsync(context, body);
            });

    private static async Task WriteJsonAsync(HttpContext context, string body)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(body, context.RequestAborted);
    }

    private static string JwksJson(int keyCount = 1)
    {
        List<string> entries = [];

        for (int index = 0; index < keyCount; index++)
        {
            using RSA rsa = RSA.Create(2048);
            RsaSecurityKey key = new(rsa.ExportParameters(false))
            {
                KeyId = "readiness-key-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture),
            };
            JsonWebKey web = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            web.Kid = key.KeyId;

            entries.Add(
                $$"""{ "kty": "{{web.Kty}}", "kid": "{{web.Kid}}", "n": "{{web.N}}", "e": "{{web.E}}", "alg": "RS256", "use": "sig" }""");
        }

        return "{ \"keys\": [ " + string.Join(", ", entries) + " ] }";
    }

    private static string ProbeValueFrom(string formBody)
    {
        string encoded = Assert.Single(
            formBody.Split('&', StringSplitOptions.RemoveEmptyEntries),
            part => part.StartsWith("token=", StringComparison.Ordinal));

        return Uri.UnescapeDataString(encoded["token=".Length..]);
    }

    private string Store()
    {
        string store = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(store);
        return store;
    }

    /// <summary>
    /// A durable runtime-state root and key, because the fixture Manifest declares a runtime-owned
    /// mutable slot and the runtime refuses to start without somewhere durable to keep it.
    /// </summary>
    private (string Root, string KeyFile) RuntimeState()
    {
        string root = Path.Combine(_root, "state-" + Guid.NewGuid().ToString("N"));
        string key = Path.Combine(_root, "key-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        File.WriteAllBytes(key, new byte[32]);
        return (root, key);
    }

    /// <summary>
    /// A mount that declares a runtime-owned OAuth refresh credential through an unset environment
    /// variable. Inspection must never need the value.
    /// </summary>
    private string WriteCredentialManifest()
    {
        string directory = Path.Combine(_root, "credential-manifest");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "manifest.json"), $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "OAuth API", "authenticationRequired": false } },
                "policy": { "inline": { "baseUrl": "https://api.example.com" } },
                "operations": {
                  "inline": {
                    "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      {
                        "slug": "list-pets",
                        "name": "List pets",
                        "binding": { "type": "http", "operation": "GET /pets", "authenticationRef": "oauth" }
                      }
                    ]
                  }
                },
                "credentials": {
                  "inline": {
                    "formatVersion": 4,
                    "credentials": [
                      {
                        "id": "oauth-refresh",
                        "scheme": "oauth2-authorization-code",
                        "slot": "refreshToken",
                        "value": { "fromEnv": "{{UnusedRefreshVariable}}" }
                      }
                    ]
                  }
                },
                "authentication": {
                  "inline": {
                    "formatVersion": 2,
                    "profiles": [
                      {
                        "id": "oauth",
                        "kind": "oauth2-authorization-code-pkce-refresh",
                        "configuration": {
                          "strategyId": "oauth2-authorization-code-pkce-refresh",
                          "inputs": { "clientId": "example-client" },
                          "clientId": "example-client",
                          "tokenEndpoint": "https://auth.example.com/oauth2/token",
                          "authorizationEndpoint": "https://auth.example.com/oauth2/authorize",
                          "tokenAuthMethod": "none",
                          "scopes": ["pets.read"],
                          "resource": "https://api.example.com"
                        },
                        "authenticationOrigins": ["https://auth.example.com:443"],
                        "destinationOrigins": ["https://api.example.com:443"],
                        "credentialRef": ["oauth-refresh"],
                        "scopeFingerprint": "0000000000000000000000000000000000000000000000000000000000000001",
                        "slots": [
                          { "slot": "refreshToken", "authorityEpoch": 1, "runtimeRevision": 0 }
                        ]
                      }
                    ]
                  }
                }
              }
            }
            """);
        return directory;
    }

    /// <summary>Counts requests and can be made to fail loudly if the probe calls it at all.</summary>
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage>? _responder;
        private int _requests;

        private StubHandler(Func<HttpRequestMessage, HttpResponseMessage>? responder) => _responder = responder;

        internal int Requests => Volatile.Read(ref _requests);

        internal static StubHandler Refusing() => new(null);

        internal static StubHandler Answering(Func<HttpRequestMessage, HttpResponseMessage> responder)
            => new(responder);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requests);

            return _responder is null
                ? throw new InvalidOperationException(
                    $"The readiness probe sent '{request.RequestUri}' where no request was permitted.")
                : Task.FromResult(_responder(request));
        }
    }

    /// <summary>Holds every request open until the client's own timeout fires.</summary>
    private sealed class DelayingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(20), cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class ThrowingHandler(Exception failure) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
            => Task.FromException<HttpResponseMessage>(failure);
    }
}
