using System;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Authorization;

/// <summary>
/// The restricted opt-in OIDC metadata fallback: URL construction, exactly which RFC 8414 outcomes
/// may reach the issuer-derived OIDC well-known, which must never reach it, and how the fallback
/// document is validated.
/// </summary>
/// <remarks>
/// Every refusal case asserts the requested paths, not only the outcome: "no fallback" means the
/// OIDC path never appears on the wire, so a policy that failed closed after asking a second origin
/// would not pass.
/// </remarks>
public sealed class IssuerDiscoveryFallbackTests
{
    private const string Rfc8414Path = "/.well-known/oauth-authorization-server";
    private const string OidcPath = "/.well-known/openid-configuration";

    /// <summary>
    /// OIDC Discovery appends its well-known to the issuer path, unlike RFC 8414's insert-before-path.
    /// </summary>
    [Theory]
    [InlineData("https://example.com", "https://example.com/.well-known/openid-configuration")]
    [InlineData("https://example.com/", "https://example.com/.well-known/openid-configuration")]
    [InlineData("https://example.com/tenant-a", "https://example.com/tenant-a/.well-known/openid-configuration")]
    [InlineData("https://example.com/tenant-a/", "https://example.com/tenant-a/.well-known/openid-configuration")]
    [InlineData("https://example.com/tenant-a/deployment-b", "https://example.com/tenant-a/deployment-b/.well-known/openid-configuration")]
    [InlineData("http://127.0.0.1:5099/tenant", "http://127.0.0.1:5099/tenant/.well-known/openid-configuration")]
    public void The_oidc_url_is_appended_to_the_issuer_path(string issuer, string expected)
        => Assert.Equal(expected, IssuerMetadata.OidcDiscoveryUri(issuer).AbsoluteUri);

    /// <summary>The fallback never fires for an operator who did not enable it.</summary>
    [Fact]
    public async Task Fallback_disabled_never_requests_the_oidc_route()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                await WriteJwksMetadataAsync(context);
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address, fallback: false),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/issuer-discovery-unusable", refusal!.Code);
        Assert.Equal(new[] { Rfc8414Path }, server.RequestedPaths);
    }

    /// <summary>
    /// Exactly a definitive 404/410 from the RFC 8414 URL permits the issuer-derived OIDC URL,
    /// and the OIDC document then feeds the same endpoint validation.
    /// </summary>
    [Theory]
    [InlineData(StatusCodes.Status404NotFound)]
    [InlineData(StatusCodes.Status410Gone)]
    public async Task A_definitive_absence_uses_the_issuer_derived_oidc_route(int status)
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = status;
                    return;
                }

                await WriteJwksMetadataAsync(context);
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
        Assert.Equal(new[] { Rfc8414Path, OidcPath }, server.RequestedPaths);
    }

    /// <summary>A valid primary document ends discovery even though the fallback is enabled.</summary>
    [Fact]
    public async Task A_successful_rfc8414_document_never_requests_the_oidc_route()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context => await WriteJwksMetadataAsync(context));

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
        Assert.Equal(new[] { Rfc8414Path }, server.RequestedPaths);
    }

    /// <summary>Malformed metadata is an error to fix, not absence to reinterpret.</summary>
    [Fact]
    public async Task A_malformed_rfc8414_200_never_requests_the_oidc_route()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    await WriteJsonAsync(context, "not-json");
                    return;
                }

                await WriteJwksMetadataAsync(context);
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/issuer-metadata-invalid", refusal!.Code);
        Assert.Equal(new[] { Rfc8414Path }, server.RequestedPaths);
    }

    /// <summary>A wrong issuer is a trust mismatch, never a reason to ask a different well-known.</summary>
    [Fact]
    public async Task A_wrong_issuer_rfc8414_200_never_requests_the_oidc_route()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    await WriteJsonAsync(
                        context,
                        $"{{\"issuer\":\"https://other.example\",\"jwks_uri\":\"{AddressOf(context)}/jwks\"}}");
                    return;
                }

                await WriteJwksMetadataAsync(context);
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/issuer-metadata-invalid", refusal!.Code);
        Assert.Equal(new[] { Rfc8414Path }, server.RequestedPaths);
    }

    /// <summary>
    /// Every RFC 8414 outcome other than 404/410 ends resolution: 4xx/unsupported redirects refuse,
    /// 429/5xx remain recoverable outages, and none of them asks the OIDC URL.
    /// </summary>
    [Theory]
    [InlineData(StatusCodes.Status400BadRequest, true)]
    [InlineData(StatusCodes.Status401Unauthorized, true)]
    [InlineData(StatusCodes.Status403Forbidden, true)]
    [InlineData(StatusCodes.Status429TooManyRequests, false)]
    [InlineData(StatusCodes.Status500InternalServerError, false)]
    [InlineData(StatusCodes.Status503ServiceUnavailable, false)]
    [InlineData(StatusCodes.Status301MovedPermanently, true)]
    [InlineData(StatusCodes.Status302Found, true)]
    [InlineData(StatusCodes.Status307TemporaryRedirect, true)]
    [InlineData(StatusCodes.Status308PermanentRedirect, true)]
    public async Task A_non_definitive_rfc8414_outcome_never_requests_the_oidc_route(
        int status,
        bool refused)
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = status;
                    return;
                }

                await WriteJwksMetadataAsync(context);
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.Equal(refused, refusal is not null);
        Assert.Equal(new[] { Rfc8414Path }, server.RequestedPaths);
    }

    /// <summary>A transport failure is an outage; absence must be an HTTP status to count.</summary>
    [Fact]
    public async Task An_rfc8414_transport_failure_never_requests_the_oidc_route()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Abort();
                    return;
                }

                await WriteJwksMetadataAsync(context);
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
        Assert.Equal(new[] { Rfc8414Path }, server.RequestedPaths);
    }

    /// <summary>A malformed fallback document is refused, not retried or guessed around.</summary>
    [Fact]
    public async Task A_malformed_oidc_document_is_refused()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                await WriteJsonAsync(context, "not-json");
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/issuer-metadata-invalid", refusal!.Code);
        Assert.Contains("OIDC discovery fallback", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(new[] { Rfc8414Path, OidcPath }, server.RequestedPaths);
    }

    /// <summary>The fallback document must still carry the byte-exact configured issuer.</summary>
    [Fact]
    public async Task A_wrong_issuer_oidc_document_is_refused()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                await WriteJsonAsync(
                    context,
                    $"{{\"issuer\":\"https://other.example\",\"jwks_uri\":\"{AddressOf(context)}/jwks\"}}");
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/issuer-metadata-invalid", refusal!.Code);
        Assert.Contains("does not exactly match", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(new[] { Rfc8414Path, OidcPath }, server.RequestedPaths);
    }

    /// <summary>A fallback document that names two issuers is ambiguity and is refused whole.</summary>
    [Fact]
    public async Task A_duplicate_issuer_member_in_the_oidc_document_is_refused()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                string address = AddressOf(context);
                await WriteJsonAsync(
                    context,
                    $"{{\"issuer\":\"{address}/\",\"issuer\":\"{address}/\",\"jwks_uri\":\"{address}/jwks\"}}");
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/issuer-metadata-invalid", refusal!.Code);
        Assert.Contains("more than once", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>A redirect on either route is refused and never followed, even toward a live server.</summary>
    [Theory]
    [InlineData(StatusCodes.Status302Found)]
    [InlineData(StatusCodes.Status307TemporaryRedirect)]
    public async Task The_oidc_route_never_reaches_its_redirect_target(int redirectStatus)
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
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return Task.CompletedTask;
                }

                context.Response.StatusCode = redirectStatus;
                context.Response.Headers.Location = new Uri(target.Address, "/redirect-target").ToString();
                return Task.CompletedTask;
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/issuer-discovery-unusable", refusal!.Code);
        Assert.Contains("OIDC discovery fallback", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(new[] { Rfc8414Path, OidcPath }, server.RequestedPaths);
        Assert.Equal(0, target.RequestCount);
    }

    /// <summary>An advertised endpoint still passes the existing HTTPS-unless-loopback rule.</summary>
    [Fact]
    public async Task An_oidc_document_with_an_out_of_policy_endpoint_is_refused()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                await WriteJsonAsync(
                    context,
                    $"{{\"issuer\":\"{AddressOf(context)}/\",\"jwks_uri\":\"http://198.51.100.10/jwks\"}}");
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/jwks-uri-insecure", refusal!.Code);
    }

    /// <summary>A transient fallback failure may recover without an operator change.</summary>
    [Fact]
    public async Task An_oidc_5xx_stays_an_outage()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = context.Request.Path.Value == Rfc8414Path
                    ? StatusCodes.Status404NotFound
                    : StatusCodes.Status503ServiceUnavailable;
                return Task.CompletedTask;
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
        Assert.Equal(new[] { Rfc8414Path, OidcPath }, server.RequestedPaths);
    }

    /// <summary>Absent after both permitted routes is definitive, not transient.</summary>
    [Fact]
    public async Task An_oidc_404_is_a_definitive_refusal()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return Task.CompletedTask;
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/issuer-discovery-unusable", refusal!.Code);
        Assert.Contains("OIDC discovery fallback", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(new[] { Rfc8414Path, OidcPath }, server.RequestedPaths);
    }

    /// <summary>
    /// A configured issuer with a path derives both well-knowns from that path, and the OIDC URL
    /// keeps the issuer's authority.
    /// </summary>
    [Fact]
    public async Task An_issuer_with_a_path_derives_the_oidc_url_from_that_path()
    {
        const string rfcPath = Rfc8414Path + "/tenant";
        const string oidcPath = "/tenant" + OidcPath;

        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == rfcPath)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                if (context.Request.Path.Value == oidcPath)
                {
                    string address = AddressOf(context);
                    await WriteJsonAsync(
                        context,
                        $"{{\"issuer\":\"{address}/tenant\",\"introspection_endpoint\":\"{address}/tenant/introspect\"}}");
                    return;
                }

                context.Response.StatusCode = StatusCodes.Status404NotFound;
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            new HostAuthorizationOptions(
                new Uri(server.Address, "/tenant").AbsoluteUri,
                HostTokenValidation.Introspection)
            {
                OidcDiscoveryFallbackEnabled = true,
            },
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
        Assert.Equal(new[] { rfcPath, oidcPath }, server.RequestedPaths);
    }

    /// <summary>
    /// Member order, extra members, whitespace and JSON escapes do not change the verdict: the
    /// decision is the decoded `issuer` string, not the text layout that carried it.
    /// </summary>
    [Fact]
    public async Task Equivalent_oidc_json_layouts_are_accepted()
    {
        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                if (context.Request.Path.Value == Rfc8414Path)
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                string host = context.Request.Host.Value ?? string.Empty;
                await WriteJsonAsync(
                    context,
                    "{\n"
                    + "  \"claims_supported\" : [ \"sub\" ],\n"
                    + $"  \"issuer\" : \"http:\\/\\/{host}\\/\",\n"
                    + "  \"token_endpoint_auth_methods_supported\": [ \"client_secret_basic\" ],\n"
                    + $"  \"jwks_uri\" : \"http:\\/\\/{host}\\/jwks\"\n"
                    + "}");
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Jwks(server.Address),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
        Assert.Equal(new[] { Rfc8414Path, OidcPath }, server.RequestedPaths);
    }

    private static HostAuthorizationOptions Jwks(Uri issuer, bool fallback = true)
        => new(issuer.AbsoluteUri, HostTokenValidation.Jwks)
        {
            OidcDiscoveryFallbackEnabled = fallback,
        };

    private static string AddressOf(HttpContext context)
        => $"http://{context.Request.Host.Value}";

    private static async Task WriteJwksMetadataAsync(HttpContext context)
    {
        string address = AddressOf(context);
        await WriteJsonAsync(context, $"{{\"issuer\":\"{address}/\",\"jwks_uri\":\"{address}/jwks\"}}");
    }

    private static async Task WriteJsonAsync(HttpContext context, string body)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(body, context.RequestAborted);
    }
}
