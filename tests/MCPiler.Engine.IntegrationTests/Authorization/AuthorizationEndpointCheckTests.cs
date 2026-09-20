using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Authorization;

/// <summary>
/// Startup trust-endpoint preflight for introspection and JWKS validation modes.
/// </summary>
public sealed class AuthorizationEndpointCheckTests
{
    [Fact]
    public async Task A_loopback_introspection_endpoint_is_usable()
    {
        await using FakeServer server = await FakeServer.StartAsync(
            "{\"introspection_endpoint\":\"{0}/introspect\",\"jwks_uri\":\"{0}/jwks\"}");

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Introspection(server.Address),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
    }

    [Fact]
    public async Task A_missing_introspection_endpoint_is_refused_by_name()
    {
        await using FakeServer server = await FakeServer.StartAsync("{\"jwks_uri\":\"{0}/jwks\"}");

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Introspection(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/introspection-endpoint-missing", refusal!.Code);
        Assert.Equal(HostConfiguration.IntrospectionEndpointKey, refusal.Setting);
    }

    [Fact]
    public async Task A_discovered_remote_http_introspection_endpoint_is_refused_before_endpoint_traffic()
    {
        await using FakeServer server = await FakeServer.StartAsync(
            "{\"introspection_endpoint\":\"http://198.51.100.10/introspect\"}");

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Introspection(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/introspection-endpoint-insecure", refusal!.Code);
        Assert.Contains("https", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_loopback_jwks_endpoint_is_usable()
    {
        await using FakeServer server = await FakeServer.StartAsync(
            "{\"issuer\":\"{0}\",\"jwks_uri\":\"{0}/jwks\"}");

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            new HostAuthorizationOptions(server.Address.AbsoluteUri, HostTokenValidation.Jwks),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
    }

    [Fact]
    public async Task A_missing_jwks_endpoint_is_refused_by_name()
    {
        await using FakeServer server = await FakeServer.StartAsync("{\"introspection_endpoint\":\"{0}/introspect\"}");

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            new HostAuthorizationOptions(server.Address.AbsoluteUri, HostTokenValidation.Jwks),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/jwks-uri-missing", refusal!.Code);
        Assert.Equal(HostConfiguration.JwksUriKey, refusal.Setting);
    }

    [Fact]
    public async Task A_discovered_remote_http_jwks_endpoint_is_refused_before_key_traffic()
    {
        await using FakeServer server = await FakeServer.StartAsync(
            "{\"jwks_uri\":\"http://198.51.100.10/jwks\"}");

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            new HostAuthorizationOptions(server.Address.AbsoluteUri, HostTokenValidation.Jwks),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/jwks-uri-insecure", refusal!.Code);
        Assert.Contains("no credential or key request", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unreachable_issuer_is_an_outage_and_not_a_refusal()
    {
        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            new HostAuthorizationOptions(UnreachableIssuer().AbsoluteUri, HostTokenValidation.Introspection),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
    }

    [Fact]
    public async Task An_explicit_remote_http_endpoint_is_rejected_by_the_same_policy()
    {
        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            new HostAuthorizationOptions(
                "https://issuer.example.test",
                HostTokenValidation.Introspection,
                IntrospectionEndpoint: "http://issuer.example.test/introspect"),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/introspection-endpoint-insecure", refusal!.Code);
    }

    [Theory]
    [InlineData(StatusCodes.Status307TemporaryRedirect)]
    [InlineData(StatusCodes.Status308PermanentRedirect)]
    public async Task Discovery_redirects_are_not_followed(int redirectStatus)
    {
        await using AuthorizationTransportServer target = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                return Task.CompletedTask;
            });
        await using AuthorizationTransportServer issuer = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = redirectStatus;
                context.Response.Headers.Location =
                    new Uri(target.Address, "/redirect-target?canary=discovery").ToString();
                return Task.CompletedTask;
            });

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            Introspection(issuer.Address),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
        Assert.Equal(1, issuer.RequestCount);
        Assert.Equal(0, target.RequestCount);
    }

    [Theory]
    [InlineData(HostTokenValidation.Introspection)]
    [InlineData(HostTokenValidation.Jwks)]
    public async Task Loopback_discovery_bypasses_a_configured_proxy(HostTokenValidation validation)
    {
        await using AuthorizationTransportServer issuer = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                context.Response.ContentType = "application/json";
                string issuerAddress = $"http://{context.Request.Host.Value}";
                return context.Response.WriteAsync(
                    $"{{\"introspection_endpoint\":\"{issuerAddress}/introspect\",\"jwks_uri\":\"{issuerAddress}/jwks\"}}",
                    context.RequestAborted);
            });
        await using AuthorizationTransportServer proxy = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status502BadGateway;
                return Task.CompletedTask;
            });

        Assert.NotNull(issuer.Address);

        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            new HostAuthorizationOptions(issuer.Address.AbsoluteUri, validation),
            new FixedWebProxy(proxy.Address),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
        Assert.Equal(1, issuer.RequestCount);
        Assert.Equal(0, proxy.RequestCount);
    }

    [Fact]
    public async Task No_authorization_configuration_has_no_endpoint_to_check()
    {
        StartupRefusal? refusal = await AuthorizationEndpointCheck.FindAsync(
            authorization: null,
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
    }

    private static HostAuthorizationOptions Introspection(Uri issuer)
        => new(issuer.AbsoluteUri, HostTokenValidation.Introspection);

    private static Uri UnreachableIssuer()
    {
        TcpListener probe = new(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return new Uri($"http://127.0.0.1:{port}");
    }

    private sealed class FakeServer : IAsyncDisposable
    {
        private readonly WebApplication _app;

        private FakeServer(WebApplication app) => _app = app;

        public Uri Address { get; private init; } = null!;

        public static async Task<FakeServer> StartAsync(string metadataTemplate)
        {
            WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            WebApplication app = builder.Build();

            app.Run(async context =>
            {
                if (!context.Request.Path.Value!.EndsWith(
                        "/.well-known/oauth-authorization-server",
                        StringComparison.Ordinal))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                string host = context.Request.Host.Value ?? string.Empty;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    metadataTemplate.Replace("{0}", $"http://{host}", StringComparison.Ordinal),
                    context.RequestAborted);
            });

            await app.StartAsync(TestContext.Current.CancellationToken);
            return new FakeServer(app)
            {
                Address = new Uri(app.Urls.Single()),
            };
        }

        public async ValueTask DisposeAsync()
        {
            using CancellationTokenSource shutdown = new(TimeSpan.FromSeconds(5));
            try
            {
                await _app.StopAsync(shutdown.Token);
            }
            catch (OperationCanceledException)
            {
                // A fake that will not stop cannot fail the test it served.
            }
            finally
            {
                await _app.DisposeAsync();
            }
        }
    }
}
