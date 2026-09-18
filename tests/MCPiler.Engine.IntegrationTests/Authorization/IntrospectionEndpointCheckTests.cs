using System;
using System.IO;
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
/// The startup refusal for a validation mode whose issuer publishes no endpoint for it.
/// </summary>
/// <remarks>
/// <para>
/// A resource server configured for introspection can only answer "this token is not known to be
/// active" when the endpoint does not exist, and that answer is indistinguishable at the client
/// from its own misconfiguration. The check reads the issuer's published metadata and refuses
/// before anything listens.
/// </para>
/// <para>
/// The negative case matters as much as the positive one: a check that refused whenever it could
/// not reach the issuer would turn an authorization-server outage into a refused start, and an
/// orchestrator that restarts a refused process would turn that outage into a restart loop.
/// </para>
/// </remarks>
public sealed class IntrospectionEndpointCheckTests
{
    [Fact]
    public async Task An_issuer_that_publishes_an_introspection_endpoint_is_usable()
    {
        await using FakeServer server = await FakeServer.StartAsync(publishesIntrospection: true);

        StartupRefusal? refusal = await IntrospectionEndpointCheck.FindAsync(
            Introspection(server.Address),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
    }

    [Fact]
    public async Task An_issuer_that_publishes_no_introspection_endpoint_is_refused_by_name()
    {
        await using FakeServer server = await FakeServer.StartAsync(publishesIntrospection: false);

        StartupRefusal? refusal = await IntrospectionEndpointCheck.FindAsync(
            Introspection(server.Address),
            TestContext.Current.CancellationToken);

        Assert.NotNull(refusal);
        Assert.Equal("auth/introspection-endpoint-missing", refusal!.Code);

        // The refusal names the setting to change and the configuration it read, so an operator
        // does not have to guess which of the two halves is wrong.
        Assert.Contains("introspection", refusal.Message, StringComparison.Ordinal);
        Assert.Contains(server.Address.AbsoluteUri, refusal.Message, StringComparison.Ordinal);
        Assert.Equal(HostConfiguration.IntrospectionEndpointKey, refusal.Setting);
    }

    [Fact]
    public async Task A_configured_endpoint_is_taken_at_its_word()
    {
        await using FakeServer server = await FakeServer.StartAsync(publishesIntrospection: false);

        StartupRefusal? refusal = await IntrospectionEndpointCheck.FindAsync(
            new HostAuthorizationOptions(
                server.Address.AbsoluteUri,
                HostTokenValidation.Introspection,
                IntrospectionEndpoint: "https://issuer.example.test/introspect"),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
    }

    [Fact]
    public async Task The_jwks_mode_never_consults_introspection()
    {
        await using FakeServer server = await FakeServer.StartAsync(publishesIntrospection: false);

        StartupRefusal? refusal = await IntrospectionEndpointCheck.FindAsync(
            new HostAuthorizationOptions(server.Address.AbsoluteUri, HostTokenValidation.Jwks),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
    }

    [Fact]
    public async Task An_unreachable_issuer_is_an_outage_and_not_a_refusal()
    {
        // A bound-then-released port: nothing listens there, so the request is refused rather
        // than answered. That is the shape of an authorization server that is currently down.
        Uri unreachable = UnreachableIssuer();

        StartupRefusal? refusal = await IntrospectionEndpointCheck.FindAsync(
            new HostAuthorizationOptions(unreachable.AbsoluteUri, HostTokenValidation.Introspection),
            TestContext.Current.CancellationToken);

        Assert.Null(refusal);
    }

    [Fact]
    public async Task A_process_that_trusts_no_issuer_has_nothing_to_check()
    {
        StartupRefusal? refusal = await IntrospectionEndpointCheck.FindAsync(
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

    /// <summary>
    /// The smallest authorization server this check needs: an RFC 8414 document that may or may
    /// not name an introspection endpoint.
    /// </summary>
    private sealed class FakeServer : IAsyncDisposable
    {
        private readonly WebApplication _app;

        private FakeServer(WebApplication app)
            => _app = app;

        public Uri Address { get; private init; } = null!;

        public static async Task<FakeServer> StartAsync(bool publishesIntrospection)
        {
            WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");

            WebApplication app = builder.Build();

            app.Run(async context =>
            {
                string host = context.Request.Host.Value ?? string.Empty;
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    publishesIntrospection
                        ? $$"""{ "issuer": "http://{{host}}", "introspection_endpoint": "http://{{host}}/introspect", "jwks_uri": "http://{{host}}/jwks" }"""
                        : $$"""{ "issuer": "http://{{host}}", "jwks_uri": "http://{{host}}/jwks" }""",
                    context.RequestAborted);
            });

            await app.StartAsync(TestContext.Current.CancellationToken);

            return new FakeServer(app) { Address = new Uri(app.Urls.Single()) };
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
