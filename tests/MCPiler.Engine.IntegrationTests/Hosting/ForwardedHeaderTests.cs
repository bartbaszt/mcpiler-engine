using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Hosting;

/// <summary>
/// How a process behind a TLS-terminating reverse proxy observes its own external address.
/// </summary>
/// <remarks>
/// <para>
/// Engine derives the canonical protected-resource identifier and the token audience from the
/// request's own scheme, authority and path. Behind a proxy that terminates TLS, the request
/// that reaches Engine is plain http, so without forwarded headers every metadata document and
/// every audience comparison would name a scheme and authority no client used — the exact
/// drift the split exists to avoid. These tests pin both the honoured case and the refusal to
/// honour an untrusted client's claim.
/// </para>
/// <para>
/// The proxy is simulated by setting the forwarded headers directly, because there is no proxy
/// in the test: what matters is that only a configured peer address is believed, and the
/// hosting middleware decides that from the connection's remote address.
/// </para>
/// </remarks>
public sealed class ForwardedHeaderTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "mcpiler-forwarded-" + Guid.NewGuid().ToString("N"));

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public ForwardedHeaderTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task A_trusted_proxy_scheme_reaches_the_protected_resource_metadata()
    {
        await using FakeAuthorizationServer authorization =
            await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await UpstreamAsync();
        string manifest = ServedManifests.Write(
            _root,
            "forwarded-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address));

        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor(manifest),
            Token,
            authorization: AuthorizationFor(authorization.Address),
            trustedProxies: ["127.0.0.1"]);

        using HttpClient client = new();
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            new Uri(engine.At("/.well-known/oauth-protected-resource/api/full").ToString()));

        // What a TLS-terminating proxy sends: the client's scheme, and the original host header
        // preserved byte-exact. Host is not a forwarded header here on purpose — the hosting
        // middleware trusts only for/proto, exactly as the Platform does, because a proxy that
        // rewrites Host is a configuration the deployment guide refuses.
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        request.Headers.Host = "public.example.test";

        using HttpResponseMessage served = await client.SendAsync(request, Token);

        Assert.Equal(HttpStatusCode.OK, served.StatusCode);

        using JsonDocument document = JsonDocument.Parse(await served.Content.ReadAsStringAsync(Token));

        Assert.Equal(
            "https://public.example.test/api/full",
            document.RootElement.GetProperty("resource").GetString());
    }

    [Fact]
    public async Task An_untrusted_client_cannot_claim_the_scheme()
    {
        await using FakeAuthorizationServer authorization =
            await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await UpstreamAsync();
        string manifest = ServedManifests.Write(
            _root,
            "untrusted-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address));

        // No trusted proxies at all: the process is reached directly, so a forwarded header is
        // an untrusted client's assertion and must not change what the process believes.
        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor(manifest),
            Token,
            authorization: AuthorizationFor(authorization.Address));

        using HttpClient client = new();
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            new Uri(engine.At("/.well-known/oauth-protected-resource/api/full").ToString()));

        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        request.Headers.Host = "attacker.example.test";

        using HttpResponseMessage served = await client.SendAsync(request, Token);

        Assert.Equal(HttpStatusCode.OK, served.StatusCode);

        using JsonDocument document = JsonDocument.Parse(await served.Content.ReadAsStringAsync(Token));

        // The scheme is the assertion that matters: an untrusted client claimed https and the
        // process still publishes http, so the audience it will accept is the address a client
        // that actually reached it over http would present. The host comes from the Host header,
        // which is what every HTTP server reads and what a deployment constrains through the
        // proxy and AllowedHosts rather than through forwarded headers.
        string resource = document.RootElement.GetProperty("resource").GetString()!;

        Assert.StartsWith("http://", resource, StringComparison.Ordinal);
        Assert.Contains("/api/full", resource, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_explicit_external_resource_ignores_host_and_forwarding_claims()
    {
        await using FakeAuthorizationServer authorization =
            await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await UpstreamAsync();
        string manifest = ServedManifests.Write(
            _root,
            "external-forwarded-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address));
        const string external = "https://tunnel.example.test/v1/mcp/stable-resource";

        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor(manifest),
            Token,
            authorization: AuthorizationFor(authorization.Address),
            trustedProxies: ["127.0.0.1"],
            externalResources: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["/api/full"] = external,
            });

        using HttpClient client = new();
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            engine.At("/.well-known/oauth-protected-resource/api/full"));
        request.Headers.Host = "attacker.example.test";
        request.Headers.TryAddWithoutValidation("Forwarded", "for=192.0.2.10;proto=http;host=forwarded.example.test");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "http");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Host", "x-forwarded.example.test");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "192.0.2.20");

        using HttpResponseMessage served = await client.SendAsync(request, Token);

        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        using JsonDocument document = JsonDocument.Parse(await served.Content.ReadAsStringAsync(Token));
        Assert.Equal(external, document.RootElement.GetProperty("resource").GetString());
    }

    private static async Task<LoopbackHost> UpstreamAsync() =>
        await LoopbackHost.StartAsync(StatusCodes.Status204NoContent, "application/json", [], Token);

    private RuntimeOptions RuntimeOptionsFor(string manifest) => new(
        [new MountRequest("/api", manifest)],
        Directory.CreateDirectory(Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"))).FullName);

    private static HostAuthorizationOptions AuthorizationFor(Uri issuer) =>
        new(issuer.AbsoluteUri, HostTokenValidation.Introspection);

    private static string Manifest(Uri upstream) => $$"""
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": {
              "name": "Forwarded Probe",
              "surfaces": [
                { "slug": "full", "isDefault": true, "requiredScopes": ["probe.read"],
                  "operations": [ { "operation": "ping", "exposure": "direct" } ] }
              ]
            } },
            "policy": { "inline": { "baseUrl": "{{upstream.AbsoluteUri}}" } },
            "operations": { "inline": { "operations": [
              { "key": "GET /ping", "method": "GET", "path": "/ping",
                "responses": { "200": { "content": { "application/json": { "schema": { "type": "object" } } } } } }
            ] } },
            "agentSurface": { "inline": { "operations": [
              { "slug": "ping", "name": "Ping", "binding": { "type": "http", "operation": "GET /ping" } }
            ] } }
          }
        }
        """;
}
