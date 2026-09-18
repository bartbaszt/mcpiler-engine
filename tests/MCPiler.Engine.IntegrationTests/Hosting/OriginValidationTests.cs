using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Hosting;

/// <summary>
/// How a browser origin is judged on a served address.
/// </summary>
/// <remarks>
/// <para>
/// The canonical transport requirement is that the MCP endpoint validates the <c>Origin</c>
/// header when it is present and rejects an unexpected origin. The header is sent by browser
/// pages, so the decision is "may this browser origin call the served address": a non-browser
/// client sends none and is served normally, while a browser presenting an origin the operator
/// did not name must be refused before it costs any admission work.
/// </para>
/// <para>
/// The endpoint that serves these addresses belongs to Engine, so the requirement moved with
/// it. These tests pin the refusal, the two passing shapes, and the fact that discovery and
/// health are not browser origins' business — a browser-based client must still be able to read
/// the metadata document that tells it how to authenticate.
/// </para>
/// </remarks>
public sealed class OriginValidationTests : IDisposable
{
    private const string StudioOrigin = "https://studio.example.test";

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "mcpiler-origin-" + Guid.NewGuid().ToString("N"));

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public OriginValidationTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task An_unexpected_origin_is_refused_on_a_served_address()
    {
        await using LoopbackHost upstream = await UpstreamAsync();
        string manifest = ServedManifests.Write(
            _root,
            "origin-refused-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address));

        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor(manifest),
            Token,
            allowedOrigins: [StudioOrigin]);

        using HttpClient client = new();
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(engine.At("/api/full").ToString()));

        request.Headers.TryAddWithoutValidation("Origin", "https://attacker.example.test");

        using HttpResponseMessage served = await client.SendAsync(request, Token);

        Assert.Equal(HttpStatusCode.Forbidden, served.StatusCode);
    }

    [Fact]
    public async Task A_configured_origin_reaches_the_endpoint()
    {
        await using LoopbackHost upstream = await UpstreamAsync();
        string manifest = ServedManifests.Write(
            _root,
            "origin-allowed-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address));

        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor(manifest),
            Token,
            allowedOrigins: [StudioOrigin]);

        using HttpClient client = new();
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(engine.At("/api/full").ToString()));

        // The same spelling with a trailing slash is admitted too: an operator may write one and
        // a browser never sends one, so the two must mean the same origin.
        request.Headers.TryAddWithoutValidation("Origin", StudioOrigin + "/");
        request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");

        using HttpResponseMessage served = await client.SendAsync(request, Token);

        // The protocol handler decides what a bare POST means; what matters is that admission did
        // not refuse it on the origin before the handler could answer.
        Assert.NotEqual(HttpStatusCode.Forbidden, served.StatusCode);
    }

    [Fact]
    public async Task A_client_without_an_origin_is_served_normally()
    {
        await using LoopbackHost upstream = await UpstreamAsync();
        string manifest = ServedManifests.Write(
            _root,
            "origin-absent-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address));

        // No allowed origins at all: a browser page has no origin it may use, and every
        // non-browser client is still served.
        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor(manifest),
            Token);

        using HttpClient client = new();
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(engine.At("/api/full").ToString()));

        request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");

        using HttpResponseMessage served = await client.SendAsync(request, Token);

        Assert.NotEqual(HttpStatusCode.Forbidden, served.StatusCode);
    }

    [Fact]
    public async Task Metadata_discovery_ignores_the_origin_header()
    {
        await using FakeAuthorizationServer authorization =
            await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await UpstreamAsync();
        string manifest = ServedManifests.Write(
            _root,
            "origin-metadata-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, authenticationRequired: true));

        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor(manifest),
            Token,
            authorization: AuthorizationFor(authorization.Address));

        using HttpClient client = new();
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            new Uri(engine.At("/.well-known/oauth-protected-resource/api/full").ToString()));

        // A browser page that is about to authenticate reads this document first, so an origin
        // header here must not be treated as an attempt to call the address itself.
        request.Headers.TryAddWithoutValidation("Origin", "https://attacker.example.test");

        using HttpResponseMessage served = await client.SendAsync(request, Token);

        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
    }

    private static async Task<LoopbackHost> UpstreamAsync() =>
        await LoopbackHost.StartAsync(StatusCodes.Status204NoContent, "application/json", [], Token);

    private static HostAuthorizationOptions AuthorizationFor(Uri issuer) =>
        new(issuer.AbsoluteUri, HostTokenValidation.Introspection);

    private RuntimeOptions RuntimeOptionsFor(string manifest) => new(
        [new MountRequest("/api", manifest)],
        Directory.CreateDirectory(Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"))).FullName);

    /// <param name="authenticationRequired">
    /// The protection the mount declares. Defaults to open, because these tests probe admission
    /// and the origin rule rather than authorization; the metadata test states protection
    /// explicitly, because an unprotected mount publishes no metadata document at all.
    /// </param>
    private static string Manifest(Uri upstream, bool authenticationRequired = false) => $$"""
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": { "inline": {
              "name": "Origin Probe",
              "authenticationRequired": {{(authenticationRequired ? "true" : "false")}},
              "surfaces": [
                { "slug": "full", "isDefault": true,
                  "operations": [ { "operation": "ping", "exposure": "direct" } ] }
              ]
            } },
            "policy": { "inline": { "baseUrl": "{{upstream.AbsoluteUri}}" } },
            "operations": { "inline": { "operations": [
              { "key": "GET /ping", "method": "GET", "path": "/ping" }
            ] } },
            "agentSurface": { "inline": { "operations": [
              { "slug": "ping", "name": "Ping", "binding": { "type": "http", "operation": "GET /ping" } }
            ] } }
          }
        }
        """;
}
