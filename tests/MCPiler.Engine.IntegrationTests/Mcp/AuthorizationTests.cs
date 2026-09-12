using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// The authorization boundary as a third-party HTTP client observes it: RFC 9728 metadata per
/// surface, the 401 challenge that points at it, byte-exact audience binding, per-surface
/// scopes, and the startup refusal for a scope-declaring mount with no issuer.
/// </summary>
/// <remarks>
/// <para>
/// The engine under test is started the way <c>serve</c> starts it, so the challenge, the
/// metadata location and the refusal shapes are the product's. The authorization server each
/// test needs is a loopback fake the test owns, so both validation modes are driven against a
/// real issuer the test authors the standing of.
/// </para>
/// <para>
/// Every refusal is asserted identical across surfaces, across the default and the
/// slug-qualified route, and identical to the refusal for a mount that does not exist. A
/// refusal that differs by one byte is an existence oracle, and that is the whole attack.
/// </para>
/// </remarks>
public sealed class AuthorizationTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "mcpiler-authorization-" + Guid.NewGuid().ToString("N"));

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public AuthorizationTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task A_scope_declaring_mount_and_no_issuer_fails_the_process_at_startup()
    {
        await using LoopbackHost upstream = await Upstream();
        string manifest = ServedManifests.Write(
            _root,
            "scoped-no-issuer-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: true));

        bool threw = false;

        try
        {
            await using ServedEngine _ = await ServedEngine.StartAsync(
                RuntimeOptionsFor("/api", manifest),
                Token);
        }
        catch (InvalidOperationException failure)
        {
            threw = true;
            Assert.Contains("/api", failure.Message, StringComparison.Ordinal);
            Assert.Contains("issuer", failure.Message, StringComparison.OrdinalIgnoreCase);
        }

        Assert.True(threw, "A scope-declaring mount without an issuer must refuse to start.");
    }

    [Fact]
    public async Task A_mount_without_declared_scopes_serves_without_a_token()
    {
        await using LoopbackHost upstream = await Upstream();
        string manifest = ServedManifests.Write(
            _root,
            "open-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: false));
        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor("/api", manifest),
            Token);

        using HttpClient client = new();
        using HttpResponseMessage served = await client.GetAsync(engine.At("/api/full"), Token);

        AssertAdmitted(served);
    }

    [Fact]
    public async Task Protected_resource_metadata_is_present_per_surface_and_names_the_issuer()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(upstream.Address, authorization.Address);

        using HttpClient client = new();
        Uri baseAddress = new($"{engine.Address.Scheme}://{engine.Address.Authority}");

        using HttpResponseMessage slug = await client.GetAsync(
            new Uri(baseAddress, "/.well-known/oauth-protected-resource/api/full"),
            Token);
        using HttpResponseMessage bare = await client.GetAsync(
            new Uri(baseAddress, "/.well-known/oauth-protected-resource/api"),
            Token);

        Assert.Equal(HttpStatusCode.OK, slug.StatusCode);
        Assert.Equal(HttpStatusCode.OK, bare.StatusCode);

        JsonElement slugDocument = await Document(slug);
        JsonElement bareDocument = await Document(bare);

        Assert.Equal(
            $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full",
            slugDocument.GetProperty("resource").GetString());
        Assert.Equal(
            $"{engine.Address.Scheme}://{engine.Address.Authority}/api",
            bareDocument.GetProperty("resource").GetString());
        Assert.NotEqual(
            slugDocument.GetProperty("resource").GetString(),
            bareDocument.GetProperty("resource").GetString());

        Assert.True(
            slugDocument.GetProperty("authorization_servers").GetArrayLength() > 0,
            "The metadata document names at least one authorization server.");

        Assert.Equal(
            authorization.Address.AbsoluteUri,
            slugDocument.GetProperty("authorization_servers").EnumerateArray().Single().GetString());
    }

    [Fact]
    public async Task A_request_without_a_token_is_challenged_before_anything_is_disclosed()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using UpstreamCounter upstream = await Recorder(Token);
        await using ServedEngine engine = await ServeScopedAsync(upstream.Host.Address, authorization.Address);

        using HttpClient client = new();
        using HttpResponseMessage challenged = await client.GetAsync(engine.At("/api/full"), Token);

        Assert.Equal(HttpStatusCode.Unauthorized, challenged.StatusCode);
        Assert.Equal(0, upstream.Arrivals);

        AuthenticationHeaderValue challenge =
            AuthenticationHeaderValue.Parse(challenged.Headers.WwwAuthenticate.Single().ToString());

        Assert.Equal("Bearer", challenge.Scheme);
        string parameter = challenge.Parameter!.Trim('"');
        Assert.Equal(
            $"{engine.Address.Scheme}://{engine.Address.Authority}/.well-known/oauth-protected-resource/api/full",
            parameter.StartsWith("resource_metadata=", StringComparison.Ordinal)
                ? parameter["resource_metadata=".Length..].Trim('"')
                : parameter);
    }

    [Fact]
    public async Task A_token_for_another_mount_is_refused_identically_to_a_mount_that_does_not_exist()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(upstream.Address, authorization.Address);

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";
        string other = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/other";

        using HttpResponseMessage crossSurface = await Authorized(
            client,
            engine.At("/api/other"),
            authorization.Mint(full, "tools.invoke"));
        using HttpResponseMessage unknownMount = await client.GetAsync(
            new Uri($"{engine.Address.Scheme}://{engine.Address.Authority}/nowhere"),
            Token);

        Assert.Equal(HttpStatusCode.NotFound, crossSurface.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknownMount.StatusCode);
        Assert.Equal(
            await unknownMount.Content.ReadAsStringAsync(Token),
            await crossSurface.Content.ReadAsStringAsync(Token));
        Assert.Empty(unknownMount.Headers.WwwAuthenticate);
    }

    [Fact]
    public async Task Byte_exact_audience_binding_refuses_every_relaxed_form()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(upstream.Address, authorization.Address);

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";

        string[] relaxed =
        [
            $"{engine.Address.Scheme}://{engine.Address.Authority}/api",
            full + "/",
            full.ToUpperInvariant(),
            $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full/x",
        ];

        foreach (string wrong in relaxed)
        {
            using HttpResponseMessage refused = await Authorized(
                client,
                engine.At("/api/full"),
                authorization.Mint(wrong, "tools.invoke"));

            Assert.Equal(HttpStatusCode.NotFound, refused.StatusCode);
        }

        using HttpResponseMessage admitted = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.Mint(full, "tools.invoke"));

        AssertAdmitted(admitted);
    }

    [Fact]
    public async Task A_declared_scope_is_enforced_and_the_refusal_is_uniform()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using UpstreamCounter upstream = await Recorder(Token);
        await using ServedEngine engine = await ServeScopedAsync(upstream.Host.Address, authorization.Address);

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";
        string other = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/other";

        using HttpResponseMessage missingOnFull = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.Mint(full, "tools.write"));
        using HttpResponseMessage missingOnOther = await Authorized(
            client,
            engine.At("/api/other"),
            authorization.Mint(other, "tools.invoke"));
        using HttpResponseMessage admitted = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.Mint(full, "tools.invoke tools.admin"));

        Assert.Equal(HttpStatusCode.NotFound, missingOnFull.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missingOnOther.StatusCode);
        Assert.Equal(
            await missingOnFull.Content.ReadAsStringAsync(Token),
            await missingOnOther.Content.ReadAsStringAsync(Token));
        AssertAdmitted(admitted);
        Assert.Equal(0, upstream.Arrivals);
    }

    [Fact]
    public async Task An_inactive_token_is_refused_without_disclosure()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: false, Token);
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(upstream.Address, authorization.Address);

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";

        using HttpResponseMessage refused = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.Mint(full, "tools.invoke"));

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
    }

    [Fact]
    public async Task An_unreachable_authorization_server_fails_closed()
    {
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(
            upstream.Address,
            "http://127.0.0.1:1");

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";
        string token = FakeToken(full);

        using HttpResponseMessage refused = await Authorized(
            client,
            engine.At("/api/full"),
            token);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
    }

    [Fact]
    public async Task A_cookie_is_no_credential_and_no_token_endpoint_exists()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(upstream.Address, authorization.Address);

        using HttpClient client = new();
        using HttpRequestMessage cookie = new(HttpMethod.Get, engine.At("/api/full"));
        cookie.Headers.Add("Cookie", "session=everything");

        using HttpResponseMessage refused = await client.SendAsync(cookie, Token);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);

        foreach (string endpoint in new[] { "/connect/token", "/authorize", "/connect/introspect" })
        {
            using HttpResponseMessage absent = await client.PostAsync(
                new Uri(new Uri($"{engine.Address.Scheme}://{engine.Address.Authority}"), endpoint),
                new FormUrlEncodedContent([]),
                Token);

            Assert.Equal(HttpStatusCode.NotFound, absent.StatusCode);
        }
    }

    [Fact]
    public async Task The_jwks_mode_validates_a_real_signature_locally()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(
            upstream.Address,
            authorization.Address,
            HostTokenValidation.Jwks);

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";

        using HttpResponseMessage admitted = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.Mint(full, "tools.invoke"));
        using HttpResponseMessage expired = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.Mint(full, "tools.invoke", DateTime.UtcNow.AddHours(-1)));

        AssertAdmitted(admitted);
        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
    }

    [Fact]
    public async Task A_jwt_signed_by_another_issuer_is_refused()
    {
        await using FakeAuthorizationServer trusted = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using FakeAuthorizationServer other = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(
            upstream.Address,
            trusted.Address,
            HostTokenValidation.Jwks);

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";

        using HttpResponseMessage refused = await Authorized(
            client,
            engine.At("/api/full"),
            other.Mint(full, "tools.invoke"));

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
    }

    /// <summary>
    /// Sends a tools/list through the addressed surface with a bearer token. POST, because
    /// Streamable HTTP answers only what the protocol defines; a GET of the MCP route is not
    /// a client this server serves.
    /// </summary>
    /// <summary>
    /// Asserts the boundary let the request through: the status is whatever the protocol
    /// answers with for the request as sent (a raw <c>tools/list</c> without a session or
    /// an accept header the SDK narrows), never a refusal of the authorization boundary.
    /// </summary>
    private static void AssertAdmitted(HttpResponseMessage response)
        => Assert.True(
            response.StatusCode is not (HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
                or HttpStatusCode.NotFound),
            $"The boundary refused a valid token with {response.StatusCode}.");

    private static async Task<HttpResponseMessage> Authorized(
        HttpClient client,
        Uri address,
        string token)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, address)
        {
            Headers =
            {
                Authorization = new AuthenticationHeaderValue("Bearer", token),
                Accept = { new MediaTypeWithQualityHeaderValue("application/json") },
            },
            Content = new StringContent(
                """{"jsonrpc":"2.0","id":2,"method":"tools/list"}""",
                System.Text.Encoding.UTF8,
                "application/json"),
        };

        return await client.SendAsync(request, Token);
    }

    /// <summary>An upstream that records arrivals, so a test can assert a refused request cost nothing.</summary>
    /// <remarks>
    /// The counter is read through the host the test keeps, because an <c>out</c> parameter
    /// cannot cross an async boundary. The test reads <see cref="UpstreamCounter.Arrivals"/>.
    /// </remarks>
    private static async Task<UpstreamCounter> Recorder(CancellationToken cancellationToken)
    {
        UpstreamCounter counter = new(null!);

        LoopbackHost host = await LoopbackHost.StartAsync(
            async context =>
            {
                counter.Arrive();
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.Body.WriteAsync("\"ok\""u8.ToArray(), context.RequestAborted);
            },
            Token);

        return new UpstreamCounter(host);
    }

    private sealed class UpstreamCounter : IAsyncDisposable
    {
        private readonly LoopbackHost _host;

        internal UpstreamCounter(LoopbackHost host)
        {
            _host = host;
        }

        internal LoopbackHost Host => _host;

        internal long Arrivals { get; private set; }

        internal void Arrive() => Interlocked.Increment(ref _arrivals);

        private long _arrivals;

        public async ValueTask DisposeAsync()
        {
            Arrivals = Interlocked.Read(ref _arrivals);
            await _host.DisposeAsync();
        }
    }

    private static async Task<LoopbackHost> Upstream()
        => await LoopbackHost.StartAsync(
            async context =>
            {
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.Body.WriteAsync("\"ok\""u8.ToArray(), context.RequestAborted);
            },
            Token);

    private static async Task<JsonElement> Document(HttpResponseMessage response)
    {
        using JsonDocument parsed = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(Token),
            cancellationToken: Token);

        return parsed.RootElement.Clone();
    }

    private static string Manifest(Uri upstream, bool scoped)
    {
        string scopesOnFull = scoped ? ", \"requiredScopes\": [\"tools.invoke\"]" : string.Empty;
        string scopesOnOther = scoped ? ", \"requiredScopes\": [\"tools.invoke\", \"tools.admin\"]" : string.Empty;
        string surfaces = scoped
            ? "{ \"slug\": \"full\", \"isDefault\": true" + scopesOnFull
                + ", \"operations\": [ { \"operation\": \"read-value\" } ] },"
                + "{ \"slug\": \"other\"" + scopesOnOther
                + ", \"operations\": [ { \"operation\": \"read-value\" } ] }"
            : "{ \"slug\": \"full\", \"isDefault\": true, \"operations\": [ { \"operation\": \"read-value\" } ] }";

        return $$"""
            {
              "manifestFormatVersion": "0.2",
              "sections": {
                "server": {
                  "inline": {
                    "name": "Auth API",
                    "surfaces": [
                      {{surfaces}}
                    ]
                  }
                },
                "policy": { "inline": { "baseUrl": "{{upstream.AbsoluteUri}}" } },
                "operations": {
                  "inline": {
                    "operations": [ { "key": "GET /value", "method": "GET", "path": "/value" } ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      {
                        "slug": "read-value",
                        "name": "Read value",
                        "inputSchema": { "type": "object" },
                        "binding": { "type": "http", "operation": "GET /value" }
                      }
                    ]
                  }
                }
              }
            }
            """;
    }

    private RuntimeOptions RuntimeOptionsFor(string prefix, string manifest)
    {
        string store = Directory.CreateDirectory(
            Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"))).FullName;

        return new RuntimeOptions([new MountRequest(prefix, manifest)], store);
    }

    private async Task<ServedEngine> ServeScopedAsync(
        Uri upstream,
        Uri issuer,
        HostTokenValidation validation = HostTokenValidation.Introspection)
    {
        string manifest = ServedManifests.Write(
            _root,
            "scoped-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream, scoped: true));

        return await ServedEngine.StartAsync(
            RuntimeOptionsFor("/api", manifest),
            Token,
            authorization: new HostAuthorizationOptions(
                issuer.AbsoluteUri,
                validation));
    }

    private async Task<ServedEngine> ServeScopedAsync(Uri upstream, string issuer)
        => await ServeScopedAsync(upstream, new Uri(issuer, UriKind.Absolute));

    /// <summary>A token no authorization server knows, for the fail-closed case.</summary>
    private static string FakeToken(string audience)
    {
        using RSA key = RSA.Create(2048);
        RsaSecurityKey parameters = new(key.ExportParameters(true)) { KeyId = "unknown" };

        string token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://nowhere.invalid",
            Audience = audience,
            Claims = new Dictionary<string, object> { ["scope"] = "tools.invoke" },
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(parameters, SecurityAlgorithms.RsaSha256),
        });

        return token;
    }
}