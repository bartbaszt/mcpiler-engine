using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

using Microsoft.Extensions.Logging;
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

    /// <summary>
    /// A scope-free mount that declares nothing is protected, and refuses to start with no issuer.
    /// </summary>
    /// <remarks>
    /// This test used to assert the opposite, and the assertion was the defect. Protection was
    /// inferred from a non-empty scope list, so a Platform export — which deliberately declares no
    /// scope — was served to anyone, and every protected-resource duty was vacuous for it. The
    /// default is now protected, and the only way to serve openly is to say so.
    /// </remarks>
    [Fact]
    public async Task A_scope_free_mount_that_declares_nothing_is_protected_and_refuses_to_start()
    {
        await using LoopbackHost upstream = await Upstream();
        string manifest = ServedManifests.Write(
            _root,
            "default-protected-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: false, authenticationRequired: null));

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

            // The refusal names the requirement in the mount's own vocabulary. A refusal that
            // talked about a missing scope would send an operator to add one, which changes
            // nothing about whether a token is required.
            Assert.Contains("requires authorization", failure.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("requires a scope", failure.Message, StringComparison.Ordinal);
        }

        Assert.True(threw, "A scope-free mount that declares nothing must be protected by default.");
    }

    /// <summary>A mount that states it is open is served without a token.</summary>
    [Fact]
    public async Task A_mount_that_declares_it_is_open_serves_without_a_token()
    {
        await using LoopbackHost upstream = await Upstream();
        string manifest = ServedManifests.Write(
            _root,
            "open-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: false, authenticationRequired: false));
        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor("/api", manifest),
            Token);

        using HttpClient client = new();
        using HttpResponseMessage served = await client.GetAsync(engine.At("/api/full"), Token);

        AssertAdmitted(served);
    }

    /// <summary>
    /// An open mount publishes no protected-resource metadata, and a protected one still does.
    /// </summary>
    /// <remarks>
    /// The metadata document names an authorization server. Serving one for a resource that
    /// requires no token would send a client through an authorization flow it does not need, and
    /// would claim the resource is protected when the Manifest says otherwise.
    /// </remarks>
    [Fact]
    public async Task An_open_mount_publishes_no_protected_resource_metadata()
    {
        await using LoopbackHost upstream = await Upstream();
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);

        string openManifest = ServedManifests.Write(
            _root,
            "open-metadata-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: false, authenticationRequired: false));
        string protectedManifest = ServedManifests.Write(
            _root,
            "protected-metadata-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: true));

        await using ServedEngine open = await ServedEngine.StartAsync(
            RuntimeOptionsFor("/api", openManifest),
            Token,
            authorization: AuthorizationFor(authorization.Address));
        await using ServedEngine guarded = await ServedEngine.StartAsync(
            RuntimeOptionsFor("/api", protectedManifest),
            Token,
            authorization: AuthorizationFor(authorization.Address));

        using HttpClient client = new();

        using HttpResponseMessage openDocument = await client.GetAsync(
            new Uri($"{open.Address.Scheme}://{open.Address.Authority}/.well-known/oauth-protected-resource/api/full"),
            Token);
        using HttpResponseMessage protectedDocument = await client.GetAsync(
            new Uri($"{guarded.Address.Scheme}://{guarded.Address.Authority}/.well-known/oauth-protected-resource/api/full"),
            Token);

        Assert.NotEqual(HttpStatusCode.OK, openDocument.StatusCode);

        // An open mount emits no challenge either: the 401 is the discovery step for a token
        // that would be required.
        Assert.Null(openDocument.Headers.WwwAuthenticate.FirstOrDefault());

        Assert.Equal(HttpStatusCode.OK, protectedDocument.StatusCode);
        Assert.Contains(
            authorization.Address.AbsoluteUri.TrimEnd('/'),
            await protectedDocument.Content.ReadAsStringAsync(Token),
            StringComparison.OrdinalIgnoreCase);
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
    public async Task An_external_resource_binding_owns_metadata_challenge_and_audience_identity()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        string manifest = ServedManifests.Write(
            _root,
            "external-resource-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: true));
        const string external = "https://tunnel.example.test/v1/mcp/tunnel-one";

        await using ServedEngine engine = await ServedEngine.StartAsync(
            RuntimeOptionsFor("/api", manifest),
            Token,
            authorization: AuthorizationFor(authorization.Address),
            externalResources: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["/api/full"] = external,
            });

        using HttpClient client = new();
        using HttpResponseMessage metadata = await client.GetAsync(
            engine.At("/.well-known/oauth-protected-resource/api/full"),
            Token);
        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
        JsonElement document = await Document(metadata);
        Assert.Equal(external, document.GetProperty("resource").GetString());

        using HttpResponseMessage challenged = await client.GetAsync(engine.At("/api/full"), Token);
        Assert.Equal(HttpStatusCode.Unauthorized, challenged.StatusCode);
        AuthenticationHeaderValue challenge =
            AuthenticationHeaderValue.Parse(challenged.Headers.WwwAuthenticate.Single().ToString());
        Assert.Contains(
            "https://tunnel.example.test/.well-known/oauth-protected-resource/v1/mcp/tunnel-one",
            challenge.Parameter,
            StringComparison.Ordinal);

        using HttpResponseMessage admitted = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.Mint(external, "tools.invoke"));
        AssertAdmitted(admitted);

        string privateResource = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";
        using HttpResponseMessage privateAudience = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.Mint(privateResource, "tools.invoke"));
        using HttpResponseMessage trailingSlashAudience = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.Mint(external + "/", "tools.invoke"));

        Assert.Equal(HttpStatusCode.NotFound, privateAudience.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, trailingSlashAudience.StatusCode);
    }

    [Fact]
    public async Task A_tunnel_audience_for_one_bound_surface_is_refused_by_another()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        string firstManifest = ServedManifests.Write(
            _root,
            "external-first-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: true));
        string secondManifest = ServedManifests.Write(
            _root,
            "external-second-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: true));
        string store = Directory.CreateDirectory(
            Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"))).FullName;
        const string first = "https://tunnel.example.test/v1/mcp/first";
        const string second = "https://tunnel.example.test/v1/mcp/second";

        await using ServedEngine engine = await ServedEngine.StartAsync(
            new RuntimeOptions(
                [new MountRequest("/first", firstManifest), new MountRequest("/second", secondManifest)],
                store),
            Token,
            authorization: AuthorizationFor(authorization.Address),
            externalResources: new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["/first/full"] = first,
                ["/second/full"] = second,
            });

        using HttpClient client = new();
        using HttpResponseMessage refused = await Authorized(
            client,
            engine.At("/second/full"),
            authorization.Mint(first, "tools.invoke"));

        Assert.Equal(HttpStatusCode.NotFound, refused.StatusCode);
    }

    [Fact]
    public async Task A_token_for_one_mount_is_refused_by_the_other_in_both_directions()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        string firstManifest = ServedManifests.Write(
            _root,
            "scoped-first-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: true));
        string secondManifest = ServedManifests.Write(
            _root,
            "scoped-second-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: true));
        string store = Directory.CreateDirectory(
            Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"))).FullName;

        await using ServedEngine engine = await ServedEngine.StartAsync(
            new RuntimeOptions(
                [
                    new MountRequest("/first", firstManifest),
                    new MountRequest("/second", secondManifest),
                ],
                store),
            Token,
            authorization: new HostAuthorizationOptions(
                authorization.Address.AbsoluteUri,
                HostTokenValidation.Introspection));

        using HttpClient client = new();
        string first = $"{engine.Address.Scheme}://{engine.Address.Authority}/first/full";
        string second = $"{engine.Address.Scheme}://{engine.Address.Authority}/second/full";

        using HttpResponseMessage firstAtSecond = await Authorized(
            client,
            engine.At("/second/full"),
            authorization.Mint(first, "tools.invoke"));
        using HttpResponseMessage secondAtFirst = await Authorized(
            client,
            engine.At("/first/full"),
            authorization.Mint(second, "tools.invoke"));
        using HttpResponseMessage unknownMount = await client.GetAsync(
            new Uri($"{engine.Address.Scheme}://{engine.Address.Authority}/nowhere"),
            Token);

        Assert.Equal(HttpStatusCode.NotFound, firstAtSecond.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, secondAtFirst.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknownMount.StatusCode);
        Assert.Equal(
            await unknownMount.Content.ReadAsStringAsync(Token),
            await firstAtSecond.Content.ReadAsStringAsync(Token));
        Assert.Equal(
            await unknownMount.Content.ReadAsStringAsync(Token),
            await secondAtFirst.Content.ReadAsStringAsync(Token));
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

        string validToken = authorization.Mint(
            $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full",
            "tools.invoke");
        using HttpRequestMessage bearerToAdministrativeEndpoint = new(
            HttpMethod.Post,
            new Uri(new Uri($"{engine.Address.Scheme}://{engine.Address.Authority}"), "/connect/token"))
        {
            Content = new FormUrlEncodedContent([]),
        };
        bearerToAdministrativeEndpoint.Headers.Authorization = new AuthenticationHeaderValue("Bearer", validToken);
        using HttpResponseMessage administrativeResponse = await client.SendAsync(
            bearerToAdministrativeEndpoint,
            Token);
        Assert.Equal(HttpStatusCode.NotFound, administrativeResponse.StatusCode);

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
    /// The jwks mode contains an encrypted token as a refusal rather than as a failure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An issuer that encrypts its access tokens publishes no signal that it does: RFC 8414 has
    /// no access-token-encryption member, and a symmetric encryption key is never published, so
    /// discovery and JWKS look identical to an issuer that only signs. A resource server
    /// therefore cannot detect the situation at startup and must contain it at validation time.
    /// </para>
    /// <para>
    /// What is asserted here is containment, not detection: whatever the token handler throws
    /// for a JWE it cannot decrypt, the answer must be a 401 that discloses nothing — never an
    /// unhandled exception, which would answer a client with a 500 and read as a defect to an
    /// operator.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_jwks_mode_refuses_an_encrypted_token_instead_of_failing()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(
            upstream.Address,
            authorization.Address,
            HostTokenValidation.Jwks);

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";

        using HttpResponseMessage response = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.MintEncrypted(full, "tools.invoke"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// The introspection mode treats an encrypted token as any other token it does not know.
    /// </summary>
    /// <remarks>
    /// Introspection is the mode that can validate a token whose content cannot be read locally,
    /// but only when the issuer recognizes it. A JWE this fake did not issue is therefore an
    /// ordinary inactive token, and the fail-closed answer is a 401 rather than a failure.
    /// </remarks>
    [Fact]
    public async Task The_introspection_mode_refuses_an_encrypted_token_it_did_not_issue()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: false, Token);
        await using LoopbackHost upstream = await Upstream();
        await using ServedEngine engine = await ServeScopedAsync(upstream.Address, authorization.Address);

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";

        using HttpResponseMessage response = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.MintEncrypted(full, "tools.invoke"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
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

    /// <summary>
    /// A token with no optional identity claim is admitted, because none is a prerequisite.
    /// </summary>
    /// <remarks>
    /// The boundary's duties are stated over the audience and the scopes. Requiring <c>sub</c> or
    /// <c>client_id</c> would reject tokens from a conforming issuer, and a deployment that
    /// introduced such a requirement while partitioning response caches would turn a standards
    /// fact into an intermittent refusal. The caller partition is derived without them.
    /// </remarks>
    [Fact]
    public async Task A_token_without_optional_identity_claims_is_admitted()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        await using UpstreamCounter upstream = await Recorder(Token);
        await using ServedEngine engine = await ServeScopedAsync(upstream.Host.Address, authorization.Address);

        using HttpClient client = new();
        string full = $"{engine.Address.Scheme}://{engine.Address.Authority}/api/full";

        using HttpResponseMessage admitted = await Authorized(
            client,
            engine.At("/api/full"),
            authorization.MintWithoutIdentityClaims(full, "tools.invoke"));

        AssertAdmitted(admitted);

        // The boundary is reached, and nothing about the missing claims made the request cost
        // an upstream call the boundary had already authorized: this is a tools/list.
        Assert.Equal(0, upstream.Arrivals);
    }

    [Fact]
    public async Task Protected_cache_entries_are_isolated_between_bearer_tokens_at_the_mcp_boundary()
    {
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(active: true, Token);
        int upstreamArrivals = 0;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref upstreamArrivals);
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.Body.WriteAsync("\"ok\""u8.ToArray(), context.RequestAborted);
            },
            Token);
        await using ServedEngine engine = await ServeScopedAsync(
            upstream.Address,
            authorization.Address,
            responseCache: new ResponseCachePolicySettings(300));

        Uri endpoint = engine.At("/api/full");
        string audience = $"{endpoint.Scheme}://{endpoint.Authority}{endpoint.AbsolutePath}";
        string firstToken = authorization.Mint(audience, "tools.invoke", DateTime.UtcNow.AddMinutes(30));
        string secondToken = authorization.Mint(audience, "tools.invoke", DateTime.UtcNow.AddMinutes(31));
        Assert.NotEqual(firstToken, secondToken);

        using McpHttpSession firstCaller = await McpHttpSession.OpenAsync(endpoint, Token, bearerToken: firstToken);
        using McpHttpSession secondCaller = await McpHttpSession.OpenAsync(endpoint, Token, bearerToken: secondToken);

        McpExchange first = await firstCaller.CallAsync("read-value", "{}", 2, Token);
        McpExchange second = await secondCaller.CallAsync("read-value", "{}", 2, Token);
        McpExchange firstAgain = await firstCaller.CallAsync("read-value", "{}", 3, Token);

        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal(HttpStatusCode.OK, firstAgain.Status);
        Assert.Equal(2, upstreamArrivals);
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

    /// <summary>
    /// A manifest whose protection and scopes the caller states independently.
    /// </summary>
    /// <param name="upstream">The loopback upstream the policy points at.</param>
    /// <param name="scoped">
    /// Whether the surfaces declare scopes. A scoped mount is a protected one, so this also
    /// states <c>authenticationRequired: true</c>: a scope under an unprotected mount is refused.
    /// </param>
    /// <param name="authenticationRequired">
    /// The protection the mount declares, or <c>null</c> to declare nothing and take the default.
    /// </param>
    private static string Manifest(
        Uri upstream,
        bool scoped,
        bool? authenticationRequired = null,
        ResponseCachePolicySettings? responseCache = null)
    {
        string scopesOnFull = scoped ? ", \"requiredScopes\": [\"tools.invoke\"]" : string.Empty;
        string scopesOnOther = scoped ? ", \"requiredScopes\": [\"tools.invoke\", \"tools.admin\"]" : string.Empty;
        string surfaces = scoped
            ? "{ \"slug\": \"full\", \"isDefault\": true" + scopesOnFull
                + ", \"operations\": [ { \"operation\": \"read-value\" } ] },"
                + "{ \"slug\": \"other\"" + scopesOnOther
                + ", \"operations\": [ { \"operation\": \"read-value\" } ] }"
            : "{ \"slug\": \"full\", \"isDefault\": true, \"operations\": [ { \"operation\": \"read-value\" } ] }";

        // Null means the document declares no protection at all, which is what the protected
        // default is asserted against. True and false are explicit statements.
        string protection = authenticationRequired switch
        {
            true => "\"authenticationRequired\": true,",
            false => "\"authenticationRequired\": false,",
            null => string.Empty,
        };
        string responseCacheMember = responseCache is { } cache
            ? $", \"responseCache\": {{\"ttlSeconds\": {cache.TtlSeconds}}}"
            : string.Empty;

        return $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": {
                  "inline": {
                    "name": "Auth API",
                    {{protection}}
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
                        "binding": { "type": "http", "operation": "GET /value" }{{responseCacheMember}}
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

    /// <summary>
    /// The resource server authenticates to an endpoint that demands a client credential.
    /// </summary>
    /// <remarks>
    /// The fake refuses an unauthenticated introspection, so an engine that presented no
    /// credential would treat every token as inactive and this test would see a 401 at the MCP
    /// address. Accepting the token therefore proves the credential reached the endpoint.
    /// </remarks>
    [Fact]
    public async Task A_configured_introspection_client_authenticates_to_a_protected_endpoint()
    {
        await using LoopbackHost upstream = await Upstream();
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token,
            introspectionClientId: "engine-resource-server",
            introspectionClientSecret: "s3cret");

        string secretFile = SecretFile("s3cret");

        await using ServedEngine engine = await ServeScopedAsync(
            upstream.Address,
            authorization.Address,
            introspectionClientId: "engine-resource-server",
            introspectionClientSecretFile: secretFile);

        string token = authorization.Mint(engine.At("/api/full").ToString(), "tools.invoke");

        using HttpClient client = new();

        HttpResponseMessage response = await Authorized(client, engine.At("/api/full"), token);

        AssertAdmitted(response);
    }

    /// <summary>
    /// A wrong secret is refused by the endpoint, and the refusal is a refusal of the token.
    /// </summary>
    /// <remarks>
    /// The engine must not fall open because its own credential was rejected: a resource server
    /// that treated a 401 from the issuer as "cannot reach the issuer, admit anyway" would turn a
    /// misconfigured client into an authentication bypass.
    /// </remarks>
    [Fact]
    public async Task A_wrong_introspection_client_secret_leaves_every_token_inactive()
    {
        await using LoopbackHost upstream = await Upstream();
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token,
            introspectionClientId: "engine-resource-server",
            introspectionClientSecret: "s3cret");

        string secretFile = SecretFile("not-the-secret");

        await using ServedEngine engine = await ServeScopedAsync(
            upstream.Address,
            authorization.Address,
            introspectionClientId: "engine-resource-server",
            introspectionClientSecretFile: secretFile);

        string token = authorization.Mint(engine.At("/api/full").ToString(), "tools.invoke");

        using HttpClient client = new();

        HttpResponseMessage response = await Authorized(client, engine.At("/api/full"), token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// An engine with no credential talking to an endpoint that demands one is refused, and the
    /// refusal discloses nothing about the tool set.
    /// </summary>
    [Fact]
    public async Task An_endpoint_that_demands_a_credential_refuses_an_unauthenticated_engine()
    {
        await using LoopbackHost upstream = await Upstream();
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token,
            introspectionClientId: "engine-resource-server",
            introspectionClientSecret: "s3cret");

        await using ServedEngine engine = await ServeScopedAsync(upstream.Address, authorization.Address);

        string token = authorization.Mint(engine.At("/api/full").ToString(), "tools.invoke");

        using HttpClient client = new();

        HttpResponseMessage response = await Authorized(client, engine.At("/api/full"), token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync(Token));
    }

    /// <summary>
    /// The client secret never appears in the host's own log records.
    /// </summary>
    /// <remarks>
    /// The canary is written to the file and then asserted absent from every record the host
    /// emits while serving a request. A secret that reaches a log is a secret that reaches
    /// whatever collects logs, which is a wider audience than the file's permissions describe.
    /// </remarks>
    [Fact]
    public async Task The_introspection_client_secret_never_reaches_a_log_record()
    {
        const string canary = "canary-7f3c1d9e-introspection-secret";

        await using LoopbackHost upstream = await Upstream();
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token,
            introspectionClientId: "engine-resource-server",
            introspectionClientSecret: canary);

        string secretFile = SecretFile(canary);

        RecordingLoggerProvider logs = new();

        await using ServedEngine engine = await ServeScopedAsync(
            upstream.Address,
            authorization.Address,
            introspectionClientId: "engine-resource-server",
            introspectionClientSecretFile: secretFile,
            loggerProvider: logs);

        string token = authorization.Mint(engine.At("/api/full").ToString(), "tools.invoke");

        using HttpClient client = new();
        await Authorized(client, engine.At("/api/full"), token);

        // The recorder has to be proven live, or the assertion below passes because nothing was
        // ever captured rather than because the secret was kept out.
        Assert.NotEmpty(logs.Text);
        Assert.DoesNotContain(canary, logs.Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unresolvable secret file refuses before the listener opens rather than per request.
    /// </summary>
    /// <remarks>
    /// A resource server that started and then failed every token would be indistinguishable at
    /// the client from a misconfigured client, and an operator would debug the wrong end. The
    /// refusal names the file, never its contents.
    /// </remarks>
    [Fact]
    public async Task An_unreadable_introspection_client_secret_refuses_at_startup()
    {
        await using LoopbackHost upstream = await Upstream();

        string missing = Path.Combine(_root, "absent-" + Guid.NewGuid().ToString("N"));

        string manifest = ServedManifests.Write(
            _root,
            "scoped-missing-secret-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream.Address, scoped: true));

        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await ServedEngine.StartAsync(
                RuntimeOptionsFor("/api", manifest),
                Token,
                authorization: new HostAuthorizationOptions(
                    "https://issuer.example.test",
                    HostTokenValidation.Introspection,
                    IntrospectionClientId: "engine-resource-server",
                    IntrospectionClientSecretFile: missing)));

        Assert.Contains(missing, failure.Message, StringComparison.Ordinal);
        Assert.Contains("does not exist", failure.Message, StringComparison.Ordinal);
    }

    private static HostAuthorizationOptions AuthorizationFor(Uri issuer)
        => new(issuer.AbsoluteUri, HostTokenValidation.Introspection);

    private async Task<ServedEngine> ServeScopedAsync(
        Uri upstream,
        Uri issuer,
        HostTokenValidation validation = HostTokenValidation.Introspection,
        string? introspectionClientId = null,
        string? introspectionClientSecretFile = null,
        ILoggerProvider? loggerProvider = null,
        ResponseCachePolicySettings? responseCache = null)
    {
        string manifest = ServedManifests.Write(
            _root,
            "scoped-" + Guid.NewGuid().ToString("N"),
            Manifest(upstream, scoped: true, responseCache: responseCache));

        return await ServedEngine.StartAsync(
            RuntimeOptionsFor("/api", manifest),
            Token,
            authorization: new HostAuthorizationOptions(
                issuer.AbsoluteUri,
                validation,
                IntrospectionClientId: introspectionClientId,
                IntrospectionClientSecretFile: introspectionClientSecretFile),
            loggerProvider: loggerProvider);
    }

    private async Task<ServedEngine> ServeScopedAsync(Uri upstream, string issuer)
        => await ServeScopedAsync(upstream, new Uri(issuer, UriKind.Absolute));

    /// <summary>
    /// Writes a secret file with a canary value and returns its path.
    /// </summary>
    /// <remarks>
    /// The value is deliberately recognizable in a log or a report, because the assertion that
    /// matters is that it appears in none of them.
    /// </remarks>
    private string SecretFile(string canary)
    {
        string path = Path.Combine(_root, "secret-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, canary + "\n");
        return path;
    }

    /// <summary>Collects every log record a host emits, so a test can assert what is not in them.</summary>
    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        private readonly StringBuilder _text = new();

        public string Text
        {
            get
            {
                lock (_text)
                {
                    return _text.ToString();
                }
            }
        }

        public ILogger CreateLogger(string categoryName) => new Recorder(this, categoryName);

        public void Dispose()
        {
        }

        private void Record(string line)
        {
            lock (_text)
            {
                _text.AppendLine(line);
            }
        }

        private sealed class Recorder(RecordingLoggerProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                ArgumentNullException.ThrowIfNull(formatter);

                owner.Record($"{logLevel} {category} {formatter(state, exception)} {exception}");
            }
        }
    }

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
