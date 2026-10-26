using System.Net;
using System.Security.Cryptography;
using System.Text;

using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;

using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Authorization;

public sealed class JwksTokenValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 28, 8, 0, 0, TimeSpan.Zero);
    private static readonly string[] SingletonAudience = ["resource"];
    private static readonly string[] ResourceThenOtherAudiences = ["resource", "other"];
    private static readonly string[] OtherThenResourceAudiences = ["other", "resource"];
    private static readonly string[] ToolsInvokeScopes = ["tools.invoke"];
    private static readonly string[] Rfc8414PathOnly = ["/.well-known/oauth-authorization-server"];
    private static readonly string[] BothDiscoveryPaths =
        ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"];
    private const string Issuer = "https://issuer.example.test";
    private const string JwksUri = "https://issuer.example.test/jwks";

    [Fact]
    public async Task String_and_singleton_array_audiences_name_one_resource_but_multi_audience_names_none()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");
        var handler = new StubHandler((_, _) => JwksResponse(key));
        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(client, Issuer, JwksUri, new FakeTimeProvider(Now));

        TokenVerification scalar = await validator.ValidateAsync(
            Mint(key, "resource"),
            TestContext.Current.CancellationToken);
        TokenVerification singleton = await validator.ValidateAsync(
            Mint(key, SingletonAudience),
            TestContext.Current.CancellationToken);
        TokenVerification first = await validator.ValidateAsync(
            Mint(key, ResourceThenOtherAudiences),
            TestContext.Current.CancellationToken);
        TokenVerification second = await validator.ValidateAsync(
            Mint(key, OtherThenResourceAudiences),
            TestContext.Current.CancellationToken);

        Assert.True(scalar.Active);
        Assert.Equal("resource", scalar.Audience);
        Assert.True(singleton.Active);
        Assert.Equal("resource", singleton.Audience);
        Assert.True(first.Active);
        Assert.Null(first.Audience);
        Assert.True(second.Active);
        Assert.Null(second.Audience);
    }

    [Fact]
    public async Task Key_set_is_reused_without_an_http_get_on_every_request()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");
        var handler = new StubHandler((_, _) => JwksResponse(key));
        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(client, Issuer, JwksUri, new FakeTimeProvider(Now));

        Assert.True((await validator.ValidateAsync(Mint(key, "one"), TestContext.Current.CancellationToken)).Active);
        Assert.True((await validator.ValidateAsync(Mint(key, "two"), TestContext.Current.CancellationToken)).Active);

        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Unknown_kid_triggers_one_bounded_refresh()
    {
        using RSA firstRsa = RSA.Create(2048);
        using RSA secondRsa = RSA.Create(2048);
        RsaSecurityKey first = SigningKey(firstRsa, "key-a");
        RsaSecurityKey second = SigningKey(secondRsa, "key-b");
        var handler = new StubHandler((call, _) => call == 1 ? JwksResponse(first) : JwksResponse(second));
        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(client, Issuer, JwksUri, new FakeTimeProvider(Now));

        Assert.True((await validator.ValidateAsync(Mint(first, "resource"), TestContext.Current.CancellationToken)).Active);
        Assert.True((await validator.ValidateAsync(Mint(second, "resource"), TestContext.Current.CancellationToken)).Active);

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task Sequential_unknown_kids_are_bounded_by_the_forced_refresh_cooldown()
    {
        using RSA trustedRsa = RSA.Create(2048);
        using RSA unknownRsa = RSA.Create(2048);
        RsaSecurityKey trusted = SigningKey(trustedRsa, "trusted");
        var handler = new StubHandler((_, _) => JwksResponse(trusted));
        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(client, Issuer, JwksUri, new FakeTimeProvider(Now));

        Assert.True((await validator.ValidateAsync(
            Mint(trusted, "resource"),
            TestContext.Current.CancellationToken)).Active);

        for (int i = 0; i < 100; i++)
        {
            RsaSecurityKey unknown = new(unknownRsa.ExportParameters(true))
            {
                KeyId = $"unknown-{i}",
            };

            Assert.False((await validator.ValidateAsync(
                Mint(unknown, "resource"),
                TestContext.Current.CancellationToken)).Active);
        }

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task Last_good_keys_survive_a_short_refresh_outage_but_not_indefinitely()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");
        var clock = new FakeTimeProvider(Now);
        var handler = new StubHandler((call, _) =>
            call == 1
                ? JwksResponse(key)
                : throw new HttpRequestException("jwks unavailable"));
        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(client, Issuer, JwksUri, clock);

        string token = Mint(key, "resource");
        Assert.True((await validator.ValidateAsync(token, TestContext.Current.CancellationToken)).Active);

        clock.Advance(TimeSpan.FromMinutes(6));

        for (int i = 0; i < 100; i++)
        {
            Assert.True((await validator.ValidateAsync(
                token,
                TestContext.Current.CancellationToken)).Active);
        }

        Assert.Equal(2, handler.Calls);

        clock.Advance(TimeSpan.FromMinutes(10));
        Assert.False((await validator.ValidateAsync(token, TestContext.Current.CancellationToken)).Active);
        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task The_production_composer_wires_observations_into_the_jwks_validator()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");

        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                string? path = context.Request.Path.Value;
                string address = $"http://{context.Request.Host.Value}";
                context.Response.ContentType = "application/json";

                if (path == "/.well-known/oauth-authorization-server")
                {
                    await context.Response.WriteAsync(
                        $"{{\"issuer\":\"{address}/\",\"jwks_uri\":\"{address}/jwks\"}}",
                        context.RequestAborted);
                    return;
                }

                await context.Response.WriteAsync(
                    (await JwksResponse(key).Content.ReadAsStringAsync(TestContext.Current.CancellationToken)),
                    context.RequestAborted);
            });

        string issuer = server.Address.AbsoluteUri;
        var observations = new IssuerAvailabilityObservations();
        ITokenValidator validator = MountAuthorizationSetup.Validator(
            new HostAuthorizationOptions(issuer, HostTokenValidation.Jwks),
            observations);

        TokenVerification verification = await validator.ValidateAsync(
            Mint(key, "resource", issuer: issuer),
            TestContext.Current.CancellationToken);

        Assert.True(verification.Active);
        IssuerAvailabilityObservation observation = Assert.Single(observations.Recent(DateTimeOffset.UtcNow));
        Assert.Equal(IssuerAvailabilityMode.Jwks, observation.Mode);
        Assert.Equal(IssuerAvailabilityCategory.KeySetRefreshed, observation.Category);
    }

    [Fact]
    public async Task A_key_refresh_records_one_timestamped_observation_per_fetch()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");
        var handler = new StubHandler((_, _) => JwksResponse(key));
        using HttpClient client = new(handler);
        var clock = new FakeTimeProvider(Now);
        var observations = new IssuerAvailabilityObservations();
        var validator = new JwksTokenValidator(
            client,
            Issuer,
            JwksUri,
            clock,
            observations: observations);

        Assert.True((await validator.ValidateAsync(Mint(key, "resource"), TestContext.Current.CancellationToken)).Active);
        Assert.True((await validator.ValidateAsync(Mint(key, "resource"), TestContext.Current.CancellationToken)).Active);

        // One fetch, one observation: serving a cached key set is not a trust interaction and must
        // not manufacture a second "issuer healthy" claim.
        Assert.Equal(1, handler.Calls);
        IssuerAvailabilityObservation observation = Assert.Single(observations.Recent(clock.GetUtcNow()));
        Assert.Equal(Now, observation.ObservedAtUtc);
        Assert.Equal(IssuerAvailabilityMode.Jwks, observation.Mode);
        Assert.Equal(IssuerAvailabilityCategory.KeySetRefreshed, observation.Category);
    }

    [Fact]
    public async Task A_key_endpoint_outage_is_recorded_while_cached_keys_keep_serving_and_recovery_is_recorded()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");
        bool failing = false;
        var clock = new FakeTimeProvider(Now);
        var handler = new StubHandler((_, _) => failing
            ? throw new HttpRequestException("jwks unavailable")
            : JwksResponse(key));
        using HttpClient client = new(handler);
        var observations = new IssuerAvailabilityObservations();
        var validator = new JwksTokenValidator(
            client,
            Issuer,
            JwksUri,
            clock,
            observations: observations);

        string token = Mint(key, "resource");
        Assert.True((await validator.ValidateAsync(token, TestContext.Current.CancellationToken)).Active);

        // Inside the accepted stale-key window an outage is recorded but locally valid tokens are
        // still evaluated: the observation reports the outage without forcing a false inactive.
        clock.Advance(TimeSpan.FromMinutes(6));
        failing = true;
        Assert.True((await validator.ValidateAsync(token, TestContext.Current.CancellationToken)).Active);
        Assert.Equal(2, handler.Calls);
        Assert.Equal(
            IssuerAvailabilityCategory.KeySetUnavailable,
            observations.Recent(clock.GetUtcNow())[0].Category);

        // After the bounded refresh cooldown the endpoint answers again and recovery is observed.
        clock.Advance(TimeSpan.FromMinutes(1));
        failing = false;
        Assert.True((await validator.ValidateAsync(token, TestContext.Current.CancellationToken)).Active);
        Assert.Equal(3, handler.Calls);
        Assert.Equal(
            [
                IssuerAvailabilityCategory.KeySetRefreshed,
                IssuerAvailabilityCategory.KeySetUnavailable,
                IssuerAvailabilityCategory.KeySetRefreshed,
            ],
            observations.Recent(clock.GetUtcNow()).Select(entry => entry.Category));
    }

    [Fact]
    public async Task An_expired_token_is_recorded_as_rejected_without_claiming_an_outage()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");
        var handler = new StubHandler((_, _) => JwksResponse(key));
        using HttpClient client = new(handler);
        var clock = new FakeTimeProvider(Now);
        var observations = new IssuerAvailabilityObservations();
        var validator = new JwksTokenValidator(
            client,
            Issuer,
            JwksUri,
            clock,
            observations: observations);

        Assert.False((await validator.ValidateAsync(
            Mint(key, "resource", expires: DateTime.UtcNow.AddMinutes(-5)),
            TestContext.Current.CancellationToken)).Active);

        IReadOnlyList<IssuerAvailabilityObservation> afterRejection = observations.Recent(clock.GetUtcNow());

        // The refresh that made the check possible is observed first, then the rejection; neither is
        // an issuer outage.
        Assert.Equal(
            [
                IssuerAvailabilityCategory.TokenRejected,
                IssuerAvailabilityCategory.KeySetRefreshed,
            ],
            afterRejection.Select(entry => entry.Category));

        // The trust endpoint is healthy throughout: a valid token is still admitted and no outage
        // category was ever recorded for the rejected one.
        Assert.True((await validator.ValidateAsync(Mint(key, "resource"), TestContext.Current.CancellationToken)).Active);
        Assert.DoesNotContain(
            observations.Recent(clock.GetUtcNow()),
            entry => entry.Category is IssuerAvailabilityCategory.KeySetUnavailable
                or IssuerAvailabilityCategory.MetadataUnavailable);
    }

    [Fact]
    public async Task Unavailable_metadata_is_recorded_as_metadata_unavailable()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");
        var handler = new StubHandler((_, request) =>
            request.RequestUri!.AbsolutePath == "/.well-known/oauth-authorization-server"
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : throw new InvalidOperationException($"unexpected request {request.RequestUri}"));
        using HttpClient client = new(handler);
        var clock = new FakeTimeProvider(Now);
        var observations = new IssuerAvailabilityObservations();
        var validator = new JwksTokenValidator(
            client,
            Issuer,
            jwksOverride: null,
            clock,
            observations: observations);

        Assert.False((await validator.ValidateAsync(Mint(key, "resource"), TestContext.Current.CancellationToken)).Active);

        Assert.Equal(
            IssuerAvailabilityCategory.MetadataUnavailable,
            Assert.Single(observations.Recent(clock.GetUtcNow())).Category);
    }

    [Fact]
    public async Task An_unusable_key_set_is_recorded_as_keys_unavailable()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");
        var handler = new StubHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        });
        using HttpClient client = new(handler);
        var clock = new FakeTimeProvider(Now);
        var observations = new IssuerAvailabilityObservations();
        var validator = new JwksTokenValidator(
            client,
            Issuer,
            JwksUri,
            clock,
            observations: observations);

        Assert.False((await validator.ValidateAsync(Mint(key, "resource"), TestContext.Current.CancellationToken)).Active);

        // Metadata resolved and the endpoint answered: the failure is key material, not the metadata
        // half, and the two categories must not be conflated.
        Assert.Equal(
            IssuerAvailabilityCategory.KeySetUnavailable,
            Assert.Single(observations.Recent(clock.GetUtcNow())).Category);
    }

    [Fact]
    public async Task An_absent_observation_buffer_changes_no_decision()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");
        var observations = new IssuerAvailabilityObservations();
        using HttpClient observedClient = new(new StubHandler((_, _) => JwksResponse(key)));
        var withStore = new JwksTokenValidator(
            observedClient,
            Issuer,
            JwksUri,
            new FakeTimeProvider(Now),
            observations: observations);
        using HttpClient plainClient = new(new StubHandler((_, _) => JwksResponse(key)));
        var withoutStore = new JwksTokenValidator(plainClient, Issuer, JwksUri, new FakeTimeProvider(Now));

        string valid = Mint(key, "resource");
        string expired = Mint(key, "resource", expires: DateTime.UtcNow.AddMinutes(-5));

        TokenVerification[] observed =
        [
            await withStore.ValidateAsync(valid, TestContext.Current.CancellationToken),
            await withStore.ValidateAsync(expired, TestContext.Current.CancellationToken),
        ];
        TokenVerification[] plain =
        [
            await withoutStore.ValidateAsync(valid, TestContext.Current.CancellationToken),
            await withoutStore.ValidateAsync(expired, TestContext.Current.CancellationToken),
        ];

        Assert.Equal(
            observed.Select(result => (result.Active, result.Audience)),
            plain.Select(result => (result.Active, result.Audience)));
        Assert.True(observed[0].Active);
        Assert.False(observed[1].Active);
        Assert.NotEmpty(observations.Recent(Now));
    }

    [Fact]
    public void The_observation_buffer_is_bounded_and_prunes_by_observation_time()
    {
        var observations = new IssuerAvailabilityObservations(maximumEntries: 4);

        for (int index = 0; index < 10; index++)
        {
            observations.Record(
                Now.AddSeconds(index),
                IssuerAvailabilityMode.Jwks,
                IssuerAvailabilityCategory.KeySetRefreshed);
        }

        Assert.Equal(4, observations.Recent(Now.AddSeconds(10)).Count);

        var windowed = new IssuerAvailabilityObservations(retention: TimeSpan.FromMinutes(1));
        windowed.Record(Now, IssuerAvailabilityMode.Introspection, IssuerAvailabilityCategory.IssuerAnswered);

        Assert.Empty(windowed.Recent(Now.AddMinutes(2)));
    }

    [Theory]
    [InlineData("{")]
    [InlineData("{}")]
    [InlineData("{\"keys\":\"not-an-array\"}")]
    public async Task Malformed_jwks_is_an_inactive_token_not_an_exception(string body)
    {
        var handler = new StubHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });
        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(client, Issuer, JwksUri, new FakeTimeProvider(Now));

        TokenVerification verification = await validator.ValidateAsync(
            "not-a-valid-jwt",
            TestContext.Current.CancellationToken);

        Assert.False(verification.Active);
    }

    /// <summary>
    /// Both permitted discovery routes carry the same document semantics into validation: the same
    /// signing keys, the same byte-exact issuer binding, the same audience and scope interpretation,
    /// and the same one-fetch key resolution.
    /// </summary>
    [Fact]
    public async Task Both_discovery_routes_produce_the_same_verification()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");

        List<string> primaryPaths = [];
        var primaryHandler = new StubHandler((_, request) =>
        {
            string path = request.RequestUri!.AbsolutePath;
            primaryPaths.Add(path);
            return path switch
            {
                "/.well-known/oauth-authorization-server" => MetadataResponse(Issuer, JwksUri),
                "/jwks" => JwksResponse(key),
                _ => throw new InvalidOperationException($"unexpected request {path}"),
            };
        });

        List<string> fallbackPaths = [];
        var fallbackHandler = new StubHandler((_, request) =>
        {
            string path = request.RequestUri!.AbsolutePath;
            fallbackPaths.Add(path);
            return path switch
            {
                "/.well-known/oauth-authorization-server" => new HttpResponseMessage(HttpStatusCode.NotFound),
                "/.well-known/openid-configuration" => MetadataResponse(Issuer, JwksUri),
                "/jwks" => JwksResponse(key),
                _ => throw new InvalidOperationException($"unexpected request {path}"),
            };
        });

        using HttpClient primaryClient = new(primaryHandler);
        using HttpClient fallbackClient = new(fallbackHandler);
        var primary = new JwksTokenValidator(primaryClient, Issuer, jwksOverride: null);
        var fallback = new JwksTokenValidator(
            fallbackClient,
            Issuer,
            jwksOverride: null,
            clock: null,
            allowOidcFallback: true);

        string scalarToken = Mint(key, "resource");
        string multiToken = Mint(key, ResourceThenOtherAudiences);

        TokenVerification primaryScalar = await primary.ValidateAsync(scalarToken, TestContext.Current.CancellationToken);
        TokenVerification primaryMulti = await primary.ValidateAsync(multiToken, TestContext.Current.CancellationToken);
        TokenVerification fallbackScalar = await fallback.ValidateAsync(scalarToken, TestContext.Current.CancellationToken);
        TokenVerification fallbackMulti = await fallback.ValidateAsync(multiToken, TestContext.Current.CancellationToken);

        // Record equality would compare the scopes list by reference, so the observable fields are
        // compared one by one; that is the semantic parity this test claims.
        Assert.Equal(primaryScalar.Active, fallbackScalar.Active);
        Assert.Equal(primaryScalar.Audience, fallbackScalar.Audience);
        Assert.Equal(primaryScalar.Scopes, fallbackScalar.Scopes);
        Assert.Equal(primaryMulti.Active, fallbackMulti.Active);
        Assert.Equal(primaryMulti.Audience, fallbackMulti.Audience);
        Assert.Equal(primaryMulti.Scopes, fallbackMulti.Scopes);
        Assert.True(primaryScalar.Active);
        Assert.Equal("resource", primaryScalar.Audience);
        Assert.Equal(ToolsInvokeScopes, primaryScalar.Scopes);
        Assert.True(primaryMulti.Active);
        Assert.Null(primaryMulti.Audience);

        // Two validations per route, one discovery answer and one key-set fetch per route.
        Assert.Equal(1, primaryPaths.Count(path => path == "/jwks"));
        Assert.Equal(1, fallbackPaths.Count(path => path == "/jwks"));
        Assert.Equal(1, fallbackPaths.Count(path => path == "/.well-known/openid-configuration"));
        Assert.DoesNotContain("/.well-known/openid-configuration", primaryPaths);
    }

    /// <summary>The configured issuer binds byte-exactly through both routes.</summary>
    [Fact]
    public async Task Both_discovery_routes_refuse_a_token_for_another_issuer()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");

        var primaryHandler = new StubHandler((_, request) => request.RequestUri!.AbsolutePath switch
        {
            "/.well-known/oauth-authorization-server" => MetadataResponse(Issuer, JwksUri),
            "/jwks" => JwksResponse(key),
            _ => throw new InvalidOperationException($"unexpected request {request.RequestUri}"),
        });
        var fallbackHandler = new StubHandler((_, request) => request.RequestUri!.AbsolutePath switch
        {
            "/.well-known/oauth-authorization-server" => new HttpResponseMessage(HttpStatusCode.NotFound),
            "/.well-known/openid-configuration" => MetadataResponse(Issuer, JwksUri),
            "/jwks" => JwksResponse(key),
            _ => throw new InvalidOperationException($"unexpected request {request.RequestUri}"),
        });

        using HttpClient primaryClient = new(primaryHandler);
        using HttpClient fallbackClient = new(fallbackHandler);
        var primary = new JwksTokenValidator(primaryClient, Issuer, jwksOverride: null);
        var fallback = new JwksTokenValidator(
            fallbackClient,
            Issuer,
            jwksOverride: null,
            clock: null,
            allowOidcFallback: true);

        string otherIssuerToken = Mint(key, "resource", issuer: Issuer + "/");

        Assert.False((await primary.ValidateAsync(otherIssuerToken, TestContext.Current.CancellationToken)).Active);
        Assert.False((await fallback.ValidateAsync(otherIssuerToken, TestContext.Current.CancellationToken)).Active);
    }

    /// <summary>An absent primary document stays inactive while fallback is off, and asks nothing else.</summary>
    [Fact]
    public async Task An_absent_rfc8414_document_is_inactive_without_enabled_fallback()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");

        List<string> paths = [];
        var handler = new StubHandler((_, request) =>
        {
            string path = request.RequestUri!.AbsolutePath;
            paths.Add(path);
            return path switch
            {
                "/.well-known/oauth-authorization-server" => new HttpResponseMessage(HttpStatusCode.NotFound),
                "/.well-known/openid-configuration" => MetadataResponse(Issuer, JwksUri),
                "/jwks" => JwksResponse(key),
                _ => throw new InvalidOperationException($"unexpected request {path}"),
            };
        });

        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(client, Issuer, jwksOverride: null);

        TokenVerification verification = await validator.ValidateAsync(
            Mint(key, "resource"),
            TestContext.Current.CancellationToken);

        Assert.False(verification.Active);
        Assert.Equal(Rfc8414PathOnly, paths);
    }

    /// <summary>
    /// Every RFC 8414 outcome other than 404/410 stays fail-closed at runtime without asking the
    /// OIDC route, even when the operator enabled the fallback.
    /// </summary>
    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task A_non_definitive_rfc8414_status_is_inactive_without_the_oidc_route(HttpStatusCode status)
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");

        List<string> paths = [];
        var handler = new StubHandler((_, request) =>
        {
            string path = request.RequestUri!.AbsolutePath;
            paths.Add(path);
            return path switch
            {
                "/.well-known/oauth-authorization-server" => new HttpResponseMessage(status),
                "/.well-known/openid-configuration" => MetadataResponse(Issuer, JwksUri),
                "/jwks" => JwksResponse(key),
                _ => throw new InvalidOperationException($"unexpected request {path}"),
            };
        });

        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(
            client,
            Issuer,
            jwksOverride: null,
            clock: null,
            allowOidcFallback: true);

        TokenVerification verification = await validator.ValidateAsync(
            Mint(key, "resource"),
            TestContext.Current.CancellationToken);

        Assert.False(verification.Active);
        Assert.Equal(["/.well-known/oauth-authorization-server"], paths);
    }

    /// <summary>A wrong-issuer fallback document fails closed before any key request.</summary>
    [Fact]
    public async Task A_wrong_issuer_oidc_document_is_inactive_without_a_key_request()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");

        List<string> paths = [];
        var handler = new StubHandler((_, request) =>
        {
            string path = request.RequestUri!.AbsolutePath;
            paths.Add(path);
            return path switch
            {
                "/.well-known/oauth-authorization-server" => new HttpResponseMessage(HttpStatusCode.NotFound),
                "/.well-known/openid-configuration" => MetadataResponse("https://other.example", JwksUri),
                "/jwks" => JwksResponse(key),
                _ => throw new InvalidOperationException($"unexpected request {path}"),
            };
        });

        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(
            client,
            Issuer,
            jwksOverride: null,
            clock: null,
            allowOidcFallback: true);

        TokenVerification verification = await validator.ValidateAsync(
            Mint(key, "resource"),
            TestContext.Current.CancellationToken);

        Assert.False(verification.Active);
        Assert.Equal(BothDiscoveryPaths, paths);
    }

    /// <summary>A duplicated endpoint member in the fallback document is unusable, not a choice.</summary>
    [Fact]
    public async Task A_duplicate_jwks_uri_in_the_oidc_document_is_inactive()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");

        List<string> paths = [];
        var handler = new StubHandler((_, request) =>
        {
            string path = request.RequestUri!.AbsolutePath;
            paths.Add(path);
            return path switch
            {
                "/.well-known/oauth-authorization-server" => new HttpResponseMessage(HttpStatusCode.NotFound),
                "/.well-known/openid-configuration" => new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        $"{{\"issuer\":\"{Issuer}\",\"jwks_uri\":\"{JwksUri}\",\"jwks_uri\":\"{JwksUri}\"}}",
                        Encoding.UTF8,
                        "application/json"),
                },
                "/jwks" => JwksResponse(key),
                _ => throw new InvalidOperationException($"unexpected request {path}"),
            };
        });

        using HttpClient client = new(handler);
        var validator = new JwksTokenValidator(
            client,
            Issuer,
            jwksOverride: null,
            clock: null,
            allowOidcFallback: true);

        TokenVerification verification = await validator.ValidateAsync(
            Mint(key, "resource"),
            TestContext.Current.CancellationToken);

        Assert.False(verification.Active);
        Assert.DoesNotContain("/jwks", paths);
    }

    /// <summary>
    /// The production composer is the path that carries the operator's setting to the validator,
    /// so a fallback driven through <see cref="MountAuthorizationSetup"/> proves the wiring, not
    /// just the constructor.
    /// </summary>
    [Fact]
    public async Task The_production_composer_drives_jwks_validation_through_the_fallback_route()
    {
        using RSA rsa = RSA.Create(2048);
        RsaSecurityKey key = SigningKey(rsa, "key-a");

        await using AuthorizationTransportServer server = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                string? path = context.Request.Path.Value;
                if (path == "/.well-known/oauth-authorization-server")
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                string address = $"http://{context.Request.Host.Value}";
                context.Response.ContentType = "application/json";

                if (path == "/.well-known/openid-configuration")
                {
                    await context.Response.WriteAsync(
                        $"{{\"issuer\":\"{address}/\",\"jwks_uri\":\"{address}/jwks\"}}",
                        context.RequestAborted);
                    return;
                }

                await context.Response.WriteAsync(
                    (await JwksResponse(key).Content.ReadAsStringAsync(TestContext.Current.CancellationToken)),
                    context.RequestAborted);
            });

        string issuer = server.Address.AbsoluteUri;
        ITokenValidator validator = MountAuthorizationSetup.Validator(
            new HostAuthorizationOptions(issuer, HostTokenValidation.Jwks)
            {
                OidcDiscoveryFallbackEnabled = true,
            });

        TokenVerification verification = await validator.ValidateAsync(
            Mint(key, "resource", issuer: issuer),
            TestContext.Current.CancellationToken);

        Assert.True(verification.Active);
        Assert.Equal("resource", verification.Audience);
        Assert.Contains("/.well-known/openid-configuration", server.RequestedPaths);
    }

    private static HttpResponseMessage MetadataResponse(string issuer, string jwksUri)
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $"{{\"issuer\":\"{issuer}\",\"jwks_uri\":\"{jwksUri}\"}}",
                Encoding.UTF8,
                "application/json"),
        };

    private static RsaSecurityKey SigningKey(RSA rsa, string kid)
        => new(rsa.ExportParameters(true)) { KeyId = kid };

    private static string Mint(
        RsaSecurityKey key,
        object audience,
        string issuer = Issuer,
        DateTime? expires = null)
    {
        Dictionary<string, object> claims = new()
        {
            ["scope"] = "tools.invoke",
        };

        SecurityTokenDescriptor descriptor = new()
        {
            Issuer = issuer,
            Claims = claims,
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = expires ?? DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
        };

        if (audience is string scalar)
        {
            descriptor.Audience = scalar;
        }
        else
        {
            claims["aud"] = audience;
        }

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static HttpResponseMessage JwksResponse(RsaSecurityKey key)
    {
        JsonWebKey web = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        web.Kid = key.KeyId;

        string body = $$"""{ "keys": [ { "kty": "{{web.Kty}}", "kid": "{{web.Kid}}", "n": "{{web.N}}", "e": "{{web.E}}", "alg": "RS256", "use": "sig" } ] }""";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan amount) => _now = _now.Add(amount);
    }

    private sealed class StubHandler(
        Func<int, HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            int call = Interlocked.Increment(ref _calls);
            return Task.FromResult(responder(call, request));
        }
    }
}
