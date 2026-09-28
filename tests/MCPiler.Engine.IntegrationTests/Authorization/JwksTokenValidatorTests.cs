using System.Net;
using System.Security.Cryptography;
using System.Text;

using MCPiler.Engine.Host.Authorization;

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

    private static RsaSecurityKey SigningKey(RSA rsa, string kid)
        => new(rsa.ExportParameters(true)) { KeyId = kid };

    private static string Mint(RsaSecurityKey key, object audience)
    {
        Dictionary<string, object> claims = new()
        {
            ["scope"] = "tools.invoke",
        };

        SecurityTokenDescriptor descriptor = new()
        {
            Issuer = Issuer,
            Claims = claims,
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = DateTime.UtcNow.AddHours(1),
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
