using System.Text;
using System.Text.Json;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Canonical;

using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// Covers the projection of an already-validated OAuth configuration and the protocol-level
/// helpers it shares with the token client.
/// </summary>
/// <remarks>
/// The manifest reader owns validation of the closed configuration schema, so these tests
/// assert what execution consumes rather than restating the reader's refusals: defaults,
/// scope/resource identity, expiry parsing and the authentication-origin guard.
/// </remarks>
public sealed class OAuthConfigurationTests
{
    [Fact]
    public void A_client_credentials_configuration_projects_its_declared_values()
    {
        var configuration = OAuthStrategyConfiguration.FromConfiguration(
            Json(
                """
                {
                  "clientId": "example-client",
                  "tokenEndpoint": "https://auth.example.com/oauth2/token",
                  "tokenAuthMethod": "client_secret_basic",
                  "scopes": ["write", "read"],
                  "resource": "https://api.example.com",
                  "audience": "api",
                  "accessTokenSafetySkewSeconds": 45,
                  "authorizationParameters": { "prompt": "consent" }
                }
                """),
            authorizationCodeRequired: false);

        Assert.Equal("example-client", configuration.ClientId);
        Assert.Equal(new Uri("https://auth.example.com/oauth2/token"), configuration.TokenEndpoint);
        Assert.Null(configuration.AuthorizationEndpoint);
        Assert.Null(configuration.RevocationEndpoint);
        Assert.Equal("client_secret_basic", configuration.TokenAuthMethod);
        Assert.Equal(["read", "write"], configuration.Scopes);
        Assert.Equal("https://api.example.com", configuration.Resource);
        Assert.Equal("api", configuration.Audience);
        Assert.Equal(TimeSpan.FromSeconds(45), configuration.AccessTokenSafetySkew);
        Assert.Equal("consent", configuration.AuthorizationParameters["prompt"]);
    }

    [Fact]
    public void An_absent_configuration_uses_the_documented_defaults()
    {
        var configuration = OAuthStrategyConfiguration.FromConfiguration(
            Json(
                """
                {
                  "clientId": "example-client",
                  "tokenEndpoint": "https://auth.example.com/token"
                }
                """),
            authorizationCodeRequired: false);

        Assert.Equal("client_secret_post", configuration.TokenAuthMethod);
        Assert.Equal(TimeSpan.FromSeconds(30), configuration.AccessTokenSafetySkew);
        Assert.Empty(configuration.Scopes);
        Assert.Null(configuration.Resource);
        Assert.Null(configuration.Audience);
        Assert.Empty(configuration.AuthorizationParameters);
    }

    [Fact]
    public void The_client_id_is_also_read_from_the_inputs_object()
    {
        // Platform accepts the client id either directly or under 'inputs'; the projection
        // accepts the same two shapes so a stored configuration crosses unchanged.
        var configuration = OAuthStrategyConfiguration.FromConfiguration(
            Json(
                """
                {
                  "inputs": { "clientId": "nested-client" },
                  "tokenEndpoint": "https://auth.example.com/token"
                }
                """),
            authorizationCodeRequired: false);

        Assert.Equal("nested-client", configuration.ClientId);
    }

    [Fact]
    public void An_authorization_code_configuration_requires_the_authorization_endpoint()
    {
        var exception = Assert.Throws<AuthenticationPlanException>(() =>
            OAuthStrategyConfiguration.FromConfiguration(
                Json(
                    """
                    {
                      "clientId": "example-client",
                      "tokenEndpoint": "https://auth.example.com/token"
                    }
                    """),
                authorizationCodeRequired: true));

        Assert.Equal("oauth", exception.ProfileId);
    }

    [Fact]
    public void Scope_resource_identity_depends_on_scopes_resource_and_audience_only()
    {
        var first = OAuthStrategyConfiguration.FromConfiguration(
            Json(
                """
                {
                  "clientId": "example-client",
                  "tokenEndpoint": "https://auth.example.com/token",
                  "scopes": ["read", "write"],
                  "resource": "https://api.example.com",
                  "audience": "api"
                }
                """),
            authorizationCodeRequired: false);

        var reordered = OAuthStrategyConfiguration.FromConfiguration(
            Json(
                """
                {
                  "clientId": "example-client",
                  "tokenEndpoint": "https://auth.example.com/token",
                  "scopes": ["write", "read"],
                  "resource": "https://api.example.com",
                  "audience": "api"
                }
                """),
            authorizationCodeRequired: false);

        // Scope order is not part of the identity: two spellings of the same request set
        // must reach the same cache entry rather than acquiring the token twice.
        Assert.Equal(first.ScopeResourceKey, reordered.ScopeResourceKey);

        var differentScope = OAuthStrategyConfiguration.FromConfiguration(
            Json(
                """
                {
                  "clientId": "example-client",
                  "tokenEndpoint": "https://auth.example.com/token",
                  "scopes": ["read"],
                  "resource": "https://api.example.com",
                  "audience": "api"
                }
                """),
            authorizationCodeRequired: false);

        var differentAudience = OAuthStrategyConfiguration.FromConfiguration(
            Json(
                """
                {
                  "clientId": "example-client",
                  "tokenEndpoint": "https://auth.example.com/token",
                  "scopes": ["read", "write"],
                  "resource": "https://api.example.com",
                  "audience": "other"
                }
                """),
            authorizationCodeRequired: false);

        Assert.NotEqual(first.ScopeResourceKey, differentScope.ScopeResourceKey);
        Assert.NotEqual(first.ScopeResourceKey, differentAudience.ScopeResourceKey);
        Assert.Equal(64, first.ScopeResourceKey.Length);
        Assert.Matches("^[0-9a-f]{64}$", first.ScopeResourceKey);
    }

    [Fact]
    public void Scope_resource_identity_ignores_the_client_secret_and_endpoints()
    {
        // The key names what a token is for, never how it was obtained, so re-encrypting or
        // rotating the client secret cannot silently reuse a token acquired for a different
        // identity.
        var first = OAuthStrategyConfiguration.FromConfiguration(
            Json(
                """
                {
                  "clientId": "example-client",
                  "tokenEndpoint": "https://auth.example.com/token",
                  "scopes": ["read"]
                }
                """),
            authorizationCodeRequired: false);

        var otherEndpoint = OAuthStrategyConfiguration.FromConfiguration(
            Json(
                """
                {
                  "clientId": "other-client",
                  "tokenEndpoint": "https://auth.example.com/other/token",
                  "scopes": ["read"]
                }
                """),
            authorizationCodeRequired: false);

        Assert.Equal(first.ScopeResourceKey, otherEndpoint.ScopeResourceKey);
    }

    [Theory]
    [InlineData("""{ "expires_in": 3600 }""", 3600)]
    [InlineData("""{ "expires_in": "3600" }""", 3600)]
    [InlineData("""{ "expires_in": 1 }""", 1)]
    public void A_valid_expiry_parses_numerically_or_textually(string payload, int seconds)
    {
        using var document = JsonDocument.Parse(payload);

        Assert.Equal(TimeSpan.FromSeconds(seconds), OAuthProtocol.ParseExpiresIn(document.RootElement));
    }

    [Theory]
    [InlineData("""{ }""")]
    [InlineData("""{ "expires_in": "soon" }""")]
    [InlineData("""{ "expires_in": 0 }""")]
    [InlineData("""{ "expires_in": -5 }""")]
    [InlineData("""{ "expires_in": 3600.5 }""")]
    public void An_invalid_expiry_is_refused(string payload)
    {
        using var document = JsonDocument.Parse(payload);

        Assert.Throws<AuthenticationPlanException>(() => OAuthProtocol.ParseExpiresIn(document.RootElement));
    }

    [Fact]
    public void An_expiry_beyond_the_maximum_lifetime_is_refused()
    {
        using var document = JsonDocument.Parse("""{ "expires_in": 2592001 }""");

        var exception = Assert.Throws<AuthenticationPlanException>(
            () => OAuthProtocol.ParseExpiresIn(document.RootElement));

        Assert.Equal("oauth", exception.ProfileId);
    }

    [Fact]
    public void The_maximum_lifetime_itself_is_accepted()
    {
        using var document = JsonDocument.Parse("""{ "expires_in": 2592000 }""");

        Assert.Equal(
            OAuthProtocol.MaximumAccessTokenLifetime,
            OAuthProtocol.ParseExpiresIn(document.RootElement));
    }

    [Fact]
    public void An_endpoint_inside_the_reviewed_scope_is_admitted()
    {
        OAuthProtocol.RequireAuthenticationOrigin(
            new Uri("https://auth.example.com/oauth2/token"),
            ["https://auth.example.com:443"]);
    }

    [Fact]
    public void An_endpoint_outside_the_reviewed_scope_is_refused_before_any_credential_is_read()
    {
        // A token request reveals a client secret, so an endpoint outside the declared
        // origins is refused outright; the refusal names no secret.
        var exception = Assert.Throws<CredentialUnavailableException>(() =>
            OAuthProtocol.RequireAuthenticationOrigin(
                new Uri("https://attacker.example.net/token"),
                ["https://auth.example.com:443"]));

        Assert.Equal("oauth", exception.CredentialId);
    }

    [Fact]
    public void A_default_port_endpoint_matches_an_origin_declared_with_explicit_port()
    {
        // The producer writes explicit ports and the deployer may write either spelling; the
        // origin list normalizes both, so a manifest cannot fail merely for spelling.
        OAuthProtocol.RequireAuthenticationOrigin(
            new Uri("https://auth.example.com/token"),
            ["https://auth.example.com:443"]);
        OAuthProtocol.RequireAuthenticationOrigin(
            new Uri("https://auth.example.com:443/token"),
            ["https://auth.example.com"]);
    }

    [Fact]
    public void A_plain_http_endpoint_is_only_admitted_when_the_scope_declares_it()
    {
        Assert.Throws<CredentialUnavailableException>(() =>
            OAuthProtocol.RequireAuthenticationOrigin(
                new Uri("http://auth.example.com/token"),
                ["https://auth.example.com:443"]));

        OAuthProtocol.RequireAuthenticationOrigin(
            new Uri("http://auth.example.com:80/token"),
            ["http://auth.example.com:80"]);
    }

    [Fact]
    public void Base64_url_uses_the_unpadded_url_safe_alphabet()
    {
        var encoded = OAuthProtocol.Base64Url([0xFB, 0xFF, 0xFE]);

        Assert.Equal("-__-", encoded);
        Assert.DoesNotContain('=', encoded);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
    }

    [Fact]
    public void A_random_token_is_unpadded_url_safe_and_unique()
    {
        var first = OAuthProtocol.CreateRandomToken(32);
        var second = OAuthProtocol.CreateRandomToken(32);

        Assert.NotEqual(first, second);
        Assert.DoesNotContain('=', first);
        Assert.DoesNotContain('+', first);
        Assert.DoesNotContain('/', first);

        // 32 random bytes encode to 43 base64url characters with padding removed.
        Assert.Equal(43, first.Length);
    }

    private static System.Text.Json.Nodes.JsonObject Json(string text) =>
        CanonicalJson.Parse(Encoding.UTF8.GetBytes(text))!.AsObject();
}
