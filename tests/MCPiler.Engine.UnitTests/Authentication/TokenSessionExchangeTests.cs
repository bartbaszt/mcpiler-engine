using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Exchange;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;
using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// The declarative token/session exchange: configuration projection, JSON Pointer selection,
/// response reading, expiry handling and destination narrowing.
/// </summary>
/// <remarks>
/// The exchange is the most configurable strategy in the format, so the tests here are mostly
/// about what the runtime still refuses when the configuration says something the reviewed
/// contract does not promise: a selector that reads nothing, material that is too long, an
/// expiry outside the admitted window, or a response-named destination outside either origin
/// list. The transport is a substitute, so no host is involved.
/// </remarks>
public sealed class TokenSessionExchangeTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private const string Endpoint = "https://auth.example.com/session";

    [Fact]
    public void A_declared_exchange_projects_every_runtime_fact()
    {
        var definition = TokenSessionExchangeDefinition.FromConfiguration(Json(DocumentedConfiguration()));

        Assert.Equal(new Uri(Endpoint), definition.Endpoint);
        Assert.Equal("POST", definition.Method);
        Assert.Equal("application/x-www-form-urlencoded", definition.MediaType);
        Assert.Equal("example-user", definition.Inputs["username"]);
        Assert.Equal(ExchangeValueSourceKind.Input, definition.Fields["username"].Kind);
        Assert.Equal("apiKey", definition.Fields["apikey"].Slot);
        Assert.Equal("2", definition.Headers["X-Api-Version"].StaticValue);
        Assert.Equal(ExchangeSelectorKind.JsonPointer, definition.TokenSelector.Kind);
        Assert.Equal("/token", definition.TokenSelector.Selector);
        Assert.Equal(ExchangeExpiryKind.RelativeSeconds, definition.Expiry!.Kind);
        Assert.Equal("header", definition.Injection.Location);
        Assert.Equal("Authorization", definition.Injection.Name);
        Assert.Equal("Bearer ", definition.Injection.Prefix);
        Assert.Equal(TimeSpan.FromMinutes(5), definition.DefaultLifetime);
        Assert.Equal(TimeSpan.FromSeconds(15), definition.SafetySkew);
        Assert.Equal([401, 403], definition.AuthenticationFailureStatusCodes.Order().ToArray());
    }

    /// <summary>The fully-populated configuration the projection test reads.</summary>
    private static string DocumentedConfiguration() => """
        {
          "strategyId": "bounded-token-session-exchange",
          "inputs": { "username": "example-user" },
          "endpoint": "https://auth.example.com/session",
          "method": "POST",
          "request": {
            "mediaType": "application/x-www-form-urlencoded",
            "fields": {
              "username": { "source": "input", "slot": "username" },
              "apikey": { "source": "secret", "slot": "apiKey" }
            },
            "headers": {
              "X-Api-Version": { "source": "static", "value": "2" }
            }
          },
          "response": {
            "token": { "source": "jsonPointer", "selector": "/token" },
            "expiry": { "kind": "relativeSeconds", "source": "jsonPointer", "selector": "/expires_in" }
          },
          "injection": { "location": "header", "name": "Authorization", "prefix": "Bearer " },
          "authFailureStatusCodes": [401, 403]
        }
        """;

    [Fact]
    public void An_exchange_without_optional_members_projects_their_defaults()
    {
        var definition = TokenSessionExchangeDefinition.FromConfiguration(Json("""
            {
              "strategyId": "bounded-token-session-exchange",
              "inputs": {},
              "endpoint": "https://auth.example.com/session",
              "method": "POST",
              "request": { "mediaType": "application/json" },
              "response": { "token": { "source": "jsonPointer", "selector": "/token" } },
              "injection": { "location": "bearer" }
            }
            """));

        Assert.Empty(definition.Fields);
        Assert.Empty(definition.Headers);
        Assert.Null(definition.BasicAuthentication);
        Assert.Null(definition.Expiry);
        Assert.Null(definition.Destination);
        Assert.Equal(TimeSpan.FromMinutes(5), definition.DefaultLifetime);
        Assert.Equal([401], definition.AuthenticationFailureStatusCodes.ToArray());
        Assert.Null(definition.Injection.Name);
        Assert.Equal(string.Empty, definition.Injection.Prefix);
    }

    [Theory]
    [InlineData("", true)]
    [InlineData("/token", true)]
    [InlineData("/a/b/0", true)]
    [InlineData("/a~1b", true)]
    [InlineData("/a~0b", true)]
    [InlineData("token", false)]
    [InlineData("/missing", false)]
    [InlineData("/a/b/01", false)]
    [InlineData("/a/b/9", false)]
    [InlineData("/a/b/-", false)]
    [InlineData("/a~2b", false)]
    public void Json_pointer_selection_matches_the_reviewed_grammar(string pointer, bool selects)
    {
        var root = JsonNode.Parse("""{"token":"t","a":{"b":["zero","one"]},"a/b":"slash","a~b":"tilde"}""");

        Assert.Equal(selects, TokenSessionExchangeDefinition.TrySelectJsonPointer(root, pointer, out _));
    }

    [Fact]
    public void A_missing_configuration_member_is_a_plan_failure_naming_the_profile()
    {
        var error = Assert.Throws<AuthenticationPlanException>(() =>
            TokenSessionExchangeDefinition.FromConfiguration(Json("""
                {
                  "strategyId": "bounded-token-session-exchange",
                  "endpoint": "https://auth.example.com/session",
                  "request": { "mediaType": "application/json" },
                  "response": { "token": { "source": "jsonPointer", "selector": "/token" } },
                  "injection": { "location": "bearer" }
                }
                """)));

        Assert.Equal("exchange", error.ProfileId);
    }

    [Fact]
    public async Task An_exchange_acquires_material_and_injects_it_as_a_header()
    {
        var transport = new RecordingTransport(Responds(
            """{"token":"session-canary","expires_in":600}""",
            "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        var acquisition = await service.AcquireAsync(
            Profile(Configuration(includeExpiry: true)),
            [Secret("apiKey", "api-canary")],
            TestContext.Current.CancellationToken);

        var request = Assert.Single(transport.Requests);

        Assert.Equal("POST", request.Method);
        Assert.Equal(new Uri(Endpoint), request.Uri);
        Assert.Equal("username=example-user&apikey=api-canary", request.Form);
        Assert.Equal("Bearer session-canary", acquisition.Credential.Value);
        Assert.Equal(CredentialScheme.Header, acquisition.Credential.Declaration.Scheme);
        Assert.Equal("Authorization", acquisition.Credential.Declaration.Slot);
        Assert.Equal(Now.AddMinutes(10), acquisition.ExpiresAtUtc);
        Assert.Null(acquisition.DestinationAuthority);
    }

    [Fact]
    public async Task An_exchange_uses_the_default_lifetime_when_the_response_states_no_expiry()
    {
        var transport = new RecordingTransport(Responds("""{"token":"session-canary"}""", "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        var acquisition = await service.AcquireAsync(
            Profile(Configuration()),
            [Secret("apiKey", "api-canary")],
            TestContext.Current.CancellationToken);

        Assert.Equal(Now.AddMinutes(5), acquisition.ExpiresAtUtc);
    }

    [Fact]
    public async Task A_unix_expiry_is_read_as_an_absolute_instant()
    {
        var unix = Now.AddMinutes(20).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var transport = new RecordingTransport(Responds(
            $$"""{"token":"session-canary","expires":{{unix}}}""",
            "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        var acquisition = await service.AcquireAsync(
            Profile(Configuration(expiryKind: "unixSeconds", expirySelector: "/expires")),
            [Secret("apiKey", "api-canary")],
            TestContext.Current.CancellationToken);

        Assert.Equal(Now.AddMinutes(20), acquisition.ExpiresAtUtc);
    }

    [Fact]
    public async Task An_expiry_beyond_the_admitted_window_is_refused()
    {
        var transport = new RecordingTransport(Responds(
            """{"token":"session-canary","expires_in":2592001}""",
            "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        var error = await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            service.AcquireAsync(
                Profile(Configuration(includeExpiry: true)),
                [Secret("apiKey", "api-canary")],
                TestContext.Current.CancellationToken).AsTask());

        Assert.DoesNotContain("session-canary", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Material_beyond_the_admitted_length_is_refused()
    {
        var oversized = new string('x', 16_385);
        var transport = new RecordingTransport(Responds(
            $$"""{"token":"{{oversized}}"}""",
            "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            service.AcquireAsync(
                Profile(Configuration()),
                [Secret("apiKey", "api-canary")],
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task A_token_endpoint_failure_is_refused_without_echoing_the_secret()
    {
        var transport = new RecordingTransport(new UpstreamResponse(
            500,
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            "application/json",
            new MemoryStream("""{"error":"server_error"}"""u8.ToArray())));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        var error = await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            service.AcquireAsync(
                Profile(Configuration()),
                [Secret("apiKey", "api-canary")],
                TestContext.Current.CancellationToken).AsTask());

        Assert.DoesNotContain("api-canary", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_json_is_refused()
    {
        var transport = new RecordingTransport(Responds("not json", "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            service.AcquireAsync(
                Profile(Configuration()),
                [Secret("apiKey", "api-canary")],
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task A_response_derived_destination_must_be_allowed_by_both_lists()
    {
        var allowedTransport = new RecordingTransport(Responds(
            """{"token":"session-canary","server":"https://api.example.com"}""",
            "application/json"));
        var service = new TokenSessionExchangeService(allowedTransport, new FixedClock(Now));

        var acquisition = await service.AcquireAsync(
            Profile(Configuration(
                destination: """
                    {
                      "selector": { "source": "jsonPointer", "selector": "/server" },
                      "allowedOrigins": ["https://*.example.com"]
                    }
                    """)),
            [Secret("apiKey", "api-canary")],
            TestContext.Current.CancellationToken);

        Assert.Equal(new Uri("https://api.example.com"), acquisition.DestinationAuthority);
    }

    [Fact]
    public async Task A_destination_outside_the_profile_scope_is_refused()
    {
        var transport = new RecordingTransport(Responds(
            """{"token":"session-canary","server":"https://evil.invalid"}""",
            "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            service.AcquireAsync(
                Profile(Configuration(
                    destination: """
                        {
                          "selector": { "source": "jsonPointer", "selector": "/server" },
                          "allowedOrigins": ["https://*.example.com"]
                        }
                        """)),
                [Secret("apiKey", "api-canary")],
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task A_destination_that_is_not_an_https_root_authority_is_refused()
    {
        var transport = new RecordingTransport(Responds(
            """{"token":"session-canary","server":"http://api.example.com/path"}""",
            "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            service.AcquireAsync(
                Profile(Configuration(
                    destination: """
                        {
                          "selector": { "source": "jsonPointer", "selector": "/server" },
                          "allowedOrigins": ["http://api.example.com:80"]
                        }
                        """)),
                [Secret("apiKey", "api-canary")],
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public void A_response_derived_authority_rebinds_the_path_and_query()
    {
        var rebound = TokenSessionExchangeService.RebindUri(
            new Uri("https://api.example.com/v1/pets?limit=5"),
            new Uri("https://eu.example.com"));

        Assert.Equal("https://eu.example.com/v1/pets?limit=5", rebound.AbsoluteUri);
    }

    [Fact]
    public async Task A_header_selector_reads_the_named_response_header()
    {
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-Session"] = ["header-canary"],
        };
        var transport = new RecordingTransport(new UpstreamResponse(
            200,
            headers,
            "application/json",
            new MemoryStream("{}"u8.ToArray())));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        var acquisition = await service.AcquireAsync(
            Profile(Configuration(tokenSelector: """{ "source": "header", "selector": "X-Session" }""")),
            [Secret("apiKey", "api-canary")],
            TestContext.Current.CancellationToken);

        Assert.Equal("Bearer header-canary", acquisition.Credential.Value);
    }

    [Fact]
    public async Task An_ambiguous_header_selector_is_refused()
    {
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-Session"] = ["one", "two"],
        };
        var transport = new RecordingTransport(new UpstreamResponse(
            200,
            headers,
            "application/json",
            new MemoryStream("{}"u8.ToArray())));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            service.AcquireAsync(
                Profile(Configuration(tokenSelector: """{ "source": "header", "selector": "X-Session" }""")),
                [Secret("apiKey", "api-canary")],
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task A_cookie_selector_reads_the_named_cookie_pair()
    {
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["Set-Cookie"] = ["JSESSIONID=\"cookie-canary\"; Path=/; HttpOnly"],
        };
        var transport = new RecordingTransport(new UpstreamResponse(
            200,
            headers,
            "application/json",
            new MemoryStream("{}"u8.ToArray())));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        var acquisition = await service.AcquireAsync(
            Profile(Configuration(tokenSelector: """{ "source": "cookie", "selector": "JSESSIONID" }""")),
            [Secret("apiKey", "api-canary")],
            TestContext.Current.CancellationToken);

        Assert.Equal("Bearer cookie-canary", acquisition.Credential.Value);
    }

    [Fact]
    public async Task An_endpoint_outside_the_reviewed_authentication_scope_is_refused_before_sending()
    {
        var transport = new RecordingTransport(Responds("""{"token":"session-canary"}""", "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        var profile = Profile(Configuration()) with
        {
            AuthenticationOrigins = ["https://elsewhere.example.com:443"],
        };

        await Assert.ThrowsAsync<CredentialUnavailableException>(() =>
            service.AcquireAsync(
                profile,
                [Secret("apiKey", "api-canary")],
                TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task Basic_authentication_maps_its_halves_into_the_authorization_header()
    {
        var transport = new RecordingTransport(Responds("""{"token":"session-canary"}""", "application/json"));
        var service = new TokenSessionExchangeService(transport, new FixedClock(Now));

        var acquisition = await service.AcquireAsync(
            Profile(BasicConfiguration()),
            [Secret("password", "password-canary")],
            TestContext.Current.CancellationToken);

        Assert.Equal("Bearer session-canary", acquisition.Credential.Value);
    }

    /// <summary>
    /// A Basic exchange: the two credential halves are the authentication, so the request carries
    /// no secret field mapping of its own.
    /// </summary>
    private static string BasicConfiguration() => """
        {
          "strategyId": "bounded-token-session-exchange",
          "inputs": { "username": "example-user" },
          "endpoint": "https://auth.example.com/session",
          "method": "POST",
          "request": {
            "mediaType": "application/x-www-form-urlencoded",
            "basic": {
              "username": { "source": "input", "slot": "username" },
              "password": { "source": "secret", "slot": "password" }
            }
          },
          "response": { "token": { "source": "jsonPointer", "selector": "/token" } },
          "injection": { "location": "header", "name": "Authorization", "prefix": "Bearer " }
        }
        """;

    [Fact]
    public async Task A_profile_of_another_kind_is_not_an_exchange()
    {
        var service = new TokenSessionExchangeService(
            new RecordingTransport(Responds("{}", "application/json")),
            new FixedClock(Now));

        await Assert.ThrowsAsync<UnsupportedAuthenticationStrategyException>(() =>
            service.AcquireAsync(
                Profile(Configuration()) with { Kind = AuthenticationKind.Static },
                [],
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public void Authentication_failure_status_codes_are_reported_for_this_kind_only()
    {
        var profile = Profile(Configuration(authenticationFailureStatusCodes: "[401, 403]"));

        Assert.True(TokenSessionExchangeService.IsAuthenticationFailure(profile, 401));
        Assert.True(TokenSessionExchangeService.IsAuthenticationFailure(profile, 403));
        Assert.False(TokenSessionExchangeService.IsAuthenticationFailure(profile, 404));
        Assert.False(TokenSessionExchangeService.IsAuthenticationFailure(
            profile with { Kind = AuthenticationKind.Static },
            401));
    }

    private static string Configuration(
        string? expiryKind = null,
        string? expirySelector = null,
        string? tokenSelector = null,
        string? destination = null,
        string? basic = null,
        bool includeExpiry = false,
        string? authenticationFailureStatusCodes = null)
    {
        var expiryMember = includeExpiry || expiryKind is not null
            ? ",\n                \"expiry\": "
                + (expiryKind is null
                    ? """{ "kind": "relativeSeconds", "source": "jsonPointer", "selector": "/expires_in" }"""
                    : $$"""{ "kind": "{{expiryKind}}", "source": "jsonPointer", "selector": "{{expirySelector}}" }""")
            : string.Empty;

        var statusCodes = authenticationFailureStatusCodes is null
            ? string.Empty
            : ",\n              \"authFailureStatusCodes\": " + authenticationFailureStatusCodes;

        return $$"""
            {
              "strategyId": "bounded-token-session-exchange",
              "inputs": { "username": "example-user" },
              "endpoint": "{{Endpoint}}",
              "method": "POST",
              "request": {
                "mediaType": "application/x-www-form-urlencoded",
                "fields": {
                  "username": { "source": "input", "slot": "username" },
                  "apikey": { "source": "secret", "slot": "apiKey" }
                },
                "headers": {
                  "X-Api-Version": { "source": "static", "value": "2" }
                }{{Basic(basic)}}
              },
              "response": {
                "token": {{tokenSelector ?? """{ "source": "jsonPointer", "selector": "/token" }"""}}{{expiryMember}}
              },
              "injection": { "location": "header", "name": "Authorization", "prefix": "Bearer " }{{Destination(destination)}}{{statusCodes}}
            }
            """;
    }

    private static string Basic(string? basic)
        => basic is null ? string.Empty : ",\n        \"basic\": " + basic;

    private static string Destination(string? destination)
        => destination is null ? string.Empty : ",\n              \"destination\": " + destination;

    private static AuthenticationProfile Profile(string configuration) =>
        new(
            "token-session-exchange",
            AuthenticationKind.TokenSessionExchange,
            Json(configuration),
            ["https://auth.example.com:443"],
            ["https://api.example.com:443"],
            ["exchange-api-key"]);

    private static ResolvedCredential Secret(string slot, string value) =>
        new(
            new ManifestCredential(
                "exchange-api-key",
                CredentialScheme.TokenSessionExchange,
                slot,
                CredentialReference.Literal("placeholder")),
            value);

    private static JsonObject Json(string text) =>
        CanonicalJson.Parse(Encoding.UTF8.GetBytes(text))!.AsObject();

    private static UpstreamResponse Responds(string body, string mediaType) => new(
        200,
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
        mediaType,
        new MemoryStream(Encoding.UTF8.GetBytes(body)));

    private sealed class RecordingTransport : IUpstreamTransport
    {
        private readonly UpstreamResponse _response;

        public RecordingTransport(UpstreamResponse response) => _response = response;

        public List<RecordedRequest> Requests { get; } = [];

        public Task<UpstreamResponse> SendAsync(
            UpstreamRequest request,
            UpstreamSendPolicy policy,
            CancellationToken cancellationToken)
        {
            Requests.Add(new RecordedRequest(
                request.Method,
                request.Uri,
                request.Body is { } body ? Encoding.UTF8.GetString(body) : string.Empty));

            return Task.FromResult(_response);
        }
    }

    private sealed record RecordedRequest(string Method, Uri Uri, string Form);

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
