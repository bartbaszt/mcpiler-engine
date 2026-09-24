using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.OAuth1;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Authentication;

/// <summary>
/// End-to-end process flows for the ported authentication runtime: a real listener observes
/// what each strategy puts on the wire, and every test asserts both that the acquired material
/// arrived and that the stored secret did not.
/// </summary>
/// <remarks>
/// <para>
/// These tests exist because the unit suites substitute the transport. A substitution proves the
/// request the runtime built; only a listener proves the request the transport sent, through the
/// redirect loop, the signing hook and the rebinding that sit between them. The canary values
/// are per-test constants rather than fixtures so a leak names the test that leaked.
/// </para>
/// <para>
/// The outbound policy is permissive here on purpose: loopback is a denied address range and
/// refusing it is the real policy working. These tests are about authentication, so they supply
/// the policy through the outbound port instead of weakening the production one.
/// </para>
/// </remarks>
public sealed class AuthenticationExecutionTests : IDisposable
{
    private const string ClientSecretCanary = "CANARY-client-secret-b41f";
    private const string RefreshTokenCanary = "CANARY-refresh-token-7d02";
    private const string AccessTokenCanary = "CANARY-access-token-9ac1";
    private const string RotatedRefreshCanary = "CANARY-rotated-refresh-3e77";
    private const string ExchangeSecretCanary = "CANARY-exchange-secret-58bd";
    private const string SessionCanary = "CANARY-session-2f16";
    private const string SigningSecretCanary = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    private const string OAuthProfileId = "oauth2-client-credentials";
    private const string AuthorizationCodeProfileId = "oauth2-authorization-code-pkce-refresh";
    private const string ExchangeProfileId = "token-session-exchange";
    private const string ChallengeProfileId = "challenge-session";
    private const string SigningProfileId = "request-signing";
    private const string OAuth1ProfileId = "oauth1-authorization";

    private const string OAuth1ConsumerSecretCanary = "CANARY-oauth1-consumer-secret-c03e";
    private const string OAuth1TokenSecretCanary = "CANARY-oauth1-token-secret-91ab";

    private readonly List<string> _variables = [];

    [Fact]
    public async Task Client_credentials_put_the_acquired_token_on_the_wire_and_never_the_secret()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => TokenHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var secret = SetVariable(ClientSecretCanary);

        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential(
                    "oauth2-client-secret",
                    CredentialScheme.OAuth2ClientCredentials,
                    "clientSecret",
                    CredentialReference.Env(secret))),
            Profile(
                host,
                OAuthProfileId,
                AuthenticationKind.OAuth2ClientCredentials,
                $$"""
                {
                  "strategyId": "oauth2-client-credentials",
                  "tokenEndpoint": "{{host.Address}}token",
                  "clientId": "example-client",
                  "tokenAuthMethod": "client_secret_post",
                  "scopes": ["read"]
                }
                """,
                credentialRef: ["oauth2-client-secret"]),
            OAuthProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        var tokenCall = Assert.Single(requests, request => request.Path == "/token");
        Assert.Contains("grant_type=client_credentials", tokenCall.Form, StringComparison.Ordinal);
        Assert.Contains("client_id=example-client", tokenCall.Form, StringComparison.Ordinal);
        Assert.Contains($"client_secret={ClientSecretCanary}", tokenCall.Form, StringComparison.Ordinal);

        var apiCall = Assert.Single(requests, request => request.Path != "/token");
        Assert.Equal($"Bearer {AccessTokenCanary}", apiCall.Authorization);

        // The stored secret authenticates the token request. It never becomes a header the API
        // receives, and the access token never reaches the token endpoint.
        Assert.DoesNotContain(ClientSecretCanary, apiCall.Authorization ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(AccessTokenCanary, tokenCall.Form ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_rotated_refresh_token_is_committed_before_the_call_returns()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => TokenHandlerAsync(context, requests, refresh: RotatedRefreshCanary),
            TestContext.Current.CancellationToken);

        var secret = SetVariable(ClientSecretCanary);
        var declaredRefresh = SetVariable(RefreshTokenCanary);
        var slots = new InMemoryMutableSlotStore();

        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential(
                    "oauth2-authorization-client",
                    CredentialScheme.OAuth2AuthorizationCode,
                    "clientSecret",
                    CredentialReference.Env(secret)),
                new ManifestCredential(
                    "oauth2-authorization-refresh",
                    CredentialScheme.OAuth2AuthorizationCode,
                    "refreshToken",
                    CredentialReference.Env(declaredRefresh))),
            Profile(
                host,
                AuthorizationCodeProfileId,
                AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
                $$"""
                {
                  "strategyId": "oauth2-authorization-code-pkce-refresh",
                  "tokenEndpoint": "{{host.Address}}token",
                  "authorizationEndpoint": "{{host.Address}}authorize",
                  "clientId": "example-client",
                  "tokenAuthMethod": "client_secret_post"
                }
                """,
                credentialRef: ["oauth2-authorization-client", "oauth2-authorization-refresh"],
                slots: [new AuthenticationSlot("refreshToken", AuthorityEpoch: 1, RuntimeRevision: 0)]),
            AuthorizationCodeProfileId);

        using var clients = PermissiveClients();
        var sender = new UpstreamSender(clients);
        var result = await RunAsync(manifest, new AuthenticationRuntime(sender, slots: slots));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        var tokenCall = Assert.Single(requests, request => request.Path == "/token");
        Assert.Contains("grant_type=refresh_token", tokenCall.Form, StringComparison.Ordinal);
        Assert.Contains($"refresh_token={RefreshTokenCanary}", tokenCall.Form, StringComparison.Ordinal);
        Assert.Contains($"client_secret={ClientSecretCanary}", tokenCall.Form, StringComparison.Ordinal);

        // The rotating provider invalidated the declared credential the moment it answered.
        // Losing the replacement would make the next process unable to authenticate at all, so
        // the commit must be observable before this call reports success.
        var stored = await slots.LoadAsync(
            AuthorizationCodeProfileId,
            "refreshToken",
            TestContext.Current.CancellationToken);

        Assert.NotNull(stored);
        Assert.Equal(RotatedRefreshCanary, stored!.Value);
        Assert.Equal(1, stored.AuthorityEpoch);
        Assert.Equal(1, stored.RuntimeRevision);

        var apiCall = Assert.Single(requests, request => request.Path != "/token");
        Assert.Equal($"Bearer {AccessTokenCanary}", apiCall.Authorization);
        Assert.DoesNotContain(RotatedRefreshCanary, apiCall.Authorization ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Token_session_exchange_injects_the_acquired_session()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => ExchangeHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var secret = SetVariable(ExchangeSecretCanary);

        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential(
                    "exchange-api-key",
                    CredentialScheme.TokenSessionExchange,
                    "apiKey",
                    CredentialReference.Env(secret))),
            Profile(
                host,
                ExchangeProfileId,
                AuthenticationKind.TokenSessionExchange,
                $$"""
                {
                  "strategyId": "bounded-token-session-exchange",
                  "inputs": { "username": "example-user" },
                  "endpoint": "{{host.Address}}session",
                  "method": "POST",
                  "request": {
                    "mediaType": "application/x-www-form-urlencoded",
                    "fields": {
                      "username": { "source": "input", "slot": "username" },
                      "apikey": { "source": "secret", "slot": "apiKey" }
                    }
                  },
                  "response": { "token": { "source": "jsonPointer", "selector": "/token" } },
                  "injection": { "location": "header", "name": "Authorization", "prefix": "Bearer " },
                  "defaultLifetimeSeconds": 300,
                  "safetySkewSeconds": 15,
                  "authFailureStatusCodes": [401]
                }
                """,
                credentialRef: ["exchange-api-key"]),
            ExchangeProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        var exchangeCall = Assert.Single(requests, request => request.Path == "/session");
        Assert.Contains("username=example-user", exchangeCall.Form, StringComparison.Ordinal);
        Assert.Contains($"apikey={ExchangeSecretCanary}", exchangeCall.Form, StringComparison.Ordinal);

        var apiCall = Assert.Single(requests, request => request.Path != "/session");
        Assert.Equal($"Bearer {SessionCanary}", apiCall.Authorization);
        Assert.DoesNotContain(ExchangeSecretCanary, apiCall.Authorization ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_challenge_session_replays_once_with_the_captured_session()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => ChallengeHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var manifest = Manifest(
            host,
            CredentialsSection.Empty,
            Profile(
                host,
                ChallengeProfileId,
                AuthenticationKind.ChallengeSession,
                """
                {
                  "strategyId": "bounded-challenge-session",
                  "challenge": {
                    "statusCodes": [409],
                    "source": "header",
                    "selector": "X-Challenge"
                  },
                  "injection": { "location": "header", "name": "Authorization", "prefix": "Bearer " },
                  "replaySafeOperationKeys": ["GET /thing"],
                  "sessionLifetimeSeconds": 3600
                }
                """,
                credentialRef: []),
            ChallengeProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        // The challenged request carried nothing; the replayed one carried the session the
        // challenge response selected. Two arrivals, not more: the flow is bounded to one
        // replay and a third request would mean the disposition was misinterpreted.
        Assert.Equal(2, requests.Count);
        Assert.Null(requests[0].Authorization);
        Assert.Equal($"Bearer {SessionCanary}", requests[1].Authorization);
    }

    [Fact]
    public async Task Request_signing_signs_the_hop_and_never_sends_the_signing_secret()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => PlainHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var secret = SetVariable(SigningSecretCanary);

        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential(
                    "signing-secret",
                    CredentialScheme.RequestSigning,
                    "signingSecret",
                    CredentialReference.Env(secret))),
            Profile(
                host,
                SigningProfileId,
                AuthenticationKind.RequestSigning,
                """
                {
                  "strategyId": "request-signing-jwt-hmac",
                  "inputs": { "accessKeyId": "0123456789abcdef01234567" }
                }
                """,
                credentialRef: ["signing-secret"]),
            SigningProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        var apiCall = Assert.Single(requests);
        Assert.NotNull(apiCall.Authorization);
        Assert.StartsWith("Ghost ", apiCall.Authorization, StringComparison.Ordinal);

        // The signing secret is key material, never a wire value.
        Assert.DoesNotContain(SigningSecretCanary, apiCall.Authorization ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_redirect_is_signed_for_the_hop_it_actually_takes()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => RedirectHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var secret = SetVariable(ExchangeSecretCanary);

        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential(
                    "signing-secret",
                    CredentialScheme.RequestSigning,
                    "signingSecret",
                    CredentialReference.Env(secret))),
            Profile(
                host,
                SigningProfileId,
                AuthenticationKind.RequestSigning,
                """
                {
                  "strategyId": "request-signing-hmac",
                  "inputs": { "accessKeyId": "EXOexamplekey" }
                }
                """,
                credentialRef: ["signing-secret"]),
            SigningProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        // A signature covers one destination and one path, so the redirected hop must carry a
        // signature computed for that hop rather than a copy of the first one. Two different
        // values prove the hook ran per hop.
        Assert.Equal(2, requests.Count);
        Assert.NotNull(requests[0].Authorization);
        Assert.NotNull(requests[1].Authorization);
        Assert.NotEqual(requests[0].Authorization, requests[1].Authorization);
        Assert.DoesNotContain(ExchangeSecretCanary, requests[1].Authorization ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_strategy_with_no_installed_handler_sends_zero_requests()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => TokenHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        // Constructed in code on purpose: the loader refuses this kind, so a manifest could
        // never carry it, and the runtime refusal is what this asserts. A profile the runtime
        // cannot execute must cost nothing on the wire — no token request, no credential request.
        var manifest = Manifest(
            host,
            CredentialsSection.Empty,
            Profile(
                host,
                "reviewed-composite",
                AuthenticationKind.ReviewedComposite,
                """{ "strategyId": "reviewed-composite", "inputs": {} }""",
                credentialRef: []),
            "reviewed-composite");

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.Authentication, result.Failure);
        Assert.Empty(requests);
    }

    [Fact]
    public async Task An_unsupported_signer_configuration_sends_zero_credential_requests()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => PlainHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var secret = SetVariable(SigningSecretCanary);

        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential(
                    "signing-secret",
                    CredentialScheme.RequestSigning,
                    "signingSecret",
                    CredentialReference.Env(secret))),
            Profile(
                host,
                SigningProfileId,
                AuthenticationKind.RequestSigning,
                """
                {
                  "strategyId": "request-signing-unreviewed",
                  "inputs": { "accessKeyId": "0123456789abcdef01234567" }
                }
                """,
                credentialRef: ["signing-secret"]),
            SigningProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.Authentication, result.Failure);

        // The refusal happened before compilation, so no request was built and none was sent.
        Assert.Empty(requests);
    }

    public void Dispose()
    {
        foreach (var variable in _variables)
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    [Fact]
    public async Task OAuth1_header_flow_signs_the_request_and_never_sends_a_secret()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => OAuth1PlainHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var consumerSecret = SetVariable(OAuth1ConsumerSecretCanary);
        var tokenSecret = SetVariable(OAuth1TokenSecretCanary);

        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential(
                    "oauth1-consumer-secret",
                    CredentialScheme.OAuth1Authorization,
                    "consumerSecret",
                    CredentialReference.Env(consumerSecret)),
                new ManifestCredential(
                    "oauth1-token",
                    CredentialScheme.OAuth1Authorization,
                    "oauthToken",
                    CredentialReference.Env(SetVariable("CANARY-oauth1-token-id-44d1"))),
                new ManifestCredential(
                    "oauth1-token-secret",
                    CredentialScheme.OAuth1Authorization,
                    "oauthTokenSecret",
                    CredentialReference.Env(tokenSecret))),
            Profile(
                host,
                OAuth1ProfileId,
                AuthenticationKind.OAuth1Authorization,
                """
                {
                  "consumerKey": "example-client",
                  "signatureMethod": "HMAC-SHA1",
                  "parameterTransport": "authorization-header"
                }
                """,
                credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"]),
            OAuth1ProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        var apiCall = Assert.Single(requests);
        Assert.NotNull(apiCall.Authorization);
        Assert.StartsWith("OAuth ", apiCall.Authorization, StringComparison.Ordinal);
        Assert.Contains("oauth_signature_method=\"HMAC-SHA1\"", apiCall.Authorization, StringComparison.Ordinal);
        Assert.Contains("oauth_token=\"CANARY-oauth1-token-id-44d1\"", apiCall.Authorization, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuth1ConsumerSecretCanary, apiCall.Authorization ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuth1TokenSecretCanary, apiCall.Authorization ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuth1ConsumerSecretCanary, apiCall.Form ?? string.Empty, StringComparison.Ordinal);
        AssertOAuthSignature(apiCall, "authorization-header", "HMAC-SHA1", "example-client", OAuth1ConsumerSecretCanary, "CANARY-oauth1-token-id-44d1", OAuth1TokenSecretCanary);
        Assert.DoesNotContain("oauth_", result.Request!.ExactUrl, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OAuth1_query_flow_carries_fresh_parameters_in_the_uri_and_no_authorization_header()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => OAuth1PlainHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var consumerSecret = SetVariable(OAuth1ConsumerSecretCanary);
        var tokenSecret = SetVariable(OAuth1TokenSecretCanary);

        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential(
                    "oauth1-consumer-secret",
                    CredentialScheme.OAuth1Authorization,
                    "consumerSecret",
                    CredentialReference.Env(consumerSecret)),
                new ManifestCredential(
                    "oauth1-token",
                    CredentialScheme.OAuth1Authorization,
                    "oauthToken",
                    CredentialReference.Env(SetVariable("CANARY-oauth1-token-id-55e2"))),
                new ManifestCredential(
                    "oauth1-token-secret",
                    CredentialScheme.OAuth1Authorization,
                    "oauthTokenSecret",
                    CredentialReference.Env(tokenSecret))),
            Profile(
                host,
                OAuth1ProfileId,
                AuthenticationKind.OAuth1Authorization,
                """
                {
                  "consumerKey": "example-client",
                  "signatureMethod": "HMAC-SHA256",
                  "parameterTransport": "query"
                }
                """,
                credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"]),
            OAuth1ProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        var apiCall = Assert.Single(requests);
        Assert.Null(apiCall.Authorization);
        Assert.Contains("oauth_signature=", apiCall.Query, StringComparison.Ordinal);
        Assert.Contains("oauth_signature_method=HMAC-SHA256", apiCall.Query, StringComparison.Ordinal);
        Assert.Contains("oauth_nonce=", apiCall.Query, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuth1ConsumerSecretCanary, apiCall.Query, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuth1TokenSecretCanary, apiCall.Query, StringComparison.Ordinal);
        AssertOAuthSignature(apiCall, "query", "HMAC-SHA256", "example-client", OAuth1ConsumerSecretCanary, "CANARY-oauth1-token-id-55e2", OAuth1TokenSecretCanary);
        Assert.DoesNotContain("oauth_", result.Request!.ExactUrl, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OAuth1_form_body_redirect_is_resigned_from_the_final_uri_and_replayed_form_body()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => OAuth1RedirectHandlerAsync(context, requests, StatusCodes.Status307TemporaryRedirect, "/moved?redirect=second"),
            TestContext.Current.CancellationToken);

        var consumerSecret = SetVariable(OAuth1ConsumerSecretCanary);
        var tokenSecret = SetVariable(OAuth1TokenSecretCanary);
        string token = "CANARY-oauth1-form-token-8c52";
        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential("oauth1-consumer-secret", CredentialScheme.OAuth1Authorization, "consumerSecret", CredentialReference.Env(consumerSecret)),
                new ManifestCredential("oauth1-token", CredentialScheme.OAuth1Authorization, "oauthToken", CredentialReference.Env(SetVariable(token))),
                new ManifestCredential("oauth1-token-secret", CredentialScheme.OAuth1Authorization, "oauthTokenSecret", CredentialReference.Env(tokenSecret))),
            Profile(
                host,
                OAuth1ProfileId,
                AuthenticationKind.OAuth1Authorization,
                """
                {
                  "consumerKey": "example-client",
                  "signatureMethod": "HMAC-SHA1",
                  "parameterTransport": "form-body"
                }
                """,
                credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"]),
            OAuth1ProfileId,
            FormOperation("POST"));

        var clock = new AdvancingClock(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        var result = await RunAsync(
            manifest,
            new AuthenticationRuntime(new UpstreamSender(PermissiveClients()), timeProvider: clock),
            new JsonObject
            {
                ["body"] = new JsonObject
                {
                    ["ordinary"] = "hello world",
                    ["tag"] = new JsonArray("one", "two"),
                },
            });

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal(2, requests.Count);
        Assert.Equal("POST", requests[0].Method);
        Assert.Equal("POST", requests[1].Method);
        Assert.Equal("/thing/thing", requests[0].Path);
        Assert.Equal("/moved", requests[1].Path);
        Assert.Contains("redirect=second", requests[1].Query, StringComparison.Ordinal);
        Assert.Equal("application/x-www-form-urlencoded", requests[0].ContentType);
        Assert.Equal("application/x-www-form-urlencoded", requests[1].ContentType);

        foreach (Recorded request in requests)
        {
            var bodyPairs = OAuth1Canonicalizer.ParseFormEncodedPairs(request.Form);
            Assert.Contains(new KeyValuePair<string, string>("ordinary", "hello world"), bodyPairs);
            Assert.Equal(2, bodyPairs.Count(pair => pair.Key == "tag"));
            Assert.Equal(1, bodyPairs.Count(pair => pair.Key == "oauth_signature"));
            AssertOAuthSignature(request, "form-body", "HMAC-SHA1", "example-client", OAuth1ConsumerSecretCanary, token, OAuth1TokenSecretCanary);
        }

        var firstOAuth = OAuth1Canonicalizer.ParseFormEncodedPairs(requests[0].Form)
            .Where(pair => pair.Key.StartsWith("oauth_", StringComparison.Ordinal))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        var secondOAuth = OAuth1Canonicalizer.ParseFormEncodedPairs(requests[1].Form)
            .Where(pair => pair.Key.StartsWith("oauth_", StringComparison.Ordinal))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        Assert.NotEqual(firstOAuth["oauth_nonce"], secondOAuth["oauth_nonce"]);
        Assert.NotEqual(firstOAuth["oauth_timestamp"], secondOAuth["oauth_timestamp"]);
        Assert.NotEqual(firstOAuth["oauth_signature"], secondOAuth["oauth_signature"]);

        // Result inspection remains the compiler's unsigned semantic request, never a captured
        // signer-mutated URL or body.
        Assert.DoesNotContain("oauth_", result.Request!.ExactUrl, StringComparison.Ordinal);
        Assert.DoesNotContain(token, result.Request.ExactUrl, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OAuth1_ineligible_body_transport_refuses_before_resolving_credentials_or_sending()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => OAuth1PlainHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var credentials = Credentials(
            new ManifestCredential(
                "oauth1-consumer-secret",
                CredentialScheme.OAuth1Authorization,
                "consumerSecret",
                CredentialReference.Env("MCPILER_TEST_OAUTH1_CONSUMER_SECRET_UNSET")),
            new ManifestCredential(
                "oauth1-token",
                CredentialScheme.OAuth1Authorization,
                "oauthToken",
                CredentialReference.Env("MCPILER_TEST_OAUTH1_TOKEN_UNSET")),
            new ManifestCredential(
                "oauth1-token-secret",
                CredentialScheme.OAuth1Authorization,
                "oauthTokenSecret",
                CredentialReference.Env("MCPILER_TEST_OAUTH1_TOKEN_SECRET_UNSET")));
        var profile = Profile(
            host,
            OAuth1ProfileId,
            AuthenticationKind.OAuth1Authorization,
            """
            {
              "consumerKey": "example-client",
              "signatureMethod": "HMAC-SHA1",
              "parameterTransport": "form-body"
            }
            """,
            credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"]);
        var manifest = Manifest(host, credentials, profile, OAuth1ProfileId);
        var secretResolver = new CountingSecretResolver();

        var result = await RunAsync(
            manifest,
            new AuthenticationRuntime(new UpstreamSender(PermissiveClients())),
            secrets: secretResolver);

        Assert.Equal(ExecutionFailureKind.Authentication, result.Failure);
        Assert.Contains("body transport", result.FailureReason!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, secretResolver.Calls);
        Assert.Empty(requests);
    }

    [Fact]
    public async Task OAuth1_original_query_collision_refuses_before_resolving_credentials_or_sending()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => OAuth1PlainHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var credentials = Credentials(
            new ManifestCredential(
                "oauth1-consumer-secret",
                CredentialScheme.OAuth1Authorization,
                "consumerSecret",
                CredentialReference.Env("MCPILER_TEST_OAUTH1_CONSUMER_SECRET_UNSET")),
            new ManifestCredential(
                "oauth1-token",
                CredentialScheme.OAuth1Authorization,
                "oauthToken",
                CredentialReference.Env("MCPILER_TEST_OAUTH1_TOKEN_UNSET")),
            new ManifestCredential(
                "oauth1-token-secret",
                CredentialScheme.OAuth1Authorization,
                "oauthTokenSecret",
                CredentialReference.Env("MCPILER_TEST_OAUTH1_TOKEN_SECRET_UNSET")));
        var profile = Profile(
            host,
            OAuth1ProfileId,
            AuthenticationKind.OAuth1Authorization,
            """
            {
              "consumerKey": "example-client",
              "signatureMethod": "HMAC-SHA1",
              "parameterTransport": "query"
            }
            """,
            credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"]);
        var operation = new ManifestOperation(
            ManifestOperation.BuildKey("GET", "/thing"),
            "GET",
            "/thing",
            Parameters: [new ManifestParameter("oauth_token", ParameterLocation.Query, Required: true)]);
        var manifest = Manifest(host, credentials, profile, OAuth1ProfileId, operation);
        var secretResolver = new CountingSecretResolver();

        var result = await RunAsync(
            manifest,
            new AuthenticationRuntime(new UpstreamSender(PermissiveClients())),
            new JsonObject { ["oauth_token"] = "CANARY-original-oauth-token" },
            secretResolver);

        Assert.Equal(ExecutionFailureKind.Authentication, result.Failure);
        Assert.Contains("oauth_token", result.FailureReason!, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-original-oauth-token", result.FailureReason!, StringComparison.Ordinal);
        Assert.Equal(0, secretResolver.Calls);
        Assert.Empty(requests);
    }

    [Fact]
    public async Task OAuth1_initial_destination_scope_refuses_before_resolving_credentials_or_sending()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => OAuth1PlainHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var credentials = Credentials(
            new ManifestCredential(
                "oauth1-consumer-secret",
                CredentialScheme.OAuth1Authorization,
                "consumerSecret",
                CredentialReference.Env("MCPILER_TEST_OAUTH1_CONSUMER_SECRET_UNSET")),
            new ManifestCredential(
                "oauth1-token",
                CredentialScheme.OAuth1Authorization,
                "oauthToken",
                CredentialReference.Env("MCPILER_TEST_OAUTH1_TOKEN_UNSET")),
            new ManifestCredential(
                "oauth1-token-secret",
                CredentialScheme.OAuth1Authorization,
                "oauthTokenSecret",
                CredentialReference.Env("MCPILER_TEST_OAUTH1_TOKEN_SECRET_UNSET")));
        var profile = Profile(
            host,
            OAuth1ProfileId,
            AuthenticationKind.OAuth1Authorization,
            """
            {
              "consumerKey": "example-client",
              "signatureMethod": "HMAC-SHA1",
              "parameterTransport": "authorization-header"
            }
            """,
            credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"])
            with
            {
                DestinationOrigins = ["https://different.example.test:443"],
            };
        var manifest = Manifest(host, credentials, profile, OAuth1ProfileId);
        var secretResolver = new CountingSecretResolver();

        var result = await RunAsync(
            manifest,
            new AuthenticationRuntime(new UpstreamSender(PermissiveClients())),
            secrets: secretResolver);

        Assert.Equal(ExecutionFailureKind.Authentication, result.Failure);
        Assert.Contains("outside the stored authentication scope", result.FailureReason!, StringComparison.Ordinal);
        Assert.Equal(0, secretResolver.Calls);
        Assert.Empty(requests);
    }

    [Fact]
    public async Task OAuth1_post_302_rewrite_signs_get_target_without_replaying_the_body()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => OAuth1RedirectHandlerAsync(context, requests, StatusCodes.Status302Found, "/moved?redirect=post-to-get"),
            TestContext.Current.CancellationToken);

        var consumerSecret = SetVariable(OAuth1ConsumerSecretCanary);
        var tokenSecret = SetVariable(OAuth1TokenSecretCanary);
        string token = "CANARY-oauth1-method-token-2a6d";
        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential("oauth1-consumer-secret", CredentialScheme.OAuth1Authorization, "consumerSecret", CredentialReference.Env(consumerSecret)),
                new ManifestCredential("oauth1-token", CredentialScheme.OAuth1Authorization, "oauthToken", CredentialReference.Env(SetVariable(token))),
                new ManifestCredential("oauth1-token-secret", CredentialScheme.OAuth1Authorization, "oauthTokenSecret", CredentialReference.Env(tokenSecret))),
            Profile(
                host,
                OAuth1ProfileId,
                AuthenticationKind.OAuth1Authorization,
                """
                {
                  "consumerKey": "example-client",
                  "signatureMethod": "HMAC-SHA256",
                  "parameterTransport": "authorization-header"
                }
                """,
                credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"]),
            OAuth1ProfileId,
            FormOperation("POST"));

        var clock = new AdvancingClock(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        var result = await RunAsync(
            manifest,
            new AuthenticationRuntime(new UpstreamSender(PermissiveClients()), timeProvider: clock),
            new JsonObject { ["body"] = new JsonObject { ["ordinary"] = "before redirect" } });

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal(2, requests.Count);
        Assert.Equal("POST", requests[0].Method);
        Assert.Equal("GET", requests[1].Method);
        Assert.NotEmpty(requests[0].Form);
        Assert.Empty(requests[1].Form);
        Assert.Contains("redirect=post-to-get", requests[1].Query, StringComparison.Ordinal);
        AssertOAuthSignature(requests[0], "authorization-header", "HMAC-SHA256", "example-client", OAuth1ConsumerSecretCanary, token, OAuth1TokenSecretCanary);
        AssertOAuthSignature(requests[1], "authorization-header", "HMAC-SHA256", "example-client", OAuth1ConsumerSecretCanary, token, OAuth1TokenSecretCanary);

        var firstOAuth = ParseOAuthAuthorization(requests[0].Authorization!);
        var secondOAuth = ParseOAuthAuthorization(requests[1].Authorization!);
        Assert.NotEqual(firstOAuth["oauth_nonce"], secondOAuth["oauth_nonce"]);
        Assert.NotEqual(firstOAuth["oauth_timestamp"], secondOAuth["oauth_timestamp"]);
        Assert.NotEqual(firstOAuth["oauth_signature"], secondOAuth["oauth_signature"]);
    }

    [Fact]
    public async Task OAuth1_query_values_are_redacted_from_transport_failure_diagnostics()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            async context =>
            {
                var recorded = await RecordOAuth1Async(context);
                lock (requests)
                {
                    requests.Add(recorded);
                }

                if (requests.Count == 1)
                {
                    context.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
                    context.Response.Headers.Location = "/malformed";
                    return;
                }

                context.Response.StatusCode = StatusCodes.Status302Found;
                // Deliberately omit Location: this failure message includes the current URI.
            },
            TestContext.Current.CancellationToken);

        var consumerSecret = SetVariable(OAuth1ConsumerSecretCanary);
        var tokenSecret = SetVariable(OAuth1TokenSecretCanary);
        string token = "CANARY-oauth1-diagnostic-token-f4b1";
        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential("oauth1-consumer-secret", CredentialScheme.OAuth1Authorization, "consumerSecret", CredentialReference.Env(consumerSecret)),
                new ManifestCredential("oauth1-token", CredentialScheme.OAuth1Authorization, "oauthToken", CredentialReference.Env(SetVariable(token))),
                new ManifestCredential("oauth1-token-secret", CredentialScheme.OAuth1Authorization, "oauthTokenSecret", CredentialReference.Env(tokenSecret))),
            Profile(
                host,
                OAuth1ProfileId,
                AuthenticationKind.OAuth1Authorization,
                """
                {
                  "consumerKey": "example-client",
                  "signatureMethod": "HMAC-SHA1",
                  "parameterTransport": "query"
                }
                """,
                credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"]),
            OAuth1ProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.Transport, result.Failure);
        Assert.Equal(2, requests.Count);
        Assert.Contains("oauth_token=%5BREDACTED%5D", result.FailureReason!, StringComparison.Ordinal);
        Assert.Contains("oauth_signature=%5BREDACTED%5D", result.FailureReason!, StringComparison.Ordinal);
        Assert.DoesNotContain(token, result.FailureReason!, StringComparison.Ordinal);
        Assert.Contains("oauth_nonce=%5BREDACTED%5D", result.FailureReason!, StringComparison.Ordinal);
        Assert.Contains("oauth_timestamp=%5BREDACTED%5D", result.FailureReason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OAuth1_redirect_is_resigned_for_the_hop_it_actually_takes()
    {
        var requests = new List<Recorded>();
        await using var host = await LoopbackHost.StartAsync(
            context => RedirectHandlerAsync(context, requests),
            TestContext.Current.CancellationToken);

        var consumerSecret = SetVariable(OAuth1ConsumerSecretCanary);
        var tokenSecret = SetVariable(OAuth1TokenSecretCanary);

        var manifest = Manifest(
            host,
            Credentials(
                new ManifestCredential(
                    "oauth1-consumer-secret",
                    CredentialScheme.OAuth1Authorization,
                    "consumerSecret",
                    CredentialReference.Env(consumerSecret)),
                new ManifestCredential(
                    "oauth1-token",
                    CredentialScheme.OAuth1Authorization,
                    "oauthToken",
                    CredentialReference.Env(SetVariable("CANARY-oauth1-token-id-66f3"))),
                new ManifestCredential(
                    "oauth1-token-secret",
                    CredentialScheme.OAuth1Authorization,
                    "oauthTokenSecret",
                    CredentialReference.Env(tokenSecret))),
            Profile(
                host,
                OAuth1ProfileId,
                AuthenticationKind.OAuth1Authorization,
                """
                {
                  "consumerKey": "example-client",
                  "signatureMethod": "HMAC-SHA1",
                  "parameterTransport": "authorization-header"
                }
                """,
                credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"]),
            OAuth1ProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        // The redirect target is a different request: it must carry a freshly computed
        // signature, never a copy of the first hop, and no secret material either way.
        Assert.Equal(2, requests.Count);
        Assert.NotNull(requests[0].Authorization);
        Assert.NotNull(requests[1].Authorization);
        Assert.NotEqual(requests[0].Authorization, requests[1].Authorization);
        Assert.Equal("/moved", requests[1].Path);
        Assert.DoesNotContain(OAuth1ConsumerSecretCanary, requests[1].Authorization ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuth1TokenSecretCanary, requests[1].Authorization ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OAuth1_redirect_outside_the_profile_scope_sends_nothing_there()
    {
        var firstRequests = new List<Recorded>();
        var secondRequests = new List<Recorded>();
        await using var second = await LoopbackHost.StartAsync(
            context => PlainHandlerAsync(context, secondRequests),
            TestContext.Current.CancellationToken);
        await using var first = await LoopbackHost.StartAsync(
            context => CrossOriginRedirectHandlerAsync(context, firstRequests, second.Address.ToString()),
            TestContext.Current.CancellationToken);

        var consumerSecret = SetVariable(OAuth1ConsumerSecretCanary);
        var tokenSecret = SetVariable(OAuth1TokenSecretCanary);

        // The broad perimeter admits both loopback origins, but the profile scope names only
        // the first: the second hop must be refused before credential material is attached.
        var manifest = ManifestWithPolicyOrigins(
            first,
            [first.Address.GetLeftPart(UriPartial.Authority), second.Address.GetLeftPart(UriPartial.Authority)],
            Credentials(
                new ManifestCredential(
                    "oauth1-consumer-secret",
                    CredentialScheme.OAuth1Authorization,
                    "consumerSecret",
                    CredentialReference.Env(consumerSecret)),
                new ManifestCredential(
                    "oauth1-token",
                    CredentialScheme.OAuth1Authorization,
                    "oauthToken",
                    CredentialReference.Env(SetVariable("CANARY-oauth1-token-id-77a4"))),
                new ManifestCredential(
                    "oauth1-token-secret",
                    CredentialScheme.OAuth1Authorization,
                    "oauthTokenSecret",
                    CredentialReference.Env(tokenSecret))),
            Profile(
                first,
                OAuth1ProfileId,
                AuthenticationKind.OAuth1Authorization,
                """
                {
                  "consumerKey": "example-client",
                  "signatureMethod": "HMAC-SHA1",
                  "parameterTransport": "authorization-header"
                }
                """,
                credentialRef: ["oauth1-consumer-secret", "oauth1-token", "oauth1-token-secret"]),
            OAuth1ProfileId);

        var result = await RunAsync(manifest, new AuthenticationRuntime(new UpstreamSender(PermissiveClients())));

        Assert.Equal(ExecutionFailureKind.Authentication, result.Failure);
        Assert.Single(firstRequests);
        Assert.Empty(secondRequests);
    }

    /// <summary>One arrival, as the listener observed it.</summary>
    private sealed record Recorded(string Path, string? Authorization, string Form, string Query)
    {
        public string Method { get; init; } = "GET";

        public string FullUri { get; init; } = string.Empty;

        public string? ContentType { get; init; }
    }

    /// <summary>Redirects the first arrival to the target, which must never be reached.</summary>
    private static async Task CrossOriginRedirectHandlerAsync(HttpContext context, List<Recorded> requests, string target)
    {
        string path = context.Request.Path.Value ?? "/";
        string form = await ReadBodyAsync(context);
        int arrival;

        lock (requests)
        {
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form, context.Request.QueryString.Value ?? string.Empty));
            arrival = requests.Count;
        }

        if (arrival == 1)
        {
            context.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
            context.Response.Headers.Location = target;
            return;
        }

        await WriteAsync(context, 200, "text/plain", "ok");
    }

    private static async Task OAuth1RedirectHandlerAsync(
        HttpContext context,
        List<Recorded> requests,
        int redirectStatus,
        string location)
    {
        Recorded recorded = await RecordOAuth1Async(context);
        int arrival;
        lock (requests)
        {
            requests.Add(recorded);
            arrival = requests.Count;
        }

        if (arrival == 1)
        {
            context.Response.StatusCode = redirectStatus;
            context.Response.Headers.Location = location;
            return;
        }

        await WriteAsync(context, StatusCodes.Status200OK, "text/plain", "ok");
    }

    private static async Task OAuth1PlainHandlerAsync(HttpContext context, List<Recorded> requests)
    {
        Recorded recorded = await RecordOAuth1Async(context);
        lock (requests)
        {
            requests.Add(recorded);
        }

        await WriteAsync(context, StatusCodes.Status200OK, "text/plain", "ok");
    }

    private static async Task<Recorded> RecordOAuth1Async(HttpContext context)
    {
        string path = context.Request.Path.Value ?? "/";
        string form = await ReadBodyAsync(context);
        string query = context.Request.QueryString.Value ?? string.Empty;
        string fullUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}{context.Request.Path}{query}";

        return new Recorded(path, context.Request.Headers.Authorization, form, query)
        {
            Method = context.Request.Method,
            FullUri = fullUri,
            ContentType = context.Request.ContentType,
        };
    }

    private static void AssertOAuthSignature(
        Recorded request,
        string transport,
        string signatureMethod,
        string consumerKey,
        string consumerSecret,
        string token,
        string tokenSecret)
    {
        var uri = new Uri(request.FullUri, UriKind.Absolute);
        var parameters = new List<KeyValuePair<string, string>>(OAuth1Canonicalizer.ParseQueryPairs(uri));
        if (OAuth1Canonicalizer.IsFormUrlEncodedContentType(request.ContentType))
        {
            parameters.AddRange(OAuth1Canonicalizer.ParseFormEncodedPairs(request.Form));
        }

        if (string.Equals(transport, "authorization-header", StringComparison.Ordinal))
        {
            parameters.AddRange(ParseOAuthAuthorization(request.Authorization!));
        }

        string signature = parameters.Single(pair => pair.Key == "oauth_signature").Value;
        parameters.RemoveAll(pair => pair.Key == "oauth_signature");

        string normalized = OAuth1Canonicalizer.NormalizeParameters([.. parameters]);
        string baseString = OAuth1Canonicalizer.BuildSignatureBaseString(
            request.Method,
            OAuth1Canonicalizer.BaseStringUri(uri),
            normalized);
        byte[] key = Encoding.UTF8.GetBytes(
            OAuth1Canonicalizer.Rfc3986Encode(consumerSecret)
            + "&"
            + OAuth1Canonicalizer.Rfc3986Encode(tokenSecret));
        byte[] message = Encoding.UTF8.GetBytes(baseString);
        byte[] digest = signatureMethod switch
        {
#pragma warning disable CA5350 // Independent test verification for the reviewed OAuth1 HMAC-SHA1 compatibility method.
            "HMAC-SHA1" => HMACSHA1.HashData(key, message),
#pragma warning restore CA5350
            "HMAC-SHA256" => HMACSHA256.HashData(key, message),
            _ => throw new InvalidOperationException($"Test verifier does not support '{signatureMethod}'."),
        };
        string expected = Convert.ToBase64String(digest);

        Assert.Equal(consumerKey, parameters.Single(pair => pair.Key == "oauth_consumer_key").Value);
        Assert.Equal(token, parameters.Single(pair => pair.Key == "oauth_token").Value);
        Assert.Equal(expected, signature);
    }

    private static Dictionary<string, string> ParseOAuthAuthorization(string value)
    {
        string parameters = value.StartsWith("OAuth ", StringComparison.Ordinal)
            ? value["OAuth ".Length..]
            : value;

        return parameters.Split(',').Select(part =>
        {
            string trimmed = part.Trim();
            int separator = trimmed.IndexOf('=');
            string name = Uri.UnescapeDataString(trimmed[..separator]);
            string quoted = trimmed[(separator + 1)..].Trim();
            return new KeyValuePair<string, string>(
                name,
                Uri.UnescapeDataString(quoted[1..^1]));
        }).ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    }

    private static ManifestOperation FormOperation(string method)
    {
        const string mediaType = "application/x-www-form-urlencoded";
        return new ManifestOperation(
            ManifestOperation.BuildKey(method, "/thing"),
            method,
            "/thing",
            RequestBody: new ManifestRequestBody(
                new Dictionary<string, ManifestMediaType>(StringComparer.Ordinal)
                {
                    [mediaType] = new ManifestMediaType(mediaType),
                },
                Required: true));
    }

    private static ManifestDocument ManifestWithPolicyOrigins(
        LoopbackHost host,
        IReadOnlyList<string> policyOrigins,
        CredentialsSection credentials,
        AuthenticationProfile profile,
        string authenticationRef,
        ManifestOperation? operation = null)
    {
        var baseUrl = new Uri(host.Address, "thing");

        operation ??= new ManifestOperation(
            ManifestOperation.BuildKey("GET", "/thing"),
            "GET",
            "/thing");

        return new ManifestDocument(
            ManifestFormatSupport.Maximum,
            new ServerSection("test-server", Version: "1.0.0"),
            new PolicySection(baseUrl, policyOrigins),
            new OperationsSection([operation]),
            new AgentSurfaceSection(
            [
                new AgentOperationEntry(
                    "get-thing",
                    "Get thing",
                    new HttpBinding(operation.Key, AuthenticationRef: authenticationRef)),
            ]),
            credentials,
            new AuthenticationSection([profile]));
    }

    private static async Task<EngineExecutionResult> RunAsync(
        ManifestDocument manifest,
        AuthenticationRuntime runtime,
        JsonObject? arguments = null,
        IManifestSecretResolver? secrets = null)
    {
        using var clients = PermissiveClients();
        using var owned = runtime;
        var service = new ExecutionService(
            new UpstreamSender(clients),
            secrets ?? new ManifestSecretResolver(),
            files: null,
            runtime);

        return await service.ExecuteAsync(
            new ExecutionRequest(manifest, "get-thing", arguments ?? []),
            TestContext.Current.CancellationToken);
    }

    private static OutboundConnectionPolicy PermissivePolicy() => new(_ => false);

    private static UpstreamClientFactory PermissiveClients() => new(PermissivePolicy());

    /// <summary>
    /// Answers a token call with the configured material and records every arrival, so one
    /// handler can serve both the token endpoint and the API the credential is applied to.
    /// </summary>
    private static async Task TokenHandlerAsync(
        HttpContext context,
        List<Recorded> requests,
        string? refresh = null)
    {
        string path = context.Request.Path.Value ?? "/";
        string form = await ReadBodyAsync(context);

        lock (requests)
        {
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form, context.Request.QueryString.Value ?? string.Empty));
        }

        if (string.Equals(path, "/token", StringComparison.Ordinal))
        {
            var payload = new JsonObject
            {
                ["access_token"] = AccessTokenCanary,
                ["token_type"] = "Bearer",
                ["expires_in"] = 3600,
            };

            if (refresh is not null)
            {
                payload["refresh_token"] = refresh;
            }

            await WriteAsync(context, 200, "application/json", payload.ToJsonString());
            return;
        }

        await WriteAsync(context, 200, "text/plain", "ok");
    }

    private static async Task ExchangeHandlerAsync(HttpContext context, List<Recorded> requests)
    {
        string path = context.Request.Path.Value ?? "/";
        string form = await ReadBodyAsync(context);

        lock (requests)
        {
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form, context.Request.QueryString.Value ?? string.Empty));
        }

        if (string.Equals(path, "/session", StringComparison.Ordinal))
        {
            await WriteAsync(context, 200, "application/json", $$"""{ "token": "{{SessionCanary}}" }""");
            return;
        }

        await WriteAsync(context, 200, "text/plain", "ok");
    }

    /// <summary>Challenges the first arrival and accepts the replay that carries the session.</summary>
    private static async Task ChallengeHandlerAsync(HttpContext context, List<Recorded> requests)
    {
        string path = context.Request.Path.Value ?? "/";
        string form = await ReadBodyAsync(context);
        int arrival;

        lock (requests)
        {
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form, context.Request.QueryString.Value ?? string.Empty));
            arrival = requests.Count;
        }

        if (arrival == 1)
        {
            context.Response.Headers["X-Challenge"] = SessionCanary;
            await WriteAsync(context, 409, "text/plain", "challenge");
            return;
        }

        await WriteAsync(context, 200, "text/plain", "ok");
    }

    /// <summary>The first request signs and is redirected; the second is where it lands.</summary>
    private static async Task RedirectHandlerAsync(HttpContext context, List<Recorded> requests)
    {
        string path = context.Request.Path.Value ?? "/";
        string form = await ReadBodyAsync(context);
        int arrival;

        lock (requests)
        {
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form, context.Request.QueryString.Value ?? string.Empty));
            arrival = requests.Count;
        }

        if (arrival == 1)
        {
            context.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
            context.Response.Headers.Location = "/moved";
            return;
        }

        await WriteAsync(context, 200, "text/plain", "ok");
    }

    private static async Task PlainHandlerAsync(HttpContext context, List<Recorded> requests)
    {
        string path = context.Request.Path.Value ?? "/";
        string form = await ReadBodyAsync(context);

        lock (requests)
        {
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form, context.Request.QueryString.Value ?? string.Empty));
        }

        await WriteAsync(context, 200, "text/plain", "ok");
    }

    private static async Task WriteAsync(HttpContext context, int status, string mediaType, string body)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(body);
        context.Response.StatusCode = status;
        context.Response.ContentType = mediaType;
        context.Response.ContentLength = bytes.Length;
        await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
    }

    private static async Task<string> ReadBodyAsync(HttpContext context)
    {
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
        return await reader.ReadToEndAsync(context.RequestAborted);
    }

    private static ManifestDocument Manifest(
        LoopbackHost host,
        CredentialsSection credentials,
        AuthenticationProfile profile,
        string authenticationRef,
        ManifestOperation? operation = null)
    {
        var baseUrl = new Uri(host.Address, "thing");

        operation ??= new ManifestOperation(
            ManifestOperation.BuildKey("GET", "/thing"),
            "GET",
            "/thing");

        return new ManifestDocument(
            ManifestFormatSupport.Maximum,
            new ServerSection("test-server", Version: "1.0.0"),
            new PolicySection(baseUrl, [host.Address.GetLeftPart(UriPartial.Authority)]),
            new OperationsSection([operation]),
            new AgentSurfaceSection(
            [
                new AgentOperationEntry(
                    "get-thing",
                    "Get thing",
                    new HttpBinding(operation.Key, AuthenticationRef: authenticationRef)),
            ]),
            credentials,
            new AuthenticationSection([profile]));
    }

    private static CredentialsSection Credentials(params ManifestCredential[] credentials) =>
        credentials.Length == 0 ? CredentialsSection.Empty : new CredentialsSection(credentials);

    private static AuthenticationProfile Profile(
        LoopbackHost host,
        string id,
        AuthenticationKind kind,
        string configuration,
        IReadOnlyList<string> credentialRef,
        IReadOnlyList<AuthenticationSlot>? slots = null)
    {
        string origin = host.Address.GetLeftPart(UriPartial.Authority);

        return new AuthenticationProfile(
            id,
            kind,
            CanonicalJson.Parse(Encoding.UTF8.GetBytes(configuration))!.AsObject(),
            [origin],
            [origin],
            credentialRef,
            ScopeFingerprint: null,
            slots ?? []);
    }

    private string SetVariable(string value)
    {
        var name = "MCPILER_AUTH_TEST_" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        Environment.SetEnvironmentVariable(name, value);
        _variables.Add(name);
        return name;
    }

    private sealed class AdvancingClock(DateTimeOffset start) : TimeProvider
    {
        private long _seconds = -1;

        public override DateTimeOffset GetUtcNow()
            => start.AddSeconds(Interlocked.Increment(ref _seconds));
    }

    private sealed class CountingSecretResolver : IManifestSecretResolver
    {
        public int Calls { get; private set; }

        public ValueTask<IReadOnlyList<ResolvedCredential>> ResolveAsync(
            CredentialsSection credentials,
            IReadOnlyList<string> credentialRefs,
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromResult<IReadOnlyList<ResolvedCredential>>([]);
        }
    }
}

