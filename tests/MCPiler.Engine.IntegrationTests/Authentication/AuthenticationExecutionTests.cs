using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

using MCPiler.Engine.Authentication;
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

    /// <summary>One arrival, as the listener observed it.</summary>
    private sealed record Recorded(string Path, string? Authorization, string Form);

    private static async Task<EngineExecutionResult> RunAsync(
        ManifestDocument manifest,
        AuthenticationRuntime runtime)
    {
        using var clients = PermissiveClients();
        using var owned = runtime;
        var service = new ExecutionService(
            new UpstreamSender(clients),
            new ManifestSecretResolver(),
            files: null,
            runtime);

        return await service.ExecuteAsync(
            new ExecutionRequest(manifest, "get-thing", []),
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
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form));
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
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form));
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
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form));
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
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form));
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
            requests.Add(new Recorded(path, context.Request.Headers.Authorization, form));
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
        string authenticationRef)
    {
        var baseUrl = new Uri(host.Address, "thing");

        ManifestOperation operation = new(
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
}

