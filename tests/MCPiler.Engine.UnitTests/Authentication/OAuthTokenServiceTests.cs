using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Caching;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;
using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// The OAuth acquisition path: client-credentials and refresh grants, cache reuse, single-flight
/// coalescing, and rotation commit ordering.
/// </summary>
/// <remarks>
/// The transport is a substitute, so the assertions are about what the service asked for and what
/// it did with the answer. The ordering assertions matter most: a rotating provider makes
/// commit-before-publish the difference between a usable deployment and one holding a credential
/// the provider has already retired.
/// </remarks>
public sealed class OAuthTokenServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private const string TokenEndpoint = "https://auth.example.com/oauth2/token";

    [Fact]
    public async Task Client_credentials_acquires_a_bearer_and_requests_scope_resource_and_audience()
    {
        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var service = Service(transport);

        var acquisition = await service.AcquireAsync(
            ClientCredentialsProfile(),
            [Secret("oauth2-client-credentials", "clientSecret", "client-canary")],
            CancellationToken.None);

        var credential = Assert.Single(acquisition.Credentials);

        Assert.Equal(CredentialScheme.Bearer, credential.Declaration.Scheme);
        Assert.Equal("access-a", credential.Value);

        var sent = Assert.Single(transport.Requests);
        Assert.Contains("grant_type=client_credentials", sent.Form, StringComparison.Ordinal);
        Assert.Contains("scope=read%20write", sent.Form, StringComparison.Ordinal);
        Assert.Contains("resource=https%3A%2F%2Fapi.example.com", sent.Form, StringComparison.Ordinal);
        Assert.Contains("audience=api", sent.Form, StringComparison.Ordinal);

        // The client secret travels to the reviewed endpoint and nowhere else.
        Assert.Contains("client_secret=client-canary", sent.Form, StringComparison.Ordinal);
        Assert.Contains("client_id=example-client", sent.Form, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Client_secret_basic_form_encodes_each_component_before_base64()
    {
        // RFC 6749 Appendix B: a space is "+" and a literal "+" is "%2B" before the colon join and
        // Base64, so a client id/secret containing those characters still decodes to the exact value.
        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var client = new OAuthTokenEndpointClient(transport, new AdvanceableClock(Now));
        var configuration = Configuration(
            """{"clientId":"client id+1","tokenEndpoint":"https://auth.example.com/oauth2/token","tokenAuthMethod":"client_secret_basic"}""");

        await client.ExchangeAsync(
            configuration,
            ["https://auth.example.com:443"],
            new Dictionary<string, string> { ["grant_type"] = "client_credentials" },
            "sec ret+%/value",
            CancellationToken.None);

        var sent = Assert.Single(transport.Requests);
        var basic = Assert.Single(sent.Headers["Authorization"]);
        Assert.StartsWith("Basic ", basic, StringComparison.Ordinal);

        // The decoded halves must equal the form-encoded components, not the raw values.
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(basic["Basic ".Length..]));
        Assert.Equal("client+id%2B1:sec+ret%2B%25%2Fvalue", decoded);

        // The raw secret must not appear anywhere on the wire, including diagnostics.
        Assert.DoesNotContain("sec ret+%/value", decoded, StringComparison.Ordinal);
        Assert.All(sent.Headers.Values, values =>
            Assert.All(values, value => Assert.DoesNotContain("sec ret+%/value", value, StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Revocation_client_secret_basic_form_encodes_each_component_before_base64()
    {
        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var client = new OAuthTokenEndpointClient(transport, new AdvanceableClock(Now));
        var configuration = Configuration(
            """{"clientId":"id:+","tokenEndpoint":"https://auth.example.com/oauth2/token","revocationEndpoint":"https://auth.example.com/oauth2/revoke","tokenAuthMethod":"client_secret_basic"}""");

        await client.RevokeRefreshTokenAsync(
            configuration,
            ["https://auth.example.com:443"],
            "refresh-canary",
            "pwd a+b%c",
            CancellationToken.None);

        var sent = Assert.Single(transport.Requests);
        var basic = Assert.Single(sent.Headers["Authorization"]);
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(basic["Basic ".Length..]));
        Assert.Equal("id%3A%2B:pwd+a%2Bb%25c", decoded);
    }

    [Fact]
    public async Task Client_secret_basic_preserves_non_BMP_characters_as_utf8_bytes()
    {
        // R1.3 / MTH-SECRET-4: a char-by-char encoder splits a UTF-16 surrogate pair into two lone
        // surrogates and encodes each as the replacement character (%EF%BF%BD%EF%BF%BD). The RFC 6749
        // form encoding must instead emit the UTF-8 bytes of the code point (U+1F600 -> %F0%9F%98%80).
        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var client = new OAuthTokenEndpointClient(transport, new AdvanceableClock(Now));
        var configuration = Configuration(
            """{"clientId":"emoji-client","tokenEndpoint":"https://auth.example.com/oauth2/token","tokenAuthMethod":"client_secret_basic"}""");

        await client.ExchangeAsync(
            configuration,
            ["https://auth.example.com:443"],
            new Dictionary<string, string> { ["grant_type"] = "client_credentials" },
            "p\u00e4ss\U0001F600word",
            CancellationToken.None);

        var sent = Assert.Single(transport.Requests);
        var basic = Assert.Single(sent.Headers["Authorization"]);
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(basic["Basic ".Length..]));

        Assert.Equal("emoji-client:p%C3%A4ss%F0%9F%98%80word", decoded);
        Assert.DoesNotContain("%EF%BF%BD", decoded, StringComparison.Ordinal);

        // The raw secret must never appear on the wire or in diagnostics.
        Assert.DoesNotContain("p\u00e4ss\U0001F600word", decoded, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_cached_token_is_reused_without_another_exchange()
    {
        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var service = Service(transport);
        var profile = ClientCredentialsProfile();
        IReadOnlyList<ResolvedCredential> credentials =
            [Secret("oauth2-client-credentials", "clientSecret", "client-canary")];

        var first = await service.AcquireAsync(profile, credentials, CancellationToken.None);
        var second = await service.AcquireAsync(profile, credentials, CancellationToken.None);

        Assert.Equal("access-a", first.Credentials[0].Value);
        Assert.Equal("access-a", second.Credentials[0].Value);
        Assert.Single(transport.Requests);
    }

    [Fact]
    public async Task A_token_within_the_safety_skew_is_reacquired()
    {
        // 40 seconds of life with 30 seconds of skew leaves 10 usable seconds; advancing the clock
        // past that must force a new exchange rather than return a token about to expire.
        var transport = new RecordingTransport(Responds("access-a", expiresIn: 40), Responds("access-b", expiresIn: 3600));
        var clock = new AdvanceableClock(Now);
        var service = Service(transport, clock);

        var first = await service.AcquireAsync(ClientCredentialsProfile(), [Secret("oauth2-client-credentials", "clientSecret", "s")], CancellationToken.None);
        clock.Advance(TimeSpan.FromSeconds(20));
        var second = await service.AcquireAsync(ClientCredentialsProfile(), [Secret("oauth2-client-credentials", "clientSecret", "s")], CancellationToken.None);

        Assert.Equal("access-a", first.Credentials[0].Value);
        Assert.Equal("access-b", second.Credentials[0].Value);
        Assert.Equal(2, transport.Requests.Count);
    }

    [Fact]
    public async Task A_new_runtime_revision_does_not_reuse_the_previous_token()
    {
        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600), Responds("access-b", expiresIn: 3600));
        var service = Service(transport);

        var first = await service.AcquireAsync(
            ClientCredentialsProfile(slot: new AuthenticationSlot("clientSecret", 1, 0)),
            [Secret("oauth2-client-credentials", "clientSecret", "s")],
            CancellationToken.None);

        var second = await service.AcquireAsync(
            ClientCredentialsProfile(slot: new AuthenticationSlot("clientSecret", 1, 1)),
            [Secret("oauth2-client-credentials", "clientSecret", "s")],
            CancellationToken.None);

        Assert.Equal("access-a", first.Credentials[0].Value);
        Assert.Equal("access-b", second.Credentials[0].Value);
        Assert.Equal(2, transport.Requests.Count);
    }

    [Fact]
    public async Task A_grant_without_a_client_secret_is_refused_before_any_request()
    {
        var transport = new RecordingTransport();
        var service = Service(transport);

        await Assert.ThrowsAsync<CredentialUnavailableException>(async () =>
            await service.AcquireAsync(ClientCredentialsProfile(), [], CancellationToken.None).AsTask());

        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task An_authorization_code_profile_without_a_refresh_token_is_refused()
    {
        var transport = new RecordingTransport();
        var service = Service(transport);

        await Assert.ThrowsAsync<CredentialUnavailableException>(async () =>
            await service.AcquireAsync(AuthorizationCodeProfile(), [], CancellationToken.None).AsTask());

        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task A_rotated_refresh_token_is_committed_before_the_acquisition_is_returned()
    {
        var slots = new InMemoryMutableSlotStore();
        var rotations = new List<RotatedRefreshToken>();

        // The seam proves ordering: when the store is asked to commit, the service must not yet
        // have returned the acquisition this token produced.
        var returned = false;
        slots.OnBeforeCommitAsync = _ =>
        {
            Assert.False(returned, "the rotation was published before it was durable");
            return ValueTask.CompletedTask;
        };

        var transport = new RecordingTransport(RespondsWithRefresh("access-a", "rotated-refresh", expiresIn: 3600));
        var service = Service(
            transport,
            slots: slots,
            onRotated: (rotation, _) =>
            {
                rotations.Add(rotation);
                return ValueTask.CompletedTask;
            });

        var profile = AuthorizationCodeProfile(slot: new AuthenticationSlot("refreshToken", 1, 0));
        var acquisition = await service.AcquireAsync(
            profile,
            [Secret("oauth2-authorization-code", "clientSecret", "client-secret-canary"), Secret("oauth2-authorization-code", "refreshToken", "initial-refresh")],
            CancellationToken.None);

        returned = true;

        Assert.Equal("access-a", acquisition.Credentials[0].Value);
        Assert.Equal(1, acquisition.AuthorityEpoch);
        Assert.Equal(1, acquisition.RuntimeRevision);

        var stored = await slots.LoadAsync(profile.Id, "refreshToken", CancellationToken.None);
        Assert.NotNull(stored);
        Assert.Equal("rotated-refresh", stored!.Value);
        Assert.Equal(1, stored.AuthorityEpoch);
        Assert.Equal(1, stored.RuntimeRevision);

        var rotation = Assert.Single(rotations);
        Assert.Equal("refreshToken", rotation.Slot);
        Assert.Equal(0, rotation.PreviousRuntimeRevision);
        Assert.Equal(1, rotation.RuntimeRevision);
    }

    [Fact]
    public async Task A_committed_rotation_is_preferred_over_the_declared_refresh_token()
    {
        var slots = new InMemoryMutableSlotStore();
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", null, 1, 5, "stored-refresh"),
            CancellationToken.None);

        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var service = Service(transport, slots: slots);

        await service.AcquireAsync(
            AuthorizationCodeProfile(slot: new AuthenticationSlot("refreshToken", 1, 0)),
            [Secret("oauth2-authorization-code", "clientSecret", "client-secret-canary"), Secret("oauth2-authorization-code", "refreshToken", "declared-refresh")],
            CancellationToken.None);

        Assert.Contains("refresh_token=stored-refresh", transport.Requests[0].Form, StringComparison.Ordinal);
        Assert.DoesNotContain("declared-refresh", transport.Requests[0].Form, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_rotation_from_an_older_authority_epoch_is_never_used()
    {
        var slots = new InMemoryMutableSlotStore();
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", null, 1, 9, "old-epoch-refresh"),
            CancellationToken.None);

        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var service = Service(transport, slots: slots);

        // The deployment now declares epoch 2: an explicit operator action superseded everything
        // the runtime rotated under epoch 1, so the declared value is authoritative again.
        await service.AcquireAsync(
            AuthorizationCodeProfile(slot: new AuthenticationSlot("refreshToken", 2, 0)),
            [Secret("oauth2-authorization-code", "clientSecret", "client-secret-canary"), Secret("oauth2-authorization-code", "refreshToken", "declared-refresh")],
            CancellationToken.None);

        Assert.Contains("refresh_token=declared-refresh", transport.Requests[0].Form, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_rotation_with_a_mismatched_scope_fingerprint_is_never_used()
    {
        var slots = new InMemoryMutableSlotStore();
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "different-scope", 1, 5, "wrong-scope-refresh"),
            CancellationToken.None);

        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var service = Service(transport, slots: slots);

        await service.AcquireAsync(
            AuthorizationCodeProfile(slot: new AuthenticationSlot("refreshToken", 1, 0), scopeFingerprint: "deployed-scope"),
            [Secret("oauth2-authorization-code", "clientSecret", "client-secret-canary"), Secret("oauth2-authorization-code", "refreshToken", "declared-refresh")],
            CancellationToken.None);

        Assert.Contains("refresh_token=declared-refresh", transport.Requests[0].Form, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_rotation_newer_than_the_generation_input_is_used()
    {
        var slots = new InMemoryMutableSlotStore();
        await slots.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", null, 1, 7, "newer-refresh"),
            CancellationToken.None);

        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var service = Service(transport, slots: slots);

        // The generation input says revision 3; the local record is revision 7 because a rotation
        // happened after the generation was compiled. The newer local record wins.
        await service.AcquireAsync(
            AuthorizationCodeProfile(slot: new AuthenticationSlot("refreshToken", 1, 3)),
            [Secret("oauth2-authorization-code", "clientSecret", "client-secret-canary"), Secret("oauth2-authorization-code", "refreshToken", "declared-refresh")],
            CancellationToken.None);

        Assert.Contains("refresh_token=newer-refresh", transport.Requests[0].Form, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_invalid_grant_refuses_without_retrying()
    {
        var transport = new RecordingTransport((_, _, _) => Task.FromResult(new UpstreamResponse(
            400,
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            "application/json",
            new MemoryStream(Encoding.UTF8.GetBytes("""{"error":"invalid_grant"}""")))));
        var service = Service(transport);

        var error = await Assert.ThrowsAsync<CredentialUnavailableException>(async () =>
            await service.AcquireAsync(
                AuthorizationCodeProfile(slot: new AuthenticationSlot("refreshToken", 1, 0)),
                [Secret("oauth2-authorization-code", "clientSecret", "client-secret-canary"), Secret("oauth2-authorization-code", "refreshToken", "retired-refresh")],
                CancellationToken.None).AsTask());

        Assert.Contains("authorized again", error.Message, StringComparison.OrdinalIgnoreCase);

        // Exactly one request: a rotating provider must not see the retired value presented twice.
        Assert.Single(transport.Requests);
    }

    [Fact]
    public async Task Concurrent_callers_present_the_refresh_token_once()
    {
        var release = new TaskCompletionSource();
        var arrivals = 0;

        var transport = new RecordingTransport(async (_, _, token) =>
        {
            Interlocked.Increment(ref arrivals);
            await release.Task.WaitAsync(token);
            return Responds("access-a", expiresIn: 3600);
        });

        var service = Service(transport);
        var profile = AuthorizationCodeProfile(slot: new AuthenticationSlot("refreshToken", 1, 0));
        IReadOnlyList<ResolvedCredential> credentials =
            [Secret("oauth2-authorization-code", "clientSecret", "client-secret-canary"), Secret("oauth2-authorization-code", "refreshToken", "shared-refresh")];
        var cancellationToken = TestContext.Current.CancellationToken;

        var first = service.AcquireAsync(profile, credentials, cancellationToken).AsTask();
        var second = service.AcquireAsync(profile, credentials, cancellationToken).AsTask();

        await Task.Delay(50, cancellationToken);
        Assert.Equal(1, Volatile.Read(ref arrivals));

        release.SetResult();

        Assert.Equal("access-a", (await first).Credentials[0].Value);
        Assert.Equal("access-a", (await second).Credentials[0].Value);
        Assert.Single(transport.Requests);
    }

    [Fact]
    public async Task A_rotation_notification_is_not_invoked_when_nothing_rotated()
    {
        var rotations = 0;
        var transport = new RecordingTransport(Responds("access-a", expiresIn: 3600));
        var service = Service(
            transport,
            onRotated: (_, _) =>
            {
                Interlocked.Increment(ref rotations);
                return ValueTask.CompletedTask;
            });

        await service.AcquireAsync(
            AuthorizationCodeProfile(slot: new AuthenticationSlot("refreshToken", 1, 0)),
            [Secret("oauth2-authorization-code", "clientSecret", "client-secret-canary"), Secret("oauth2-authorization-code", "refreshToken", "refresh")],
            CancellationToken.None);

        Assert.Equal(0, rotations);
    }

    [Fact]
    public async Task An_unsupported_kind_is_refused()
    {
        var transport = new RecordingTransport();
        var service = Service(transport);

        await Assert.ThrowsAsync<UnsupportedAuthenticationStrategyException>(async () =>
            await service.AcquireAsync(StaticProfile(), [], CancellationToken.None).AsTask());
    }

    private static OAuthTokenService Service(
        RecordingTransport transport,
        AdvanceableClock? clock = null,
        InMemoryMutableSlotStore? slots = null,
        Func<RotatedRefreshToken, CancellationToken, ValueTask>? onRotated = null)
    {
        var timeProvider = clock ?? new AdvanceableClock(Now);

        return new OAuthTokenService(
            new OAuthTokenEndpointClient(transport, timeProvider),
            new AccessTokenCache(),
            new AccessTokenSingleFlight(),
            slots ?? new InMemoryMutableSlotStore(),
            timeProvider,
            onRotated);
    }

    private static AuthenticationProfile ClientCredentialsProfile(AuthenticationSlot? slot = null) =>
        Profile(
            AuthenticationKind.OAuth2ClientCredentials,
            $$"""
            {
              "strategyId": "oauth2-client-credentials",
              "clientId": "example-client",
              "tokenEndpoint": "{{TokenEndpoint}}",
              "tokenAuthMethod": "client_secret_post",
              "scopes": ["read", "write"],
              "resource": "https://api.example.com",
              "audience": "api",
              "accessTokenSafetySkewSeconds": 30
            }
            """,
            slot);

    private static AuthenticationProfile AuthorizationCodeProfile(
        AuthenticationSlot? slot = null,
        string? scopeFingerprint = null) =>
        Profile(
            AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
            $$"""
            {
              "strategyId": "oauth2-authorization-code-pkce-refresh",
              "clientId": "example-client",
              "tokenEndpoint": "{{TokenEndpoint}}",
              "authorizationEndpoint": "https://auth.example.com/oauth2/authorize",
              "tokenAuthMethod": "client_secret_post"
            }
            """,
            slot,
            scopeFingerprint);

    private static OAuthStrategyConfiguration Configuration(string json)
        => OAuthStrategyConfiguration.FromConfiguration(
            CanonicalJson.Parse(Encoding.UTF8.GetBytes(json))!.AsObject(),
            authorizationCodeRequired: false);

    private static AuthenticationProfile StaticProfile() =>
        Profile(AuthenticationKind.Static, """{ "strategyId": "static", "inputs": {} }""");

    private static AuthenticationProfile Profile(
        AuthenticationKind kind,
        string json,
        AuthenticationSlot? slot = null,
        string? scopeFingerprint = null)
    {
        var configuration = CanonicalJson.Parse(Encoding.UTF8.GetBytes(json))!.AsObject();

        return new AuthenticationProfile(
            "oauth",
            kind,
            configuration,
            ["https://auth.example.com:443"],
            ["https://api.example.com:443"],
            [],
            scopeFingerprint,
            slot is null ? [] : [slot]);
    }

    private static ResolvedCredential Secret(string scheme, string slot, string value) =>
        new(
            new ManifestCredential($"declared-{slot}", SchemeOf(scheme), slot, CredentialReference.Literal("placeholder")),
            value);

    private static CredentialScheme SchemeOf(string scheme) => scheme switch
    {
        "oauth2-client-credentials" => CredentialScheme.OAuth2ClientCredentials,
        "oauth2-authorization-code" => CredentialScheme.OAuth2AuthorizationCode,
        "bearer" => CredentialScheme.Bearer,
        _ => CredentialScheme.Header,
    };

    private static UpstreamResponse Responds(string accessToken, long expiresIn)
        => new(
            200,
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            "application/json",
            new MemoryStream(Encoding.UTF8.GetBytes(
                $$"""{"access_token":"{{accessToken}}","token_type":"Bearer","expires_in":{{expiresIn}}}""")));

    private static UpstreamResponse RespondsWithRefresh(string accessToken, string refreshToken, long expiresIn)
        => new(
            200,
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            "application/json",
            new MemoryStream(Encoding.UTF8.GetBytes(
                $$"""{"access_token":"{{accessToken}}","token_type":"Bearer","expires_in":{{expiresIn}},"refresh_token":"{{refreshToken}}"}""")));

    private sealed class RecordingTransport : IUpstreamTransport
    {
        private readonly Func<UpstreamRequest, UpstreamSendPolicy, CancellationToken, Task<UpstreamResponse>>? _handler;
        private readonly Queue<UpstreamResponse> _responses = new();

        public RecordingTransport(params UpstreamResponse[] responses)
        {
            _handler = null;
            foreach (var response in responses)
            {
                _responses.Enqueue(response);
            }
        }

        public RecordingTransport(Func<UpstreamRequest, UpstreamSendPolicy, CancellationToken, Task<UpstreamResponse>> handler)
            => _handler = handler;

        public List<RecordedRequest> Requests { get; } = [];

        public Task<UpstreamResponse> SendAsync(UpstreamRequest request, UpstreamSendPolicy policy, CancellationToken cancellationToken)
        {
            Requests.Add(new RecordedRequest(request.Method, request.Uri, Form(request), request.Headers));

            return _handler is not null
                ? _handler(request, policy, cancellationToken)
                : Task.FromResult(_responses.Count > 1 ? _responses.Dequeue() : _responses.Peek());
        }

        private static string Form(UpstreamRequest request)
            => request.Body is { } body ? Encoding.UTF8.GetString(body) : string.Empty;
    }

    private sealed record RecordedRequest(
        string Method,
        Uri Uri,
        string Form,
        IReadOnlyDictionary<string, string[]> Headers);

    private sealed class AdvanceableClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }
}
