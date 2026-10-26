using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// The bounded Authorization Code + PKCE attempt engine: request construction, reserved-field
/// precedence, single-use callback admission, exchange, and the redaction/refusal matrix.
/// </summary>
/// <remarks>
/// The transport is a substitute, so the assertions are about what the attempt asked for, what it
/// refused to do before asking, and what it never printed. The state and PKCE binding matter most:
/// a callback that is not bound to exactly one live attempt must never reach the token endpoint.
/// </remarks>
public sealed class OAuthAuthorizationAttemptTests
{
    private const string TokenEndpoint = "https://auth.example.com/oauth2/token";
    private const string AuthorizationEndpoint = "https://auth.example.com/oauth2/authorize";

    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri RedirectUri = new("http://127.0.0.1:57431/oauth/callback");

    [Fact]
    public void The_authorization_url_carries_the_protocol_fields_and_the_attempt_state()
    {
        var clock = Clock();
        var attempt = Attempt(Profile(), EmptyTransport(), clock);

        Assert.Equal("code", QueryValue(attempt.AuthorizationUrl, "response_type"));
        Assert.Equal("example-client", QueryValue(attempt.AuthorizationUrl, "client_id"));
        Assert.Equal(RedirectUri.AbsoluteUri, QueryValue(attempt.AuthorizationUrl, "redirect_uri"));
        Assert.Equal("read write", QueryValue(attempt.AuthorizationUrl, "scope"));
        Assert.Equal("https://api.example.com", QueryValue(attempt.AuthorizationUrl, "resource"));
        Assert.Equal("api", QueryValue(attempt.AuthorizationUrl, "audience"));
        Assert.Equal("S256", QueryValue(attempt.AuthorizationUrl, "code_challenge_method"));
        Assert.Equal(attempt.State, QueryValue(attempt.AuthorizationUrl, "state"));
        Assert.Equal(43, QueryValue(attempt.AuthorizationUrl, "code_challenge").Length);
        Assert.DoesNotContain("code_verifier", attempt.AuthorizationUrl.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_attempt_refuses_a_callback_before_it_is_begun()
    {
        var attempt = Attempt(Profile(), EmptyTransport(), Clock());

        var exception = await Refuses(attempt, $"?code=the-code&state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.AttemptNotPending, exception.Error);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Created, attempt.Status);
    }

    [Fact]
    public async Task A_callback_completes_the_attempt_once_and_binds_the_pkce_challenge()
    {
        var clock = Clock();
        var transport = new RecordingTransport(_ => Responds("CANARY-access", "CANARY-refresh"));
        var attempt = Attempt(Profile(), transport, clock);
        var challenge = QueryValue(attempt.AuthorizationUrl, "code_challenge");
        attempt.Begin();

        var result = await attempt.CompleteAsync($"?code=the-code&state={attempt.State}", CancellationToken.None);

        var sent = Assert.Single(transport.Requests);
        var form = Form(sent);
        Assert.Contains("grant_type=authorization_code", form, StringComparison.Ordinal);
        Assert.Contains("code=the-code", form, StringComparison.Ordinal);
        Assert.Contains("client_id=example-client", form, StringComparison.Ordinal);
        Assert.Contains($"redirect_uri={Uri.EscapeDataString(RedirectUri.AbsoluteUri)}", form, StringComparison.Ordinal);

        // The verifier the attempt kept is the preimage of the challenge it advertised.
        var verifier = FormValue(form, "code_verifier");
        Assert.Equal(43, verifier.Length);
        Assert.Equal(challenge, Challenge(verifier));
        Assert.DoesNotContain(challenge, form, StringComparison.Ordinal);

        Assert.Equal("CANARY-access", result.AccessToken);
        Assert.Equal("CANARY-refresh", result.RefreshToken);
        Assert.Equal("oauth", result.Binding.ProfileId);
        Assert.Equal("mount-1", result.Binding.Mount);
        Assert.Equal("refreshToken", result.Binding.Slot);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Committed, attempt.Status);

        // Admission is single-use: the same callback cannot complete it a second time.
        var replay = await Refuses(attempt, $"?code=the-code&state={attempt.State}");
        Assert.Equal(OAuthAuthorizationAttemptError.AttemptNotPending, replay.Error);
        Assert.Single(transport.Requests);
    }

    [Fact]
    public async Task A_callback_with_the_wrong_state_is_refused_before_any_egress()
    {
        var transport = EmptyTransport();
        var attempt = Attempt(Profile(), transport, Clock());
        attempt.Begin();

        var exception = await Refuses(attempt, "?code=the-code&state=someone-elses-state");

        Assert.Equal(OAuthAuthorizationAttemptError.StateMismatch, exception.Error);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Failed, attempt.Status);
        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task A_callback_without_state_is_refused()
    {
        var attempt = Attempt(Profile(), EmptyTransport(), Clock());
        attempt.Begin();

        var exception = await Refuses(attempt, "?code=the-code");

        Assert.Equal(OAuthAuthorizationAttemptError.MissingState, exception.Error);
    }

    [Fact]
    public async Task A_callback_without_code_or_error_is_refused()
    {
        var attempt = Attempt(Profile(), EmptyTransport(), Clock());
        attempt.Begin();

        var exception = await Refuses(attempt, $"?state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.MissingCode, exception.Error);
    }

    [Fact]
    public async Task A_denied_callback_is_reported_as_denied_without_egress()
    {
        var transport = EmptyTransport();
        var attempt = Attempt(Profile(), transport, Clock());
        attempt.Begin();

        var exception = await Refuses(attempt, $"?error=access_denied&state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.ProviderDenied, exception.Error);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Denied, attempt.Status);
        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task A_callback_carrying_both_a_code_and_an_error_is_refused()
    {
        var attempt = Attempt(Profile(), EmptyTransport(), Clock());
        attempt.Begin();

        var exception = await Refuses(attempt, $"?code=the-code&error=access_denied&state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.AmbiguousCallback, exception.Error);
    }

    [Theory]
    [InlineData("the-code", "", OAuthAuthorizationAttemptError.AmbiguousCallback)]
    [InlineData(null, "", OAuthAuthorizationAttemptError.ProviderDenied)]
    [InlineData("", "access_denied", OAuthAuthorizationAttemptError.AmbiguousCallback)]
    [InlineData("", "", OAuthAuthorizationAttemptError.AmbiguousCallback)]
    public async Task Forwarded_callback_preserves_presence_of_empty_reserved_parameters(
        string? code,
        string? error,
        OAuthAuthorizationAttemptError expected)
    {
        var directTransport = EmptyTransport();
        var direct = Attempt(Profile(), directTransport, Clock());
        direct.Begin();

        string query = $"?state={direct.State}"
            + (code is null ? string.Empty : $"&code={code}")
            + (error is null ? string.Empty : $"&error={error}");
        var directRefusal = await Refuses(direct, query);
        Assert.Equal(expected, directRefusal.Error);

        var forwardedTransport = EmptyTransport();
        var forwarded = Attempt(Profile(), forwardedTransport, Clock());
        forwarded.Begin();
        string forwardedQuery = $"?state={forwarded.State}"
            + (code is null ? string.Empty : $"&code={code}")
            + (error is null ? string.Empty : $"&error={error}");
        Assert.True(StandaloneAuthorizationCallback.TryRead(
            forwardedQuery, out string? state, out string? forwardedCode, out string? forwardedError));

        var forwardedRefusal = await Assert.ThrowsAsync<OAuthAuthorizationAttemptException>(
            async () => await forwarded.CompleteAsync(
                state, forwardedCode, forwardedError, CancellationToken.None));
        Assert.Equal(directRefusal.Error, forwardedRefusal.Error);
        Assert.Equal(direct.Status, forwarded.Status);
        Assert.Empty(directTransport.Requests);
        Assert.Empty(forwardedTransport.Requests);
    }

    [Theory]
    [InlineData(null, OAuthAuthorizationAttemptError.MissingState)]
    [InlineData("", OAuthAuthorizationAttemptError.StateMismatch)]
    [InlineData("unrelated-state", OAuthAuthorizationAttemptError.StateMismatch)]
    public async Task Forwarded_callback_distinguishes_missing_and_empty_state(
        string? suppliedState,
        OAuthAuthorizationAttemptError expected)
    {
        var directTransport = EmptyTransport();
        var direct = Attempt(Profile(), directTransport, Clock());
        direct.Begin();
        string rawQuery = "?code=the-code"
            + (suppliedState is null ? string.Empty : $"&state={suppliedState}");
        var directRefusal = await Refuses(direct, rawQuery);
        Assert.Equal(expected, directRefusal.Error);

        var forwardedTransport = EmptyTransport();
        var forwarded = Attempt(Profile(), forwardedTransport, Clock());
        forwarded.Begin();
        Assert.True(StandaloneAuthorizationCallback.TryRead(
            rawQuery, out string? state, out string? code, out string? error));
        var forwardedRefusal = await Assert.ThrowsAsync<OAuthAuthorizationAttemptException>(
            async () => await forwarded.CompleteAsync(state, code, error, CancellationToken.None));

        Assert.Equal(directRefusal.Error, forwardedRefusal.Error);
        Assert.Equal(direct.Status, forwarded.Status);
        Assert.Empty(directTransport.Requests);
        Assert.Empty(forwardedTransport.Requests);
    }

    [Fact]
    public async Task A_duplicate_parameter_under_an_encoded_name_is_refused()
    {
        var attempt = Attempt(Profile(), EmptyTransport(), Clock());
        attempt.Begin();

        // '%63ode' decodes to 'code', so the callback carries two codes even though the raw names differ.
        var exception = await Refuses(attempt, $"?code=one&%63ode=two&state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.DuplicateCallbackParameter, exception.Error);
    }

    [Fact]
    public async Task A_malformed_percent_escape_is_refused()
    {
        var attempt = Attempt(Profile(), EmptyTransport(), Clock());
        attempt.Begin();

        var exception = await Refuses(attempt, $"?code=the-code&state={attempt.State}&extra=%zz");

        Assert.Equal(OAuthAuthorizationAttemptError.MalformedCallback, exception.Error);
    }

    [Fact]
    public async Task An_expired_attempt_is_refused()
    {
        var clock = Clock();
        var attempt = Attempt(Profile(), EmptyTransport(), clock, lifetime: TimeSpan.FromMinutes(1));
        attempt.Begin();
        clock.Advance(TimeSpan.FromMinutes(2));

        var exception = await Refuses(attempt, $"?code=the-code&state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.AttemptExpired, exception.Error);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Expired, attempt.Status);
    }

    [Fact]
    public async Task A_cancelled_attempt_cannot_complete()
    {
        var transport = EmptyTransport();
        var attempt = Attempt(Profile(), transport, Clock());
        attempt.Begin();
        attempt.Cancel();

        var exception = await Refuses(attempt, $"?code=the-code&state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.AttemptNotPending, exception.Error);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Cancelled, attempt.Status);
        Assert.Empty(transport.Requests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancelling_during_the_provider_exchange_prevents_publishing_the_result(bool forwarded)
    {
        // The provider may complete a request even after the local operator has cancelled it.
        // The cancelled attempt must never return credentials to the durable commit path.
        var transport = new DeferredTransport();
        var attempt = Attempt(Profile(), transport, Clock());
        attempt.Begin();

        Task<OAuthAuthorizationResult> completion = forwarded
            ? attempt.CompleteAsync(attempt.State, "the-code", null, CancellationToken.None).AsTask()
            : attempt.CompleteAsync($"?code=the-code&state={attempt.State}", CancellationToken.None).AsTask();

        await transport.Sent.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        attempt.Cancel();
        transport.Finish(Responds("CANARY-access", "CANARY-refresh"));

        var refused = await Assert.ThrowsAsync<OAuthAuthorizationAttemptException>(
            () => completion.WaitAsync(TestContext.Current.CancellationToken));
        Assert.Equal(OAuthAuthorizationAttemptError.AttemptNotPending, refused.Error);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Cancelled, attempt.Status);
    }

    [Fact]
    public async Task A_callback_at_the_exact_expiration_instant_is_refused()
    {
        var clock = Clock();
        var transport = EmptyTransport();
        var attempt = Attempt(Profile(), transport, clock, lifetime: TimeSpan.FromMinutes(1));
        attempt.Begin();
        clock.Advance(TimeSpan.FromMinutes(1));

        var refused = await Refuses(attempt, $"?code=the-code&state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.AttemptExpired, refused.Error);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Expired, attempt.Status);
        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task An_exchange_without_a_refresh_token_publishes_nothing()
    {
        // A refresh-required profile becomes durable only with a usable refresh token, so a bare
        // access token is refused rather than cached as though authorization succeeded.
        var transport = new RecordingTransport(_ => Responds("CANARY-access", refreshToken: null));
        var attempt = Attempt(Profile(), transport, Clock());
        attempt.Begin();

        var exception = await Refuses(attempt, $"?code=the-code&state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.RefreshTokenRequired, exception.Error);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Failed, attempt.Status);
    }

    [Fact]
    public async Task A_malformed_token_response_is_reported_as_an_exchange_failure()
    {
        var transport = new RecordingTransport(_ => RespondsRaw("not-json"));
        var attempt = Attempt(Profile(), transport, Clock());
        attempt.Begin();

        var exception = await Refuses(attempt, $"?code=the-code&state={attempt.State}");

        Assert.Equal(OAuthAuthorizationAttemptError.ProviderExchangeFailed, exception.Error);
        Assert.Equal(OAuthAuthorizationAttemptStatus.Failed, attempt.Status);
        Assert.NotNull(exception.InnerException);
    }

    [Fact]
    public void An_extension_parameter_may_not_override_a_protocol_owned_field()
    {
        var profile = Profile(authorizationParametersJson: """{ "resource": "https://evil.example.com" }""");

        var exception = Assert.Throws<OAuthAuthorizationAttemptException>(() => Create(profile));

        Assert.Equal(OAuthAuthorizationAttemptError.AuthorizationParameterRefused, exception.Error);
    }

    [Fact]
    public void An_extension_parameter_that_collides_after_decoding_is_refused()
    {
        // The manifest reader sees the literal name 'st%61te', not 'state'; the engine decodes it.
        var profile = Profile(authorizationParametersJson: """{ "st%61te": "shadow" }""");

        var exception = Assert.Throws<OAuthAuthorizationAttemptException>(() => Create(profile));

        Assert.Equal(OAuthAuthorizationAttemptError.AuthorizationParameterRefused, exception.Error);
    }

    [Fact]
    public void An_authorization_endpoint_query_is_preserved_and_a_collision_is_refused()
    {
        var preserved = Attempt(
            Profile(authorizationEndpoint: AuthorizationEndpoint + "?prompt=login"),
            EmptyTransport(),
            Clock());

        Assert.Equal("login", QueryValue(preserved.AuthorizationUrl, "prompt"));
        Assert.Equal("code", QueryValue(preserved.AuthorizationUrl, "response_type"));

        var colliding = Profile(
            authorizationParametersJson: """{ "prompt": "consent" }""",
            authorizationEndpoint: AuthorizationEndpoint + "?prompt=login");

        var exception = Assert.Throws<OAuthAuthorizationAttemptException>(() => Create(colliding));
        Assert.Equal(OAuthAuthorizationAttemptError.AuthorizationParameterRefused, exception.Error);
    }

    [Fact]
    public void A_non_authorization_code_profile_is_refused()
    {
        var profile = new AuthenticationProfile(
            "oauth",
            AuthenticationKind.OAuth2ClientCredentials,
            CanonicalJson.Parse(Encoding.UTF8.GetBytes(
                $$"""
                {
                  "strategyId": "oauth2-client-credentials",
                  "clientId": "example-client",
                  "tokenEndpoint": "{{TokenEndpoint}}"
                }
                """))!.AsObject(),
            ["https://auth.example.com:443"],
            ["https://api.example.com:443"],
            [],
            null,
            [new AuthenticationSlot("clientSecret", 1, 0)]);

        var exception = Assert.Throws<OAuthAuthorizationAttemptException>(() => Create(profile));

        Assert.Equal(OAuthAuthorizationAttemptError.UnsupportedProfile, exception.Error);
    }

    [Theory]
    [InlineData("https://auth.example.com/oauth/callback")]
    [InlineData("http://127.0.0.1/oauth/callback")]
    [InlineData("http://0.0.0.0:57431/oauth/callback")]
    [InlineData("http://127.0.0.1:57431/")]
    [InlineData("http://127.0.0.1:57431/oauth/callback?extra=1")]
    public void A_redirect_uri_that_is_not_an_exact_loopback_registration_is_refused(string redirect)
    {
        var clock = Clock();

        var exception = Assert.Throws<OAuthAuthorizationAttemptException>(() =>
            OAuthAuthorizationAttempt.Create(
                Request(Profile(), redirectUri: new Uri(redirect)),
                new OAuthTokenEndpointClient(EmptyTransport(), clock),
                clock));

        Assert.Equal(OAuthAuthorizationAttemptError.RedirectUriInvalid, exception.Error);
    }

    [Fact]
    public void A_missing_client_secret_for_a_secret_method_is_refused_before_egress()
    {
        var clock = Clock();
        var transport = EmptyTransport();

        var exception = Assert.Throws<OAuthAuthorizationAttemptException>(() =>
            OAuthAuthorizationAttempt.Create(
                Request(Profile(), clientSecret: null),
                new OAuthTokenEndpointClient(transport, clock),
                clock));

        Assert.Equal(OAuthAuthorizationAttemptError.MissingClientSecret, exception.Error);
        Assert.Empty(transport.Requests);
    }

    [Fact]
    public async Task A_basic_client_secret_is_encoded_and_never_echoed_in_the_form()
    {
        var clock = Clock();
        var transport = new RecordingTransport(_ => Responds("CANARY-access", "CANARY-refresh"));
        var attempt = Attempt(Profile(tokenAuthMethod: "client_secret_basic"), transport, clock, clientSecret: "p\u00e4ss\U0001F600");
        attempt.Begin();

        await attempt.CompleteAsync($"?code=the-code&state={attempt.State}", CancellationToken.None);

        var sent = Assert.Single(transport.Requests);
        var basic = Assert.Single(sent.Headers["Authorization"]);
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(basic["Basic ".Length..]));
        Assert.Equal("example-client:p%C3%A4ss%F0%9F%98%80", decoded);
        Assert.DoesNotContain("client_secret", Form(sent), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_attempt_output_never_reveals_a_code_verifier_or_token()
    {
        var transport = new RecordingTransport(_ => Responds("CANARY-access-token", "CANARY-refresh-token"));
        var attempt = Attempt(Profile(), transport, Clock());
        attempt.Begin();

        await attempt.CompleteAsync($"?code=CANARY-code&state={attempt.State}", CancellationToken.None);

        var text = attempt.ToString();
        Assert.DoesNotContain("CANARY-access-token", text, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-refresh-token", text, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-code", text, StringComparison.Ordinal);
        Assert.DoesNotContain(FormValue(Form(Assert.Single(transport.Requests)), "code_verifier"), text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_registry_bounds_concurrent_attempts_by_state()
    {
        var clock = Clock();
        var registry = new OAuthAuthorizationAttemptRegistry(capacity: 1, clock);

        var first = Attempt(Profile(), EmptyTransport(), clock);
        var second = Attempt(Profile(), EmptyTransport(), clock);

        Assert.True(registry.TryRegister(first));
        Assert.False(registry.TryRegister(second));
        Assert.Same(first, registry.Find(first.State));

        Assert.Same(first, registry.Remove(first.State));
        Assert.True(registry.TryRegister(second));
    }

    [Fact]
    public void The_registry_never_admits_two_attempts_under_the_same_state()
    {
        var clock = Clock();
        var registry = new OAuthAuthorizationAttemptRegistry(capacity: 4, clock);
        var attempt = Attempt(Profile(), EmptyTransport(), clock);

        Assert.True(registry.TryRegister(attempt));
        Assert.False(registry.TryRegister(attempt));
    }

    [Fact]
    public void The_registry_prunes_an_attempt_after_its_lifetime()
    {
        var clock = Clock();
        var registry = new OAuthAuthorizationAttemptRegistry(capacity: 1, clock);
        var attempt = Attempt(Profile(), EmptyTransport(), clock, lifetime: TimeSpan.FromMinutes(1));

        Assert.True(registry.TryRegister(attempt));
        Assert.Equal(1, registry.Count);

        clock.Advance(TimeSpan.FromMinutes(2));

        Assert.Equal(0, registry.Count);
        Assert.Null(registry.Find(attempt.State));
    }

    private static Task<OAuthAuthorizationAttemptException> Refuses(OAuthAuthorizationAttempt attempt, string query)
        => Assert.ThrowsAsync<OAuthAuthorizationAttemptException>(
            async () => await attempt.CompleteAsync(query, CancellationToken.None));

    private static OAuthAuthorizationAttempt Create(AuthenticationProfile profile, string? clientSecret = "client-secret-canary")
    {
        var clock = Clock();
        return OAuthAuthorizationAttempt.Create(
            Request(profile, clientSecret: clientSecret),
            new OAuthTokenEndpointClient(EmptyTransport(), clock),
            clock);
    }

    private static OAuthAuthorizationAttempt Attempt(
        AuthenticationProfile profile,
        IUpstreamTransport transport,
        AdvanceableClock clock,
        string? clientSecret = "client-secret-canary",
        TimeSpan? lifetime = null)
        => OAuthAuthorizationAttempt.Create(
            Request(profile, clientSecret: clientSecret, lifetime: lifetime),
            new OAuthTokenEndpointClient(transport, clock),
            clock);

    private static OAuthAuthorizationAttemptRequest Request(
        AuthenticationProfile profile,
        string? clientSecret = "client-secret-canary",
        Uri? redirectUri = null,
        TimeSpan? lifetime = null)
    {
        var configuration = OAuthStrategyConfiguration.FromConfiguration(
            profile.Configuration,
            authorizationCodeRequired: profile.Kind == AuthenticationKind.OAuth2AuthorizationCodePkceRefresh);

        return new OAuthAuthorizationAttemptRequest(
            "mount-1",
            profile,
            profile.Slots[0],
            configuration,
            redirectUri ?? RedirectUri,
            clientSecret,
            lifetime);
    }

    private static AuthenticationProfile Profile(
        string? authorizationEndpoint = null,
        string? authorizationParametersJson = null,
        string tokenAuthMethod = "client_secret_post")
    {
        var parameters = authorizationParametersJson is null
            ? string.Empty
            : $""", "authorizationParameters": {authorizationParametersJson}""";

        var json =
            $$"""
            {
              "strategyId": "oauth2-authorization-code-pkce-refresh",
              "clientId": "example-client",
              "tokenEndpoint": "{{TokenEndpoint}}",
              "authorizationEndpoint": "{{authorizationEndpoint ?? AuthorizationEndpoint}}",
              "tokenAuthMethod": "{{tokenAuthMethod}}",
              "scopes": ["read", "write"],
              "resource": "https://api.example.com",
              "audience": "api"{{parameters}}
            }
            """;

        return new AuthenticationProfile(
            "oauth",
            AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
            CanonicalJson.Parse(Encoding.UTF8.GetBytes(json))!.AsObject(),
            ["https://auth.example.com:443"],
            ["https://api.example.com:443"],
            [],
            null,
            [new AuthenticationSlot("refreshToken", 1, 0)]);
    }

    private static AdvanceableClock Clock() => new(Now);

    private static RecordingTransport EmptyTransport() => new(_ => throw new InvalidOperationException("no request expected"));

    private static string QueryValue(Uri uri, string name)
    {
        var query = uri.Query.StartsWith('?') ? uri.Query[1..] : uri.Query;

        foreach (var segment in query.Split('&'))
        {
            var separator = segment.IndexOf('=');
            if (separator >= 0 && Uri.UnescapeDataString(segment[..separator]) == name)
            {
                return Uri.UnescapeDataString(segment[(separator + 1)..]);
            }
        }

        throw new InvalidOperationException($"Query parameter '{name}' was not present.");
    }

    private static string Form(UpstreamRequest request)
        => request.Body is { } body ? Encoding.UTF8.GetString(body) : string.Empty;

    private static string FormValue(string form, string name)
    {
        foreach (var segment in form.Split('&'))
        {
            var separator = segment.IndexOf('=');
            if (separator >= 0 && Uri.UnescapeDataString(segment[..separator]) == name)
            {
                return Uri.UnescapeDataString(segment[(separator + 1)..]);
            }
        }

        throw new InvalidOperationException($"Form value '{name}' was not present.");
    }

    private static string Challenge(string verifier)
        => Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static UpstreamResponse Responds(string accessToken, string? refreshToken)
        => RespondsRaw(refreshToken is null
            ? $$"""{"access_token":"{{accessToken}}","token_type":"Bearer","expires_in":300}"""
            : $$"""{"access_token":"{{accessToken}}","token_type":"Bearer","expires_in":300,"refresh_token":"{{refreshToken}}"}""");

    private static UpstreamResponse RespondsRaw(string body)
        => new(
            200,
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            "application/json",
            new MemoryStream(Encoding.UTF8.GetBytes(body)));

    private sealed class RecordingTransport(Func<UpstreamRequest, UpstreamResponse> responder) : IUpstreamTransport
    {
        public List<UpstreamRequest> Requests { get; } = [];

        public Task<UpstreamResponse> SendAsync(UpstreamRequest request, UpstreamSendPolicy policy, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(responder(request));
        }
    }

    private sealed class DeferredTransport : IUpstreamTransport
    {
        private readonly TaskCompletionSource<UpstreamResponse> _response = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<bool> Sent { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<UpstreamResponse> SendAsync(UpstreamRequest request, UpstreamSendPolicy policy, CancellationToken cancellationToken)
        {
            Sent.TrySetResult(true);
            return _response.Task.WaitAsync(cancellationToken);
        }

        public void Finish(UpstreamResponse response) => _response.SetResult(response);
    }

    private sealed class AdvanceableClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }
}
