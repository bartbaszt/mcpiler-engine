using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Authorization;

/// <summary>
/// Bounded issuer-result caching and single-flight behavior for RFC 7662 validation.
/// </summary>
public sealed class IntrospectionTokenValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly Uri Endpoint = new("http://127.0.0.1:5099/introspect");

    [Fact]
    public async Task A_positive_result_is_reused_until_its_configured_ttl()
    {
        var clock = new FakeTimeProvider(Now);
        var handler = new StubHandler((_, _) => ActiveResponse(clock.GetUtcNow().AddMinutes(5)));
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, clock, ttlSeconds: 30);

        Assert.True((await validator.ValidateAsync("token-a", TestContext.Current.CancellationToken)).Active);
        Assert.True((await validator.ValidateAsync("token-a", TestContext.Current.CancellationToken)).Active);

        Assert.Equal(1, handler.Calls);

        clock.Advance(TimeSpan.FromSeconds(31));
        Assert.True((await validator.ValidateAsync("token-a", TestContext.Current.CancellationToken)).Active);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task A_positive_result_never_outlives_the_issuer_expiration()
    {
        var clock = new FakeTimeProvider(Now);
        var handler = new StubHandler((_, _) => ActiveResponse(clock.GetUtcNow().AddSeconds(5)));
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, clock, ttlSeconds: 30);

        Assert.True((await validator.ValidateAsync("token-exp", TestContext.Current.CancellationToken)).Active);
        clock.Advance(TimeSpan.FromSeconds(6));

        Assert.True((await validator.ValidateAsync("token-exp", TestContext.Current.CancellationToken)).Active);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task An_active_response_without_a_future_expiration_is_not_positive_cached()
    {
        var handler = new StubHandler((_, _) => ActiveResponse(expiration: null));
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, new FakeTimeProvider(Now), ttlSeconds: 30);

        Assert.True((await validator.ValidateAsync("token-no-exp", TestContext.Current.CancellationToken)).Active);
        Assert.True((await validator.ValidateAsync("token-no-exp", TestContext.Current.CancellationToken)).Active);

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task A_parseable_inactive_response_is_negative_cached_for_at_most_five_seconds()
    {
        var clock = new FakeTimeProvider(Now);
        var handler = new StubHandler((_, _) => InactiveResponse());
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, clock, ttlSeconds: 30);

        Assert.False((await validator.ValidateAsync("token-negative", TestContext.Current.CancellationToken)).Active);
        Assert.False((await validator.ValidateAsync("token-negative", TestContext.Current.CancellationToken)).Active);
        Assert.Equal(1, handler.Calls);

        clock.Advance(TimeSpan.FromSeconds(6));
        Assert.False((await validator.ValidateAsync("token-negative", TestContext.Current.CancellationToken)).Active);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task A_negative_result_ttl_is_capped_by_the_configured_positive_ttl()
    {
        var clock = new FakeTimeProvider(Now);
        var handler = new StubHandler((_, _) => InactiveResponse());
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, clock, ttlSeconds: 2);

        await validator.ValidateAsync("token-negative-short", TestContext.Current.CancellationToken);
        clock.Advance(TimeSpan.FromSeconds(3));
        await validator.ValidateAsync("token-negative-short", TestContext.Current.CancellationToken);

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task Zero_ttl_bypasses_positive_and_negative_result_caches()
    {
        var positiveHandler = new StubHandler((_, _) => ActiveResponse(Now.AddMinutes(5)));
        using var positiveClient = new HttpClient(positiveHandler);
        var positive = CreateValidator(positiveClient, new FakeTimeProvider(Now), ttlSeconds: 0);
        await positive.ValidateAsync("token-zero-positive", TestContext.Current.CancellationToken);
        await positive.ValidateAsync("token-zero-positive", TestContext.Current.CancellationToken);

        var negativeHandler = new StubHandler((_, _) => InactiveResponse());
        using var negativeClient = new HttpClient(negativeHandler);
        var negative = CreateValidator(negativeClient, new FakeTimeProvider(Now), ttlSeconds: 0);
        await negative.ValidateAsync("token-zero-negative", TestContext.Current.CancellationToken);
        await negative.ValidateAsync("token-zero-negative", TestContext.Current.CancellationToken);

        Assert.Equal(2, positiveHandler.Calls);
        Assert.Equal(2, negativeHandler.Calls);
    }

    [Fact]
    public async Task Zero_ttl_does_not_single_flight_concurrent_requests_for_the_same_token()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new StubHandler(async (_, cancellationToken) =>
        {
            await gate.Task.WaitAsync(cancellationToken);
            return ActiveResponse(Now.AddMinutes(5));
        });
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, new FakeTimeProvider(Now), ttlSeconds: 0);

        Task<TokenVerification> first = validator.ValidateAsync(
            "same-zero-ttl-token",
            TestContext.Current.CancellationToken);
        await WaitForCallsAsync(handler, 1);

        Task<TokenVerification> second = validator.ValidateAsync(
            "same-zero-ttl-token",
            TestContext.Current.CancellationToken);
        await WaitForCallsAsync(handler, 2);

        Assert.Equal(2, handler.Calls);

        gate.SetResult();
        Assert.True((await first).Active);
        Assert.True((await second).Active);
        Assert.Equal(2, handler.Calls);
    }

    [Theory]
    [InlineData("{\"active\":\"true\"}", 200)]
    [InlineData("{\"aud\":\"resource\"}", 200)]
    [InlineData("{", 200)]
    [InlineData("{\"active\":true}", 503)]
    [InlineData("{\"active\":true}", 401)]
    public async Task Non_authoritative_or_transport_failures_are_not_cached(string body, int statusCode)
    {
        var handler = new StubHandler((_, _) => new HttpResponseMessage((HttpStatusCode)statusCode)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, new FakeTimeProvider(Now), ttlSeconds: 30);

        Assert.False((await validator.ValidateAsync("token-failure", TestContext.Current.CancellationToken)).Active);
        Assert.False((await validator.ValidateAsync("token-failure", TestContext.Current.CancellationToken)).Active);

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task A_transport_failure_is_not_cached()
    {
        var handler = new StubHandler(
            (Func<int, HttpRequestMessage, HttpResponseMessage>)((_, _) =>
                throw new HttpRequestException("issuer unavailable")));
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, new FakeTimeProvider(Now), ttlSeconds: 30);

        Assert.False((await validator.ValidateAsync("token-transport", TestContext.Current.CancellationToken)).Active);
        Assert.False((await validator.ValidateAsync("token-transport", TestContext.Current.CancellationToken)).Active);

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task A_timeout_failure_is_not_cached()
    {
        var handler = new StubHandler(
            (Func<int, CancellationToken, Task<HttpResponseMessage>>)((_, _) =>
                Task.FromException<HttpResponseMessage>(new TaskCanceledException("issuer timed out"))));
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, new FakeTimeProvider(Now), ttlSeconds: 30);

        Assert.False((await validator.ValidateAsync("token-timeout", TestContext.Current.CancellationToken)).Active);
        Assert.False((await validator.ValidateAsync("token-timeout", TestContext.Current.CancellationToken)).Active);

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task Equivalent_json_layouts_produce_the_same_active_verdict()
    {
        var clock = new FakeTimeProvider(Now);
        var responses = new Queue<string>([
            $$"""{ "active": true, "aud": "resource", "scope": "read write", "exp": {{Now.AddMinutes(5).ToUnixTimeSeconds()}} }""",
            $$"""{ "exp": {{Now.AddMinutes(5).ToUnixTimeSeconds()}}, "scope": "read write", "unrelated": 1, "aud": "resource", "active": true }""",
        ]);
        var handler = new StubHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responses.Dequeue(), Encoding.UTF8, "application/json"),
        });
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, clock, ttlSeconds: 0);

        TokenVerification first = await validator.ValidateAsync("token-layout-a", TestContext.Current.CancellationToken);
        TokenVerification second = await validator.ValidateAsync("token-layout-b", TestContext.Current.CancellationToken);

        Assert.True(first.Active);
        Assert.True(second.Active);
        Assert.Equal(first.Active, second.Active);
        Assert.Equal(first.Audience, second.Audience);
        Assert.Equal(first.Scopes, second.Scopes);
        Assert.Equal(first.ExpiresAt, second.ExpiresAt);
        Assert.Equal(first.IsAuthoritativeInactive, second.IsAuthoritativeInactive);
    }

    [Fact]
    public void The_result_cache_is_bounded_across_positive_and_negative_entries()
    {
        var cache = new IntrospectionResultCache();
        TokenVerification positive = new(true, "resource", ["read"]);

        for (var index = 0; index < IntrospectionResultCache.MaximumEntries; index++)
        {
            cache.Set($"digest-{index}", positive, Now.AddSeconds(index + 1), Now);
        }

        cache.Set("digest-overflow", TokenVerification.Inactive with { IsAuthoritativeInactive = true }, Now.AddHours(1), Now);

        Assert.Equal(IntrospectionResultCache.MaximumEntries, cache.Count);
        Assert.False(cache.TryGet("digest-0", Now, out _));
        Assert.True(cache.TryGet("digest-overflow", Now, out TokenVerification? cached));
        Assert.False(cached!.Active);
    }

    [Fact]
    public async Task Concurrent_misses_for_one_digest_share_one_introspection_request()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new StubHandler(async (_, cancellationToken) =>
        {
            await gate.Task.WaitAsync(cancellationToken);
            return ActiveResponse(expiration: null);
        });
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, new FakeTimeProvider(Now), ttlSeconds: 30);

        Task<TokenVerification> first = validator.ValidateAsync("same-token", TestContext.Current.CancellationToken);
        await WaitForCallsAsync(handler, 1);
        Task<TokenVerification> second = validator.ValidateAsync("same-token", TestContext.Current.CancellationToken);
        Assert.Equal(1, handler.Calls);

        gate.SetResult();
        Assert.True((await first).Active);
        Assert.True((await second).Active);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task A_raw_bearer_is_not_retained_in_the_cache_key()
    {
        const string rawToken = "Bearer secret-value-that-must-not-be-retained";
        var handler = new StubHandler((_, _) => ActiveResponse(Now.AddMinutes(5)));
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, new FakeTimeProvider(Now), ttlSeconds: 30);

        await validator.ValidateAsync(rawToken, TestContext.Current.CancellationToken);

        FieldInfo cacheField = typeof(IntrospectionTokenValidator).GetField(
            "_cache",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        var cache = (IntrospectionResultCache)cacheField.GetValue(validator)!;
        FieldInfo entriesField = typeof(IntrospectionResultCache).GetField(
            "_entries",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        var entries = (System.Collections.IDictionary)entriesField.GetValue(cache)!;

        Assert.Single(entries.Keys.Cast<object>());
        Assert.DoesNotContain(rawToken, entries.Keys.Cast<object>().Select(static key => key.ToString()));
        Assert.Equal(64, entries.Keys.Cast<object>().Single().ToString()!.Length);
    }

    [Fact]
    public async Task Cancellation_of_one_waiter_does_not_pin_or_cancel_the_shared_operation()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new StubHandler(async (_, cancellationToken) =>
        {
            await gate.Task.WaitAsync(cancellationToken);
            return ActiveResponse(expiration: null);
        });
        using var client = new HttpClient(handler);
        var validator = CreateValidator(client, new FakeTimeProvider(Now), ttlSeconds: 30);

        using var cancelled = new CancellationTokenSource();
        Task<TokenVerification> first = validator.ValidateAsync("cancelled-waiter", cancelled.Token);
        await WaitForCallsAsync(handler, 1);
        cancelled.Cancel();
        try
        {
            await first;
            Assert.Fail("The cancelled waiter should observe cancellation.");
        }
        catch (OperationCanceledException)
        {
            // The shared issuer operation must continue for the other waiter.
        }

        Task<TokenVerification> second = validator.ValidateAsync("cancelled-waiter", TestContext.Current.CancellationToken);
        Assert.Equal(1, handler.Calls);

        gate.SetResult();
        Assert.True((await second).Active);
        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData(StatusCodes.Status307TemporaryRedirect)]
    [InlineData(StatusCodes.Status308PermanentRedirect)]
    public async Task Runtime_introspection_redirects_do_not_forward_bearer_or_client_credentials(
        int redirectStatus)
    {
        const string bearerCanary = "bearer-canary-must-not-cross-hop";
        const string clientId = "client-canary";
        const string clientSecret = "secret-canary";
        string secretPath = Path.Combine(
            Path.GetTempPath(),
            $"mcpiler-introspection-{Guid.NewGuid():N}.secret");
        await File.WriteAllTextAsync(secretPath, clientSecret, TestContext.Current.CancellationToken);

        await using AuthorizationTransportServer target = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                return Task.CompletedTask;
            });
        await using AuthorizationTransportServer endpoint = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = redirectStatus;
                context.Response.Headers.Location =
                    new Uri(target.Address, "/redirect-target?canary=introspection").ToString();
                return Task.CompletedTask;
            });

        try
        {
            ITokenValidator validator = MountAuthorizationSetup.Validator(
                new HostAuthorizationOptions(
                    endpoint.Address.AbsoluteUri,
                    HostTokenValidation.Introspection,
                    IntrospectionEndpoint: new Uri(endpoint.Address, "/introspect").AbsoluteUri,
                    IntrospectionClientId: clientId,
                    IntrospectionClientSecretFile: secretPath)
                {
                    IntrospectionCacheTtlSeconds = 0,
                });

            TokenVerification verification = await validator.ValidateAsync(
                bearerCanary,
                TestContext.Current.CancellationToken);

            Assert.False(verification.Active);
            Assert.Equal(1, endpoint.RequestCount);
            Assert.Contains(bearerCanary, endpoint.LastBody ?? string.Empty, StringComparison.Ordinal);
            string expectedAuthorization = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret)}"));
            Assert.Equal($"Basic {expectedAuthorization}", endpoint.LastAuthorization);
            Assert.Equal(0, target.RequestCount);
            Assert.DoesNotContain(bearerCanary, target.LastBody ?? string.Empty, StringComparison.Ordinal);
            Assert.DoesNotContain(clientSecret, target.LastAuthorization ?? string.Empty, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(secretPath);
        }
    }

    [Theory]
    [InlineData(StatusCodes.Status307TemporaryRedirect)]
    [InlineData(StatusCodes.Status308PermanentRedirect)]
    public async Task Runtime_jwks_redirects_are_not_followed(int redirectStatus)
    {
        await using AuthorizationTransportServer target = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                return Task.CompletedTask;
            });
        await using AuthorizationTransportServer endpoint = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = redirectStatus;
                context.Response.Headers.Location =
                    new Uri(target.Address, "/redirect-target?canary=jwks").ToString();
                return Task.CompletedTask;
            });

        ITokenValidator validator = MountAuthorizationSetup.Validator(
            new HostAuthorizationOptions(
                endpoint.Address.AbsoluteUri,
                HostTokenValidation.Jwks,
                JwksUri: new Uri(endpoint.Address, "/jwks").AbsoluteUri));

        TokenVerification verification = await validator.ValidateAsync(
            "jwks-token-canary",
            TestContext.Current.CancellationToken);

        Assert.False(verification.Active);
        Assert.Equal(1, endpoint.RequestCount);
        Assert.Equal(0, target.RequestCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Loopback_http_introspection_bypasses_proxy_and_keeps_credentials_direct(bool useLocalhost)
    {
        const string bearerCanary = "bearer-canary-must-stay-loopback";
        const string clientId = "client-canary";
        const string clientSecret = "secret-canary";

        await using AuthorizationTransportServer target = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(
                    "{\"active\":true,\"exp\":4102444800}",
                    context.RequestAborted);
            });
        await using AuthorizationTransportServer proxy = await AuthorizationTransportServer.StartAsync(
            context =>
            {
                context.Response.StatusCode = StatusCodes.Status502BadGateway;
                return Task.CompletedTask;
            });

        Uri targetAddress = useLocalhost
            ? new UriBuilder(target.Address) { Host = "localhost" }.Uri
            : target.Address;
        string endpoint = new Uri(targetAddress, "/introspect").AbsoluteUri;

        using HttpClient client = AuthorizationHttpClientFactory.Create(
            TimeSpan.FromSeconds(5),
            new FixedWebProxy(proxy.Address));
        var validator = new IntrospectionTokenValidator(
            client,
            targetAddress.AbsoluteUri,
            endpoint,
            clientId,
            clientSecret,
            cacheTtlSeconds: 0);

        TokenVerification verification = await validator.ValidateAsync(
            bearerCanary,
            TestContext.Current.CancellationToken);

        Assert.True(verification.Active);
        Assert.Equal(1, target.RequestCount);
        Assert.Equal(0, proxy.RequestCount);
        Assert.Contains(bearerCanary, target.LastBody ?? string.Empty, StringComparison.Ordinal);
        string expectedAuthorization = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret)}"));
        Assert.Equal($"Basic {expectedAuthorization}", target.LastAuthorization);
        Assert.DoesNotContain(bearerCanary, proxy.LastBody ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(clientSecret, proxy.LastAuthorization ?? string.Empty, StringComparison.Ordinal);
    }

    private static IntrospectionTokenValidator CreateValidator(
        HttpClient client,
        TimeProvider clock,
        int ttlSeconds)
        => new(
            client,
            "https://issuer.example.test",
            Endpoint.AbsoluteUri,
            cacheTtlSeconds: ttlSeconds,
            clock: clock);

    private static HttpResponseMessage ActiveResponse(DateTimeOffset? expiration)
    {
        string exp = expiration is { } value
            ? $", \"exp\": {value.ToUnixTimeSeconds()}"
            : string.Empty;
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $"{{\"active\":true,\"aud\":\"resource\",\"scope\":\"read write\"{exp}}}",
                Encoding.UTF8,
                "application/json"),
        };
    }

    private static HttpResponseMessage InactiveResponse()
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"active\":false}", Encoding.UTF8, "application/json"),
        };

    private static async Task WaitForCallsAsync(StubHandler handler, int expected)
    {
        for (var attempt = 0; attempt < 100 && handler.Calls < expected; attempt++)
        {
            await Task.Delay(5, TestContext.Current.CancellationToken);
        }

        Assert.Equal(expected, handler.Calls);
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan amount) => _now = _now.Add(amount);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<int, CancellationToken, Task<HttpResponseMessage>> _responder;
        private int _calls;

        public StubHandler(Func<int, HttpRequestMessage, HttpResponseMessage> responder)
            : this((number, _) => Task.FromResult(responder(number, null!)))
        {
        }

        public StubHandler(Func<int, CancellationToken, Task<HttpResponseMessage>> responder)
            => _responder = responder;

        public int Calls => Volatile.Read(ref _calls);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            int number = Interlocked.Increment(ref _calls);
            return _responder(number, cancellationToken);
        }
    }
}
