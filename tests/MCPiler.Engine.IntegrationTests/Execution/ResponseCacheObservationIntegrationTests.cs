using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Execution;

/// <summary>
/// The sanitized per-invocation cache decision a serving process emits for operators.
/// </summary>
/// <remarks>
/// <para>
/// These tests drive the real <see cref="ExecutionService"/> against a loopback upstream, so the
/// decision under test is the one the invocation path produces rather than a value a test
/// assembled. The observation is read back through the same bounded buffer the operator channel
/// exposes.
/// </para>
/// <para>
/// The canary assertions are the important half. A decision buffer that reported the right
/// hit/miss shape while carrying a bearer token or a response body would satisfy a state-only
/// test and still be a disclosure.
/// </para>
/// </remarks>
public sealed class ResponseCacheObservationIntegrationTests
{
    private const string BodyCanary = "canary-response-body-value";

    [Fact]
    public async Task A_miss_then_a_hit_are_distinguishable_with_age_and_remaining_ttl()
    {
        int sends = 0;
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync($"{{\"ok\":\"{BodyCanary}\"}}", context.RequestAborted);
        });

        ManifestDocument manifest = Cacheable(host.Address);
        using Harness harness = new();

        await InvokeAsync(harness, manifest);
        await InvokeAsync(harness, manifest);

        Assert.Equal(1, sends);

        ResponseCacheObservation observation = Assert.IsType<ResponseCacheObservation>(harness.Cache.Observe());

        // Every invocation counts, and only the producer reached the upstream.
        Assert.Equal(2, observation.Invocations);
        Assert.Equal(1, observation.UpstreamSends);
        Assert.Equal(2, observation.Recent.Count);

        ResponseCacheDecision miss = observation.Recent[0];
        ResponseCacheDecision hit = observation.Recent[1];

        Assert.Equal(ResponseCacheDecisionKind.Miss, miss.Kind);
        Assert.Equal(ResponseCacheExecution.Upstream, miss.Execution);
        Assert.Equal(ResponseCacheFlightRole.Producer, miss.FlightRole);
        Assert.Equal(ResponseCacheDecisionReason.Stored, miss.Reason);
        Assert.NotNull(miss.KeyFingerprint);

        Assert.Equal(ResponseCacheDecisionKind.Hit, hit.Kind);
        Assert.Equal(ResponseCacheExecution.Cached, hit.Execution);
        Assert.Equal(ResponseCacheFlightRole.None, hit.FlightRole);
        Assert.Equal(ResponseCacheDecisionReason.Hit, hit.Reason);
        Assert.Equal(300, hit.EffectiveTtlSeconds);

        // A hit that followed a miss is younger than its effective TTL and has time remaining.
        // The two are measured independently and each truncates to whole seconds, so their sum can
        // sit one second below the TTL without either being inconsistent with it.
        Assert.NotNull(hit.AgeSeconds);
        Assert.NotNull(hit.RemainingTtlSeconds);
        Assert.InRange(hit.AgeSeconds!.Value, 0, 300);
        Assert.InRange(hit.RemainingTtlSeconds!.Value, 0, 300);
        Assert.InRange(hit.AgeSeconds.Value + hit.RemainingTtlSeconds.Value, 299, 300);
    }

    [Fact]
    public async Task A_bypass_names_its_closed_reason_without_a_key()
    {
        await using LoopbackHost host = await StartAsync(async context =>
        {
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        // No authored cache policy: the invocation bypasses because nothing opted in.
        ManifestDocument manifest = ExecutionManifests.For(host.Address);
        using Harness harness = new();

        await InvokeAsync(harness, manifest);

        ResponseCacheObservation observation = Assert.IsType<ResponseCacheObservation>(harness.Cache.Observe());
        ResponseCacheDecision decision = Assert.Single(observation.Recent);

        Assert.Equal(ResponseCacheDecisionKind.Bypass, decision.Kind);
        Assert.Equal(ResponseCacheDecisionReason.PolicyAbsent, decision.Reason);

        // No key was derived, so no fingerprint exists to disclose.
        Assert.Null(decision.KeyFingerprint);

        // A bypass is not a consulted invocation, so it does not inflate the count.
        Assert.Equal(0, observation.Invocations);
        Assert.Equal(1, observation.UpstreamSends);
    }

    [Fact]
    public async Task Joined_waiters_are_distinguishable_and_do_not_duplicate_upstream_counts()
    {
        using SemaphoreSlim release = new(0);
        int sends = 0;
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);

            // The first caller is held until the others have joined its flight, so the joined
            // arm is reached rather than raced past.
            await release.WaitAsync(context.RequestAborted);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        ManifestDocument manifest = Cacheable(host.Address);
        using Harness harness = new();

        Task<EngineExecutionResult> producer = InvokeAsync(harness, manifest);

        await WaitUntilAsync(() => harness.Cache.FlightCount == 1);

        ConcurrentQueue<Task<EngineExecutionResult>> waiters = new();

        for (int index = 0; index < 4; index++)
        {
            waiters.Enqueue(InvokeAsync(harness, manifest));
        }

        await WaitUntilAsync(() => harness.Cache.WaitingCallerCount == 4);
        release.Release(10);

        await producer;
        await Task.WhenAll(waiters);

        Assert.Equal(1, sends);

        ResponseCacheObservation observation = Assert.IsType<ResponseCacheObservation>(harness.Cache.Observe());

        Assert.Equal(5, observation.Recent.Count);
        Assert.Equal(1, observation.UpstreamSends);

        // Exactly one producer, four joined waiters, and every joined waiter consumed the shared
        // response rather than calling upstream. The producer reached the upstream itself; the
        // four waiters consumed what it published.
        Assert.Equal(1, observation.Recent.Count(static decision => decision.FlightRole == ResponseCacheFlightRole.Producer));
        Assert.Equal(4, observation.Recent.Count(static decision => decision.FlightRole == ResponseCacheFlightRole.Joined));
        Assert.Equal(4, observation.Recent.Count(static decision => decision.Execution == ResponseCacheExecution.Cached));
        Assert.Equal(1, observation.Recent.Count(static decision => decision.Execution == ResponseCacheExecution.Upstream));
    }

    [Fact]
    public async Task No_decision_carries_a_body_credential_or_caller_token()
    {
        const string SecretCanary = "sk-live-canary-not-for-telemetry";
        int sends = 0;
        await using LoopbackHost host = await StartAsync(async context =>
        {
            Interlocked.Increment(ref sends);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            context.Response.Headers["X-Edge"] = "edge";
            await context.Response.WriteAsync($"{{\"secret\":\"{SecretCanary}\"}}", context.RequestAborted);
        });

        ManifestDocument manifest = Cacheable(host.Address);
        using Harness harness = new();
        CallerPartition caller = new("caller-token-derived-partition-value", IsCallerSpecific: true);

        await InvokeAsync(harness, manifest, caller);
        await InvokeAsync(harness, manifest, caller);

        Assert.Equal(1, sends);

        ResponseCacheObservation observation = Assert.IsType<ResponseCacheObservation>(harness.Cache.Observe());

        // Serialize exactly what the operator channel would render and prove neither the response
        // body nor the credential the caller presented is present.
        string rendered = System.Text.Json.JsonSerializer.Serialize(observation.Recent);
        Assert.DoesNotContain(BodyCanary, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretCanary, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(caller.OpaqueValue, rendered, StringComparison.Ordinal);

        // A request-body-bearing operation must also never appear. The operation here has none, so
        // the assertion is that the fingerprint is not the request bytes.
        Assert.All(observation.Recent, decision =>
        {
            Assert.NotNull(decision.KeyFingerprint);
            Assert.Equal(12, decision.KeyFingerprint!.Length);
        });
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        CancellationToken token = TestContext.Current.CancellationToken;

        for (int attempt = 0; attempt < 500 && !condition(); attempt++)
        {
            await Task.Delay(10, token);
        }

        Assert.True(condition(), "The expected cache state was not reached within the bounded wait.");
    }

    private static Task<LoopbackHost> StartAsync(RequestDelegate handler)
        => LoopbackHost.StartAsync(handler, TestContext.Current.CancellationToken);

    private static ManifestDocument Cacheable(Uri baseUrl)
        => ExecutionManifests.For(baseUrl, responseCache: new ResponseCachePolicySettings(300));

    private static async Task<EngineExecutionResult> InvokeAsync(
        Harness harness,
        ManifestDocument manifest,
        CallerPartition? caller = null)
        => await harness.Service.ExecuteAsync(
            new ExecutionRequest(manifest, ExecutionManifests.Slug, [])
            {
                CallerPartition = caller ?? CallerPartition.Public,
            },
            TestContext.Current.CancellationToken);

    private sealed class Harness : IDisposable
    {
        private readonly UpstreamClientFactory _clients;

        internal Harness()
        {
            byte[] identityKey = RandomNumberGenerator.GetBytes(32);
            _clients = new UpstreamClientFactory(new OutboundConnectionPolicy(static _ => false));
            Cache = new ResponseCache("/api", "generation-1", ResponseCacheOptions.Default, identityKey);
            Service = new ExecutionService(
                new UpstreamSender(_clients),
                new ManifestSecretResolver(),
                files: null,
                authentication: null,
                Cache,
                identityKey);
        }

        internal ResponseCache Cache { get; }

        internal ExecutionService Service { get; }

        public void Dispose()
        {
            Cache.Dispose();
            _clients.Dispose();
        }
    }
}
