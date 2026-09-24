using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Runtime;

using Xunit;

#pragma warning disable VSTHRD003 // The bounded TCS barriers deliberately coordinate concurrent cache callers.

namespace MCPiler.Engine.IntegrationTests.Execution;

public sealed class ResponseCacheFlightIntegrationTests
{
    [Fact]
    public async Task Identical_concurrent_misses_share_one_counted_upstream_send()
    {
        const int callers = 12;
        using ResponseCache cache = CreateCache();
        TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource allJoined = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseUpstream = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int arrivals = 0;
        int upstreamSends = 0;

        Task<ResponseCacheEnvelope?>[] invocations = Enumerable.Range(0, callers)
            .Select(async _ =>
            {
                await start.Task;
                ResponseCacheLookup lookup = cache.Acquire(Identity(), 300);
                if (Interlocked.Increment(ref arrivals) == callers)
                {
                    allJoined.TrySetResult();
                }

                if (lookup.Kind == ResponseCacheLookupKind.Hit)
                {
                    return lookup.Envelope;
                }

                if (lookup.Flight is not { } flight)
                {
                    Interlocked.Increment(ref upstreamSends);
                    return Envelope();
                }

                if (!flight.IsProducer)
                {
                    return await flight.WaitAsync(CancellationToken.None);
                }

                try
                {
                    Interlocked.Increment(ref upstreamSends);
                    await releaseUpstream.Task;
                    ResponseCacheEnvelope response = Envelope();
                    ResponseCacheEnvelope? stored = cache.TryStore(lookup.Key!, response, 300);
                    Assert.NotNull(stored);
                    flight.Publish(stored);
                    return stored;
                }
                finally
                {
                    flight.Dispose();
                }
            })
            .ToArray();

        start.TrySetResult();
        await allJoined.Task;
        Assert.Equal(1, Volatile.Read(ref upstreamSends));
        releaseUpstream.TrySetResult();

        ResponseCacheEnvelope?[] results = await Task.WhenAll(invocations);
        Assert.Equal(1, Volatile.Read(ref upstreamSends));
        Assert.All(results, static result => Assert.NotNull(result));
        Assert.All(results, result => Assert.Equal(EnvelopeBody, result!.Body.ToArray()));
    }

    [Fact]
    public async Task Ineligible_producer_is_not_shared_and_joiners_take_their_own_live_path()
    {
        const int callers = 6;
        using ResponseCache cache = CreateCache();
        TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource allJoined = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseProducer = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int arrivals = 0;
        int upstreamSends = 0;

        Task[] invocations = Enumerable.Range(0, callers)
            .Select(async _ =>
            {
                await start.Task;
                ResponseCacheLookup lookup = cache.Acquire(Identity(), 300);
                if (Interlocked.Increment(ref arrivals) == callers)
                {
                    allJoined.TrySetResult();
                }

                if (lookup.Flight is not { } flight)
                {
                    Interlocked.Increment(ref upstreamSends);
                    return;
                }

                if (!flight.IsProducer)
                {
                    ResponseCacheEnvelope? shared = await flight.WaitAsync(CancellationToken.None);
                    if (shared is null)
                    {
                        // An ineligible/no-store producer shares no response; this caller makes
                        // its own ordinary upstream request instead.
                        Interlocked.Increment(ref upstreamSends);
                    }

                    return;
                }

                try
                {
                    Interlocked.Increment(ref upstreamSends);
                    await releaseProducer.Task;
                    flight.Abandon();
                }
                finally
                {
                    flight.Dispose();
                }
            })
            .ToArray();

        start.TrySetResult();
        await allJoined.Task;
        Assert.Equal(1, Volatile.Read(ref upstreamSends));
        releaseProducer.TrySetResult();
        await Task.WhenAll(invocations);

        Assert.Equal(callers, Volatile.Read(ref upstreamSends));
        Assert.Equal(0, cache.EntryCount);
    }

    private static ResponseCache CreateCache()
        => new("/api", "generation", ResponseCacheOptions.Default, new byte[32]);

    private static ResponseCacheIdentity Identity()
        => new()
        {
            OperationSlug = "list-items",
            ResolvedBindingSemantics = "http:binding-1",
            EffectiveHttpOperationKey = "GET /items",
            Method = "GET",
            EffectiveUri = "https://api.example.test/items",
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Accept"] = ["application/json"],
            },
            UpstreamAuthority = "authority-1",
            CallerPartition = "caller-1",
            PolicyFingerprint = "response-cache:ttl=300",
        };

    private static ResponseCacheEnvelope Envelope()
        => ResponseCacheEnvelope.Capture(
            200,
            "application/json",
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = ["application/json"],
            },
            EnvelopeBody);

    private static byte[] EnvelopeBody => "{\"items\":[]}"u8.ToArray();
}

#pragma warning restore VSTHRD003
