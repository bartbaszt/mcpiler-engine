using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Runtime;

using Xunit;

#pragma warning disable VSTHRD003 // The registry tests intentionally await bounded TaskCompletionSource barriers.

namespace MCPiler.Engine.UnitTests.Execution.ResponseCaching;

public sealed class ResponseFlightRegistryTests
{
    [Fact]
    public async Task Same_key_joins_one_producer_and_shares_only_the_published_envelope()
    {
        using ResponseFlightRegistry registry = new(ResponseCacheOptions.HardMaxFlightsPerMount);
        ResponseCacheKey key = Key("same");
        ResponseFlightAdmission producer = registry.JoinOrBegin(key);
        ResponseFlightAdmission waiter = registry.JoinOrBegin(key);
        ResponseCacheEnvelope envelope = Envelope();

        Assert.Equal(ResponseFlightAdmissionKind.Producer, producer.Kind);
        Assert.Equal(ResponseFlightAdmissionKind.Joined, waiter.Kind);
        Assert.NotNull(producer.Lease);
        Assert.NotNull(waiter.Lease);

        Task<ResponseCacheEnvelope?> pending = waiter.Lease!.WaitAsync(CancellationToken.None);
        producer.Lease!.Publish(envelope);
        producer.Lease.Dispose();

        Assert.Same(envelope, await pending);
        Assert.Equal(0, registry.Count);
    }

    [Fact]
    public async Task Ineligible_or_failed_producer_publishes_no_response_for_waiters()
    {
        using ResponseFlightRegistry registry = new(ResponseCacheOptions.HardMaxFlightsPerMount);
        ResponseFlightAdmission producer = registry.JoinOrBegin(Key("no-store"));
        ResponseFlightAdmission waiter = registry.JoinOrBegin(Key("no-store"));
        Task<ResponseCacheEnvelope?> pending = waiter.Lease!.WaitAsync(CancellationToken.None);

        producer.Lease!.Abandon();
        producer.Lease.Dispose();

        Assert.Null(await pending);
        Assert.Equal(0, registry.Count);
        Assert.Equal(ResponseFlightAdmissionKind.Producer, registry.JoinOrBegin(Key("no-store")).Kind);
    }

    [Fact]
    public async Task Cancelling_one_wait_does_not_cancel_producer_or_other_waiters()
    {
        using ResponseFlightRegistry registry = new(ResponseCacheOptions.HardMaxFlightsPerMount);
        ResponseFlightAdmission producer = registry.JoinOrBegin(Key("cancel"));
        ResponseFlightAdmission cancelledWaiter = registry.JoinOrBegin(Key("cancel"));
        ResponseFlightAdmission remainingWaiter = registry.JoinOrBegin(Key("cancel"));
        using CancellationTokenSource cancellation = new();
        Task<ResponseCacheEnvelope?> cancelled = cancelledWaiter.Lease!.WaitAsync(cancellation.Token);
        Task<ResponseCacheEnvelope?> remaining = remainingWaiter.Lease!.WaitAsync(CancellationToken.None);

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);

        ResponseCacheEnvelope envelope = Envelope();
        producer.Lease!.Publish(envelope);
        producer.Lease.Dispose();

        Assert.Same(envelope, await remaining);
        Assert.Equal(0, registry.Count);
    }

    [Fact]
    public async Task A_bounded_concurrent_join_has_one_producer_without_timing_assumptions()
    {
        const int callers = 16;
        using ResponseFlightRegistry registry = new(ResponseCacheOptions.HardMaxFlightsPerMount);
        ResponseCacheKey key = Key("barrier");
        TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int producers = 0;
        ResponseFlightAdmission[] admissions = new ResponseFlightAdmission[callers];

        Task[] arrivals = Enumerable.Range(0, callers)
            .Select(async index =>
            {
                await start.Task;
                ResponseFlightAdmission admission = registry.JoinOrBegin(key);
                admissions[index] = admission;
                if (admission.Kind == ResponseFlightAdmissionKind.Producer)
                {
                    Interlocked.Increment(ref producers);
                }
            })
            .ToArray();

        start.SetResult();
        await Task.WhenAll(arrivals);

        Assert.Equal(1, producers);
        Assert.Equal(1, registry.Count);
        ResponseFlightLease producer = Assert.Single(
            admissions,
            static item => item.Kind == ResponseFlightAdmissionKind.Producer).Lease!;
        producer.Abandon();
        producer.Dispose();
        Assert.Equal(0, registry.Count);
    }

    [Fact]
    public void Registry_never_exceeds_256_registered_flights()
    {
        using ResponseFlightRegistry registry = new(ResponseCacheOptions.HardMaxFlightsPerMount);
        List<ResponseFlightLease> producers = [];

        for (int index = 0; index < ResponseCacheOptions.HardMaxFlightsPerMount; index++)
        {
            ResponseFlightAdmission admission = registry.JoinOrBegin(Key(index.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            Assert.Equal(ResponseFlightAdmissionKind.Producer, admission.Kind);
            producers.Add(admission.Lease!);
        }

        ResponseFlightAdmission overflow = registry.JoinOrBegin(Key("overflow"));

        Assert.Equal(ResponseFlightAdmissionKind.CapacityBypass, overflow.Kind);
        Assert.Null(overflow.Lease);
        Assert.Equal(ResponseCacheOptions.HardMaxFlightsPerMount, registry.Count);

        producers[0].Abandon();
        producers[0].Dispose();
        Assert.Equal(ResponseCacheOptions.HardMaxFlightsPerMount - 1, registry.Count);
        Assert.Equal(ResponseFlightAdmissionKind.Producer, registry.JoinOrBegin(Key("overflow")).Kind);

        foreach (ResponseFlightLease producer in producers.Skip(1))
        {
            producer.Abandon();
            producer.Dispose();
        }
    }

    [Fact]
    public void Admitted_waiters_are_bounded_independently_and_overflow_bypasses_immediately()
    {
        // MTH-RUN-1: waiter admission is bounded independently of producer capacity, so a burst all
        // targeting one in-flight key cannot retain an unbounded number of waiters. The extra caller
        // is refused an admission immediately (bypass) and is not retained.
        using ResponseFlightRegistry registry = new(maximumFlights: 4, maximumWaiters: 3);
        ResponseCacheKey key = Key("bounded-waiters");
        ResponseFlightAdmission producer = registry.JoinOrBegin(key);
        Assert.Equal(ResponseFlightAdmissionKind.Producer, producer.Kind);

        List<ResponseFlightLease> waiters = [];
        for (int index = 0; index < 3; index++)
        {
            ResponseFlightAdmission joined = registry.JoinOrBegin(key);
            Assert.Equal(ResponseFlightAdmissionKind.Joined, joined.Kind);
            waiters.Add(joined.Lease!);
        }

        Assert.Equal(3, registry.WaiterCount);

        ResponseFlightAdmission overflow = registry.JoinOrBegin(key);

        Assert.Equal(ResponseFlightAdmissionKind.CapacityBypass, overflow.Kind);
        Assert.Null(overflow.Lease);
        Assert.Equal(3, registry.WaiterCount);

        // A waiter leaving by cancellation/timeout releases only its own admission reservation,
        // after which a new waiter can be admitted again.
        waiters[0].Dispose();
        Assert.Equal(2, registry.WaiterCount);
        ResponseFlightAdmission admittedAgain = registry.JoinOrBegin(key);
        Assert.Equal(ResponseFlightAdmissionKind.Joined, admittedAgain.Kind);
        Assert.Equal(3, registry.WaiterCount);

        producer.Lease!.Abandon();
        producer.Lease.Dispose();
        admittedAgain.Lease!.Dispose();
        foreach (ResponseFlightLease waiter in waiters.Skip(1))
        {
            waiter.Dispose();
        }

        Assert.Equal(0, registry.WaiterCount);
    }

    [Fact]
    public void Different_opaque_keys_get_independent_producers()
    {
        using ResponseFlightRegistry registry = new(4);

        Assert.Equal(ResponseFlightAdmissionKind.Producer, registry.JoinOrBegin(Key("a")).Kind);
        Assert.Equal(ResponseFlightAdmissionKind.Producer, registry.JoinOrBegin(Key("b")).Kind);
        Assert.Equal(2, registry.Count);
    }

    private static ResponseCacheKey Key(string operation)
        => ResponseCacheKeyDerivation.Derive(
            new byte[32],
            "activation",
            "/api",
            "generation",
            new ResponseCacheEpoch(0, 0),
            Identity(operation),
            60)!;

    private static ResponseCacheIdentity Identity(string operation)
        => new()
        {
            OperationSlug = operation,
            ResolvedBindingSemantics = "http:binding",
            EffectiveHttpOperationKey = "GET /items",
            Method = "GET",
            EffectiveUri = "https://api.example.test/items",
            UpstreamAuthority = "authority",
            CallerPartition = "caller",
            PolicyFingerprint = "ttl=60",
        };

    private static ResponseCacheEnvelope Envelope()
        => ResponseCacheEnvelope.Capture(
            200,
            "application/json",
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            [1, 2, 3]);
}

#pragma warning restore VSTHRD003
