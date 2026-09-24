using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.ResponseCaching;

public sealed class ResponseCacheTests
{
    private static readonly byte[] IdentityKey = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();

    [Fact]
    public void A_candidate_is_copied_and_served_as_a_hit()
    {
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache cache = CreateCache(clock);
        byte[] body = "{\"pets\":[]}"u8.ToArray();
        Dictionary<string, string[]> headers = Headers("application/json");

        ResponseCacheLookup producer = cache.Acquire(Identity(), 300);
        Assert.Equal(ResponseCacheLookupKind.Miss, producer.Kind);
        ResponseFlightLease flight = Assert.IsType<ResponseFlightLease>(producer.Flight);

        ResponseCacheEnvelope candidate = ResponseCacheEnvelope.Capture(200, "application/json", headers, body);
        ResponseCacheEnvelope stored = Assert.IsType<ResponseCacheEnvelope>(cache.TryStore(producer.Key!, candidate, 300));
        flight.Publish(stored);
        flight.Dispose();

        body[0] = (byte)'x';
        headers["Content-Type"][0] = "text/plain";

        ResponseCacheLookup hit = cache.Acquire(Identity(), 300);
        Assert.Equal(ResponseCacheLookupKind.Hit, hit.Kind);
        Assert.Equal("application/json", hit.Envelope!.MediaType);
        Assert.Equal("{\"pets\":[]}", System.Text.Encoding.UTF8.GetString(hit.Envelope.Body.Span));
        Assert.Equal(1, cache.EntryCount);
    }

    [Fact]
    public void An_envelope_preserves_header_order_and_merges_case_variant_names()
    {
        Dictionary<string, string[]> headers = new(StringComparer.Ordinal)
        {
            ["X-First"] = ["one"],
            ["x-first"] = ["two"],
            ["X-Second"] = ["three"],
        };

        ResponseCacheEnvelope envelope = ResponseCacheEnvelope.Capture(200, "application/json", headers, "{}"u8.ToArray());

        Assert.Equal(["X-First", "X-Second"], envelope.Headers.Select(static header => header.Key));
        Assert.Equal(["one", "two"], envelope.Headers[0].Value);
        Assert.Equal(["three"], envelope.Headers[1].Value);
    }

    [Fact]
    public void Expiry_uses_monotonic_time_and_releases_accounting()
    {
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache cache = CreateCache(clock);
        Store(cache, Identity(), 1, new byte[20]);

        Assert.Equal(1, cache.EntryCount);
        clock.Advance(TimeSpan.FromSeconds(2));

        ResponseCacheLookup expired = cache.Acquire(Identity(), 1);
        Assert.Equal(ResponseCacheLookupKind.Miss, expired.Kind);
        Assert.Equal(0, cache.EntryCount);
        Assert.Equal(0, cache.AccountedBytes);
        expired.Flight!.Abandon();
        expired.Flight.Dispose();
    }

    [Fact]
    public void Host_ttl_ceiling_caps_stored_lifetime()
    {
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache cache = new(
            "/api",
            "generation",
            ResponseCacheOptions.Default with { MaxTtlSeconds = 60 },
            IdentityKey,
            clock);

        Store(cache, Identity(), 86400, new byte[10]);
        clock.Advance(TimeSpan.FromSeconds(61));

        ResponseCacheLookup expired = cache.Acquire(Identity(), 86400);
        Assert.Equal(ResponseCacheLookupKind.Miss, expired.Kind);
        expired.Flight!.Abandon();
        expired.Flight.Dispose();
    }

    [Fact]
    public void Entry_and_retained_header_limits_refuse_storage_without_failing_live_work()
    {
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache cache = new(
            "/api",
            "generation",
            ResponseCacheOptions.Default with { MaxBodyBytes = 4 },
            IdentityKey,
            clock);

        ResponseCacheLookup bodyProducer = cache.Acquire(Identity(), 300);
        ResponseCacheEnvelope largeBody = ResponseCacheEnvelope.Capture(200, "application/json", Headers("application/json"), new byte[5]);
        Assert.Null(cache.TryStore(bodyProducer.Key!, largeBody, 300));
        bodyProducer.Flight!.Abandon();
        bodyProducer.Flight.Dispose();
        Assert.Equal(0, cache.EntryCount);

        ResponseCacheLookup headerProducer = cache.Acquire(Identity() with { OperationSlug = "large-headers" }, 300);
        Dictionary<string, string[]> hugeHeaders = new(StringComparer.OrdinalIgnoreCase)
        {
            ["X-Large"] = [new string('x', checked((int)ResponseCacheOptions.HardMaxRetainedHeaderBytesPerEntry + 1))],
        };
        ResponseCacheEnvelope headerCandidate = ResponseCacheEnvelope.Capture(200, "application/json", hugeHeaders, []);
        Assert.Null(cache.TryStore(headerProducer.Key!, headerCandidate, 300));
        headerProducer.Flight!.Abandon();
        headerProducer.Flight.Dispose();
        Assert.Equal(0, cache.EntryCount);
    }

    [Fact]
    public void Accounting_evicts_least_recently_used_entries_under_pressure()
    {
        const long budget = 2300;
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache cache = new(
            "/api",
            "generation",
            ResponseCacheOptions.Default with { MaxRetainedBytesPerMount = budget, MaxEntriesPerMount = 8 },
            IdentityKey,
            clock);

        Store(cache, Identity() with { OperationSlug = "first" }, 300, new byte[300]);
        Store(cache, Identity() with { OperationSlug = "second" }, 300, new byte[300]);
        ResponseCacheLookup touched = cache.Acquire(Identity() with { OperationSlug = "first" }, 300);
        Assert.Equal(ResponseCacheLookupKind.Hit, touched.Kind);
        Store(cache, Identity() with { OperationSlug = "third" }, 300, new byte[700]);

        Assert.True(cache.AccountedBytes <= budget);
        Assert.Equal(ResponseCacheLookupKind.Hit, cache.Acquire(Identity() with { OperationSlug = "first" }, 300).Kind);
        ResponseCacheLookup missing = cache.Acquire(Identity() with { OperationSlug = "second" }, 300);
        Assert.Equal(ResponseCacheLookupKind.Miss, missing.Kind);
        missing.Flight!.Abandon();
        missing.Flight.Dispose();
        Assert.Equal(ResponseCacheLookupKind.Hit, cache.Acquire(Identity() with { OperationSlug = "third" }, 300).Kind);
    }

    [Fact]
    public void Expired_entries_are_removed_before_live_lru_entries_under_pressure()
    {
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache cache = new(
            "/api",
            "generation",
            ResponseCacheOptions.Default with { MaxEntriesPerMount = 2 },
            IdentityKey,
            clock);

        Store(cache, Identity() with { OperationSlug = "expired" }, 1, new byte[20]);
        Store(cache, Identity() with { OperationSlug = "live" }, 300, new byte[20]);
        clock.Advance(TimeSpan.FromSeconds(2));
        Store(cache, Identity() with { OperationSlug = "new" }, 300, new byte[20]);

        Assert.Equal(2, cache.EntryCount);
        Assert.Equal(ResponseCacheLookupKind.Hit, cache.Acquire(Identity() with { OperationSlug = "live" }, 300).Kind);
        Assert.Equal(ResponseCacheLookupKind.Hit, cache.Acquire(Identity() with { OperationSlug = "new" }, 300).Kind);
    }

    [Fact]
    public void Scoped_clear_removes_only_matching_operation_and_uses_new_scoped_epoch()
    {
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache cache = CreateCache(clock);
        Store(cache, Identity() with { OperationSlug = "one" }, 300, new byte[10]);
        Store(cache, Identity() with { OperationSlug = "two" }, 300, new byte[10]);

        ResponseCacheClearResult result = cache.Clear("one");

        Assert.Equal(1, result.RemovedEntries);
        ResponseCacheLookup cleared = cache.Acquire(Identity() with { OperationSlug = "one" }, 300);
        Assert.Equal(ResponseCacheLookupKind.Miss, cleared.Kind);
        cleared.Flight!.Abandon();
        cleared.Flight.Dispose();
        Assert.Equal(ResponseCacheLookupKind.Hit, cache.Acquire(Identity() with { OperationSlug = "two" }, 300).Kind);
    }

    [Fact]
    public void A_producer_from_the_cleared_epoch_cannot_repopulate_its_operation()
    {
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache cache = CreateCache(clock);
        ResponseCacheLookup producer = cache.Acquire(Identity() with { OperationSlug = "one" }, 300);
        ResponseCacheEpoch oldEpoch = producer.Key!.Epoch;

        cache.Clear("one");

        ResponseCacheEnvelope candidate = ResponseCacheEnvelope.Capture(200, "application/json", Headers("application/json"), [1, 2, 3]);
        Assert.Null(cache.TryStore(producer.Key, candidate, 300));
        Assert.NotEqual(oldEpoch, cache.CurrentEpoch("one"));
        producer.Flight!.Publish(candidate);
        producer.Flight.Dispose();
        ResponseCacheLookup newEpoch = cache.Acquire(Identity() with { OperationSlug = "one" }, 300);
        Assert.Equal(ResponseCacheLookupKind.Miss, newEpoch.Kind);
        newEpoch.Flight!.Abandon();
        newEpoch.Flight.Dispose();
    }

    [Fact]
    public void A_fresh_cache_instance_starts_cold_and_has_a_distinct_activation()
    {
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache first = CreateCache(clock);
        using ResponseCache second = CreateCache(clock);
        Store(first, Identity(), 300, new byte[10]);

        Assert.NotEqual(first.Activation, second.Activation);
        Assert.Equal(0, second.EntryCount);
        ResponseCacheLookup secondMiss = second.Acquire(Identity(), 300);
        Assert.Equal(ResponseCacheLookupKind.Miss, secondMiss.Kind);
        secondMiss.Flight!.Abandon();
        secondMiss.Flight.Dispose();
    }

    [Fact]
    public void Zero_ceiling_disables_cache_without_throwing()
    {
        TestClock clock = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
        using ResponseCache cache = new(
            "/api",
            "generation",
            ResponseCacheOptions.Default with { MaxTtlSeconds = 0 },
            IdentityKey,
            clock);

        Assert.Equal(ResponseCacheLookupKind.Bypass, cache.Acquire(Identity(), 300).Kind);
        Assert.Equal(0, cache.EntryCount);
    }

    private static ResponseCache CreateCache(TestClock clock)
        => new("/api", "generation", ResponseCacheOptions.Default, IdentityKey, clock);

    private static void Store(ResponseCache cache, ResponseCacheIdentity identity, int ttlSeconds, byte[] body)
    {
        ResponseCacheLookup lookup = cache.Acquire(identity, ttlSeconds);
        Assert.Equal(ResponseCacheLookupKind.Miss, lookup.Kind);
        ResponseCacheEnvelope stored = Assert.IsType<ResponseCacheEnvelope>(cache.TryStore(
            lookup.Key!,
            ResponseCacheEnvelope.Capture(200, "application/json", Headers("application/json"), body),
            ttlSeconds));
        lookup.Flight!.Publish(stored);
        lookup.Flight.Dispose();
    }

    private static Dictionary<string, string[]> Headers(string mediaType)
        => new(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = [mediaType],
            ["X-Page"] = ["1"],
        };

    private static ResponseCacheIdentity Identity()
        => new()
        {
            OperationSlug = "list-pets",
            ResolvedBindingSemantics = "http:binding-1",
            EffectiveHttpOperationKey = "GET /pets",
            Method = "GET",
            EffectiveUri = "https://api.example.test/pets",
            Headers = Headers("application/json"),
            UpstreamAuthority = "authority-1",
            CallerPartition = "caller-1",
            PolicyFingerprint = "response-cache:ttl=300",
        };

    private sealed class TestClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _utcNow = start;
        private long _timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public override long GetTimestamp() => _timestamp;

        public void Advance(TimeSpan value)
        {
            _utcNow += value;
            _timestamp += value.Ticks;
        }
    }
}
