using System;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Authentication.Caching;
using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// Caching and coalescing for an acquired access token.
/// </summary>
/// <remarks>
/// The cache is where a rotation bug shows up as a wrong credential rather than as a refused
/// request, so the assertions are about identity: which key a token is found under, and which keys
/// a rotation invalidates by construction.
/// </remarks>
public sealed class AccessTokenCacheTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static AccessTokenKey Key(
        string profileId = "oauth",
        long authorityEpoch = 1,
        long runtimeRevision = 0,
        string scopeResourceKey = "scope") =>
        new(profileId, authorityEpoch, runtimeRevision, scopeResourceKey);

    [Fact]
    public void A_fresh_token_is_returned()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(), new CachedAccessToken("token-a", Now.AddMinutes(5)));

        Assert.True(cache.TryGet(Key(), TimeSpan.Zero, Now, out var token));
        Assert.Equal("token-a", token.Value);
    }

    [Fact]
    public void A_token_inside_the_safety_skew_is_refused_and_removed()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(), new CachedAccessToken("token-a", Now.AddSeconds(10)));

        Assert.False(cache.TryGet(Key(), TimeSpan.FromSeconds(30), Now, out _));

        // Removed rather than kept: leaving it would let the next caller re-evaluate the same
        // borderline entry instead of acquiring once.
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void A_different_authority_epoch_is_a_different_token()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(authorityEpoch: 1), new CachedAccessToken("token-epoch-1", Now.AddMinutes(5)));

        // A new epoch means the operator's desired state changed. The old token was minted under
        // the previous configuration and must not be reachable from the new key.
        Assert.False(cache.TryGet(Key(authorityEpoch: 2), TimeSpan.Zero, Now, out _));
        Assert.True(cache.TryGet(Key(authorityEpoch: 1), TimeSpan.Zero, Now, out _));
    }

    [Fact]
    public void A_different_runtime_revision_is_a_different_token()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(runtimeRevision: 3), new CachedAccessToken("token-r3", Now.AddMinutes(5)));

        Assert.False(cache.TryGet(Key(runtimeRevision: 4), TimeSpan.Zero, Now, out _));
    }

    [Fact]
    public void A_different_scope_or_resource_is_a_different_token()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(scopeResourceKey: "audience-a"), new CachedAccessToken("token-a", Now.AddMinutes(5)));

        // A resource/audience change must not reuse a token minted for the previous audience.
        Assert.False(cache.TryGet(Key(scopeResourceKey: "audience-b"), TimeSpan.Zero, Now, out _));
    }

    [Fact]
    public void A_different_profile_is_a_different_token()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(profileId: "one"), new CachedAccessToken("token-one", Now.AddMinutes(5)));

        Assert.False(cache.TryGet(Key(profileId: "two"), TimeSpan.Zero, Now, out _));
    }

    [Fact]
    public void Invalidation_removes_only_the_named_profile()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(profileId: "one"), new CachedAccessToken("token-one", Now.AddMinutes(5)));
        cache.Set(Key(profileId: "two"), new CachedAccessToken("token-two", Now.AddMinutes(5)));

        cache.InvalidateProfile("one");

        Assert.False(cache.TryGet(Key(profileId: "one"), TimeSpan.Zero, Now, out _));
        Assert.True(cache.TryGet(Key(profileId: "two"), TimeSpan.Zero, Now, out _));
    }

    [Fact]
    public void Invalidation_removes_every_epoch_and_revision_of_one_profile()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(profileId: "one", authorityEpoch: 1), new CachedAccessToken("a", Now.AddMinutes(5)));
        cache.Set(Key(profileId: "one", authorityEpoch: 2, runtimeRevision: 7), new CachedAccessToken("b", Now.AddMinutes(5)));

        cache.InvalidateProfile("one");

        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void The_entry_count_stays_bounded_and_evicts_the_entry_closest_to_expiry()
    {
        var cache = new AccessTokenCache();

        for (var index = 0; index < AccessTokenCache.MaximumEntries; index++)
        {
            cache.Set(
                Key(profileId: $"profile-{index}"),
                new CachedAccessToken($"token-{index}", Now.AddSeconds(60 + index)));
        }

        Assert.Equal(AccessTokenCache.MaximumEntries, cache.Count);

        // One more entry must evict the earliest-expiring one rather than grow the cache.
        cache.Set(Key(profileId: "overflow"), new CachedAccessToken("token-overflow", Now.AddDays(1)));

        Assert.Equal(AccessTokenCache.MaximumEntries, cache.Count);
        Assert.False(cache.TryGet(Key(profileId: "profile-0"), TimeSpan.Zero, Now, out _));
        Assert.True(cache.TryGet(Key(profileId: "overflow"), TimeSpan.Zero, Now, out _));
    }

    [Fact]
    public void Overwriting_a_live_key_does_not_evict()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(), new CachedAccessToken("first", Now.AddMinutes(1)));
        cache.Set(Key(), new CachedAccessToken("second", Now.AddMinutes(10)));

        Assert.Equal(1, cache.Count);
        Assert.True(cache.TryGet(Key(), TimeSpan.Zero, Now, out var token));
        Assert.Equal("second", token.Value);
    }

    [Fact]
    public void Clear_empties_the_cache()
    {
        var cache = new AccessTokenCache();
        cache.Set(Key(), new CachedAccessToken("token", Now.AddMinutes(5)));

        cache.Clear();

        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public async Task Concurrent_callers_of_one_key_coalesce_onto_one_acquisition()
    {
        using var singleFlight = new AccessTokenSingleFlight();
        var arrivals = 0;
        var release = new TaskCompletionSource();
        var cancellationToken = TestContext.Current.CancellationToken;

        ValueTask<string> Acquire(CancellationToken token) => AcquireCore(token);

        async ValueTask<string> AcquireCore(CancellationToken token)
        {
            Interlocked.Increment(ref arrivals);
            await release.Task.WaitAsync(token);
            return "token";
        }

        var first = singleFlight.RunAsync("key", Acquire, cancellationToken).AsTask();
        var second = singleFlight.RunAsync("key", Acquire, cancellationToken).AsTask();

        // Two callers are waiting on the same gate; the acquisition has begun exactly once.
        await Task.Delay(20, cancellationToken);
        Assert.Equal(1, Volatile.Read(ref arrivals));

        release.SetResult();

        Assert.Equal("token", await first);
        Assert.Equal("token", await second);
    }

    [Fact]
    public async Task Callers_of_different_keys_do_not_block_each_other()
    {
        using var singleFlight = new AccessTokenSingleFlight();
        var firstRelease = new TaskCompletionSource();
        var secondRan = false;
        var cancellationToken = TestContext.Current.CancellationToken;

        async ValueTask<string> First(CancellationToken token)
        {
            await firstRelease.Task.WaitAsync(token);
            return "first";
        }

        var first = singleFlight.RunAsync("one", First, cancellationToken).AsTask();

        var second = await singleFlight.RunAsync(
            "two",
            _ =>
            {
                secondRan = true;
                return ValueTask.FromResult("second");
            },
            cancellationToken);

        Assert.True(secondRan);
        Assert.Equal("second", second);

        firstRelease.SetResult();
        Assert.Equal("first", await first);
    }

    [Fact]
    public async Task A_failed_acquisition_releases_the_gate_for_the_next_caller()
    {
        using var singleFlight = new AccessTokenSingleFlight();

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await singleFlight.RunAsync<string>(
                "key",
                _ => throw new InvalidOperationException("refused"),
                CancellationToken.None).AsTask());

        // The gate must not stay held: one refused acquisition would otherwise block every later
        // caller of that profile for the process lifetime.
        var result = await singleFlight.RunAsync("key", _ => ValueTask.FromResult("recovered"), CancellationToken.None);

        Assert.Equal("recovered", result);
    }

    [Fact]
    public async Task Idle_per_profile_gates_are_removed_so_synchronization_state_is_bounded()
    {
        // MTH-RUN-4: many distinct profiles completing single-flight work over time must not leave
        // per-profile synchronization state behind. Once the last caller for a key leaves, its gate
        // is removed; a later caller for the same key simply recreates it.
        using var singleFlight = new AccessTokenSingleFlight();

        for (int index = 0; index < 500; index++)
        {
            await singleFlight.RunAsync(
                $"profile-{index}",
                _ => ValueTask.FromResult("ok"),
                CancellationToken.None);
        }

        Assert.Equal(0, singleFlight.Count);

        // Reuse of a previously seen key still works after its idle gate was removed.
        var reused = await singleFlight.RunAsync(
            "profile-42",
            _ => ValueTask.FromResult("again"),
            CancellationToken.None);
        Assert.Equal("again", reused);
        Assert.Equal(0, singleFlight.Count);
    }

    [Fact]
    public async Task A_disposed_single_flight_refuses_use()
    {
        var singleFlight = new AccessTokenSingleFlight();
        singleFlight.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await singleFlight.RunAsync("key", _ => ValueTask.FromResult("x"), CancellationToken.None).AsTask());
    }
}
