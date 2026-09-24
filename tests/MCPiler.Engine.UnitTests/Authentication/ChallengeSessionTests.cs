using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Challenge;
using MCPiler.Engine.Authentication.Exchange;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// Covers the challenge-session runtime: the closed definition projection, the bounded capture
/// cache, and the disposition the runtime derives from one received response.
/// </summary>
/// <remarks>
/// Nothing here reaches a host. A challenge is a reaction to a response the Engine already
/// received, so every decision is a pure function of the profile, the response and the clock.
/// </remarks>
public sealed class ChallengeSessionTests
{
    private const string SessionCanary = "CANARY-3f21a9-session";

    [Fact]
    public void A_minimal_configuration_projects_the_documented_defaults()
    {
        var definition = ChallengeSessionDefinition.FromConfiguration(Json(
            """
            {
              "strategyId": "bounded-challenge-session",
              "challenge": { "source": "header", "selector": "X-Challenge" },
              "injection": { "location": "cookie", "name": "session" }
            }
            """));

        Assert.Equal([ChallengeSessionDefinition.DefaultStatusCode], definition.StatusCodes);
        Assert.Equal(ExchangeSelectorKind.Header, definition.SelectorKind);
        Assert.Equal("X-Challenge", definition.Selector);
        Assert.Equal("cookie", definition.Injection.Location);
        Assert.Equal("session", definition.Injection.Name);
        Assert.Empty(definition.ReplaySafeOperationKeys);
        Assert.Equal(ChallengeSessionDefinition.DefaultSessionLifetime, definition.SessionLifetime);
    }

    [Fact]
    public void A_documented_configuration_projects_every_runtime_fact()
    {
        var definition = ChallengeSessionDefinition.FromConfiguration(Json(
            """
            {
              "strategyId": "bounded-challenge-session",
              "inputs": { "username": "example-user" },
              "challenge": { "statusCodes": [409, 419], "source": "cookie", "selector": "challenge" },
              "injection": { "location": "header", "name": "Authorization", "prefix": "Bearer " },
              "replaySafeOperationKeys": ["GET /pets", "GET /pets/{id}"],
              "sessionLifetimeSeconds": 3600
            }
            """));

        Assert.Equal([409, 419], definition.StatusCodes.Order().ToList());
        Assert.Equal(ExchangeSelectorKind.Cookie, definition.SelectorKind);
        Assert.Equal("challenge", definition.Selector);
        Assert.Equal("header", definition.Injection.Location);
        Assert.Equal("Authorization", definition.Injection.Name);
        Assert.Equal("Bearer ", definition.Injection.Prefix);
        Assert.Equal(["GET /pets", "GET /pets/{id}"], definition.ReplaySafeOperationKeys.Order(StringComparer.Ordinal));
        Assert.Equal(TimeSpan.FromHours(1), definition.SessionLifetime);
    }

    [Fact]
    public void A_lifetime_outside_the_admitted_window_falls_back_to_the_default()
    {
        // The reader refuses this at load; the projection states a runtime fact rather than
        // re-validating, so an out-of-range value is the default rather than a crash.
        var definition = ChallengeSessionDefinition.FromConfiguration(Json(
            """
            {
              "strategyId": "bounded-challenge-session",
              "challenge": { "source": "header", "selector": "X-Challenge" },
              "injection": { "location": "bearer" },
              "sessionLifetimeSeconds": 99999999
            }
            """));

        Assert.Equal(ChallengeSessionDefinition.DefaultSessionLifetime, definition.SessionLifetime);
    }

    [Fact]
    public void A_configuration_without_a_selector_is_refused()
    {
        var error = Assert.Throws<AuthenticationPlanException>(() => ChallengeSessionDefinition.FromConfiguration(Json(
            """
            {
              "strategyId": "bounded-challenge-session",
              "challenge": { "source": "header" },
              "injection": { "location": "bearer" }
            }
            """)));

        Assert.Equal("challenge", error.ProfileId);
    }

    [Fact]
    public void A_configuration_without_an_injection_location_is_refused()
    {
        var error = Assert.Throws<AuthenticationPlanException>(() => ChallengeSessionDefinition.FromConfiguration(Json(
            """
            {
              "strategyId": "bounded-challenge-session",
              "challenge": { "source": "header", "selector": "X-Challenge" }
            }
            """)));

        Assert.Equal("challenge", error.ProfileId);
    }

    [Fact]
    public void A_named_injection_without_a_wire_name_is_refused()
    {
        Assert.Throws<AuthenticationPlanException>(() => ChallengeSessionDefinition.FromConfiguration(Json(
            """
            {
              "strategyId": "bounded-challenge-session",
              "challenge": { "source": "header", "selector": "X-Challenge" },
              "injection": { "location": "cookie" }
            }
            """)));
    }

    [Fact]
    public void A_cache_capture_is_usable_only_for_its_own_profile_epoch_and_revision()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);

        cache.Set(new ChallengeSessionEntry("profile-a", 1, 0, SessionCanary, Now.AddMinutes(5)));

        Assert.True(cache.TryGet("profile-a", 1, 0, out var entry));
        Assert.Equal(SessionCanary, entry!.Value);

        Assert.False(cache.TryGet("profile-a", 2, 0, out _));
        Assert.False(cache.TryGet("profile-a", 1, 1, out _));
        Assert.False(cache.TryGet("profile-b", 1, 0, out _));
        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public void A_cache_capture_stops_being_usable_at_its_expiry()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);

        cache.Set(new ChallengeSessionEntry("profile", 1, 0, SessionCanary, Now.AddSeconds(30)));

        clock.Advance(TimeSpan.FromSeconds(31));

        Assert.False(cache.TryGet("profile", 1, 0, out _));
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void The_cache_stays_bounded_and_evicts_the_earliest_expiry()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);

        for (var index = 0; index < ChallengeSessionCache.MaximumEntries; index++)
        {
            cache.Set(new ChallengeSessionEntry(
                "profile",
                1,
                index,
                "value-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture),
                Now.AddMinutes(index + 1)));
        }

        Assert.Equal(ChallengeSessionCache.MaximumEntries, cache.Count);

        // One more entry evicts the earliest-expiring capture, not the newest one.
        cache.Set(new ChallengeSessionEntry("profile", 1, 99_999, "newest", Now.AddHours(1)));

        Assert.Equal(ChallengeSessionCache.MaximumEntries, cache.Count);
        Assert.False(cache.TryGet("profile", 1, 0, out _));
        Assert.True(cache.TryGet("profile", 1, 99_999, out _));
    }

    [Fact]
    public void Overwriting_a_live_capture_does_not_evict_anything()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);

        for (var index = 0; index < ChallengeSessionCache.MaximumEntries; index++)
        {
            cache.Set(new ChallengeSessionEntry("profile", 1, index, "value", Now.AddMinutes(index + 1)));
        }

        cache.Set(new ChallengeSessionEntry("profile", 1, 0, "replaced", Now.AddMinutes(1)));

        Assert.Equal(ChallengeSessionCache.MaximumEntries, cache.Count);
        Assert.True(cache.TryGet("profile", 1, 0, out var entry));
        Assert.Equal("replaced", entry!.Value);
    }

    [Fact]
    public void Invalidating_a_profile_drops_every_epoch_and_revision_of_it_only()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);

        cache.Set(new ChallengeSessionEntry("profile", 1, 0, "one", Now.AddMinutes(5)));
        cache.Set(new ChallengeSessionEntry("profile", 2, 0, "two", Now.AddMinutes(5)));
        cache.Set(new ChallengeSessionEntry("other", 1, 0, "three", Now.AddMinutes(5)));

        cache.InvalidateProfile("profile");

        // Both epochs of the invalidated profile are gone; another profile's capture survives.
        Assert.Equal(1, cache.Count);
        Assert.False(cache.TryGet("profile", 1, 0, out _));
        Assert.False(cache.TryGet("profile", 2, 0, out _));
        Assert.True(cache.TryGet("other", 1, 0, out _));
    }

    [Fact]
    public void Without_a_captured_session_the_service_resolves_nothing()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        Assert.Null(service.ResolveCredential(Profile(Configured()), runtimeRevision: 0, authorityEpoch: 0));
    }

    [Fact]
    public void A_captured_session_resolves_to_the_configured_injection()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);

        cache.Set(new ChallengeSessionEntry("challenge-session", 1, 0, SessionCanary, Now.AddMinutes(5)));

        var service = new ChallengeSessionService(cache, clock);
        var credential = service.ResolveCredential(Profile(Configured()), runtimeRevision: 0, authorityEpoch: 1);

        Assert.NotNull(credential);
        Assert.Equal(CredentialScheme.Header, credential!.Credential.Declaration.Scheme);
        Assert.Equal("Authorization", credential.Credential.Declaration.Slot);
        Assert.Equal("Bearer " + SessionCanary, credential.Credential.Value);

        // The capture's own expiry travels with it: a response obtained under this session must
        // not outlive the upstream authority that granted it.
        Assert.Equal(Now.AddMinutes(5), credential.ExpiresAtUtc);
    }

    [Fact]
    public void A_captured_session_under_another_epoch_is_not_revealed()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);

        cache.Set(new ChallengeSessionEntry("challenge-session", 1, 0, SessionCanary, Now.AddMinutes(5)));

        var service = new ChallengeSessionService(cache, clock);

        Assert.Null(service.ResolveCredential(Profile(Configured()), runtimeRevision: 0, authorityEpoch: 2));
    }

    [Fact]
    public void A_response_outside_the_challenge_status_set_needs_no_reaction()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        var result = service.ProcessResponse(
            Profile(Configured()),
            "GET /pets",
            statusCode: 200,
            Headers(("X-Challenge", [SessionCanary])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.None, result.Disposition);
        Assert.Null(result.PublicMessage);
    }

    [Fact]
    public void A_challenge_for_a_replay_safe_operation_is_captured_and_replayed_once()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);
        var service = new ChallengeSessionService(cache, clock);

        var result = service.ProcessResponse(
            Profile(Configured()),
            "GET /pets",
            statusCode: 409,
            Headers(("X-Challenge", [SessionCanary])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.Replay, result.Disposition);
        Assert.Null(result.PublicMessage);

        Assert.True(cache.TryGet("challenge-session", 1, 0, out var entry));
        Assert.Equal(SessionCanary, entry!.Value);
        Assert.Equal(Now.AddMinutes(5), entry.ExpiresAtUtc);
    }

    [Fact]
    public void A_second_challenge_after_the_retry_is_reported_as_repeated()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        var result = service.ProcessResponse(
            Profile(Configured()),
            "GET /pets",
            statusCode: 409,
            Headers(("X-Challenge", [SessionCanary])),
            replayAttempt: 1,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.RepeatedChallenge, result.Disposition);
        Assert.NotNull(result.PublicMessage);
    }

    [Fact]
    public void A_challenge_for_an_operation_outside_the_replay_safe_set_requires_negotiation()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        var result = service.ProcessResponse(
            Profile(Configured()),
            "DELETE /pets/{id}",
            statusCode: 409,
            Headers(("X-Challenge", [SessionCanary])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.NegotiationRequired, result.Disposition);
        Assert.NotNull(result.PublicMessage);
    }

    [Fact]
    public void A_challenge_is_never_replayed_automatically_when_replay_is_disallowed()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        var result = service.ProcessResponse(
            Profile(Configured()),
            "GET /pets",
            statusCode: 409,
            Headers(("X-Challenge", [SessionCanary])),
            replayAttempt: 0,
            automaticReplayAllowed: false);

        Assert.Equal(ChallengeSessionDisposition.NegotiationRequired, result.Disposition);
    }

    [Fact]
    public void A_challenge_without_the_configured_selector_is_invalid()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        var result = service.ProcessResponse(
            Profile(Configured()),
            "GET /pets",
            statusCode: 409,
            Headers(("X-Other", [SessionCanary])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.InvalidChallenge, result.Disposition);
        Assert.NotNull(result.PublicMessage);
        Assert.DoesNotContain(SessionCanary, result.PublicMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void An_ambiguous_or_oversize_challenge_value_is_invalid()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        var ambiguous = service.ProcessResponse(
            Profile(Configured()),
            "GET /pets",
            statusCode: 409,
            Headers(("X-Challenge", [SessionCanary, "second"])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.InvalidChallenge, ambiguous.Disposition);

        var oversize = service.ProcessResponse(
            Profile(Configured()),
            "GET /pets",
            statusCode: 409,
            Headers(("X-Challenge", [new string('c', 16_385)])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.InvalidChallenge, oversize.Disposition);
    }

    [Fact]
    public void A_cookie_challenge_reads_only_the_named_cookie()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);
        var service = new ChallengeSessionService(cache, clock);

        var result = service.ProcessResponse(
            Profile(CookieConfigured()),
            "GET /pets",
            statusCode: 419,
            Headers(("Set-Cookie", ["other=ignored; Path=/", $"challenge=\"{SessionCanary}\"; Path=/; HttpOnly"])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.Replay, result.Disposition);
        Assert.True(cache.TryGet("challenge-session", 1, 0, out var entry));
        Assert.Equal(SessionCanary, entry!.Value);
    }

    [Fact]
    public void A_cookie_challenge_with_two_matching_cookies_is_invalid()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        var result = service.ProcessResponse(
            Profile(CookieConfigured()),
            "GET /pets",
            statusCode: 419,
            Headers(("Set-Cookie", ["challenge=one; Path=/", "challenge=two; Path=/other"])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.InvalidChallenge, result.Disposition);
    }

    [Fact]
    public void A_non_challenge_profile_is_never_processed()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        var result = service.ProcessResponse(
            Profile(Configured(), AuthenticationKind.Static),
            "GET /pets",
            statusCode: 409,
            Headers(("X-Challenge", [SessionCanary])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        Assert.Equal(ChallengeSessionDisposition.None, result.Disposition);
    }

    [Fact]
    public void A_non_challenge_profile_cannot_resolve_a_session_credential()
    {
        var service = new ChallengeSessionService(new ChallengeSessionCache(new FixedClock(Now)), new FixedClock(Now));

        Assert.Throws<UnsupportedAuthenticationStrategyException>(
            () => service.ResolveCredential(Profile(Configured(), AuthenticationKind.OAuth2ClientCredentials), 0, 0));
    }

    [Fact]
    public void Invalidating_a_profile_drops_its_capture()
    {
        var clock = new FixedClock(Now);
        var cache = new ChallengeSessionCache(clock);
        var service = new ChallengeSessionService(cache, clock);

        _ = service.ProcessResponse(
            Profile(Configured()),
            "GET /pets",
            statusCode: 409,
            Headers(("X-Challenge", [SessionCanary])),
            replayAttempt: 0,
            automaticReplayAllowed: true);

        service.InvalidateProfile("challenge-session");

        Assert.Equal(0, cache.Count);
        Assert.Null(service.ResolveCredential(Profile(Configured()), 0, 1));
    }

    private static readonly DateTimeOffset Now = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    private static AuthenticationProfile Profile(JsonObject configuration, AuthenticationKind kind = AuthenticationKind.ChallengeSession) =>
        new(
            "challenge-session",
            kind,
            configuration,
            ["https://api.example.com:443"],
            ["https://api.example.com:443"],
            [],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            [new AuthenticationSlot("session", AuthorityEpoch: 1, RuntimeRevision: 0)]);

    private static JsonObject Configured() => Json(
        """
        {
          "strategyId": "bounded-challenge-session",
          "challenge": { "statusCodes": [409], "source": "header", "selector": "X-Challenge" },
          "injection": { "location": "header", "name": "Authorization", "prefix": "Bearer " },
          "replaySafeOperationKeys": ["GET /pets"],
          "sessionLifetimeSeconds": 300
        }
        """);

    private static JsonObject CookieConfigured() => Json(
        """
        {
          "strategyId": "bounded-challenge-session",
          "challenge": { "statusCodes": [419], "source": "cookie", "selector": "challenge" },
          "injection": { "location": "cookie", "name": "session" },
          "replaySafeOperationKeys": ["GET /pets"],
          "sessionLifetimeSeconds": 300
        }
        """);

    private static JsonObject Json(string text) =>
        CanonicalJson.Parse(Encoding.UTF8.GetBytes(text))!.AsObject();

    private static IReadOnlyDictionary<string, string[]> Headers(params (string Name, string[] Values)[] headers) =>
        headers.ToDictionary(header => header.Name, header => header.Values, StringComparer.OrdinalIgnoreCase);

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }
}
