using System.Globalization;

using MCPiler.Engine.Authentication.Exchange;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.Challenge;

/// <summary>What the runtime should do after an upstream response carried a configured challenge.</summary>
public enum ChallengeSessionDisposition
{
    /// <summary>The response is not a configured challenge and needs no reaction.</summary>
    None,

    /// <summary>The reviewed session value was captured and the operation may be sent once more.</summary>
    Replay,

    /// <summary>Negotiation is required: automatic replay is not safe for this response or operation.</summary>
    NegotiationRequired,

    /// <summary>A second challenge arrived after the single permitted retry.</summary>
    RepeatedChallenge,

    /// <summary>The challenge arrived but did not carry a usable reviewed session value.</summary>
    InvalidChallenge,
}

/// <summary>The disposition and the sanitized message an operator may see.</summary>
/// <param name="Disposition">What to do next.</param>
/// <param name="PublicMessage">A bounded, secret-free explanation; null when nothing happened.</param>
public sealed record ChallengeSessionResult(
    ChallengeSessionDisposition Disposition,
    string? PublicMessage = null);

/// <summary>
/// The runtime facts of a challenge-session profile.
///
/// The manifest reader is the validation authority for the closed configuration schema; this
/// projection re-states only what execution needs, so a reader change cannot silently change
/// runtime behaviour without also changing what arrives here.
/// </summary>
/// <param name="StatusCodes">Upstream status codes that carry a challenge.</param>
/// <param name="SelectorKind">Whether the session value is read from a header or a cookie.</param>
/// <param name="Selector">The header or cookie name.</param>
/// <param name="Injection">How the captured session value is injected into later requests.</param>
/// <param name="ReplaySafeOperationKeys">Operation keys that may be sent again after a capture.</param>
/// <param name="SessionLifetime">How long a captured session value remains usable.</param>
public sealed record ChallengeSessionDefinition(
    IReadOnlySet<int> StatusCodes,
    ExchangeSelectorKind SelectorKind,
    string Selector,
    Exchange.SessionInjectionDefinition Injection,
    IReadOnlySet<string> ReplaySafeOperationKeys,
    TimeSpan SessionLifetime)
{
    /// <summary>The longest session the format admits, so an injected credential cannot outlive the reviewed bound.</summary>
    public static TimeSpan MaximumSessionLifetime { get; } = TimeSpan.FromDays(30);

    /// <summary>Default lifetime when the profile omits one.</summary>
    public static TimeSpan DefaultSessionLifetime { get; } = TimeSpan.FromHours(8);

    /// <summary>The default challenge status code.</summary>
    public static int DefaultStatusCode { get; } = 409;

    /// <summary>Projects an already-validated configuration object.</summary>
    /// <param name="configuration">The manifest profile configuration.</param>
    public static ChallengeSessionDefinition FromConfiguration(System.Text.Json.Nodes.JsonObject configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var statusCodes = new HashSet<int>();
        var challenge = configuration["challenge"] as System.Text.Json.Nodes.JsonObject;

        if (challenge?["statusCodes"] is System.Text.Json.Nodes.JsonArray declared)
        {
            foreach (var item in declared)
            {
                if (item is System.Text.Json.Nodes.JsonValue value && value.TryGetValue<int>(out var status))
                {
                    statusCodes.Add(status);
                }
            }
        }

        if (statusCodes.Count == 0)
        {
            statusCodes.Add(DefaultStatusCode);
        }

        var source = challenge?["source"] is System.Text.Json.Nodes.JsonValue sourceValue
            && sourceValue.TryGetValue<string>(out var sourceText)
            ? sourceText
            : "header";

        var selector = challenge?["selector"] is System.Text.Json.Nodes.JsonValue selectorValue
            && selectorValue.TryGetValue<string>(out var selectorText)
            ? selectorText
            : throw new AuthenticationPlanException("challenge", "The challenge-session profile declares no selector.");

        var injection = ReadInjection(configuration);
        var replaySafe = ReadReplaySafeKeys(configuration);
        var lifetime = ReadLifetime(configuration);

        return new ChallengeSessionDefinition(
            statusCodes,
            string.Equals(source, "cookie", StringComparison.Ordinal)
                ? ExchangeSelectorKind.Cookie
                : ExchangeSelectorKind.Header,
            selector,
            injection,
            replaySafe,
            lifetime);
    }

    private static Exchange.SessionInjectionDefinition ReadInjection(
        System.Text.Json.Nodes.JsonObject configuration)
    {
        if (configuration["injection"] is not System.Text.Json.Nodes.JsonObject injection
            || injection["location"] is not System.Text.Json.Nodes.JsonValue locationValue
            || !locationValue.TryGetValue<string>(out var location))
        {
            throw new AuthenticationPlanException(
                "challenge",
                "The challenge-session profile declares no injection location.");
        }

        var name = injection["name"] is System.Text.Json.Nodes.JsonValue nameValue
            && nameValue.TryGetValue<string>(out var nameText)
            ? nameText
            : null;

        var prefix = injection["prefix"] is System.Text.Json.Nodes.JsonValue prefixValue
            && prefixValue.TryGetValue<string>(out var prefixText)
            ? prefixText
            : null;

        return Exchange.SessionInjectionDefinition.FromValidated(location, name, prefix);
    }

    private static IReadOnlySet<string> ReadReplaySafeKeys(
        System.Text.Json.Nodes.JsonObject configuration)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);

        if (configuration["replaySafeOperationKeys"] is System.Text.Json.Nodes.JsonArray declared)
        {
            foreach (var item in declared)
            {
                if (item is System.Text.Json.Nodes.JsonValue value
                    && value.TryGetValue<string>(out var key)
                    && key.Length > 0)
                {
                    keys.Add(key);
                }
            }
        }

        return keys;
    }

    private static TimeSpan ReadLifetime(System.Text.Json.Nodes.JsonObject configuration)
    {
        if (configuration["sessionLifetimeSeconds"] is System.Text.Json.Nodes.JsonValue value
            && value.TryGetValue<int>(out var seconds)
            && seconds is >= 1 and <= 2_592_000)
        {
            return TimeSpan.FromSeconds(seconds);
        }

        return DefaultSessionLifetime;
    }
}

/// <summary>A captured session value with the profile identity and revision that produced it.</summary>
/// <param name="ProfileId">Manifest-local profile identity.</param>
/// <param name="AuthorityEpoch">The authority epoch the capture belongs to.</param>
/// <param name="RuntimeRevision">The runtime revision the capture belongs to.</param>
/// <param name="Value">The captured session material.</param>
/// <param name="ExpiresAtUtc">When the capture stops being usable.</param>
public sealed record ChallengeSessionEntry(
    string ProfileId,
    long AuthorityEpoch,
    long RuntimeRevision,
    string Value,
    DateTimeOffset ExpiresAtUtc);

/// <summary>The session credential to apply now, with the expiry of the capture behind it.</summary>
/// <param name="Credential">The credential to apply to the outgoing request.</param>
/// <param name="ExpiresAtUtc">When the captured session stops being usable.</param>
public sealed record ChallengeSessionCredential(
    ResolvedCredential Credential,
    DateTimeOffset ExpiresAtUtc);

/// <summary>
/// A bounded in-memory store for captured challenge sessions, keyed on the exact profile
/// authority state. A new epoch or revision therefore never observes a session captured under a
/// different operator decision.
/// </summary>
public sealed class ChallengeSessionCache
{
    /// <summary>Most sessions one Engine process keeps; eviction is by earliest expiry.</summary>
    public const int MaximumEntries = 256;

    private readonly TimeProvider _timeProvider;
    private readonly Lock _gate = new();
    private readonly Dictionary<(string ProfileId, long AuthorityEpoch, long RuntimeRevision), ChallengeSessionEntry> _entries = [];

    /// <summary>Creates a cache bound to a clock.</summary>
    public ChallengeSessionCache(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        _timeProvider = timeProvider;
    }

    /// <summary>Reads a live capture for the exact profile authority state.</summary>
    public bool TryGet(
        string profileId,
        long authorityEpoch,
        long runtimeRevision,
        out ChallengeSessionEntry? entry)
    {
        var key = (profileId, authorityEpoch, runtimeRevision);

        lock (_gate)
        {
            if (_entries.TryGetValue(key, out var candidate))
            {
                if (candidate.ExpiresAtUtc > _timeProvider.GetUtcNow())
                {
                    entry = candidate;
                    return true;
                }

                _entries.Remove(key);
            }
        }

        entry = null;
        return false;
    }

    /// <summary>Captures a session value, replacing any earlier capture for the same state.</summary>
    public void Set(ChallengeSessionEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        lock (_gate)
        {
            if (_entries.Count >= MaximumEntries && !_entries.ContainsKey((entry.ProfileId, entry.AuthorityEpoch, entry.RuntimeRevision)))
            {
                var oldest = _entries.MinBy(pair => pair.Value.ExpiresAtUtc);

                if (oldest.Key != default)
                {
                    _entries.Remove(oldest.Key);
                }
            }

            _entries[(entry.ProfileId, entry.AuthorityEpoch, entry.RuntimeRevision)] = entry;
        }
    }

    /// <summary>Removes every capture for one profile, whatever its authority state.</summary>
    public void InvalidateProfile(string profileId)
    {
        lock (_gate)
        {
            foreach (var key in _entries.Keys.Where(key => string.Equals(key.ProfileId, profileId, StringComparison.Ordinal)).ToList())
            {
                _entries.Remove(key);
            }
        }
    }

    /// <summary>The number of live entries, for diagnostics and tests.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }
}

/// <summary>
/// Challenge-response authentication over a response this Engine already received.
///
/// Nothing here makes an outbound request: a challenge is only ever a reaction to a response, so
/// the service is pure with respect to the network and the caller stays in control of the single
/// permitted replay.
/// </summary>
public sealed class ChallengeSessionService
{
    private readonly ChallengeSessionCache _cache;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates the service over a session cache and a clock.</summary>
    public ChallengeSessionService(ChallengeSessionCache cache, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _cache = cache;
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// The session credential to apply now, or null when no unexpired capture exists. A caller
    /// sends the operation unauthenticated and learns from the response whether a challenge is due.
    /// </summary>
    /// <remarks>
    /// The expiry travels with the credential because a response obtained under a captured session
    /// must not outlive it: the session is the authority the upstream granted, and a cache entry
    /// that survived it would serve an answer under a credential the upstream has already retired.
    /// </remarks>
    public ChallengeSessionCredential? ResolveCredential(
        AuthenticationProfile profile,
        long runtimeRevision,
        long authorityEpoch)
    {
        ArgumentNullException.ThrowIfNull(profile);

        if (profile.Kind != AuthenticationKind.ChallengeSession)
        {
            throw new UnsupportedAuthenticationStrategyException(
                $"The resolved authentication profile is not a challenge-session strategy but '{profile.Kind}'.");
        }

        if (!_cache.TryGet(profile.Id, authorityEpoch, runtimeRevision, out var entry) || entry is null)
        {
            return null;
        }

        var definition = ChallengeSessionDefinition.FromConfiguration(profile.Configuration);

        return new ChallengeSessionCredential(
            definition.Injection.CreateCredential(entry.Value),
            entry.ExpiresAtUtc);
    }

    /// <summary>Decides what a just-received response means for the profile.</summary>
    /// <param name="profile">The challenge-session profile governing the operation.</param>
    /// <param name="operationKey">The executed operation's key, matched against the replay-safe set.</param>
    /// <param name="statusCode">The upstream status code.</param>
    /// <param name="headers">The upstream response headers.</param>
    /// <param name="replayAttempt">0 for the initial response, 1 for the single permitted retry.</param>
    /// <param name="automaticReplayAllowed">False when an explicit freeze must not be replayed.</param>
    public ChallengeSessionResult ProcessResponse(
        AuthenticationProfile profile,
        string operationKey,
        int statusCode,
        IReadOnlyDictionary<string, string[]> headers,
        int replayAttempt,
        bool automaticReplayAllowed)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(headers);

        if (profile.Kind != AuthenticationKind.ChallengeSession)
        {
            return new ChallengeSessionResult(ChallengeSessionDisposition.None);
        }

        var definition = ChallengeSessionDefinition.FromConfiguration(profile.Configuration);

        if (!definition.StatusCodes.Contains(statusCode))
        {
            return new ChallengeSessionResult(ChallengeSessionDisposition.None);
        }

        var authorityEpoch = DeclaredAuthorityEpoch(profile);
        var runtimeRevision = DeclaredRuntimeRevision(profile);

        if (!TryReadSelector(definition, headers, out var value))
        {
            return new ChallengeSessionResult(
                ChallengeSessionDisposition.InvalidChallenge,
                "The upstream authentication challenge did not include the reviewed session value.");
        }

        if (value.Length is 0 or > TokenSessionExchangeService.MaximumMaterialLength)
        {
            return new ChallengeSessionResult(
                ChallengeSessionDisposition.InvalidChallenge,
                "The upstream authentication challenge returned an invalid session value.");
        }

        _cache.Set(new ChallengeSessionEntry(
            profile.Id,
            authorityEpoch,
            runtimeRevision,
            value,
            _timeProvider.GetUtcNow().Add(definition.SessionLifetime)));

        if (!automaticReplayAllowed || !definition.ReplaySafeOperationKeys.Contains(operationKey))
        {
            return new ChallengeSessionResult(
                ChallengeSessionDisposition.NegotiationRequired,
                "Upstream authentication negotiation is required before this operation can be sent again.");
        }

        if (replayAttempt >= 1)
        {
            return new ChallengeSessionResult(
                ChallengeSessionDisposition.RepeatedChallenge,
                "The upstream authentication challenge repeated after the single permitted retry.");
        }

        return new ChallengeSessionResult(ChallengeSessionDisposition.Replay);
    }

    /// <summary>Drops every capture for one profile after an explicit operator change.</summary>
    public void InvalidateProfile(string profileId)
    {
        ArgumentException.ThrowIfNullOrEmpty(profileId);

        _cache.InvalidateProfile(profileId);
    }

    private static bool TryReadSelector(
        ChallengeSessionDefinition definition,
        IReadOnlyDictionary<string, string[]> headers,
        out string value)
    {
        value = string.Empty;

        switch (definition.SelectorKind)
        {
            case ExchangeSelectorKind.Header:
                if (!headers.TryGetValue(definition.Selector, out var headerValues)
                    || headerValues.Length != 1
                    || string.IsNullOrEmpty(headerValues[0])
                    || headerValues[0].Length > TokenSessionExchangeService.MaximumMaterialLength)
                {
                    return false;
                }

                value = headerValues[0];
                return true;

            case ExchangeSelectorKind.Cookie:
                var matches = new List<string>();

                if (headers.TryGetValue("Set-Cookie", out var cookies))
                {
                    foreach (var cookie in cookies)
                    {
                        var separator = cookie.IndexOf(';', StringComparison.Ordinal);
                        var pair = separator >= 0 ? cookie[..separator] : cookie;
                        var equals = pair.IndexOf('=', StringComparison.Ordinal);

                        if (equals <= 0)
                        {
                            continue;
                        }

                        var name = pair[..equals].Trim();

                        if (!string.Equals(name, definition.Selector, StringComparison.Ordinal))
                        {
                            continue;
                        }

                        matches.Add(Unquote(pair[(equals + 1)..].Trim()));
                    }
                }

                if (matches.Count != 1 || string.IsNullOrEmpty(matches[0])
                    || matches[0].Length > TokenSessionExchangeService.MaximumMaterialLength)
                {
                    return false;
                }

                value = matches[0];
                return true;

            default:
                return false;
        }
    }

    private static string Unquote(string value)
    {
        if (value.Length >= 2
            && value.StartsWith('"')
            && value.EndsWith('"'))
        {
            return value[1..^1];
        }

        return value;
    }

    private static long DeclaredAuthorityEpoch(AuthenticationProfile profile) =>
        profile.Slots.Count > 0 ? profile.Slots[0].AuthorityEpoch : 0;

    private static long DeclaredRuntimeRevision(AuthenticationProfile profile) =>
        profile.Slots.Count > 0 ? profile.Slots[0].RuntimeRevision : 0;
}
