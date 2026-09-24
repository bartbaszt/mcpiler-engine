namespace MCPiler.Engine.Runtime;

/// <summary>Whether a cache-enabled invocation hit, missed, or bypassed the cache.</summary>
public enum ResponseCacheDecisionKind
{
    /// <summary>An entry matching the request identity was served without an upstream call.</summary>
    Hit,

    /// <summary>The cache was consulted and no entry matched; the invocation went upstream.</summary>
    Miss,

    /// <summary>The cache was not consulted, or a consulted key could not be used.</summary>
    Bypass,
}

/// <summary>Where an invocation's response actually came from.</summary>
public enum ResponseCacheExecution
{
    /// <summary>No response was produced by this invocation.</summary>
    None,

    /// <summary>The invocation reached the upstream itself.</summary>
    Upstream,

    /// <summary>The invocation consumed a cached or shared raw response.</summary>
    Cached,
}

/// <summary>The exact-key single-flight role an invocation held.</summary>
public enum ResponseCacheFlightRole
{
    /// <summary>The invocation did not register or join a flight.</summary>
    None,

    /// <summary>The invocation began the flight for its key and performed the upstream call.</summary>
    Producer,

    /// <summary>The invocation joined an in-flight producer for its key instead of calling upstream.</summary>
    Joined,
}

/// <summary>
/// The closed vocabulary of reasons a cache decision can carry.
/// </summary>
/// <remarks>
/// Every value is a stable, lowercase token that names a condition the admission layer can
/// produce. It never embeds a request value, a key preimage or a header. The mapping is
/// exercised by the Engine test suite so adding an admission arm without a reason fails.
/// </remarks>
public static class ResponseCacheDecisionReason
{
    /// <summary>An entry was served from cache.</summary>
    public const string Hit = "hit";

    /// <summary>The cache was consulted and no entry matched.</summary>
    public const string Miss = "miss";

    /// <summary>Response caching is disabled for this mount.</summary>
    public const string Disabled = "disabled";

    /// <summary>The operation declares no response-cache policy, so no entry was looked up.</summary>
    public const string PolicyAbsent = "policy-absent";

    /// <summary>The transport carries request state the cache key cannot represent.</summary>
    public const string TransportState = "transport-state";

    /// <summary>The authored policy or the host ceiling cannot admit a usable TTL.</summary>
    public const string InvalidPolicy = "invalid-policy";

    /// <summary>The request identity lacks an authority, partition or materialized body.</summary>
    public const string UnknownDimension = "unknown-dimension";

    /// <summary>The mount's producer-flight ceiling is reached.</summary>
    public const string FlightCapacity = "flight-capacity";

    /// <summary>The cache was disposed during the invocation.</summary>
    public const string Disposed = "disposed";

    /// <summary>The request method is not cacheable.</summary>
    public const string UnsupportedMethod = "unsupported-method";

    /// <summary>The request carried a range or conditional header.</summary>
    public const string RangeOrConditional = "range-or-conditional";

    /// <summary>The request directed that the response not be served from or stored in a cache.</summary>
    public const string RequestDirective = "request-directive";

    /// <summary>A request cache directive could not be parsed.</summary>
    public const string MalformedRequestHeader = "malformed-request-header";

    /// <summary>The response status is not a cacheable success.</summary>
    public const string UnsuccessfulStatus = "unsuccessful-status";

    /// <summary>The response was a partial (206) response.</summary>
    public const string PartialResponse = "partial-response";

    /// <summary>The exchange followed a redirect.</summary>
    public const string Redirected = "redirected";

    /// <summary>The response was a binary/file response.</summary>
    public const string FileResponse = "file-response";

    /// <summary>The response media type is not cacheable.</summary>
    public const string UnsupportedMediaType = "unsupported-media-type";

    /// <summary>The response carried a conditional-request precondition.</summary>
    public const string ConditionalRequest = "conditional-request";

    /// <summary>The response carried authentication-establishing metadata.</summary>
    public const string AuthenticationMetadata = "authentication-metadata";

    /// <summary>The response directed that it not be stored.</summary>
    public const string ResponseDirective = "response-directive";

    /// <summary>The response's <c>Vary</c> could not be represented by the cache key.</summary>
    public const string UnsupportedVary = "unsupported-vary";

    /// <summary>A caller-specific response would have been stored under a shared partition.</summary>
    public const string PublicPrivateResponse = "public-private-response";

    /// <summary>The response's freshness metadata could not be parsed.</summary>
    public const string MalformedFreshness = "malformed-freshness";

    /// <summary>The response's usable freshness had already elapsed.</summary>
    public const string FreshnessExpired = "freshness-expired";

    /// <summary>The authority under which the response was produced expires too soon.</summary>
    public const string AuthorityExpired = "authority-expired";

    /// <summary>A hit was unusable because the invocation's own response ceiling is smaller.</summary>
    public const string ResponseSizeExceeded = "response-size-exceeded";

    /// <summary>A live response was admitted into the cache.</summary>
    public const string Stored = "stored";

    /// <summary>
    /// A live response was not admitted, and the post-exchange identity or clear epoch no longer
    /// matched the key the lookup began under.
    /// </summary>
    public const string NotStored = "not-stored";

    /// <summary>A join waited for a producer that published no shared response.</summary>
    public const string Joined = "joined";

    /// <summary>The invocation's outcome was a failure and carried no cache decision.</summary>
    public const string Failed = "failed";

    /// <summary>The invocation's response was admitted but refused by a per-entry or per-mount ceiling.</summary>
    public const string AdmissionRefused = "admission-refused";

    /// <summary>The invocation produced no response to reason about.</summary>
    public const string Unavailable = "unavailable";

    /// <summary>The invocation executed upstream after a producer stored nothing.</summary>
    public const string LiveSend = "live-send";
}

/// <summary>One sanitized response-cache decision for a single invocation.</summary>
/// <param name="ObservedAtUtc">When the invocation finished.</param>
/// <param name="OperationSlug">The agent-operation slug the invocation ran.</param>
/// <param name="Kind">Hit, miss or bypass.</param>
/// <param name="Execution">Whether the response came from cache or the upstream.</param>
/// <param name="Reason">A <see cref="ResponseCacheDecisionReason"/> token.</param>
/// <param name="KeyFingerprint">
/// A short derivative of the fixed cache-key digest, or null when no key existed. It is never
/// the preimage.
/// </param>
/// <param name="EffectiveTtlSeconds">The effective TTL in seconds, when one was established.</param>
/// <param name="AgeSeconds">For a hit, how long the entry had existed.</param>
/// <param name="RemainingTtlSeconds">For a hit, how much of the effective TTL remained.</param>
/// <param name="FlightRole">The invocation's single-flight role.</param>
/// <param name="EntryBytes">The accounted size of the stored entry, when one was stored.</param>
/// <param name="Stored">Whether the invocation's response was admitted into the cache.</param>
public sealed record ResponseCacheDecision(
    DateTimeOffset ObservedAtUtc,
    string OperationSlug,
    ResponseCacheDecisionKind Kind,
    ResponseCacheExecution Execution,
    string Reason,
    string? KeyFingerprint,
    int? EffectiveTtlSeconds,
    int? AgeSeconds,
    int? RemainingTtlSeconds,
    ResponseCacheFlightRole FlightRole,
    long? EntryBytes,
    bool Stored);

/// <summary>
/// A bounded, sanitized view of one mount's recent cache behavior.
/// </summary>
/// <param name="MountPrefix">The mount the observation belongs to.</param>
/// <param name="Invocations">How many invocations consulted this mount's cache.</param>
/// <param name="UpstreamSends">How many of those reached the upstream themselves.</param>
/// <param name="Recent">
/// The most recent sanitized decisions, newest last. Never more than the mount's own bound,
/// and never older than the observation window.
/// </param>
public sealed record ResponseCacheObservation(
    string MountPrefix,
    long Invocations,
    long UpstreamSends,
    IReadOnlyList<ResponseCacheDecision> Recent);

/// <summary>The bounded result of clearing one mount's cache, optionally for one operation.</summary>
/// <param name="MountPrefix">The mount that was cleared.</param>
/// <param name="OperationSlug">The operation filter, or null for the whole mount.</param>
/// <param name="RemovedEntries">How many completed entries were removed.</param>
/// <param name="MountEpoch">The mount clear epoch after the action.</param>
/// <param name="OperationEpoch">The operation clear epoch after the action (zero for a whole-mount clear).</param>
public sealed record ResponseCacheClearOutcome(
    string MountPrefix,
    string? OperationSlug,
    int RemovedEntries,
    long MountEpoch,
    long OperationEpoch);
