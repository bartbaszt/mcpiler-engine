namespace MCPiler.Engine.Host.Authorization;

/// <summary>Which trust endpoint produced an issuer availability observation.</summary>
internal enum IssuerAvailabilityMode
{
    /// <summary>The issuer's published key set answered local signature validation.</summary>
    Jwks = 0,

    /// <summary>The issuer's RFC 7662 introspection endpoint answered a standing question.</summary>
    Introspection = 1,
}

/// <summary>One stable, sanitized category of trust interaction outcome.</summary>
/// <remarks>
/// Every category names what this process asked and what came back. None of them can carry a token,
/// a key, an endpoint spelling, a response body or a user identity, because the vocabulary has no
/// place for one: the operator surface is read by people who are troubleshooting, not by anyone who
/// should learn an upstream document's contents or a caller's standing beyond the category.
/// </remarks>
internal enum IssuerAvailabilityCategory
{
    /// <summary>The issuer's key set was fetched and is usable for local signature validation.</summary>
    KeySetRefreshed,

    /// <summary>No usable metadata document resolved, so no trust endpoint could be named.</summary>
    MetadataUnavailable,

    /// <summary>Metadata resolved, but the key endpoint failed or published unusable material.</summary>
    KeySetUnavailable,

    /// <summary>
    /// A presented token was refused locally while key material was available. That is a token
    /// decision, not an issuer outage, and the two must never be reported as one.
    /// </summary>
    TokenRejected,

    /// <summary>The introspection endpoint answered, and the answer named the token active.</summary>
    IssuerAnswered,

    /// <summary>
    /// The introspection endpoint answered <c>active:false</c>: an authoritative statement that the
    /// token is not usable, which is distinct from an endpoint that could not answer.
    /// </summary>
    TokenInactive,

    /// <summary>The introspection request failed, timed out or returned an unusable answer.</summary>
    IntrospectionUnavailable,
}

/// <summary>One timestamped, sanitized trust observation.</summary>
/// <param name="ObservedAtUtc">When this process observed the outcome, by its own clock.</param>
/// <param name="Mode">The validation mode that produced the observation.</param>
/// <param name="Category">The stable category of the outcome.</param>
internal readonly record struct IssuerAvailabilityObservation(
    DateTimeOffset ObservedAtUtc,
    IssuerAvailabilityMode Mode,
    IssuerAvailabilityCategory Category);

/// <summary>The stable spelling of one observation's mode or category.</summary>
/// <remarks>
/// The operator channel and every test read the vocabulary from here, so a script matching
/// <c>keys-unavailable</c> matches exactly the category the validator recorded.
/// </remarks>
internal static class IssuerAvailabilityNames
{
    /// <summary>Writes the wire spelling of <paramref name="mode"/>.</summary>
    internal static string Write(IssuerAvailabilityMode mode)
        => mode is IssuerAvailabilityMode.Jwks ? "jwks" : "introspection";

    /// <summary>Writes the wire spelling of <paramref name="category"/>.</summary>
    internal static string Write(IssuerAvailabilityCategory category) => category switch
    {
        IssuerAvailabilityCategory.KeySetRefreshed => "keys-refreshed",
        IssuerAvailabilityCategory.MetadataUnavailable => "metadata-unavailable",
        IssuerAvailabilityCategory.KeySetUnavailable => "keys-unavailable",
        IssuerAvailabilityCategory.TokenRejected => "token-rejected",
        IssuerAvailabilityCategory.IssuerAnswered => "issuer-answered",
        IssuerAvailabilityCategory.TokenInactive => "token-inactive",
        _ => "introspection-unavailable",
    };
}

/// <summary>The fixed, non-secret fail-closed consequence of one observation category.</summary>
/// <remarks>
/// The text is selected from the category and mode alone. Nothing observed at runtime is
/// interpolated, so this cannot become a channel for an endpoint spelling, a response member or a
/// credential, however the shared resolvers and validators evolve their own messages.
/// </remarks>
internal static class IssuerAvailabilityEffects
{
    /// <summary>Describes the fail-closed effect of one observed category.</summary>
    internal static string Describe(IssuerAvailabilityMode mode, IssuerAvailabilityCategory category)
        => (mode, category) switch
        {
            (_, IssuerAvailabilityCategory.KeySetRefreshed) =>
                "none; a refreshed key set answered local token validation under the accepted JWKS policy",
            (_, IssuerAvailabilityCategory.IssuerAnswered) =>
                "none; the issuer answered the introspection request",
            (_, IssuerAvailabilityCategory.TokenRejected) =>
                "none; the presented token was refused, which is a token decision and not an issuer outage",
            (_, IssuerAvailabilityCategory.TokenInactive) =>
                "none; the issuer stated that the presented token is inactive",
            (_, IssuerAvailabilityCategory.MetadataUnavailable) =>
                "fail-closed; protected requests are refused unless a bounded cached key set or positive introspection result still covers them",
            (IssuerAvailabilityMode.Jwks, IssuerAvailabilityCategory.KeySetUnavailable) =>
                "fail-closed; a bounded stale key set may still answer, otherwise protected requests are refused",
            _ =>
                "fail-closed; protected requests are refused unless the bounded positive introspection cache still covers them",
        };
}

/// <summary>
/// A narrow, bounded, in-memory record of recent issuer trust observations.
/// </summary>
/// <remarks>
/// <para>
/// This is diagnostic state, deliberately not an audit log and deliberately not an input to any
/// authorization decision. Recording one cannot change a verdict: every observation is written as a
/// side effect of the decision the validators already made, and <see cref="Record"/> cannot throw.
/// Absence of history means no observation was ever recorded, never that validation behaved
/// differently.
/// </para>
/// <para>
/// Bounded in two directions — a maximum entry count and a retention window — so a long-lived
/// serving process cannot accumulate unbounded operator state. Discarded with the process, like the
/// authorization outcome buffer; the operator surface says so rather than inventing history.
/// </para>
/// </remarks>
/// <param name="retention">How long an observation stays visible.</param>
/// <param name="maximumEntries">How many observations are retained at most.</param>
internal sealed class IssuerAvailabilityObservations(
    TimeSpan? retention = null,
    int maximumEntries = IssuerAvailabilityObservations.DefaultMaximumEntries)
{
    /// <summary>How many observations are retained at most.</summary>
    internal const int DefaultMaximumEntries = 32;

    /// <summary>How long an observation stays visible.</summary>
    internal static readonly TimeSpan DefaultRetention = TimeSpan.FromMinutes(10);

    private readonly object _gate = new();
    private readonly LinkedList<IssuerAvailabilityObservation> _entries = new();
    private readonly TimeSpan _retention = retention ?? DefaultRetention;

    /// <summary>The entry ceiling, for a bounded-state assertion.</summary>
    internal int MaximumEntries { get; } = maximumEntries <= 0 ? DefaultMaximumEntries : maximumEntries;

    /// <summary>The number of observations currently retained. Prunes first.</summary>
    internal int Count
    {
        get
        {
            lock (_gate)
            {
                Prune(TimeProvider.System.GetUtcNow());
                return _entries.Count;
            }
        }
    }

    /// <summary>Records one observation, dropping the oldest once the ceiling is reached.</summary>
    /// <remarks>
    /// Deliberately free of validation and allocation beyond one list node: this is called on the
    /// request's path, and a diagnostic that could throw would turn a token verdict into a failure.
    /// </remarks>
    internal void Record(
        DateTimeOffset observedAtUtc,
        IssuerAvailabilityMode mode,
        IssuerAvailabilityCategory category)
    {
        lock (_gate)
        {
            Prune(observedAtUtc);
            _entries.AddFirst(new IssuerAvailabilityObservation(observedAtUtc, mode, category));

            while (_entries.Count > MaximumEntries)
            {
                _entries.RemoveLast();
            }
        }
    }

    /// <summary>Returns the retained observations, newest first, at most <paramref name="maximum"/> of them.</summary>
    internal IReadOnlyList<IssuerAvailabilityObservation> Recent(
        DateTimeOffset now,
        int maximum = DefaultMaximumEntries)
    {
        if (maximum <= 0)
        {
            return [];
        }

        lock (_gate)
        {
            Prune(now);
            List<IssuerAvailabilityObservation> report = [];

            foreach (IssuerAvailabilityObservation observation in _entries)
            {
                if (report.Count == maximum)
                {
                    break;
                }

                report.Add(observation);
            }

            return report;
        }
    }

    /// <summary>Discards every retained observation.</summary>
    internal void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
        }
    }

    private void Prune(DateTimeOffset now)
    {
        if (_retention <= TimeSpan.Zero)
        {
            _entries.Clear();
            return;
        }

        if (_entries.Count == 0)
        {
            return;
        }

        DateTimeOffset oldest = now - _retention;

        while (_entries.Last is { } tail && tail.Value.ObservedAtUtc < oldest)
        {
            _entries.RemoveLast();
        }
    }
}
