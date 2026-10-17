namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// One recent authorization outcome, sanitized for an operator.
/// </summary>
/// <remarks>
/// Every field here is either a category this process chose or an identity the operator already
/// supplied. An upstream error body, a callback query, a token, a verifier and a client secret
/// have no field to travel in, which is the point: the buffer cannot leak what it cannot hold.
/// </remarks>
/// <param name="AtUtc">When the outcome was observed.</param>
/// <param name="Verb">The verb that produced it, for example <c>authorize</c>.</param>
/// <param name="Mount">The mount prefix the outcome concerns.</param>
/// <param name="Profile">The profile id the outcome concerns.</param>
/// <param name="Category">A stable category: <c>local</c> or <c>provider</c>.</param>
/// <param name="Code">A stable, scriptable outcome category.</param>
/// <param name="Message">A bounded, non-secret description.</param>
public sealed record AuthorizationOutcome(
    DateTimeOffset AtUtc,
    string Verb,
    string Mount,
    string Profile,
    string Category,
    string Code,
    string Message);

/// <summary>
/// A narrow, bounded, in-memory record of recent authorization outcomes.
/// </summary>
/// <remarks>
/// <para>
/// This is not an audit log and does not claim to be one. It holds nothing durable, it is discarded
/// with the process, and the diagnostic surface says so rather than inventing a history it cannot
/// produce. What it is for is letting an operator see what just happened without re-reading a
/// terminal, and making failure categories machine-readable.
/// </para>
/// <para>
/// Bounded in two directions — a maximum entry count and a retention window — so a long-lived
/// in-host process cannot accumulate unbounded operator state.
/// </para>
/// </remarks>
/// <param name="retention">How long an outcome stays visible.</param>
/// <param name="maximumEntries">How many outcomes are retained at most.</param>
public sealed class AuthorizationOutcomeLog(TimeSpan? retention = null, int maximumEntries = AuthorizationOutcomeLog.DefaultMaximumEntries)
{
    /// <summary>How many outcomes are retained at most.</summary>
    public const int DefaultMaximumEntries = 32;

    /// <summary>How long an outcome stays visible.</summary>
    public static readonly TimeSpan DefaultRetention = TimeSpan.FromMinutes(10);

    /// <summary>The outcomes of this process, used when a caller does not supply its own.</summary>
    public static AuthorizationOutcomeLog Shared { get; } = new();

    private readonly object _gate = new();
    private readonly LinkedList<AuthorizationOutcome> _entries = new();
    private readonly TimeSpan _retention = retention ?? DefaultRetention;

    /// <summary>The entry ceiling, for a bounded-state assertion.</summary>
    public int MaximumEntries { get; } = maximumEntries <= 0 ? DefaultMaximumEntries : maximumEntries;

    /// <summary>The number of outcomes currently retained. Prunes first.</summary>
    public int Count
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

    /// <summary>Records one outcome, dropping the oldest once the ceiling is reached.</summary>
    public void Record(AuthorizationOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(outcome);

        lock (_gate)
        {
            Prune(TimeProvider.System.GetUtcNow());
            _entries.AddFirst(outcome);

            while (_entries.Count > MaximumEntries)
            {
                _entries.RemoveLast();
            }
        }
    }

    /// <summary>Returns the retained outcomes, newest first, at most <paramref name="maximum"/> of them.</summary>
    public IReadOnlyList<AuthorizationOutcome> Recent(DateTimeOffset now, int maximum = DefaultMaximumEntries)
    {
        if (maximum <= 0)
        {
            return [];
        }

        lock (_gate)
        {
            Prune(now);
            List<AuthorizationOutcome> report = [];

            foreach (AuthorizationOutcome outcome in _entries)
            {
                if (report.Count == maximum)
                {
                    break;
                }

                report.Add(outcome);
            }

            return report;
        }
    }

    /// <summary>Discards every retained outcome.</summary>
    public void Clear()
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

        while (_entries.Last is { } tail && tail.Value.AtUtc < oldest)
        {
            _entries.RemoveLast();
        }
    }
}
