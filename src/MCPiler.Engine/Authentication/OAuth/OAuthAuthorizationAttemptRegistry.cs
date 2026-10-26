namespace MCPiler.Engine.Authentication.OAuth;

/// <summary>
/// A bounded, in-memory set of live authorization attempts, keyed by their one-time state. It
/// admits a limited number of concurrent attempts and prunes any attempt that has reached a
/// terminal state or passed its lifetime, so neither a restart nor a busy operator accumulates
/// attempts without limit.
/// </summary>
/// <remarks>
/// The registry holds no durable state and stores nothing a process restart should retain. It
/// exists so an operator channel can complete one bound attempt and refuse a replayed or
/// superseded one deterministically.
/// </remarks>
public sealed class OAuthAuthorizationAttemptRegistry
{
    /// <summary>The number of concurrent attempts admitted when a capacity is not supplied.</summary>
    public const int DefaultCapacity = 8;

    private readonly object _gate = new();
    private readonly Dictionary<string, OAuthAuthorizationAttempt> _attempts = new(StringComparer.Ordinal);
    private readonly int _capacity;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a registry with a bounded capacity.</summary>
    /// <param name="capacity">The greatest number of concurrent attempts the registry admits.</param>
    /// <param name="timeProvider">The clock used to prune expired attempts.</param>
    public OAuthAuthorizationAttemptRegistry(int capacity = DefaultCapacity, TimeProvider? timeProvider = null)
    {
        if (capacity <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity), capacity, "The attempt capacity must be positive.");
        }

        _capacity = capacity;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>The greatest number of concurrent attempts the registry admits.</summary>
    public int Capacity => _capacity;

    /// <summary>The number of live attempts after pruning terminal and expired ones.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                Prune();
                return _attempts.Count;
            }
        }
    }

    /// <summary>
    /// Admits an attempt. Admission is refused when the registry is full or when an attempt with
    /// the same state is already registered, so a state can never complete two attempts.
    /// </summary>
    /// <param name="attempt">The attempt to admit.</param>
    /// <returns>Whether the attempt was admitted.</returns>
    public bool TryRegister(OAuthAuthorizationAttempt attempt)
    {
        ArgumentNullException.ThrowIfNull(attempt);

        lock (_gate)
        {
            Prune();

            if (_attempts.ContainsKey(attempt.State) || _attempts.Count >= _capacity)
            {
                return false;
            }

            _attempts.Add(attempt.State, attempt);
            return true;
        }
    }

    /// <summary>Finds a live attempt by its state, or returns <c>null</c>.</summary>
    /// <param name="state">The one-time state the attempt was registered under.</param>
    /// <returns>The attempt, or <c>null</c> when it is unknown, terminal or expired.</returns>
    public OAuthAuthorizationAttempt? Find(string state)
    {
        ArgumentException.ThrowIfNullOrEmpty(state);

        lock (_gate)
        {
            Prune();
            return _attempts.GetValueOrDefault(state);
        }
    }

    /// <summary>Removes an attempt by its state so its state can no longer be looked up.</summary>
    /// <param name="state">The one-time state the attempt was registered under.</param>
    /// <returns>The removed attempt, or <c>null</c> when none was registered.</returns>
    public OAuthAuthorizationAttempt? Remove(string state)
    {
        ArgumentException.ThrowIfNullOrEmpty(state);

        lock (_gate)
        {
            if (_attempts.Remove(state, out var attempt))
            {
                return attempt;
            }

            return null;
        }
    }

    private void Prune()
    {
        var now = _timeProvider.GetUtcNow();
        var stale = _attempts
            .Where(pair => pair.Value.IsTerminal || pair.Value.ExpiresAtUtc <= now)
            .Select(static pair => pair.Key)
            .ToArray();

        foreach (var state in stale)
        {
            _attempts.Remove(state);
        }
    }
}
