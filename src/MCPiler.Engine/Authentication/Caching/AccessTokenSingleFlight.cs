namespace MCPiler.Engine.Authentication.Caching;

/// <summary>
/// Ensures one acquisition runs at a time per key, so concurrent callers of the same credential
/// coalesce onto one upstream request.
/// </summary>
/// <remarks>
/// <para>
/// Without this, a burst of tool calls arriving as one token expires would each present the same
/// refresh credential upstream. A provider that rotates the refresh token on every use would then
/// invalidate the replacement produced by whichever call finished first, and every later caller
/// would be holding a value the provider already retired. Coalescing is a correctness
/// requirement for rotating providers, not an optimization.
/// </para>
/// <para>
/// The loser of the race re-checks its cache inside the gate, so a token acquired while it waited
/// is returned rather than re-fetched.
/// </para>
/// </remarks>
public sealed class AccessTokenSingleFlight : IDisposable
{
    private readonly Dictionary<string, Gate> _gates = new(StringComparer.Ordinal);
    private readonly object _entries = new();
    private bool _disposed;

    /// <summary>The number of per-key gates currently retained. For bounded-growth assertions.</summary>
    public int Count
    {
        get
        {
            lock (_entries)
            {
                return _gates.Count;
            }
        }
    }

    /// <summary>Runs <paramref name="acquire"/> under the gate for <paramref name="key"/>.</summary>
    public async ValueTask<T> RunAsync<T>(
        string key,
        Func<CancellationToken, ValueTask<T>> acquire,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(acquire);
        ObjectDisposedException.ThrowIf(_disposed, this);

        Gate gate;
        lock (_entries)
        {
            if (!_gates.TryGetValue(key, out var existing))
            {
                existing = new Gate();
                _gates[key] = existing;
            }

            existing.Users++;
            gate = existing;
        }

        try
        {
            await gate.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                return await acquire(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                gate.Semaphore.Release();
            }
        }
        finally
        {
            // Deterministic idle removal: once the last caller for a key leaves, the gate stops
            // being retained, so synchronization state cannot accumulate per profile that ever ran
            // and then went quiet. A later caller for the same key simply recreates the gate; while
            // any caller holds it the entry stays, so live coalescing is never weakened.
            lock (_entries)
            {
                gate.Users--;
                if (gate.Users <= 0
                    && _gates.TryGetValue(key, out var current)
                    && ReferenceEquals(current, gate))
                {
                    _gates.Remove(key);
                }
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_entries)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            foreach (var gate in _gates.Values)
            {
                gate.Semaphore.Dispose();
            }

            _gates.Clear();
        }
    }

    private sealed class Gate
    {
        internal SemaphoreSlim Semaphore { get; } = new(1, 1);

        internal int Users { get; set; }
    }
}
