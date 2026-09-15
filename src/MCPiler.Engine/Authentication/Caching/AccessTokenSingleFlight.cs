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
    private readonly Dictionary<string, SemaphoreSlim> _gates = new(StringComparer.Ordinal);
    private readonly object _entries = new();
    private bool _disposed;

    /// <summary>Runs <paramref name="acquire"/> under the gate for <paramref name="key"/>.</summary>
    public async ValueTask<T> RunAsync<T>(
        string key,
        Func<CancellationToken, ValueTask<T>> acquire,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(acquire);
        ObjectDisposedException.ThrowIf(_disposed, this);

        SemaphoreSlim gate;
        lock (_entries)
        {
            if (!_gates.TryGetValue(key, out var existing))
            {
                existing = new SemaphoreSlim(1, 1);
                _gates[key] = existing;
            }

            gate = existing;
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            return await acquire(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
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
                gate.Dispose();
            }

            _gates.Clear();
        }
    }
}
