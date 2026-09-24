namespace MCPiler.Engine.Execution.ResponseCaching;

internal enum ResponseFlightAdmissionKind
{
    Producer,
    Joined,
    CapacityBypass,
}

internal sealed record ResponseFlightAdmission(ResponseFlightAdmissionKind Kind, ResponseFlightLease? Lease);

/// <summary>Per-mount exact-key producer registry.</summary>
internal sealed class ResponseFlightRegistry : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<ResponseCacheKey, ResponseFlightState> _flights = [];
    private readonly int _maximumFlights;
    private bool _disposed;

    internal ResponseFlightRegistry(int maximumFlights)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maximumFlights);
        _maximumFlights = maximumFlights;
    }

    internal int Count
    {
        get
        {
            lock (_gate)
            {
                return _flights.Count;
            }
        }
    }

    internal int WaiterCount
    {
        get
        {
            lock (_gate)
            {
                int count = 0;
                foreach (ResponseFlightState state in _flights.Values)
                {
                    count += state.WaiterCount;
                }

                return count;
            }
        }
    }

    internal ResponseFlightAdmission JoinOrBegin(ResponseCacheKey key)
    {
        ArgumentNullException.ThrowIfNull(key);

        lock (_gate)
        {
            if (_disposed)
            {
                return new ResponseFlightAdmission(ResponseFlightAdmissionKind.CapacityBypass, null);
            }

            if (_flights.TryGetValue(key, out ResponseFlightState? existing))
            {
                existing.RegisterWaiter();
                return new ResponseFlightAdmission(
                    ResponseFlightAdmissionKind.Joined,
                    new ResponseFlightLease(this, key, existing, isProducer: false));
            }

            if (_flights.Count >= _maximumFlights)
            {
                return new ResponseFlightAdmission(ResponseFlightAdmissionKind.CapacityBypass, null);
            }

            ResponseFlightState state = new();
            _flights.Add(key, state);
            return new ResponseFlightAdmission(
                ResponseFlightAdmissionKind.Producer,
                new ResponseFlightLease(this, key, state, isProducer: true));
        }
    }

    internal void Complete(ResponseCacheKey key, ResponseFlightState state, ResponseCacheEnvelope? envelope)
    {
        lock (_gate)
        {
            if (_flights.TryGetValue(key, out ResponseFlightState? current) && ReferenceEquals(current, state))
            {
                _flights.Remove(key);
            }
        }

        state.Complete(envelope);
    }

    public void Dispose()
    {
        ResponseFlightState[] pending;

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            pending = [.. _flights.Values];
            _flights.Clear();
        }

        foreach (ResponseFlightState state in pending)
        {
            state.Complete(null);
        }
    }
}

internal sealed class ResponseFlightLease : IDisposable
{
    private readonly ResponseFlightRegistry _registry;
    private readonly ResponseCacheKey _key;
    private readonly ResponseFlightState _state;
    private readonly bool _isProducer;
    private int _completed;

    internal ResponseFlightLease(
        ResponseFlightRegistry registry,
        ResponseCacheKey key,
        ResponseFlightState state,
        bool isProducer)
    {
        _registry = registry;
        _key = key;
        _state = state;
        _isProducer = isProducer;
    }

    internal bool IsProducer => _isProducer;

    internal async Task<ResponseCacheEnvelope?> WaitAsync(CancellationToken cancellationToken)
    {
        if (_isProducer)
        {
            throw new InvalidOperationException("A producer cannot wait on its own flight.");
        }

        return await _state.Completion.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    internal void Publish(ResponseCacheEnvelope? admittedEnvelope)
    {
        if (!_isProducer)
        {
            throw new InvalidOperationException("Only the flight producer may publish a result.");
        }

        if (Interlocked.Exchange(ref _completed, 1) == 0)
        {
            _registry.Complete(_key, _state, admittedEnvelope);
        }
    }

    /// <summary>Releases a failed/ineligible producer; waiters then follow their own live path.</summary>
    internal void Abandon() => Publish(null);

    public void Dispose()
    {
        if (_isProducer && Interlocked.Exchange(ref _completed, 1) == 0)
        {
            _registry.Complete(_key, _state, null);
        }
    }
}

internal sealed class ResponseFlightState
{
    private readonly TaskCompletionSource<ResponseCacheEnvelope?> _completion =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _waiterCount;

    internal Task<ResponseCacheEnvelope?> Completion => _completion.Task;

    internal int WaiterCount => Volatile.Read(ref _waiterCount);

    internal void RegisterWaiter() => Interlocked.Increment(ref _waiterCount);

    internal void Complete(ResponseCacheEnvelope? envelope) => _completion.TrySetResult(envelope);
}
