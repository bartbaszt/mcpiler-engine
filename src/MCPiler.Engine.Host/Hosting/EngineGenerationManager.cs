namespace MCPiler.Engine.Host.Hosting;

/// <summary>How the process decides which mounts it serves.</summary>
internal enum HostMode
{
    /// <summary>A fixed mount set loaded from local Manifest inputs before the listener opens.</summary>
    File,

    /// <summary>A mount set obtained and replaced while the process is running.</summary>
    Managed,
}

/// <summary>Takes one generation lease for an admission.</summary>
/// <remarks>
/// A session's handlers outlive the request that configured them, so they must lease per call
/// through a delegate rather than capture the generation active at handshake; the generation they
/// captured may have been retired and disposed by the time the call arrives.
/// </remarks>
internal delegate EngineGenerationLease? GenerationLeaseSource();

/// <summary>
/// Owns the active generation and hands out one lease per admission.
/// </summary>
/// <remarks>
/// <para>
/// The manager is the only place the active generation can change. Activation installs a
/// completely-built candidate in one critical section and then retires the previous
/// generation; a lease attempt therefore either wins on the old generation (before the
/// exchange) or on the new one (after), and can never observe a half-installed state.
/// </para>
/// <para>
/// Retirement is separate from activation on purpose. The old generation keeps serving
/// existing leases while it drains, so a request that resolved a surface does not have its
/// connection pool closed under it. Only when the last lease is released — or the caller's
/// deadline abandons the remainder — is the execution graph and its secret buffers disposed.
/// </para>
/// <para>
/// A refused candidate never reaches this type: whoever built it throws before calling
/// <see cref="Activate"/>, which is what keeps a failed activation invisible to callers.
/// </para>
/// </remarks>
internal sealed class EngineGenerationManager : IDisposable
{
    private readonly object _gate = new();
    private EngineGeneration? _current;
    private bool _disposed;

    internal EngineGenerationManager(HostMode mode)
    {
        Mode = mode;
    }

    /// <summary>How this process decides which mounts it serves.</summary>
    internal HostMode Mode { get; }

    /// <summary>The installed generation, or null before the first activation.</summary>
    internal EngineGeneration? Current
    {
        get
        {
            lock (_gate)
            {
                return _current;
            }
        }
    }

    /// <summary>Whether the process has a generation to serve.</summary>
    internal bool HasGeneration => Current is not null;

    /// <summary>
    /// A delegate that takes one lease from this manager, for a component that needs to lease
    /// without holding the manager.
    /// </summary>
    /// <remarks>
    /// A session's handlers outlive the request that configured them. They must therefore take a
    /// fresh lease per call rather than capture the generation that was active at handshake, and
    /// they must do it through the manager, because the generation they captured may have been
    /// retired and disposed by the time the call arrives.
    /// </remarks>
    internal GenerationLeaseSource LeaseSource => Lease;

    private EngineGenerationLease? Lease() => TryLease(out EngineGenerationLease? lease) ? lease : null;

    /// <summary>Takes one admission claim on the active generation.</summary>
    /// <remarks>
    /// False only when the process has no generation or is shutting down. Admission never
    /// blocks on a swap: the exchange is one critical section, so a caller that raced an
    /// activation is simply given the newer generation.
    /// </remarks>
    internal bool TryLease(out EngineGenerationLease? lease)
    {
        lock (_gate)
        {
            if (_disposed || _current is not { } current)
            {
                lease = null;
                return false;
            }

            return current.TryLease(out lease);
        }
    }

    /// <summary>Installs a fully-built candidate and retires the generation it replaced.</summary>
    /// <remarks>
    /// <para>
    /// Returns the retirement task for the superseded generation so the caller can bound the
    /// drain or observe it. The task completes when every outstanding lease on the old
    /// generation has been released and its execution graph disposed.
    /// </para>
    /// <para>
    /// Re-installing the generation that is already active is a no-op. Retiring it would stop
    /// admitting callers on the very generation the process serves, which is the opposite of what
    /// the caller asked for and would survive until the next activation.
    /// </para>
    /// </remarks>
    internal Task Activate(EngineGeneration candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        EngineGeneration? previous;

        lock (_gate)
        {
            if (_disposed)
            {
                candidate.Dispose();
                throw new ObjectDisposedException(nameof(EngineGenerationManager));
            }

            previous = _current;

            if (ReferenceEquals(previous, candidate))
            {
                return Task.CompletedTask;
            }

            _current = candidate;
        }

        return previous is null ? Task.CompletedTask : previous.RetireAsync();
    }

    /// <summary>The generation a caller would be admitted to right now.</summary>
    /// <remarks>
    /// For tests and diagnostics only. Resolving a surface must go through
    /// <see cref="TryLease"/>, because a generation read here can be retired before it is used.
    /// </remarks>
    internal long? CurrentNumber => Current?.Number;

    /// <summary>
    /// The identity the next activation should use.
    /// </summary>
    /// <remarks>
    /// Derived from the installed generation rather than kept in a counter, so a monotonic
    /// sequence survives regardless of how many candidates were built and then refused. A number
    /// is bookkeeping for diagnostics and tests; two generations can never be current at once, so
    /// deriving the successor from the current one is exact.
    /// </remarks>
    internal long NextNumber => (Current?.Number ?? -1) + 1;

    /// <inheritdoc />
    public void Dispose()
    {
        EngineGeneration? current;

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            current = _current;
            _current = null;
        }

        current?.Dispose();
    }
}
