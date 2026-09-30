using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;
using ModelContextProtocol.Protocol;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// One immutable set of mounts the process can serve, together with everything derived from it.
/// </summary>
/// <remarks>
/// <para>
/// A generation is what makes activation atomic. Every decision a request needs — which surfaces
/// exist, which addresses route to them, which tool definitions they advertise, which execution
/// graph and secret buffers serve them — belongs to exactly one generation, so a request that
/// leased a generation can never mix a route from one mount set with the execution of another.
/// </para>
/// <para>
/// Nothing here changes after construction. Replacing the served mounts means building a new
/// generation beside this one and swapping the manager's pointer; a candidate that cannot be
/// built is simply never installed and the previous generation keeps serving unchanged.
/// </para>
/// <para>
/// Retirement is deliberately not disposal. A superseded generation stays alive while requests
/// it already admitted are still running, and only its last released lease lets the execution
/// graph and its secret buffers be disposed. <see cref="RetireAsync"/> is how the activator
/// observes that drain.
/// </para>
/// </remarks>
internal sealed class EngineGeneration : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<string, IReadOnlyList<Tool>> _definitions = new(StringComparer.Ordinal);
    private readonly IReadOnlyDictionary<string, string> _externalResources;
    private readonly TaskCompletionSource _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _leases;
    private bool _retired;
    private bool _disposed;

    internal EngineGeneration(
        long number,
        MountSet mounts,
        EngineExecution execution,
        bool ownsExecution = true,
        IReadOnlyDictionary<string, string>? externalResources = null)
    {
        ArgumentNullException.ThrowIfNull(mounts);
        ArgumentNullException.ThrowIfNull(execution);

        Number = number;
        Mounts = mounts;
        Execution = execution;
        OwnsExecution = ownsExecution;
        _externalResources = externalResources is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(externalResources, StringComparer.Ordinal);
    }

    /// <summary>Monotonic identity, for diagnostics and tests only.</summary>
    internal long Number { get; }

    /// <summary>Every mount, surface and address this generation serves.</summary>
    internal MountSet Mounts { get; }

    /// <summary>
    /// Whether disposing this generation disposes the execution graph with it.
    /// </summary>
    /// <remarks>
    /// A managed generation is built and owned by the process, so it owns its execution graph. A
    /// file-mode generation wraps the execution the command runner created and disposes, so it
    /// must not dispose what it does not own.
    /// </remarks>
    internal bool OwnsExecution { get; }

    /// <summary>The execution graph and secret buffers built for this mount set.</summary>
    internal EngineExecution Execution { get; }

    /// <summary>Outstanding admissions.</summary>
    internal int LeaseCount
    {
        get
        {
            lock (_gate)
            {
                return _leases;
            }
        }
    }

    /// <summary>Whether this generation has been replaced and no longer admits callers.</summary>
    internal bool IsRetired
    {
        get
        {
            lock (_gate)
            {
                return _retired;
            }
        }
    }

    /// <summary>
    /// Whether this generation has released its execution graph.
    /// </summary>
    /// <remarks>
    /// For tests and diagnostics. Disposal is the observable end of retirement: a generation that
    /// has drained must not keep an outbound pool or secret buffers alive, and a test that could
    /// only observe the lease count would not be asserting that.
    /// </remarks>
    internal bool IsDisposed
    {
        get
        {
            lock (_gate)
            {
                return _disposed;
            }
        }
    }

    /// <summary>Takes one admission claim, or reports that this generation no longer admits.</summary>
    internal bool TryLease(out EngineGenerationLease? lease)
    {
        lock (_gate)
        {
            if (_retired || _disposed)
            {
                lease = null;
                return false;
            }

            _leases++;
            lease = new EngineGenerationLease(this);
            return true;
        }
    }

    /// <summary>
    /// Resolves a mapped address to the surface this generation serves there.
    /// </summary>
    /// <remarks>
    /// An address that this generation does not serve is a refusal, not an empty answer: after an
    /// activation removed a route, a request still holding the old address must fail rather than
    /// be silently redirected to whatever now occupies the prefix.
    /// </remarks>
    internal bool TryResolve(string address, out SurfaceResolution? resolution)
    {
        ArgumentException.ThrowIfNullOrEmpty(address);

        foreach (MountedSurfaceAddress entry in Mounts.Addresses)
        {
            if (!string.Equals(entry.Path, address, StringComparison.Ordinal))
            {
                continue;
            }

            resolution = new SurfaceResolution(entry.Mount, entry.Surface, entry.Path);
            return true;
        }

        resolution = null;
        return false;
    }

    /// <summary>
    /// Returns the one protected-resource identity this generation owns for an admitted surface.
    /// </summary>
    /// <remarks>
    /// External-resource bindings are keyed by the explicit surface route, even when a default
    /// surface was reached through its shorter mount-prefix alias. That keeps one canonical
    /// external identity per concrete surface. An unbound surface retains the request-derived
    /// direct identity, including the exact address alias the client used.
    /// </remarks>
    internal string EffectiveResourceIdentity(
        SurfaceResolution resolution,
        string requestDerivedIdentity)
    {
        ArgumentNullException.ThrowIfNull(resolution);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestDerivedIdentity);

        string surfaceRoute = resolution.Mount.Prefix + "/" + resolution.Surface.Slug;

        return _externalResources.TryGetValue(surfaceRoute, out string? external)
            ? external
            : requestDerivedIdentity;
    }

    /// <summary>
    /// The tool definitions one surface advertises at one negotiated protocol revision.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Memoized per generation rather than per process: the same surface slug can describe a
    /// different contract after an activation, and a cache that outlived its generation would
    /// advertise the superseded tool set indefinitely.
    /// </para>
    /// <para>
    /// Keyed by address as well as slug, because two mounts may both declare a surface with the
    /// same slug. Keying by slug alone would hand the second mount the first mount's tools, which
    /// is a cross-mount disclosure rather than a cache miss.
    /// </para>
    /// </remarks>
    internal IReadOnlyList<Tool> Definitions(
        string address,
        MountedSurface surface,
        string? negotiatedProtocolRevision)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentNullException.ThrowIfNull(surface);

        string key = address
            + '\u001f' + surface.Slug
            + '\u001f' + (negotiatedProtocolRevision ?? string.Empty);

        lock (_gate)
        {
            if (_definitions.TryGetValue(key, out IReadOnlyList<Tool>? cached))
            {
                return cached;
            }

            IReadOnlyList<Tool> definitions = SdkTranslation.Define(surface, negotiatedProtocolRevision);
            _definitions[key] = definitions;
            return definitions;
        }
    }

    /// <summary>Stops admitting callers and reports when the last outstanding lease is released.</summary>
    /// <remarks>
    /// Retirement ends in disposal. A superseded generation that merely stopped admitting but
    /// kept its execution graph alive would leak one outbound connection pool and its secret
    /// buffers per activation, so the observer guarantees the release even when the last lease
    /// was dropped by a request thread that could not dispose it itself.
    /// </remarks>
    internal async Task RetireAsync()
    {
        bool drained;

        lock (_gate)
        {
            _retired = true;
            drained = _leases <= 0;
        }

        if (drained)
        {
            _drained.TrySetResult();
        }
        else
        {
            Task completed = _drained.Task;

            if (!completed.IsCompleted)
            {
                await Task.WhenAny(completed).ConfigureAwait(false);
            }
        }

        Dispose();
    }

    /// <summary>Releases one admission claim.</summary>
    /// <remarks>
    /// The last release of a retired generation disposes it. Doing it here as well as in
    /// <see cref="RetireAsync"/> means an activator that never observed the retirement task
    /// still cannot leak: whichever path drains the generation last releases its resources
    /// exactly once, because <see cref="Dispose"/> is idempotent.
    /// </remarks>
    internal void Release()
    {
        bool drained;

        lock (_gate)
        {
            _leases--;
            drained = _retired && _leases <= 0;
        }

        if (drained)
        {
            _drained.TrySetResult();
            Dispose();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        bool drained;

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _retired = true;
            drained = _leases <= 0;
        }

        if (drained)
        {
            _drained.TrySetResult();
        }

        if (OwnsExecution)
        {
            Execution.Dispose();
        }
    }
}

/// <summary>Where one mapped address led inside a leased generation.</summary>
/// <param name="Mount">The mount that owns the addressed surface.</param>
/// <param name="Surface">The surface served at the address.</param>
/// <param name="Address">The exact mapped address that resolved, for diagnostics and identity.</param>
internal sealed record SurfaceResolution(MountedManifest Mount, MountedSurface Surface, string Address);
