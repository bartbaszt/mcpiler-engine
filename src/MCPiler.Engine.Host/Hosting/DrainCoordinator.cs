using Microsoft.AspNetCore.Builder;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>Coordinates admission and the bounded drain of in-flight tool invocations.</summary>
/// <remarks>
/// Admission and the active set share one lock so shutdown cannot race a new invocation into the
/// drain after it has decided the process is empty. Calls admitted before drain keep running until
/// the configured deadline. At the deadline their linked cancellation tokens are canceled only
/// after the tool names have been snapshotted for the operator report.
/// </remarks>
internal sealed class DrainCoordinator : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<long, string> _active = [];
    private readonly CancellationTokenSource _abandon = new();
    private readonly TaskCompletionSource _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private long _nextId;
    private bool _accepting = true;

    /// <summary>Whether shutdown has closed admission.</summary>
    internal bool IsDraining
    {
        get
        {
            lock (_gate)
            {
                return !_accepting;
            }
        }
    }

    /// <summary>Admits one tool invocation and links it to the force-abandon signal.</summary>
    internal bool TryEnter(
        string tool,
        CancellationToken callerCancellation,
        out InvocationLease? lease)
    {
        lock (_gate)
        {
            if (!_accepting)
            {
                lease = null;
                return false;
            }

            long id = ++_nextId;
            string name = string.IsNullOrEmpty(tool) ? "<unnamed>" : tool;
            _active.Add(id, name);
            lease = new InvocationLease(this, id, callerCancellation, _abandon.Token);
            return true;
        }
    }

    /// <summary>Closes admission without interrupting work already admitted.</summary>
    internal void BeginDrain()
    {
        lock (_gate)
        {
            if (!_accepting)
            {
                return;
            }

            _accepting = false;

            if (_active.Count == 0)
            {
                _drained.TrySetResult();
            }
        }
    }

    /// <summary>Waits for admitted work until the deadline and cancels what remains afterwards.</summary>
    internal async Task<DrainReport> DrainAsync(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "The drain timeout must be positive.");
        }

        BeginDrain();

        Task completed = _drained.Task;

        if (completed.IsCompleted)
        {
            return DrainReport.Drained;
        }

        Task deadline = Task.Delay(timeout, CancellationToken.None);

        if (await Task.WhenAny(completed, deadline).ConfigureAwait(false) == completed)
        {
            await completed.ConfigureAwait(false);
            return DrainReport.Drained;
        }

        IReadOnlyList<string> abandoned = SnapshotActive();
        _abandon.Cancel();
        return new DrainReport(abandoned);
    }

    /// <summary>Runs the drain and then closes the HTTP listener.</summary>
    internal async Task<DrainReport> ShutdownAsync(WebApplication app, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(app);

        DrainReport report = await DrainAsync(timeout).ConfigureAwait(false);

        // Calls that crossed the deadline have just received the force-abandon token. The normal
        // host stop now closes the listener and lets cancellation unwind through the request path.
        await app.StopAsync(CancellationToken.None).ConfigureAwait(false);
        return report;
    }

    /// <inheritdoc />
    public void Dispose() => _abandon.Dispose();

    private IReadOnlyList<string> SnapshotActive()
    {
        lock (_gate)
        {
            return [.. _active.OrderBy(static pair => pair.Key).Select(static pair => pair.Value)];
        }
    }

    private void Leave(long id)
    {
        lock (_gate)
        {
            _active.Remove(id);

            if (!_accepting && _active.Count == 0)
            {
                _drained.TrySetResult();
            }
        }
    }

    /// <summary>One admitted invocation. Disposing it removes the invocation from the active set.</summary>
    internal sealed class InvocationLease : IDisposable
    {
        private readonly DrainCoordinator _owner;
        private readonly long _id;
        private readonly CancellationTokenSource _linked;
        private int _disposed;

        internal InvocationLease(
            DrainCoordinator owner,
            long id,
            CancellationToken callerCancellation,
            CancellationToken abandonCancellation)
        {
            _owner = owner;
            _id = id;
            _linked = CancellationTokenSource.CreateLinkedTokenSource(
                callerCancellation,
                abandonCancellation);
        }

        /// <summary>The caller deadline plus the shutdown abandon deadline.</summary>
        internal CancellationToken CancellationToken => _linked.Token;

        /// <inheritdoc />
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _linked.Dispose();
            _owner.Leave(_id);
        }
    }
}

/// <summary>The invocations that were still active when the drain window expired.</summary>
internal sealed record DrainReport(IReadOnlyList<string> AbandonedTools)
{
    internal static DrainReport Drained { get; } = new([]);

    internal bool Completed => AbandonedTools.Count == 0;
}
