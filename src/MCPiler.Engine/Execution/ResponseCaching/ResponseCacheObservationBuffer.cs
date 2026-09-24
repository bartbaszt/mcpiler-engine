using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Execution.ResponseCaching;

/// <summary>
/// A bounded ring of sanitized recent cache decisions owned by one mount.
/// </summary>
/// <remarks>
/// <para>
/// The buffer is observation only. It never holds a key preimage, a credential, a body, a
/// caller token or a full sensitive header; each decision is the already-sanitized projection
/// the runtime builds. It is therefore not cache content and not desired state, and clearing
/// the cache does not need to clear it.
/// </para>
/// <para>
/// Two bounds hold independently: at most <see cref="MaxDecisions"/> decisions, and nothing
/// older than <see cref="Window"/>. Both are enforced here rather than by a background sweep,
/// so a mount that receives a burst and then goes quiet still discards its history the next
/// time anything is recorded or observed. The reported invocation and upstream-send counts are
/// derived from the retained decisions, so a joined waiter is never counted as an upstream
/// call and no count can outlive the window it describes.
/// </para>
/// </remarks>
internal sealed class ResponseCacheObservationBuffer
{
    /// <summary>The most decisions one mount retains.</summary>
    internal const int MaxDecisions = 1000;

    /// <summary>The longest a decision is retained.</summary>
    internal static readonly TimeSpan Window = TimeSpan.FromHours(1);

    private readonly object _gate = new();
    private readonly LinkedList<ResponseCacheDecision> _decisions = [];

    /// <summary>Records one decision and trims the buffer to its bounds.</summary>
    internal void Record(ResponseCacheDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);

        lock (_gate)
        {
            _decisions.AddLast(decision);
            TrimLocked(decision.ObservedAtUtc);
        }
    }

    /// <summary>
    /// Snapshots the retained decisions and their counts, discarding anything that has aged out.
    /// </summary>
    /// <remarks>
    /// The counts are derived from the retained decisions rather than kept as separate counters,
    /// so they describe exactly the same bounded window as the list and can never drift from it.
    /// A joined waiter consumes a cached response and is therefore not an upstream call, which is
    /// what keeps a shared producer from being counted more than once.
    /// </remarks>
    internal ResponseCacheObservation Snapshot(string mountPrefix, TimeProvider clock)
    {
        ArgumentException.ThrowIfNullOrEmpty(mountPrefix);
        ArgumentNullException.ThrowIfNull(clock);

        lock (_gate)
        {
            TrimLocked(clock.GetUtcNow());

            long consulted = 0;
            long upstream = 0;

            foreach (ResponseCacheDecision decision in _decisions)
            {
                if (decision.Kind != ResponseCacheDecisionKind.Bypass)
                {
                    consulted++;
                }

                if (decision.Execution == ResponseCacheExecution.Upstream)
                {
                    upstream++;
                }
            }

            return new ResponseCacheObservation(mountPrefix, consulted, upstream, [.. _decisions]);
        }
    }

    private void TrimLocked(DateTimeOffset now)
    {
        while (_decisions.Count > MaxDecisions)
        {
            _decisions.RemoveFirst();
        }

        DateTimeOffset cutoff = now - Window;

        while (_decisions.First is { } first && first.Value.ObservedAtUtc < cutoff)
        {
            _decisions.RemoveFirst();
        }
    }
}
