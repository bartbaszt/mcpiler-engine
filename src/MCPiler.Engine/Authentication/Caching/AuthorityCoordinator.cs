namespace MCPiler.Engine.Authentication.Caching;

/// <summary>
/// Serializes an explicit authority transition and an ordinary token acquisition that share one
/// runtime-owned slot, and carries a per-slot generation that advances when a transition commits.
/// </summary>
/// <remarks>
/// <para>
/// A refresh, a reauthorization and a clear all read the same slot authority and then commit a
/// successor. Without a shared gate an older completion can land after a newer explicit decision
/// and either write a regressed revision or publish a token minted under the displaced authority.
/// The gate is keyed by the slot identity, so a profile whose authority changes cannot race its own
/// acquisition, while distinct slots still proceed independently.
/// </para>
/// <para>
/// The generation is an in-memory fence, not durable authority. A transition advances it after its
/// commit; an acquisition captures it before its provider call and refuses to publish a result
/// whose generation moved while it was in flight. The durable decision version is the authoritative
/// compare token for the write; the generation is the cheap read-path companion that lets a cache
/// hit and a provider result be discarded without re-reading the store. Because the whole of a
/// transition runs under the same gate, a generation can only move across a completed transition,
/// never in the middle of one this caller is performing.
/// </para>
/// <para>
/// The generation map is bounded by the manifest-local slot identities a process can serve
/// (mount-scoped profiles each declaring a small set of slots), never by arbitrary caller input, so
/// it cannot grow without bound the way a gate keyed by an external identifier could.
/// </para>
/// </remarks>
public sealed class AuthorityCoordinator
{
    private readonly AccessTokenSingleFlight _flights;
    private readonly object _sync = new();
    private readonly Dictionary<string, long> _generations = new(StringComparer.Ordinal);

    /// <summary>Creates a coordinator over the acquisition gate it shares with the token service.</summary>
    /// <param name="flights">
    /// The acquisition coalescing gate. The runtime owns its lifetime; the coordinator only uses
    /// it, so a transition and an acquisition contend on the same synchronization object.
    /// </param>
    public AuthorityCoordinator(AccessTokenSingleFlight flights)
    {
        ArgumentNullException.ThrowIfNull(flights);

        _flights = flights;
    }

    /// <summary>The stable identity of one slot: its profile and slot name.</summary>
    public static string Identity(string profileId, string slot)
        => string.Concat(profileId, "\u001f", slot);

    /// <summary>The current fence value for a slot; zero before any explicit transition.</summary>
    public long Generation(string profileId, string slot)
    {
        ArgumentException.ThrowIfNullOrEmpty(profileId);
        ArgumentNullException.ThrowIfNull(slot);

        lock (_sync)
        {
            return _generations.TryGetValue(Identity(profileId, slot), out var generation)
                ? generation
                : 0;
        }
    }

    /// <summary>
    /// Advances the fence for one slot. Called once an explicit authority transition (authorize,
    /// reauthorize or clear) has committed, so an acquisition that started under the displaced
    /// authority can detect the change and refuse to publish.
    /// </summary>
    public void Advance(string profileId, string slot)
    {
        ArgumentException.ThrowIfNullOrEmpty(profileId);
        ArgumentNullException.ThrowIfNull(slot);

        lock (_sync)
        {
            var key = Identity(profileId, slot);
            _generations[key] = _generations.TryGetValue(key, out var generation)
                ? generation + 1
                : 1;
        }
    }

    /// <summary>Runs <paramref name="work"/> under the exclusive gate for one slot.</summary>
    public ValueTask<T> RunExclusiveAsync<T>(
        string profileId,
        string slot,
        Func<CancellationToken, ValueTask<T>> work,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(profileId);
        ArgumentNullException.ThrowIfNull(slot);
        ArgumentNullException.ThrowIfNull(work);

        return _flights.RunAsync(Identity(profileId, slot), work, cancellationToken);
    }
}
