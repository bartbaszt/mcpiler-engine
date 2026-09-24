using System.Security.Cryptography;

using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Execution.ResponseCaching;

internal enum ResponseCacheLookupKind
{
    Hit,
    Miss,
    Bypass,
}

internal enum ResponseCacheBypassReason
{
    None,
    Disabled,
    UnknownDimension,
    FlightCapacity,
    Disposed,
}

internal sealed record ResponseCacheLookup(
    ResponseCacheLookupKind Kind,
    ResponseCacheBypassReason BypassReason,
    ResponseCacheKey? Key,
    ResponseCacheEnvelope? Envelope,
    ResponseFlightLease? Flight);


/// <summary>One bounded in-memory cache and flight registry owned by one mounted generation.</summary>
/// <remarks>
/// The cache owns only immutable raw response envelopes and opaque HMAC keys. Its activation
/// token and entry/flight state are local to this instance, so a replacement generation starts
/// cold even when its Manifest and mount prefix are byte-identical to the previous generation.
/// </remarks>
internal sealed class ResponseCache : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<ResponseCacheKey, LinkedListNode<StoredEntry>> _entries = [];
    private readonly LinkedList<StoredEntry> _lru = [];
    private readonly Dictionary<string, long> _operationEpochs = new(StringComparer.Ordinal);
    private readonly byte[] _identityKey;
    private readonly TimeProvider _clock;
    private readonly ResponseFlightRegistry _flights;
    private readonly ResponseCacheObservationBuffer _observations = new();
    private readonly ResponseCacheOptions _options;
    private readonly string _mountPrefix;
    private readonly string? _generationLabel;
    private readonly string _activation;
    private long _mountEpoch;
    private long _accountedBytes;
    private bool _disposed;

    internal ResponseCache(
        string mountPrefix,
        string? generationLabel,
        ResponseCacheOptions options,
        byte[] identityKey,
        TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(mountPrefix);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(identityKey);

        _mountPrefix = mountPrefix;
        _generationLabel = generationLabel;
        _identityKey = [.. identityKey];
        _clock = clock ?? TimeProvider.System;
        _options = options.ClampToHardMaxima();
        string activationNonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        _activation = CacheIdentity.Derive(_identityKey, "mount-activation-1", mountPrefix, generationLabel, activationNonce);
        _flights = new ResponseFlightRegistry(ResponseCacheOptions.HardMaxFlightsPerMount);
    }

    internal int EntryCount
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    internal long AccountedBytes
    {
        get
        {
            lock (_gate)
            {
                return _accountedBytes;
            }
        }
    }

    internal int FlightCount => _flights.Count;

    internal int WaitingCallerCount => _flights.WaiterCount;

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

    internal string Activation => _activation;

    internal ResponseCacheOptions Options => _options;

    internal DateTimeOffset GetUtcNow() => _clock.GetUtcNow();

    /// <summary>The monotonic timestamp used to measure entry age and remaining TTL.</summary>
    internal long GetTimestamp() => _clock.GetTimestamp();

    /// <summary>The ticks per second of <see cref="GetTimestamp"/>.</summary>
    internal long TimestampFrequency => _clock.TimestampFrequency;

    /// <summary>Whether a post-exchange identity still names the lookup key's dimensions.</summary>
    internal bool HasSameKey(ResponseCacheKey expected, ResponseCacheIdentity identity, int authoredTtlSeconds)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(identity);

        lock (_gate)
        {
            if (_disposed || !EpochIsCurrent(expected))
            {
                return false;
            }

            ResponseCacheKey? actual = ResponseCacheKeyDerivation.Derive(
                _identityKey,
                _activation,
                _mountPrefix,
                _generationLabel,
                expected.Epoch,
                identity,
                Math.Min(authoredTtlSeconds, _options.MaxTtlSeconds));

            return expected.Equals(actual);
        }
    }

    /// <summary>
    /// Looks up a stored response or joins/begins the exact-key producer flight.
    /// A missing caller/authority partition or an unmaterialized request body bypasses caching.
    /// </summary>
    internal ResponseCacheLookup Acquire(ResponseCacheIdentity identity, int authoredTtlSeconds)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (!_options.Enabled || authoredTtlSeconds <= 0)
        {
            return Bypass(ResponseCacheBypassReason.Disabled);
        }

        if (identity.UpstreamAuthority is not { Length: > 0 }
            || identity.CallerPartition is not { Length: > 0 }
            || identity.HasStreamingBody)
        {
            return Bypass(ResponseCacheBypassReason.UnknownDimension);
        }

        lock (_gate)
        {
            if (_disposed)
            {
                return Bypass(ResponseCacheBypassReason.Disposed);
            }

            ResponseCacheEpoch epoch = EpochFor(identity.OperationSlug);
            ResponseCacheKey? key = ResponseCacheKeyDerivation.Derive(
                _identityKey,
                _activation,
                _mountPrefix,
                _generationLabel,
                epoch,
                identity,
                Math.Min(authoredTtlSeconds, _options.MaxTtlSeconds));

            if (key is null)
            {
                return Bypass(ResponseCacheBypassReason.UnknownDimension);
            }

            if (TryGetLocked(key, out ResponseCacheEnvelope? cached))
            {
                return new ResponseCacheLookup(ResponseCacheLookupKind.Hit, ResponseCacheBypassReason.None, key, cached, null);
            }

            // Clear updates epochs under this same lock. Registration cannot therefore race a
            // key derived from the old epoch into the flight table after a clear has returned.
            ResponseFlightAdmission admission = _flights.JoinOrBegin(key);

            return admission.Kind switch
            {
                ResponseFlightAdmissionKind.Producer =>
                    new ResponseCacheLookup(ResponseCacheLookupKind.Miss, ResponseCacheBypassReason.None, key, null, admission.Lease),
                ResponseFlightAdmissionKind.Joined =>
                    new ResponseCacheLookup(ResponseCacheLookupKind.Miss, ResponseCacheBypassReason.None, key, null, admission.Lease),
                _ => Bypass(ResponseCacheBypassReason.FlightCapacity),
            };
        }
    }

    /// <summary>
    /// Stores a candidate if current clear epochs and per-entry/mount ceilings still permit it.
    /// A null result is an admission bypass; it never rejects the live execution result.
    /// </summary>
    internal ResponseCacheEnvelope? TryStore(ResponseCacheKey key, ResponseCacheEnvelope envelope, int effectiveTtlSeconds)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(envelope);

        lock (_gate)
        {
            if (_disposed
                || !_options.Enabled
                || !EpochIsCurrent(key)
                || effectiveTtlSeconds < ResponseCacheOptions.MinimumTtlSeconds
                || envelope.Body.Length > _options.MaxBodyBytes
                || envelope.RetainedHeaderBytes > ResponseCacheOptions.HardMaxRetainedHeaderBytesPerEntry)
            {
                return null;
            }

            effectiveTtlSeconds = Math.Min(effectiveTtlSeconds, _options.MaxTtlSeconds);
            if (effectiveTtlSeconds < ResponseCacheOptions.MinimumTtlSeconds)
            {
                return null;
            }

            long accountedBytes = checked(envelope.AccountedBytes + key.Digest.Length);
            if (accountedBytes > _options.MaxRetainedBytesPerMount)
            {
                return null;
            }

            RemoveExpiredLocked(_clock.GetTimestamp());

            if (_entries.TryGetValue(key, out LinkedListNode<StoredEntry>? replaced))
            {
                RemoveLocked(replaced);
            }

            while (_entries.Count >= _options.MaxEntriesPerMount
                || _accountedBytes + accountedBytes > _options.MaxRetainedBytesPerMount)
            {
                LinkedListNode<StoredEntry>? oldest = _lru.Last;
                if (oldest is null)
                {
                    return null;
                }

                RemoveLocked(oldest);
            }

            long storedAtTimestamp = _clock.GetTimestamp();
            long ttlTicks = checked((long)effectiveTtlSeconds * _clock.TimestampFrequency);
            long expiresAtTimestamp = checked(storedAtTimestamp + ttlTicks);
            ResponseCacheEnvelope snapshot = envelope.CopyForStorage(
                _clock.GetUtcNow(),
                storedAtTimestamp,
                expiresAtTimestamp,
                effectiveTtlSeconds,
                key.OperationSlug);
            StoredEntry item = new(key, snapshot, accountedBytes);
            LinkedListNode<StoredEntry> node = _lru.AddFirst(item);
            _entries.Add(key, node);
            _accountedBytes += accountedBytes;
            return snapshot;
        }
    }

    /// <summary>Clears one operation or the whole mount and advances the matching clear epoch.</summary>
    internal ResponseCacheClearResult Clear(string? operationSlug)
    {
        lock (_gate)
        {
            long operationEpoch = 0;
            if (operationSlug is null)
            {
                _mountEpoch++;
            }
            else
            {
                _operationEpochs.TryGetValue(operationSlug, out operationEpoch);
                operationEpoch++;
                _operationEpochs[operationSlug] = operationEpoch;
            }

            int removed = 0;
            LinkedListNode<StoredEntry>? node = _lru.First;
            while (node is not null)
            {
                LinkedListNode<StoredEntry>? next = node.Next;
                if (operationSlug is null || string.Equals(node.Value.Envelope.OperationSlug, operationSlug, StringComparison.Ordinal))
                {
                    RemoveLocked(node);
                    removed++;
                }

                node = next;
            }

            return new ResponseCacheClearResult(_mountEpoch, operationEpoch, removed, operationSlug);
        }
    }

    /// <summary>Returns the current scoped epoch, primarily for deterministic verification.</summary>
    internal ResponseCacheEpoch CurrentEpoch(string operationSlug)
    {
        ArgumentException.ThrowIfNullOrEmpty(operationSlug);

        lock (_gate)
        {
            return EpochFor(operationSlug);
        }
    }

    /// <summary>Records one sanitized cache decision for operator inspection.</summary>
    internal void RecordObservation(ResponseCacheDecision decision)
        => _observations.Record(decision);

    /// <summary>Snapshots the bounded recent decisions this mount retains.</summary>
    internal ResponseCacheObservation Observe()
        => _observations.Snapshot(_mountPrefix, _clock);

    /// <summary>Clears the mount's cache and advances its clear epoch, or one operation's.</summary>
    internal ResponseCacheClearOutcome ClearScope(string? operationSlug)
    {
        if (operationSlug is { Length: 0 })
        {
            operationSlug = null;
        }

        ResponseCacheClearResult result = Clear(operationSlug);

        return new ResponseCacheClearOutcome(
            _mountPrefix,
            operationSlug,
            result.RemovedEntries,
            result.MountEpoch,
            result.OperationEpoch);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _entries.Clear();
            _lru.Clear();
            _accountedBytes = 0;
        }

        _flights.Dispose();
        CryptographicOperations.ZeroMemory(_identityKey);
    }

    private bool TryGetLocked(ResponseCacheKey key, out ResponseCacheEnvelope? envelope)
    {
        if (!EpochIsCurrent(key) || !_entries.TryGetValue(key, out LinkedListNode<StoredEntry>? node))
        {
            envelope = null;
            return false;
        }

        long now = _clock.GetTimestamp();
        if (now >= node.Value.Envelope.ExpiresAtTimestamp)
        {
            RemoveLocked(node);
            envelope = null;
            return false;
        }

        _lru.Remove(node);
        _lru.AddFirst(node);
        envelope = node.Value.Envelope;
        return true;
    }

    private ResponseCacheEpoch EpochFor(string operationSlug)
    {
        _operationEpochs.TryGetValue(operationSlug, out long operationEpoch);
        return new ResponseCacheEpoch(_mountEpoch, operationEpoch);
    }

    private bool EpochIsCurrent(ResponseCacheKey key)
        => key.Epoch == EpochFor(key.OperationSlug);

    private void RemoveExpiredLocked(long now)
    {
        LinkedListNode<StoredEntry>? node = _lru.First;
        while (node is not null)
        {
            LinkedListNode<StoredEntry>? next = node.Next;
            if (now >= node.Value.Envelope.ExpiresAtTimestamp)
            {
                RemoveLocked(node);
            }

            node = next;
        }
    }

    private void RemoveLocked(LinkedListNode<StoredEntry> node)
    {
        _lru.Remove(node);
        _entries.Remove(node.Value.Key);
        _accountedBytes -= node.Value.AccountedBytes;
    }

    private static ResponseCacheLookup Bypass(ResponseCacheBypassReason reason)
        => new(ResponseCacheLookupKind.Bypass, reason, null, null, null);

    private sealed record StoredEntry(ResponseCacheKey Key, ResponseCacheEnvelope Envelope, long AccountedBytes);
}

internal sealed record ResponseCacheClearResult(
    long MountEpoch,
    long OperationEpoch,
    int RemovedEntries,
    string? OperationSlug);
