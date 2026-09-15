using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.Caching;

/// <summary>
/// Identifies one cached access token.
/// </summary>
/// <remarks>
/// Every part of this key is a non-secret identity. The profile id and the mutable-slot authority
/// epoch/revision are manifest-local, so a rotation that opened a new authority epoch or advanced
/// the runtime revision cannot read a token issued under the previous one. The scope/resource key
/// is the configuration projection that decides which token a grant produces; without it a
/// resource-server change would reuse a token minted for a different audience.
/// </remarks>
/// <param name="ProfileId">The manifest-local profile identity.</param>
/// <param name="AuthorityEpoch">The authority epoch the token was acquired under.</param>
/// <param name="RuntimeRevision">The runtime revision the token was acquired under.</param>
/// <param name="ScopeResourceKey">The configuration identity the token was minted for.</param>
public readonly record struct AccessTokenKey(
    string ProfileId,
    long AuthorityEpoch,
    long RuntimeRevision,
    string ScopeResourceKey);

/// <summary>One cached access token and the instant it stops being usable.</summary>
/// <param name="Value">The token material. Never logged or reported.</param>
/// <param name="ExpiresAtUtc">When the upstream considers it expired.</param>
public sealed record CachedAccessToken(string Value, DateTimeOffset ExpiresAtUtc);

/// <summary>
/// A bounded in-memory access-token cache.
/// </summary>
/// <remarks>
/// <para>
/// Per process and in-memory by design. An access token is an ephemeral derived value: it is
/// cheaper to acquire again after a restart than to persist, and persisting it would widen the
/// set of secret material Engine keeps at rest for no operational gain. Only the rotating refresh
/// credential is durable, and that lives in the bounded runtime store, not here.
/// </para>
/// <para>
/// The entry count is bounded so an Engine serving many profiles cannot be made to hold an
/// unbounded number of live tokens. Eviction is oldest-expiry-first, which is the entry closest
/// to being useless anyway.
/// </para>
/// </remarks>
public sealed class AccessTokenCache
{
    /// <summary>The most tokens one process will hold.</summary>
    public const int MaximumEntries = 1024;

    private readonly object _gate = new();
    private readonly Dictionary<AccessTokenKey, CachedAccessToken> _entries = [];

    /// <summary>
    /// Returns the cached token when it has more than <paramref name="safetySkew"/> left, and
    /// removes it otherwise. A stale entry is removed rather than left for the next caller to
    /// re-evaluate.
    /// </summary>
    public bool TryGet(AccessTokenKey key, TimeSpan safetySkew, DateTimeOffset now, out CachedAccessToken token)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out var cached))
            {
                token = null!;
                return false;
            }

            if (cached.ExpiresAtUtc - safetySkew <= now)
            {
                _entries.Remove(key);
                token = null!;
                return false;
            }

            token = cached;
            return true;
        }
    }

    /// <summary>Stores a token, evicting the entry closest to expiry when the bound is reached.</summary>
    public void Set(AccessTokenKey key, CachedAccessToken token)
    {
        ArgumentNullException.ThrowIfNull(token);

        lock (_gate)
        {
            if (!_entries.ContainsKey(key) && _entries.Count >= MaximumEntries)
            {
                var oldest = default(AccessTokenKey);
                var found = false;

                foreach (var (candidate, value) in _entries)
                {
                    if (!found || value.ExpiresAtUtc < _entries[oldest].ExpiresAtUtc)
                    {
                        oldest = candidate;
                        found = true;
                    }
                }

                if (found)
                {
                    _entries.Remove(oldest);
                }
            }

            _entries[key] = token;
        }
    }

    /// <summary>Removes every token acquired for one profile.</summary>
    public void InvalidateProfile(string profileId)
    {
        lock (_gate)
        {
            var stale = _entries.Keys
                .Where(key => string.Equals(key.ProfileId, profileId, StringComparison.Ordinal))
                .ToList();

            foreach (var key in stale)
            {
                _entries.Remove(key);
            }
        }
    }

    /// <summary>Removes every token this process holds. For tests and shutdown accounting.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
        }
    }

    /// <summary>The number of live entries. For bounded-growth assertions.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }
}
