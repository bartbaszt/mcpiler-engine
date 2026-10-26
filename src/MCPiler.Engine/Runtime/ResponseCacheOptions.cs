namespace MCPiler.Engine.Runtime;

/// <summary>
/// Host-only response-cache ceilings carried into each Engine generation.
/// </summary>
/// <remarks>
/// These values are not Manifest policy and are never synchronized as desired state. They
/// narrow the Engine hard ceilings; a zero capacity or TTL ceiling disables caching without
/// changing ordinary HTTP execution. The host binding refuses attempts to exceed hard maxima.
/// </remarks>
public sealed record ResponseCacheOptions
{
    /// <summary>The maximum cacheable body size for one entry: 8 MiB.</summary>
    public const long HardMaxBodyBytes = 8L * 1024 * 1024;

    /// <summary>The maximum accounted cache memory retained by one mount: 256 MiB.</summary>
    public const long HardMaxRetainedBytesPerMount = 256L * 1024 * 1024;

    /// <summary>The maximum completed entries retained by one mount.</summary>
    public const int HardMaxEntriesPerMount = 4096;

    /// <summary>The maximum effective response-cache TTL.</summary>
    public const int HardMaxTtlSeconds = 86_400;

    /// <summary>The minimum authored TTL accepted by the Manifest contract.</summary>
    public const int MinimumTtlSeconds = 1;

    /// <summary>The retained response-header ceiling per entry: 64 KiB.</summary>
    public const long HardMaxRetainedHeaderBytesPerEntry = 64L * 1024;

    /// <summary>The maximum registered producer flights per mount.</summary>
    public const int HardMaxFlightsPerMount = 256;

    /// <summary>The maximum admitted waiters across one mount's producer flights.</summary>
    public const int HardMaxWaitersPerMount = 1024;

    /// <summary>Hard ceilings used when host configuration supplies no narrowing.</summary>
    public static ResponseCacheOptions Default { get; } = new();

    /// <summary>The largest body an entry may retain.</summary>
    public long MaxBodyBytes { get; init; } = HardMaxBodyBytes;

    /// <summary>The largest accounted cache size one mount may retain.</summary>
    public long MaxRetainedBytesPerMount { get; init; } = HardMaxRetainedBytesPerMount;

    /// <summary>The largest number of completed entries one mount may retain.</summary>
    public int MaxEntriesPerMount { get; init; } = HardMaxEntriesPerMount;

    /// <summary>The largest effective TTL in seconds. Zero disables response caching.</summary>
    public int MaxTtlSeconds { get; init; } = HardMaxTtlSeconds;

    /// <summary>The largest number of independent producer flights one mount may register.</summary>
    public int MaxFlightsPerMount { get; init; } = HardMaxFlightsPerMount;

    /// <summary>The largest number of admitted waiters across one mount's producer flights.</summary>
    public int MaxWaitersPerMount { get; init; } = HardMaxWaitersPerMount;

    /// <summary>Whether one or more effective capacity/TTL ceilings disables caching.</summary>
    public bool IsDisabled => MaxBodyBytes <= 0
        || MaxRetainedBytesPerMount <= 0
        || MaxEntriesPerMount <= 0
        || MaxTtlSeconds <= 0;

    /// <summary>Whether an effective cache may be created.</summary>
    public bool Enabled => !IsDisabled;

    /// <summary>Returns settings clamped to Engine's hard ceilings.</summary>
    /// <remarks>
    /// Host configuration rejects widening with an actionable message. This second boundary
    /// keeps programmatic RuntimeOptions from ever making the cache more permissive.
    /// </remarks>
    internal ResponseCacheOptions ClampToHardMaxima()
        => this with
        {
            MaxBodyBytes = Math.Clamp(MaxBodyBytes, 0, HardMaxBodyBytes),
            MaxRetainedBytesPerMount = Math.Clamp(MaxRetainedBytesPerMount, 0, HardMaxRetainedBytesPerMount),
            MaxEntriesPerMount = Math.Clamp(MaxEntriesPerMount, 0, HardMaxEntriesPerMount),
            MaxTtlSeconds = Math.Clamp(MaxTtlSeconds, 0, HardMaxTtlSeconds),
            MaxFlightsPerMount = Math.Clamp(MaxFlightsPerMount, 0, HardMaxFlightsPerMount),
            MaxWaitersPerMount = Math.Clamp(MaxWaitersPerMount, 0, HardMaxWaitersPerMount),
        };
}
