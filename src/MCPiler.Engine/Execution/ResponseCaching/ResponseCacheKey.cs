using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace MCPiler.Engine.Execution.ResponseCaching;

/// <summary>The semantic, pre-send facts that identify one cacheable request.</summary>
/// <remarks>
/// The caller supplies only facts it can know after ordinary request compilation and
/// authorization/credential resolution. A missing authority or caller partition, or a
/// streaming body that cannot be represented before send, makes the identity unavailable and
/// therefore bypasses caching.
/// </remarks>
internal sealed record ResponseCacheIdentity
{
    internal string? ManifestGeneration { get; init; }

    internal required string OperationSlug { get; init; }

    internal required string ResolvedBindingSemantics { get; init; }

    internal string? EffectiveHttpOperationKey { get; init; }

    internal required string Method { get; init; }

    internal required string EffectiveUri { get; init; }

    internal IReadOnlyDictionary<string, string[]> Headers { get; init; } =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

    internal IReadOnlyCollection<string> SensitiveHeaders { get; init; } = [];

    /// <summary>
    /// Sensitive header values already represented by <see cref="UpstreamAuthority"/>.
    /// Other sensitive values are transiently HMACed into the request identity themselves.
    /// </summary>
    internal IReadOnlyCollection<string> AuthorityRepresentedSensitiveHeaders { get; init; } = [];

    internal byte[]? Body { get; init; }

    /// <summary>True for a replayable/streaming body whose digest is not materialized pre-send.</summary>
    internal bool HasStreamingBody { get; init; }

    /// <summary>An already-opaque digest describing the authority used for the request.</summary>
    internal string? UpstreamAuthority { get; init; }

    /// <summary>An already-opaque digest describing the admitted caller partition.</summary>
    internal string? CallerPartition { get; init; }

    /// <summary>The normalized, authored cache-policy fingerprint.</summary>
    internal required string PolicyFingerprint { get; init; }
}

/// <summary>An opaque 32-byte HMAC-SHA-256 cache key.</summary>
internal sealed class ResponseCacheKey : IEquatable<ResponseCacheKey>
{
    private readonly byte[] _digest;
    private readonly int _hashCode;

    internal ResponseCacheKey(byte[] digest, string operationSlug, ResponseCacheEpoch epoch)
    {
        ArgumentNullException.ThrowIfNull(digest);
        ArgumentException.ThrowIfNullOrEmpty(operationSlug);

        if (digest.Length != 32)
        {
            throw new ArgumentException("A response-cache key must be exactly 32 bytes.", nameof(digest));
        }

        _digest = [.. digest];
        OperationSlug = operationSlug;
        Epoch = epoch;
        Fingerprint = Convert.ToHexStringLower(_digest.AsSpan(0, 6));
        _hashCode = BinaryPrimitives.ReadInt32BigEndian(_digest);
    }

    /// <summary>The operation label used only for scoped clear and sanitized diagnostics.</summary>
    internal string OperationSlug { get; }

    /// <summary>The scoped clear epoch encoded into this key.</summary>
    internal ResponseCacheEpoch Epoch { get; }

    /// <summary>A short derivative safe for operator-facing comparison.</summary>
    internal string Fingerprint { get; }

    internal ReadOnlySpan<byte> Digest => _digest;

    public bool Equals(ResponseCacheKey? other)
        => other is not null && _digest.AsSpan().SequenceEqual(other._digest);

    public override bool Equals(object? obj) => obj is ResponseCacheKey other && Equals(other);

    public override int GetHashCode() => _hashCode;

    public override string ToString() => Fingerprint;
}

/// <summary>The per-mount and per-operation epochs used by one request identity.</summary>
internal readonly record struct ResponseCacheEpoch(long Mount, long Operation)
{
}

/// <summary>Derives the fixed-length key from the typed request identity.</summary>
internal static class ResponseCacheKeyDerivation
{
    private const string FormatVersion = "response-cache-key-1";
    private const string CredentialValueMarker = "<credential-value-represented-by-authority>";

    /// <summary>
    /// Builds a key, returning null when an identity dimension cannot be proven before send.
    /// </summary>
    internal static ResponseCacheKey? Derive(
        byte[] identityKey,
        string mountActivation,
        string mountPrefix,
        string? generationLabel,
        ResponseCacheEpoch epoch,
        ResponseCacheIdentity identity,
        int effectiveTtlSeconds)
    {
        ArgumentNullException.ThrowIfNull(identityKey);
        ArgumentException.ThrowIfNullOrEmpty(mountActivation);
        ArgumentException.ThrowIfNullOrEmpty(mountPrefix);
        ArgumentNullException.ThrowIfNull(identity);

        if (identity.HasStreamingBody
            || string.IsNullOrEmpty(identity.UpstreamAuthority)
            || string.IsNullOrEmpty(identity.CallerPartition)
            || string.IsNullOrEmpty(identity.OperationSlug)
            || string.IsNullOrEmpty(identity.ResolvedBindingSemantics)
            || string.IsNullOrEmpty(identity.EffectiveHttpOperationKey)
            || string.IsNullOrEmpty(identity.Method)
            || string.IsNullOrEmpty(identity.EffectiveUri)
            || string.IsNullOrEmpty(identity.PolicyFingerprint)
            || identity.Headers.Any(static pair => string.IsNullOrEmpty(pair.Key)
                || pair.Value is null
                || pair.Value.Any(static value => value is null)))
        {
            return null;
        }

        List<string?> parts =
        [
            FormatVersion,
            mountActivation,
            mountPrefix,
            generationLabel,
            identity.ManifestGeneration,
            identity.OperationSlug,
            identity.ResolvedBindingSemantics,
            identity.EffectiveHttpOperationKey,
            identity.Method,
            identity.EffectiveUri,
        ];

        AppendCanonicalHeaders(
            parts,
            identityKey,
            identity.Headers,
            identity.SensitiveHeaders,
            identity.AuthorityRepresentedSensitiveHeaders);
        AppendBody(parts, identity.Body);
        parts.Add(identity.UpstreamAuthority);
        parts.Add(identity.CallerPartition);
        parts.Add(identity.PolicyFingerprint);
        parts.Add(effectiveTtlSeconds.ToString(CultureInfo.InvariantCulture));
        parts.Add(epoch.Mount.ToString(CultureInfo.InvariantCulture));
        parts.Add(epoch.Operation.ToString(CultureInfo.InvariantCulture));

        byte[] digest = CacheIdentity.DeriveBytes(identityKey, [.. parts]);
        return new ResponseCacheKey(digest, identity.OperationSlug, epoch);
    }

    /// <summary>Returns a transient SHA-256 digest for materialized request-body bytes.</summary>
    internal static byte[] DigestBody(ReadOnlySpan<byte> body) => SHA256.HashData(body);

    private static void AppendBody(List<string?> parts, byte[]? body)
    {
        if (body is null)
        {
            parts.Add(null);
            parts.Add(null);
            return;
        }

        parts.Add(body.Length.ToString(CultureInfo.InvariantCulture));
        parts.Add(Convert.ToHexStringLower(DigestBody(body)));
    }

    private static void AppendCanonicalHeaders(
        List<string?> parts,
        byte[] identityKey,
        IReadOnlyDictionary<string, string[]> headers,
        IReadOnlyCollection<string> sensitiveHeaders,
        IReadOnlyCollection<string> authorityRepresentedSensitiveHeaders)
    {
        HashSet<string> sensitive = new(sensitiveHeaders, StringComparer.OrdinalIgnoreCase);
        HashSet<string> authorityRepresented = new(
            authorityRepresentedSensitiveHeaders,
            StringComparer.OrdinalIgnoreCase);
        SortedDictionary<string, List<string>> grouped = new(StringComparer.Ordinal);

        foreach ((string name, string[] values) in headers)
        {
            string normalizedName = name.ToLowerInvariant();

            if (!grouped.TryGetValue(normalizedName, out List<string>? mergedValues))
            {
                mergedValues = [];
                grouped.Add(normalizedName, mergedValues);
            }

            // A caller-provided dictionary can contain duplicate HTTP names with different
            // casing even though the HTTP header namespace is case-insensitive. Merge them
            // before sorting; append each value sequence unchanged.
            mergedValues.AddRange(values);
        }

        parts.Add(grouped.Count.ToString(CultureInfo.InvariantCulture));

        foreach ((string name, List<string> values) in grouped)
        {
            parts.Add(name);
            parts.Add(values.Count.ToString(CultureInfo.InvariantCulture));

            // Credential values resolved from the current authority are already represented by
            // the opaque authority digest. Other sensitive values (for example a caller-supplied
            // Authorization header) still separate requests, but enter only as a keyed derivative.
            if (sensitive.Contains(name))
            {
                foreach (string _ in values)
                {
                    parts.Add(authorityRepresented.Contains(name)
                        ? CredentialValueMarker
                        : CacheIdentity.DeriveValue(identityKey, _));
                }

                continue;
            }

            foreach (string value in values)
            {
                parts.Add(value);
            }
        }
    }
}
