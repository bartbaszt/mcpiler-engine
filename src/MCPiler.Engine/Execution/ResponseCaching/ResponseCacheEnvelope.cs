using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace MCPiler.Engine.Execution.ResponseCaching;

/// <summary>An immutable copy of the raw response fields downstream execution consumes.</summary>
internal sealed class ResponseCacheEnvelope
{
    private const long EntryOverheadBytes = 512;
    private const long HeaderLineOverheadBytes = 16;

    private ResponseCacheEnvelope(
        int statusCode,
        string? mediaType,
        ImmutableArray<KeyValuePair<string, ImmutableArray<string>>> headers,
        byte[] body,
        long retainedHeaderBytes,
        DateTimeOffset storedAtUtc,
        long storedAtTimestamp,
        long expiresAtTimestamp,
        int effectiveTtlSeconds,
        string operationSlug)
    {
        StatusCode = statusCode;
        MediaType = mediaType;
        Headers = headers;
        _body = body;
        RetainedHeaderBytes = retainedHeaderBytes;
        AccountedBytes = checked(EntryOverheadBytes + body.LongLength + retainedHeaderBytes);
        StoredAtUtc = storedAtUtc;
        StoredAtTimestamp = storedAtTimestamp;
        ExpiresAtTimestamp = expiresAtTimestamp;
        EffectiveTtlSeconds = effectiveTtlSeconds;
        OperationSlug = operationSlug;
    }

    private readonly byte[] _body;

    internal int StatusCode { get; }

    internal string? MediaType { get; }

    internal ImmutableArray<KeyValuePair<string, ImmutableArray<string>>> Headers { get; }

    internal ReadOnlyMemory<byte> Body => _body;

    internal long RetainedHeaderBytes { get; }

    /// <summary>Body + retained headers + a fixed allowance for entry/index metadata.</summary>
    internal long AccountedBytes { get; }

    internal DateTimeOffset StoredAtUtc { get; }

    internal long StoredAtTimestamp { get; }

    internal long ExpiresAtTimestamp { get; }

    internal int EffectiveTtlSeconds { get; }

    internal string OperationSlug { get; }

    internal static ResponseCacheEnvelope Capture(
        int statusCode,
        string? mediaType,
        IReadOnlyDictionary<string, string[]> headers,
        byte[] body)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(body);

        long retainedHeaderBytes = MeasureRetainedHeaderBytes(headers);
        return CaptureCore(statusCode, mediaType, headers, body, retainedHeaderBytes);
    }

    internal static bool TryCapture(
        int statusCode,
        string? mediaType,
        IReadOnlyDictionary<string, string[]> headers,
        byte[] body,
        long maximumHeaderBytes,
        [NotNullWhen(true)] out ResponseCacheEnvelope? envelope)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(body);
        envelope = null;

        try
        {
            long retainedHeaderBytes = MeasureRetainedHeaderBytes(headers);
            if (retainedHeaderBytes > maximumHeaderBytes)
            {
                return false;
            }

            envelope = CaptureCore(statusCode, mediaType, headers, body, retainedHeaderBytes);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException)
        {
            // Malformed/unrepresentable response metadata is an admission bypass, not a live
            // execution failure. The already-bounded response remains available to its caller.
            return false;
        }
    }

    private static ResponseCacheEnvelope CaptureCore(
        int statusCode,
        string? mediaType,
        IReadOnlyDictionary<string, string[]> headers,
        byte[] body,
        long retainedHeaderBytes)
    {
        List<KeyValuePair<string, ImmutableArray<string>>> copy = [];
        Dictionary<string, int> indexes = new(StringComparer.OrdinalIgnoreCase);

        foreach ((string name, string[] values) in headers)
        {
            ImmutableArray<string> valueCopy = [.. values];
            if (indexes.TryGetValue(name, out int existingIndex))
            {
                KeyValuePair<string, ImmutableArray<string>> existing = copy[existingIndex];
                copy[existingIndex] = new KeyValuePair<string, ImmutableArray<string>>(
                    existing.Key,
                    existing.Value.AddRange(valueCopy));
            }
            else
            {
                indexes.Add(name, copy.Count);
                copy.Add(new KeyValuePair<string, ImmutableArray<string>>(name, valueCopy));
            }
        }

        return new ResponseCacheEnvelope(
            statusCode,
            mediaType,
            [.. copy],
            [.. body],
            retainedHeaderBytes,
            DateTimeOffset.MinValue,
            0,
            0,
            0,
            string.Empty);
    }

    private static long MeasureRetainedHeaderBytes(IReadOnlyDictionary<string, string[]> headers)
    {
        long retained = 0;
        HashSet<string> names = new(StringComparer.OrdinalIgnoreCase);

        foreach ((string name, string[] values) in headers)
        {
            if (string.IsNullOrEmpty(name) || values is null)
            {
                throw new ArgumentException("Response headers cannot contain a missing name or value list.", nameof(headers));
            }

            if (names.Add(name))
            {
                retained = checked(retained + HeaderLineOverheadBytes + Encoding.UTF8.GetByteCount(name));
            }
            foreach (string value in values)
            {
                if (value is null)
                {
                    throw new ArgumentException("Response header values cannot be null.", nameof(headers));
                }

                retained = checked(retained + Encoding.UTF8.GetByteCount(value));
            }
        }

        return retained;
    }

    internal ResponseCacheEnvelope CopyForStorage(
        DateTimeOffset storedAtUtc,
        long storedAtTimestamp,
        long expiresAtTimestamp,
        int effectiveTtlSeconds,
        string operationSlug)
        => new(
            StatusCode,
            MediaType,
            Headers,
            Body.ToArray(),
            RetainedHeaderBytes,
            storedAtUtc,
            storedAtTimestamp,
            expiresAtTimestamp,
            effectiveTtlSeconds,
            operationSlug);
}
