namespace MCPiler.Engine.Execution;

/// <summary>Raised when a response exceeds the configured decoded-byte ceiling.</summary>
public sealed class ResponseSizeLimitException(long observed, long limit)
    : Exception($"The response exceeded the size limit of {limit} bytes (observed {observed} decoded bytes).")
{
    /// <summary>The number of decoded bytes read when the ceiling was crossed.</summary>
    public long ObservedBytes { get; } = observed;

    /// <summary>The ceiling that was crossed.</summary>
    public long Limit { get; } = limit;
}

/// <summary>
/// Copies a response payload with a ceiling counted over DECODED bytes.
/// </summary>
/// <remarks>
/// <para>
/// Counting decoded bytes is the point. A declared content length can be truthful, absent, or a lie,
/// and a compressed payload can be small on the wire and unbounded once expanded, so the only figure
/// worth enforcing is the count of bytes actually produced.
/// </para>
/// <para>
/// The copy streams. It never materializes the whole payload to measure it, because doing so would
/// spend exactly the memory the ceiling exists to protect. The ceiling is therefore crossed at most
/// one read buffer beyond the limit, and the copy stops there.
/// </para>
/// </remarks>
public static class BoundedResponseReader
{
    private const int BufferSize = 81920;

    /// <summary>Copies <paramref name="source"/> into <paramref name="destination"/> with a decoded-byte ceiling.</summary>
    public static async Task CopyWithLimitAsync(
        Stream source,
        Stream destination,
        long limit,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[BufferSize];
        long total = 0;
        int read;

        while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            total += read;

            if (total > limit)
            {
                throw new ResponseSizeLimitException(total, limit);
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Reads the full decoded payload with the ceiling enforced.</summary>
    public static async Task<byte[]> ReadAllWithLimitAsync(
        Stream source,
        long limit,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();

        await CopyWithLimitAsync(source, buffer, limit, cancellationToken).ConfigureAwait(false);

        return buffer.ToArray();
    }
}
