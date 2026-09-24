using System.Buffers;

namespace MCPiler.Engine.JmesPath;

/// <summary>
/// A byte sink that refuses to grow past a limit instead of truncating.
/// </summary>
/// <remarks>
/// <para>
/// Every serialization in profile 1 is bounded by a number the author declared, and the
/// distinction that matters is between "did not produce output" and "produced output that was
/// cut short". A truncating writer would hand back a syntactically valid document describing a
/// different value, which is worse than a refusal in every direction: it looks like success,
/// it cannot be detected downstream, and it silently changes what a caller receives.
/// </para>
/// <para>
/// So the limit is enforced by refusing to hand out a span that would cross it. The caller
/// catches <see cref="BufferFullException"/> and reports the declared bound; whatever was
/// written is discarded with the buffer.
/// </para>
/// </remarks>
internal sealed class BoundedJsonBuffer : IBufferWriter<byte>, IDisposable
{
    private readonly long _maxBytes;
    private byte[]? _buffer;
    private int _written;

    /// <summary>Creates a buffer that will refuse to exceed <paramref name="maxBytes"/>.</summary>
    internal BoundedJsonBuffer(long maxBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 1);

        _maxBytes = maxBytes;
        _buffer = ArrayPool<byte>.Shared.Rent(InitialCapacity(maxBytes));
    }

    /// <summary>What has been written so far.</summary>
    internal ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _written);

    /// <summary>A copy of what has been written, for handing across a boundary.</summary>
    internal byte[] ToArray() => WrittenSpan.ToArray();

    /// <inheritdoc />
    public void Advance(int count) => _written += count;

    /// <inheritdoc />
    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return _buffer.AsMemory(_written);
    }

    /// <inheritdoc />
    public Span<byte> GetSpan(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return _buffer.AsSpan(_written);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        byte[]? buffer = _buffer;
        _buffer = null;
        _written = 0;

        if (buffer is not null)
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static int InitialCapacity(long maxBytes)
        => (int)Math.Min(maxBytes, 4096);

    private void Ensure(int sizeHint)
    {
        if (sizeHint <= 0)
        {
            sizeHint = 1;
        }

        byte[] current = _buffer
            ?? throw new ObjectDisposedException(nameof(BoundedJsonBuffer));

        if (current.Length - _written >= sizeHint)
        {
            return;
        }

        long required = (long)_written + sizeHint;

        if (required > _maxBytes)
        {
            throw new BufferFullException(_maxBytes);
        }

        int target = (int)Math.Min(_maxBytes, Math.Max(required, current.Length * 2L));
        byte[] grown = ArrayPool<byte>.Shared.Rent(target);
        current.AsSpan(0, _written).CopyTo(grown);
        ArrayPool<byte>.Shared.Return(current);
        _buffer = grown;
    }

    /// <summary>The refusal a bounded serialization raises when it would cross its limit.</summary>
    internal sealed class BufferFullException : Exception
    {
        internal BufferFullException(long maxBytes)
            : base($"The serialized value would exceed the declared limit of {maxBytes} bytes.")
            => MaxBytes = maxBytes;

        /// <summary>The limit that was crossed.</summary>
        internal long MaxBytes { get; }
    }
}
