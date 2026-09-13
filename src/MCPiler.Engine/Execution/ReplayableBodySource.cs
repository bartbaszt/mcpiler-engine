namespace MCPiler.Engine.Execution;

/// <summary>
/// A request payload that can write itself again without retaining an opened stream.
/// </summary>
/// <remarks>
/// Redirects that preserve a request body need a fresh read of the same payload. Implementations
/// therefore open any backing resource inside <see cref="CopyToAsync"/> and close it before the
/// call returns. The execution that owns the source disposes it exactly once when the invocation
/// ends, including refusal, cancellation and transport failure paths.
/// </remarks>
public abstract class ReplayableBodySource : IAsyncDisposable
{
    /// <summary>
    /// Bytes already owned by the caller, when this source was explicitly constructed from a
    /// buffer. Store-backed production sources return null and can only be consumed by streaming.
    /// </summary>
    internal virtual ReadOnlyMemory<byte>? BufferedBytes => null;

    /// <summary>The exact payload length when it is known without reading the payload.</summary>
    public abstract long? Length { get; }

    /// <summary>Writes one fresh replay of the payload to <paramref name="destination"/>.</summary>
    public abstract ValueTask CopyToAsync(Stream destination, CancellationToken cancellationToken);

    /// <inheritdoc />
    public abstract ValueTask DisposeAsync();

    /// <summary>Wraps already-buffered non-streaming bytes in the same replay contract.</summary>
    public static ReplayableBodySource FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return new BufferedBodySource(bytes);
    }

    private sealed class BufferedBodySource(byte[] bytes) : ReplayableBodySource
    {
        private int _disposed;

        internal override ReadOnlyMemory<byte>? BufferedBytes => bytes;

        public override long? Length => bytes.LongLength;

        public override ValueTask CopyToAsync(Stream destination, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(destination);
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return destination.WriteAsync(bytes, cancellationToken);
        }

        public override ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _disposed, 1);
            return ValueTask.CompletedTask;
        }
    }
}
