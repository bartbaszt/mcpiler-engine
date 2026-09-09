using System.IO.Compression;
using MCPiler.Engine.Execution;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Covers the decoded-byte ceiling. The limit exists so a hostile or misconfigured upstream cannot
/// exhaust memory, so the tests assert how much was read and not only that the call failed.
/// </summary>
public sealed class BoundedResponseReaderTests
{
    /// <summary>A stream that reports how many bytes the reader actually pulled from it.</summary>
    private sealed class CountingStream(byte[] content) : Stream
    {
        private readonly MemoryStream _inner = new(content);

        public long BytesRead { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _inner.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private static byte[] Bytes(int count)
    {
        var content = new byte[count];

        for (var i = 0; i < count; i++)
        {
            content[i] = (byte)(i % 251);
        }

        return content;
    }

    [Fact]
    public async Task A_payload_under_the_limit_is_returned_whole()
    {
        var content = Bytes(1024);

        var read = await BoundedResponseReader.ReadAllWithLimitAsync(
            new MemoryStream(content),
            limit: 4096,
            TestContext.Current.CancellationToken);

        Assert.Equal(content, read);
    }

    [Fact]
    public async Task A_payload_exactly_at_the_limit_succeeds()
    {
        // The ceiling is inclusive: the limit is the largest payload that is still acceptable, so an
        // exclusive comparison here would reject a response the configuration permits.
        var content = Bytes(2048);

        var read = await BoundedResponseReader.ReadAllWithLimitAsync(
            new MemoryStream(content),
            limit: 2048,
            TestContext.Current.CancellationToken);

        Assert.Equal(2048, read.Length);
    }

    [Fact]
    public async Task A_payload_one_byte_over_the_limit_is_refused()
    {
        var ex = await Assert.ThrowsAsync<ResponseSizeLimitException>(
            () => BoundedResponseReader.ReadAllWithLimitAsync(
                new MemoryStream(Bytes(2049)),
                limit: 2048,
                TestContext.Current.CancellationToken));

        Assert.Equal(2048, ex.Limit);
        Assert.Equal(2049, ex.ObservedBytes);
    }

    [Fact]
    public async Task An_empty_payload_is_accepted_even_under_a_zero_limit()
    {
        var read = await BoundedResponseReader.ReadAllWithLimitAsync(
            new MemoryStream([]),
            limit: 0,
            TestContext.Current.CancellationToken);

        Assert.Empty(read);
    }

    [Fact]
    public async Task A_single_byte_is_refused_under_a_zero_limit()
        => await Assert.ThrowsAsync<ResponseSizeLimitException>(
            () => BoundedResponseReader.ReadAllWithLimitAsync(
                new MemoryStream([1]),
                limit: 0,
                TestContext.Current.CancellationToken));

    [Fact]
    public async Task An_oversized_payload_is_not_read_to_its_end()
    {
        // The point of the ceiling. A 4 MiB payload under a 1 KiB limit must not be pulled in full;
        // the reader stops within one buffer of detecting the excess.
        var source = new CountingStream(Bytes(4 * 1024 * 1024));

        await Assert.ThrowsAsync<ResponseSizeLimitException>(
            () => BoundedResponseReader.ReadAllWithLimitAsync(
                source,
                limit: 1024,
                TestContext.Current.CancellationToken));

        Assert.True(
            source.BytesRead <= 1024 + 81920,
            $"read {source.BytesRead} bytes for a 1024-byte limit; the ceiling is not bounding the read");
        Assert.True(source.BytesRead < 4 * 1024 * 1024);
    }

    [Fact]
    public async Task A_compressed_payload_is_measured_after_decoding()
    {
        // A small compressed body can decode to an enormous one, which is the shape the ceiling exists
        // to stop. The reader sees the decoded stream, so the limit applies to decoded bytes.
        var raw = new byte[512 * 1024];
        using var compressed = new MemoryStream();

        using (var gzip = new GZipStream(compressed, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            await gzip.WriteAsync(raw, TestContext.Current.CancellationToken);
        }

        compressed.Position = 0;

        Assert.True(compressed.Length < 4096, "the fixture must be small once compressed to be meaningful");

        using var decoding = new GZipStream(compressed, CompressionMode.Decompress);

        await Assert.ThrowsAsync<ResponseSizeLimitException>(
            () => BoundedResponseReader.ReadAllWithLimitAsync(
                decoding,
                limit: 4096,
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task The_copy_overload_stops_writing_once_the_limit_is_exceeded()
    {
        // CHARACTERIZATION of a consequence worth stating: the destination keeps whatever was written
        // before the excess was detected. A caller that streams to durable storage must therefore
        // discard the destination on failure rather than assume it was left untouched.
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<ResponseSizeLimitException>(
            () => BoundedResponseReader.CopyWithLimitAsync(
                new MemoryStream(Bytes(200_000)),
                destination,
                limit: 1024,
                TestContext.Current.CancellationToken));

        Assert.True(
            destination.Length <= 1024,
            $"wrote {destination.Length} bytes past a 1024-byte limit");
    }

    [Fact]
    public async Task The_copy_overload_writes_every_byte_of_an_accepted_payload()
    {
        var content = Bytes(100_000);
        using var destination = new MemoryStream();

        await BoundedResponseReader.CopyWithLimitAsync(
            new MemoryStream(content),
            destination,
            limit: 200_000,
            TestContext.Current.CancellationToken);

        Assert.Equal(content, destination.ToArray());
    }

    [Fact]
    public async Task A_cancelled_read_is_abandoned_rather_than_completed()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => BoundedResponseReader.ReadAllWithLimitAsync(
                new MemoryStream(Bytes(200_000)),
                limit: 1_000_000,
                cts.Token));
    }
}
