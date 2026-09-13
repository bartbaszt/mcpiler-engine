using MCPiler.Engine.Host.Files;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

public sealed class FileTransferStreamingTests
{
    [Fact]
    public async Task Download_writes_the_first_chunk_before_the_source_reaches_end()
    {
        TaskCompletionSource firstWrite = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseRemainder = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using GateReadStream source = new("first"u8.ToArray(), "-rest"u8.ToArray(), releaseRemainder.Task);
        await using SignalWriteStream destination = new(firstWrite);
        DefaultHttpContext context = new();
        context.Response.Body = destination;

        Task copy = FileTransferEndpoints.StreamContentAsync(context, source);

        await firstWrite.Task.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        Assert.False(copy.IsCompleted, "The response was not allowed to wait for the whole source before its first write.");

        releaseRemainder.SetResult();
        await copy;

        Assert.Equal("first-rest"u8.ToArray(), destination.Bytes);
    }

    private sealed class GateReadStream(
        byte[] first,
        byte[] remainder,
        Task releaseRemainder) : Stream
    {
        private int _stage;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => first.LongLength + remainder.LongLength;
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (_stage == 0)
            {
                _stage = 1;
                first.CopyTo(buffer);
                return first.Length;
            }

            if (_stage == 1)
            {
                _stage = 2;
                await releaseRemainder.WaitAsync(cancellationToken);
                remainder.CopyTo(buffer);
                return remainder.Length;
            }

            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class SignalWriteStream(TaskCompletionSource firstWrite) : MemoryStream
    {
        public byte[] Bytes => ToArray();

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await base.WriteAsync(buffer, cancellationToken);
            firstWrite.TrySetResult();
        }
    }
}
