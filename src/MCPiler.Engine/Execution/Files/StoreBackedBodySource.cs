namespace MCPiler.Engine.Execution.Files;

/// <summary>A replayable request source backed by one durable Engine file record.</summary>
internal sealed class StoreBackedBodySource(
    FileHandleStore store,
    FileHandleReference reference) : ReplayableBodySource
{
    private int _disposed;

    public override long? Length => reference.Length;

    public override async ValueTask CopyToAsync(Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        FileHandleLookup opened = await store.OpenAsync(reference.Id, cancellationToken).ConfigureAwait(false);

        if (opened.Status != FileHandleStatus.Available || opened.Content is not { } content)
        {
            throw new FileRuntimeException(
                opened.Status == FileHandleStatus.Expired
                    ? "The stored file expired before its request body could be replayed."
                    : "The stored file is no longer available for request replay.");
        }

        await using (content.ConfigureAwait(false))
        {
            await content.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
        }
    }

    public override ValueTask DisposeAsync()
    {
        Interlocked.Exchange(ref _disposed, 1);
        return ValueTask.CompletedTask;
    }
}
