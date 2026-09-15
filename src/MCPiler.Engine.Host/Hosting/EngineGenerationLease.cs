namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// One admission's claim on one generation.
/// </summary>
/// <remarks>
/// <para>
/// A lease is what makes a generation swap safe. Between the moment a request resolves its
/// address and the moment its last byte is written, the generation it resolved against must not
/// be disposed, even if an operator activation replaced it in between. Holding a lease is that
/// promise, and releasing it is what eventually lets the superseded generation's execution
/// objects and secret buffers go.
/// </para>
/// <para>
/// A lease is disposable exactly once. Releasing a lease that was never acquired, or releasing
/// one twice, is a bug in the caller rather than a state a generation can repair.
/// </para>
/// </remarks>
internal sealed class EngineGenerationLease : IDisposable
{
    private readonly EngineGeneration _generation;
    private int _released;

    internal EngineGenerationLease(EngineGeneration generation)
    {
        _generation = generation;
    }

    /// <summary>The generation this admission resolved against.</summary>
    internal EngineGeneration Generation => _generation;

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _released, 1) != 0)
        {
            return;
        }

        _generation.Release();
    }
}
