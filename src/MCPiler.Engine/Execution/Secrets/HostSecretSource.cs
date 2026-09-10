namespace MCPiler.Engine.Execution.Secrets;

/// <summary>
/// Reads a secret from the process environment or from a file on disk.
/// </summary>
/// <remarks>
/// <para>
/// This is the whole of Engine's secret-reading capability, and it is deliberately the whole of
/// what lives here: no credential model, no policy, no message text. The three outcomes it
/// distinguishes — absent, wrong kind of entry, unreadable — are distinguished because they
/// have different corrections, not because anything here knows what the bytes are for.
/// </para>
/// <para>
/// A read failure is returned rather than thrown. The resolver has to name the reference and
/// nothing else in the diagnostic it produces, and an exception would hand it the path plus
/// whatever the platform attached.
/// </para>
/// </remarks>
public sealed class HostSecretSource : ISecretSource
{
    /// <inheritdoc />
    public string? ReadEnvironmentVariable(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return Environment.GetEnvironmentVariable(name);
    }

    /// <inheritdoc />
    public async ValueTask<SecretFileRead> ReadFileAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        if (Directory.Exists(path))
        {
            return new SecretFileRead(SecretFileStatus.NotAFile, null);
        }

        if (!File.Exists(path))
        {
            return new SecretFileRead(SecretFileStatus.NotFound, null);
        }

        try
        {
            var contents = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            return new SecretFileRead(SecretFileStatus.Read, contents);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new SecretFileRead(SecretFileStatus.Unreadable, null);
        }
    }
}
