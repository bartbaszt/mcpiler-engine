namespace MCPiler.Engine.Execution;

/// <summary>Why a secret file could not be turned into text.</summary>
public enum SecretFileStatus
{
    /// <summary>The file was read.</summary>
    Read,

    /// <summary>No entry exists at the path.</summary>
    NotFound,

    /// <summary>The path exists and is not a file.</summary>
    NotAFile,

    /// <summary>The entry exists and could not be read.</summary>
    Unreadable,
}

/// <summary>The outcome of one attempt to read a secret file.</summary>
/// <param name="Status">What happened.</param>
/// <param name="Contents">
/// The file's text when <paramref name="Status"/> is <see cref="SecretFileStatus.Read"/>, and
/// null otherwise.
/// </param>
/// <remarks>
/// A failure is a value rather than an exception because the caller has to convert it into a
/// diagnostic that names the reference and discloses nothing else. An exception would arrive
/// carrying the path and, on some platforms, a partial buffer — material the caller would then
/// have to remember not to include.
/// </remarks>
public readonly record struct SecretFileRead(SecretFileStatus Status, string? Contents);

/// <summary>
/// The two places a credential reference can point outside the manifest.
/// </summary>
/// <remarks>
/// Deliberately unaware of what a credential is. It reads a named environment variable and it
/// reads a file; which variable, which file, whether the result may be empty, whether a trailing
/// newline was part of the secret and what a failure should say are all decisions that belong to
/// the resolver, which reaches nothing.
/// </remarks>
public interface ISecretSource
{
    /// <summary>Returns the process environment variable's value, or null when it is not set.</summary>
    /// <param name="name">The variable name.</param>
    string? ReadEnvironmentVariable(string name);

    /// <summary>Reads <paramref name="path"/> as text.</summary>
    /// <param name="path">The file to read.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    ValueTask<SecretFileRead> ReadFileAsync(string path, CancellationToken cancellationToken);
}
