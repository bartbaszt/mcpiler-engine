using System.Text;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// Reads the response-cache operator secret from its deployment file.
/// </summary>
/// <remarks>
/// <para>
/// The secret authenticates the live operator channel that reads and clears in-memory cache
/// state. It is read from a file rather than a setting for the same reason the introspection
/// client secret is: a secret on a command line is visible to every process listing on the host,
/// and a file can be mounted read-only with restrictive permissions and rotated without changing
/// the process arguments.
/// </para>
/// <para>
/// The secret is deliberately its own file and never shared with the MCP caller tokens, the
/// introspection client secret or the managed-deployment secret. Those authenticate different
/// principals, and a disclosure of any of them must not also grant live cache control.
/// </para>
/// <para>
/// Reading happens once, during the startup path, so a missing or unusable file is a startup
/// refusal rather than a failure discovered at the first operator request. No refusal here ever
/// contains the secret: only the path and the reason.
/// </para>
/// </remarks>
internal static class ResponseCacheOperatorSecret
{
    /// <summary>Reads and normalizes the operator secret.</summary>
    /// <param name="path">The configured file path.</param>
    /// <param name="secret">The secret value on success.</param>
    /// <param name="refusal">
    /// A bounded, non-secret reason on failure, naming the path; null on success.
    /// </param>
    /// <returns>True when a usable secret was read.</returns>
    /// <remarks>
    /// Unlike the introspection client secret the trailing newline is trimmed but other
    /// whitespace is preserved, because an operator secret is compared byte-for-byte and a
    /// deliberate interior space must remain part of it.
    /// </remarks>
    internal static bool TryRead(string path, out string secret, out string? refusal)
    {
        secret = string.Empty;

        if (string.IsNullOrWhiteSpace(path))
        {
            refusal = "No response-cache operator secret file is configured.";
            return false;
        }

        byte[] contents;

        try
        {
            contents = File.ReadAllBytes(path);
        }
        catch (Exception failure) when (failure is FileNotFoundException or DirectoryNotFoundException)
        {
            refusal = $"The response-cache operator secret file '{path}' does not exist. "
                + "The operator channel is opt-in, so remove the setting to serve without it.";
            return false;
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
        {
            refusal = $"The response-cache operator secret file '{path}' could not be read.";
            return false;
        }

        string text = Encoding.UTF8.GetString(contents).TrimEnd('\r', '\n');

        if (text.Length == 0)
        {
            refusal = $"The response-cache operator secret file '{path}' is empty. It must hold the operator secret.";
            return false;
        }

        secret = text;
        refusal = null;
        return true;
    }
}
