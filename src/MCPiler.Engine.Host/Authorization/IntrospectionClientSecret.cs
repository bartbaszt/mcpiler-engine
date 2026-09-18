using System.Text;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// Reads the introspection client's secret from its deployment file.
/// </summary>
/// <remarks>
/// <para>
/// The secret authenticates this resource server to the issuer's introspection endpoint. It is
/// read from a file rather than a setting because a command line is visible to every process
/// listing on the host and an environment literal is visible in a container's inspectable
/// configuration; the file can be mounted read-only with restrictive permissions and rotated
/// without changing the process arguments. The same reasoning already governs the deployment
/// secret this process reads in managed mode.
/// </para>
/// <para>
/// Reading happens once, during the startup path, so a missing or unusable file is a startup
/// refusal rather than a failure discovered at the first protected request. No refusal here
/// ever contains the secret: only the path and the reason.
/// </para>
/// </remarks>
internal static class IntrospectionClientSecret
{
    /// <summary>Reads and normalizes the secret.</summary>
    /// <param name="path">The configured file path.</param>
    /// <param name="secret">The secret value on success.</param>
    /// <param name="refusal">
    /// A bounded, non-secret reason on failure, naming the path and how many bytes were observed;
    /// null on success.
    /// </param>
    /// <returns>True when a usable secret was read.</returns>
    internal static bool TryRead(string path, out string secret, out string? refusal)
    {
        secret = string.Empty;

        if (string.IsNullOrWhiteSpace(path))
        {
            refusal = "No introspection client secret file is configured.";
            return false;
        }

        byte[] contents;

        try
        {
            contents = File.ReadAllBytes(path);
        }
        catch (Exception failure) when (failure is FileNotFoundException or DirectoryNotFoundException)
        {
            refusal = $"The introspection client secret file '{path}' does not exist.";
            return false;
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
        {
            refusal = $"The introspection client secret file '{path}' could not be read.";
            return false;
        }

        // A secret file written by an editor or a secret manager commonly ends in one newline.
        // Trailing whitespace is not part of the secret and would otherwise authenticate as a
        // different value than the operator believes they deployed.
        string text = Encoding.UTF8.GetString(contents).TrimEnd('\r', '\n');

        if (text.Length == 0)
        {
            refusal = $"The introspection client secret file '{path}' is empty. It must hold the client secret.";
            return false;
        }

        secret = text;
        refusal = null;
        return true;
    }
}
