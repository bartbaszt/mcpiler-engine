namespace MCPiler.Engine.Execution.Secrets.RuntimeState;

/// <summary>
/// Reads the Engine runtime-state key from its deployment file.
/// </summary>
/// <remarks>
/// <para>
/// The key is Engine's own. It is never the Platform master key, never derived from one, and never
/// leaves this process: the file is the deployment's input and the loaded bytes live only in the
/// store adapter that consumes them.
/// </para>
/// <para>
/// Two encodings are accepted because both are ordinary ways to provision a 32-byte secret:
/// exactly 32 raw bytes, or their 64-character hexadecimal spelling. Anything else is refused by
/// length alone — the refusal reports how many bytes were observed, never the bytes themselves.
/// </para>
/// </remarks>
public static class RuntimeStateKeyFile
{
    /// <summary>The key length every accepted encoding must yield.</summary>
    public const int KeyLength = 32;

    /// <summary>Reads and validates the key file.</summary>
    /// <param name="path">The deployment-configured key-file path.</param>
    /// <param name="key">The key bytes on success.</param>
    /// <param name="refusal">
    /// A bounded, non-secret reason on failure; null on success. It names the path and the
    /// observed length only.
    /// </param>
    /// <returns>True when a usable key was read.</returns>
    public static bool TryRead(string path, out byte[] key, out string? refusal)
    {
        key = [];

        if (string.IsNullOrWhiteSpace(path))
        {
            refusal = "No runtime-state key file is configured.";
            return false;
        }

        byte[] contents;
        try
        {
            contents = File.ReadAllBytes(path);
        }
        catch (FileNotFoundException)
        {
            refusal = $"The runtime-state key file '{path}' does not exist.";
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            refusal = $"The runtime-state key file '{path}' does not exist.";
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            refusal = $"The runtime-state key file '{path}' could not be read.";
            return false;
        }

        if (contents.Length == KeyLength)
        {
            key = contents;
            refusal = null;
            return true;
        }

        var trimmed = TrimSingleTrailingNewline(contents);

        if (trimmed.Length == KeyLength * 2 && IsHexadecimal(trimmed))
        {
            key = Convert.FromHexString(trimmed);
            refusal = null;
            return true;
        }

        refusal =
            $"The runtime-state key file '{path}' is {contents.Length} bytes long; it must hold "
            + $"exactly {KeyLength} raw bytes or their {KeyLength * 2}-character hexadecimal spelling.";
        return false;
    }

    private static ReadOnlySpan<byte> TrimSingleTrailingNewline(ReadOnlySpan<byte> contents)
    {
        if (contents.Length > 0 && contents[^1] == (byte)'\n')
        {
            contents = contents[..^1];
        }

        if (contents.Length > 0 && contents[^1] == (byte)'\r')
        {
            contents = contents[..^1];
        }

        return contents;
    }

    private static bool IsHexadecimal(ReadOnlySpan<byte> value)
    {
        foreach (var character in value)
        {
            var isHex = character is >= (byte)'0' and <= (byte)'9'
                or >= (byte)'a' and <= (byte)'f'
                or >= (byte)'A' and <= (byte)'F';

            if (!isHex)
            {
                return false;
            }
        }

        return value.Length > 0;
    }
}
