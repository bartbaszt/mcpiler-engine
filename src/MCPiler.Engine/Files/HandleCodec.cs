using System.Security.Cryptography;

namespace MCPiler.Engine.Files;

/// <summary>
/// Creates and recognizes the opaque capability string that crosses the protocol boundary.
/// </summary>
/// <remarks>
/// The token is independent random material. It is never computed from a store identifier,
/// storage location, content hash, scope, sequence number, or any other file metadata, so
/// decoding the base64url representation yields no recoverable product structure.
/// </remarks>
public static class HandleCodec
{
    private const int TokenBytes = 32;
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>Creates a new 256-bit bearer capability in unpadded base64url form.</summary>
    public static string NewWire()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(TokenBytes))
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

    /// <summary>True when <paramref name="value"/> has exactly the wire shape this build issues.</summary>
    public static bool IsWireForm(string? value)
    {
        if (value is null || value.Length != ExpectedLength)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (!Alphabet.Contains(character, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static int ExpectedLength => (TokenBytes * 4 + 2) / 3;
}
