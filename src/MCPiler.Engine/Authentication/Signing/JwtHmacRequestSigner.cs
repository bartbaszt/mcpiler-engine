using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using MCPiler.Engine.Execution;

namespace MCPiler.Engine.Authentication.Signing;

/// <summary>Ghost Admin API short-lived HS256 JWT signer.</summary>
public sealed class JwtHmacRequestSigner : IRequestSigner
{
    private static readonly IReadOnlySet<string> Headers =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Authorization" };

    /// <inheritdoc />
    public string StrategyId => "request-signing-jwt-hmac";

    /// <inheritdoc />
    public IReadOnlySet<string> SensitiveHeaders => Headers;

    /// <inheritdoc />
    public IReadOnlySet<string> SensitiveQueryParameters => EmptySensitiveSet.Instance;

    /// <inheritdoc />
    public ValueTask SignAsync(
        SignableRequest request,
        RequestSigningMaterial material,
        RequestSigningAttempt attempt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(attempt);

        cancellationToken.ThrowIfCancellationRequested();

        byte[] key;
        try
        {
            key = Convert.FromHexString(material.SigningSecret);
        }
        catch (FormatException ex)
        {
            throw new CredentialUnavailableException(
                material.AccessKeyId,
                "The JWT signing secret is not valid hexadecimal material.",
                ex);
        }

        if (key.Length == 0)
        {
            throw new CredentialUnavailableException(
                material.AccessKeyId,
                "The JWT signing secret is empty.");
        }

        var issuedAt = attempt.TimestampUtc.ToUnixTimeSeconds();
        byte[] header = JsonSerializer.SerializeToUtf8Bytes(
            new { alg = "HS256", kid = material.AccessKeyId, typ = "JWT" });
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(
            new { iat = issuedAt, exp = issuedAt + 300, aud = "/admin/" });
        string signingInput = Base64Url(header) + "." + Base64Url(payload);
        byte[] signature = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(signingInput));
        CryptographicOperations.ZeroMemory(key);

        request.RemoveHeader("Authorization");
        request.SetHeader("Authorization", "Ghost " + signingInput + "." + Base64Url(signature));
        return ValueTask.CompletedTask;
    }

    private static string Base64Url(ReadOnlySpan<byte> bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
