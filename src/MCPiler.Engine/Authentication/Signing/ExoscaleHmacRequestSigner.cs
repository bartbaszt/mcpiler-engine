using System.Security.Cryptography;
using System.Text;

using MCPiler.Engine.Execution;

namespace MCPiler.Engine.Authentication.Signing;

/// <summary>Exoscale API v2 EXO2-HMAC-SHA256 signer.</summary>
public sealed class ExoscaleHmacRequestSigner : IRequestSigner
{
    private static readonly IReadOnlySet<string> Headers =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Authorization" };

    /// <inheritdoc />
    public string StrategyId => "request-signing-hmac";

    /// <inheritdoc />
    public IReadOnlySet<string> SensitiveHeaders => Headers;

    /// <inheritdoc />
    public IReadOnlySet<string> SensitiveQueryParameters => EmptySensitiveSet.Instance;

    /// <inheritdoc />
    public async ValueTask SignAsync(
        SignableRequest request,
        RequestSigningMaterial material,
        RequestSigningAttempt attempt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(attempt);

        var query = request.QueryParameters();
        string body = request.ReadBodyAsync is null
            ? string.Empty
            : StrictUtf8(await request.ReadBodyAsync(cancellationToken).ConfigureAwait(false));
        long expires = attempt.TimestampUtc.ToUnixTimeSeconds() + 60;
        string signedNames = string.Join(';', query.Select(item => item.Key));
        string signedValues = string.Concat(query.Select(item => item.Value));
        string message =
            $"{request.Method.ToUpperInvariant()} {request.Uri.AbsolutePath}\n{body}\n{signedValues}\n{signedNames}\n\n{expires}";
        byte[] signatureBytes = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(material.SigningSecret),
            Encoding.UTF8.GetBytes(message));
        string signature = Convert.ToBase64String(signatureBytes);

        string authorization = $"EXO2-HMAC-SHA256 credential={material.AccessKeyId}";
        if (query.Count > 0)
        {
            authorization += $",signed-query-args={signedNames}";
        }

        authorization += $",expires={expires},signature={signature}";

        request.RemoveHeader("Authorization");
        request.SetHeader("Authorization", authorization);
    }

    private static string StrictUtf8(byte[] bytes)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException ex)
        {
            throw new UnsupportedAuthenticationStrategyException(
                $"EXO2-HMAC-SHA256 cannot sign a non-UTF-8 request body: {ex.Message}",
                ex);
        }
    }
}
