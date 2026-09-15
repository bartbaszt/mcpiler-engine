using System.Security.Cryptography;
using System.Text;

namespace MCPiler.Engine.Authentication.Signing;

/// <summary>Subsonic/OpenSubsonic salted-token query authentication used by Navidrome.</summary>
public sealed class SubsonicMd5RequestSigner : IRequestSigner
{
    private static readonly IReadOnlySet<string> QueryParameters =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "u", "t", "s" };

    private static readonly HashSet<string> ReservedNames =
        new(StringComparer.OrdinalIgnoreCase) { "u", "p", "t", "s", "v", "c", "f" };

    /// <inheritdoc />
    public string StrategyId => "request-signing-subsonic-md5";

    /// <inheritdoc />
    public IReadOnlySet<string> SensitiveHeaders => EmptySensitiveSet.Instance;

    /// <inheritdoc />
    public IReadOnlySet<string> SensitiveQueryParameters => QueryParameters;

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

        string salt = attempt.Nonce.Length >= 6
            ? attempt.Nonce
            : throw new AuthenticationPlanException(
                material.AccessKeyId,
                "Subsonic signing requires a nonce of at least six characters.");

        byte[] tokenBytes = Encoding.UTF8.GetBytes(material.SigningSecret + salt);

#pragma warning disable CA5351 // MD5 is mandated by the reviewed Subsonic authentication protocol.
        string token = Convert.ToHexString(MD5.HashData(tokenBytes)).ToLowerInvariant();
#pragma warning restore CA5351

        var values = new List<KeyValuePair<string, string>>();
        foreach (var parameter in request.QueryParameters())
        {
            if (!ReservedNames.Contains(parameter.Key))
            {
                values.Add(parameter);
            }
        }

        values.Add(new KeyValuePair<string, string>("u", material.AccessKeyId));
        values.Add(new KeyValuePair<string, string>("t", token));
        values.Add(new KeyValuePair<string, string>("s", salt));
        values.Add(new KeyValuePair<string, string>("v", "1.16.1"));
        values.Add(new KeyValuePair<string, string>("c", "MCPiler"));
        values.Add(new KeyValuePair<string, string>("f", "json"));

        request.SetQuery(values);
        return ValueTask.CompletedTask;
    }
}
