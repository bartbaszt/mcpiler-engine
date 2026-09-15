using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using MCPiler.Engine.Execution;

namespace MCPiler.Engine.Authentication.Signing;

/// <summary>AWS Signature Version 4 signer for the reviewed S3-compatible Wasabi surface.</summary>
public sealed class AwsSigV4RequestSigner : IRequestSigner
{
    private const string Algorithm = "AWS4-HMAC-SHA256";

    private static readonly IReadOnlySet<string> Headers =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Authorization" };

    private static readonly HashSet<string> ExcludedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization", "connection", "content-length", "expect", "proxy-authenticate",
        "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "user-agent",
    };

    /// <inheritdoc />
    public string StrategyId => "request-signing-aws-sigv4";

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

        var uri = request.Uri;
        string region = ResolveRegion(uri);
        byte[] body = request.ReadBodyAsync is null
            ? []
            : await request.ReadBodyAsync(cancellationToken).ConfigureAwait(false);
        string payloadHash = Hex(SHA256.HashData(body));
        string amzDate = attempt.TimestampUtc.UtcDateTime
            .ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        string date = attempt.TimestampUtc.UtcDateTime
            .ToString("yyyyMMdd", CultureInfo.InvariantCulture);

        request.RemoveHeader("Authorization");
        request.RemoveHeader("x-amz-date");
        request.RemoveHeader("x-amz-content-sha256");
        request.SetHeader("x-amz-date", amzDate);
        request.SetHeader("x-amz-content-sha256", payloadHash);
        request.SetHeader("Host", uri.IsDefaultPort ? uri.IdnHost : $"{uri.IdnHost}:{uri.Port}");

        var canonicalHeaders = CanonicalHeaders(request);
        string signedHeaders = string.Join(';', canonicalHeaders.Select(item => item.Name));
        string canonicalHeaderText =
            string.Concat(canonicalHeaders.Select(item => $"{item.Name}:{item.Value}\n"));
        string canonicalRequest = string.Join('\n',
            request.Method.ToUpperInvariant(),
            CanonicalPath(uri),
            CanonicalQuery(uri),
            canonicalHeaderText,
            signedHeaders,
            payloadHash);
        string scope = $"{date}/{region}/s3/aws4_request";
        string stringToSign = string.Join('\n',
            Algorithm,
            amzDate,
            scope,
            Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest))));
        byte[] signingKey = DeriveSigningKey(material.SigningSecret, date, region, "s3");
        string signature = Hex(HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(stringToSign)));
        CryptographicOperations.ZeroMemory(signingKey);

        request.SetHeader(
            "Authorization",
            $"{Algorithm} Credential={material.AccessKeyId}/{scope}, "
                + $"SignedHeaders={signedHeaders}, Signature={signature}");
    }

    internal static string ResolveRegion(Uri uri)
    {
        var host = uri.IdnHost;
        if (host.Equals("s3.wasabisys.com", StringComparison.OrdinalIgnoreCase)
            || host.Equals("s3.amazonaws.com", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".s3.amazonaws.com", StringComparison.OrdinalIgnoreCase))
        {
            return "us-east-1";
        }

        foreach (string marker in new[] { ".s3.", "s3." })
        {
            int index = host.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                continue;
            }

            int start = index + marker.Length;
            string suffix = host[start..];
            int end = suffix.IndexOf('.');
            if (end > 0)
            {
                string region = suffix[..end];
                if (region.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-'))
                {
                    return region;
                }
            }
        }

        // A destination this signer cannot derive a reviewed region for is not a signing failure
        // the caller can remedy; it is an unsupported destination, and it fails before any
        // signature is produced.
        throw new UnsupportedAuthenticationStrategyException(
            $"AWS SigV4 S3 signing cannot derive a reviewed region from host '{host}'.");
    }

    private static (string Name, string Value)[] CanonicalHeaders(SignableRequest request)
    {
        var headers = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (var (name, values) in request.Headers)
        {
            if (ExcludedHeaders.Contains(name))
            {
                continue;
            }

            headers[name.ToLowerInvariant()] = [.. values];
        }

        return
        [
            .. headers.Select(item =>
                (item.Key, string.Join(',', item.Value.Select(NormalizeHeaderValue)))),
        ];
    }

    private static string NormalizeHeaderValue(string value)
        => string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static string CanonicalPath(Uri uri)
    {
        string escaped = uri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
        if (string.IsNullOrEmpty(escaped))
        {
            return "/";
        }

        return "/" + string.Join('/', escaped.Split('/', StringSplitOptions.None)
            .Select(segment => AwsEncode(Uri.UnescapeDataString(segment))));
    }

    private static string CanonicalQuery(Uri uri)
    {
        if (string.IsNullOrEmpty(uri.Query))
        {
            return string.Empty;
        }

        return string.Join('&', uri.Query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part =>
            {
                int separator = part.IndexOf('=', StringComparison.Ordinal);
                string name = separator < 0 ? part : part[..separator];
                string value = separator < 0 ? string.Empty : part[(separator + 1)..];
                return (
                    Name: AwsEncode(Uri.UnescapeDataString(name)),
                    Value: AwsEncode(Uri.UnescapeDataString(value)));
            })
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Value, StringComparer.Ordinal)
            .Select(item => $"{item.Name}={item.Value}"));
    }

    private static string AwsEncode(string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        var builder = new StringBuilder(bytes.Length * 3);
        foreach (byte b in bytes)
        {
            char ch = (char)b;
            if ((ch >= 'A' && ch <= 'Z')
                || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9')
                || ch is '-' or '_' or '.' or '~')
            {
                builder.Append(ch);
            }
            else
            {
                builder.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return builder.ToString();
    }

    private static byte[] DeriveSigningKey(string secret, string date, string region, string service)
    {
        byte[] dateKey = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes("AWS4" + secret),
            Encoding.UTF8.GetBytes(date));
        byte[] regionKey = HMACSHA256.HashData(dateKey, Encoding.UTF8.GetBytes(region));
        byte[] serviceKey = HMACSHA256.HashData(regionKey, Encoding.UTF8.GetBytes(service));
        return HMACSHA256.HashData(serviceKey, Encoding.UTF8.GetBytes("aws4_request"));
    }

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
