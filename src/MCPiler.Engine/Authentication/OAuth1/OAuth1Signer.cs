using System.Security.Cryptography;
using System.Text;

namespace MCPiler.Engine.Authentication.OAuth1;

/// <summary>
/// OAuth 1.0a signature methods over an already-built signature base string. Secrets are
/// revealed only inside these methods at signing time; failure messages name the method,
/// never the material.
/// </summary>
internal static class OAuth1Signer
{
    /// <summary>RFC 5849 §3.4.2: base64(HMAC-SHA1(encoded secrets key, base string)).</summary>
    public static string SignHmacSha1(string signatureBaseString, string consumerSecret, string tokenSecret)
    {
        ArgumentNullException.ThrowIfNull(signatureBaseString);
        ArgumentNullException.ThrowIfNull(consumerSecret);
        ArgumentNullException.ThrowIfNull(tokenSecret);

        byte[] key = Encoding.UTF8.GetBytes(
            OAuth1Canonicalizer.Rfc3986Encode(consumerSecret)
            + "&"
            + OAuth1Canonicalizer.Rfc3986Encode(tokenSecret));
#pragma warning disable CA5350 // HMAC-SHA1 is mandated by the reviewed OAuth 1.0a compatibility profile.
        byte[] signature = HMACSHA1.HashData(key, Encoding.UTF8.GetBytes(signatureBaseString));
#pragma warning restore CA5350
        return Convert.ToBase64String(signature);
    }

    /// <summary>Reviewed HMAC-SHA256 extension: same construction with SHA-256.</summary>
    public static string SignHmacSha256(string signatureBaseString, string consumerSecret, string tokenSecret)
    {
        ArgumentNullException.ThrowIfNull(signatureBaseString);
        ArgumentNullException.ThrowIfNull(consumerSecret);
        ArgumentNullException.ThrowIfNull(tokenSecret);

        byte[] key = Encoding.UTF8.GetBytes(
            OAuth1Canonicalizer.Rfc3986Encode(consumerSecret)
            + "&"
            + OAuth1Canonicalizer.Rfc3986Encode(tokenSecret));
        return Convert.ToBase64String(
            HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(signatureBaseString)));
    }

    /// <summary>RFC 5849 §3.4.3: PKCS#1 v1.5 RSA-SHA1 over the base string, base64-encoded.</summary>
    public static string SignRsaSha1(string signatureBaseString, string privateKeyPem)
    {
        ArgumentNullException.ThrowIfNull(signatureBaseString);
        ArgumentNullException.ThrowIfNull(privateKeyPem);

        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
#pragma warning disable CA5350 // RSA-SHA1 is mandated by the reviewed OAuth 1.0a compatibility profile.
            byte[] signature = rsa.SignData(
                Encoding.UTF8.GetBytes(signatureBaseString),
                HashAlgorithmName.SHA1,
                RSASignaturePadding.Pkcs1);
#pragma warning restore CA5350
            return Convert.ToBase64String(signature);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            throw new InvalidOperationException("OAuth1 RSA-SHA1 signing failed: the stored private key is unusable.", ex);
        }
    }

    /// <summary>
    /// RFC 5849 §3.4.4: the encoded secret pair itself. This method provides no integrity
    /// protection; it stays available only as a reviewed compatibility option.
    /// </summary>
    public static string SignPlaintext(string consumerSecret, string tokenSecret)
    {
        ArgumentNullException.ThrowIfNull(consumerSecret);
        ArgumentNullException.ThrowIfNull(tokenSecret);

        return OAuth1Canonicalizer.Rfc3986Encode(consumerSecret)
            + "&"
            + OAuth1Canonicalizer.Rfc3986Encode(tokenSecret);
    }

    /// <summary>
    /// Dispatches closed method-specific material to its signature method. Unknown methods and
    /// material that does not belong to the method fail closed.
    /// </summary>
    public static string ComputeSignature(
        OAuth1SigningMaterial material,
        string signatureMethod,
        string signatureBaseString)
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(signatureBaseString);

        return (material, signatureMethod) switch
        {
            (OAuth1SigningMaterial.SharedSecretMaterial hmac, OAuth1Vocabulary.HmacSha1)
                => SignHmacSha1(signatureBaseString, hmac.ConsumerSecret, hmac.TokenSecret),
            (OAuth1SigningMaterial.SharedSecretMaterial hmac, OAuth1Vocabulary.HmacSha256)
                => SignHmacSha256(signatureBaseString, hmac.ConsumerSecret, hmac.TokenSecret),
            (OAuth1SigningMaterial.RsaMaterial rsa, OAuth1Vocabulary.RsaSha1)
                => SignRsaSha1(signatureBaseString, rsa.PrivateKeyPem),
            (OAuth1SigningMaterial.SharedSecretMaterial plaintext, OAuth1Vocabulary.Plaintext)
                => SignPlaintext(plaintext.ConsumerSecret, plaintext.TokenSecret),
            _ => throw new InvalidOperationException(
                $"OAuth1 signing refused: material shape '{material.GetType().Name}' does not match signature method '{signatureMethod}'."),
        };
    }
}
