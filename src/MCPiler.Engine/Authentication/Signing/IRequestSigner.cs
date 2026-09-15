using System.Security.Cryptography;

namespace MCPiler.Engine.Authentication.Signing;

/// <summary>
/// One signing attempt: the timestamp and nonce a reviewed signer binds into its signature.
/// </summary>
/// <remarks>
/// Carried as a value rather than read from a clock inside a signer so that a redirect chain can
/// reuse one attempt for its first hop and a deterministic test can pin the exact input. The
/// nonce exists for signers whose protocol requires a salt (Subsonic) or replay marker.
/// </remarks>
/// <param name="TimestampUtc">The instant the attempt was created.</param>
/// <param name="Nonce">A lower-case hexadecimal nonce.</param>
public sealed record RequestSigningAttempt(DateTimeOffset TimestampUtc, string Nonce)
{
    /// <summary>Creates an attempt from the supplied clock and a fresh 8-byte nonce.</summary>
    public static RequestSigningAttempt Create(TimeProvider timeProvider)
        => new(
            timeProvider.GetUtcNow(),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant());
}

/// <summary>The non-secret key identity and the secret material a signer consumes.</summary>
/// <param name="StrategyId">The reviewed signer kind.</param>
/// <param name="AccessKeyId">The public key identifier, supplied by manifest configuration.</param>
/// <param name="SigningSecret">The resolved secret. Never rendered into a diagnostic.</param>
public sealed record RequestSigningMaterial(string StrategyId, string AccessKeyId, string SigningSecret);

/// <summary>
/// One reviewed request signer over the transport-neutral request model.
/// </summary>
/// <remarks>
/// The signature of this interface is deliberately <see cref="SignableRequest"/> rather than a
/// framework request object. The reviewed signers are protocol cryptography — canonicalization,
/// HMAC, digest — and none of it needs a socket, a client or a framework type. Keeping them on a
/// host-free model is what lets the whole signing path be exercised against a substitute that
/// opens nothing.
/// </remarks>
public interface IRequestSigner
{
    /// <summary>The reviewed signer kind this instance implements.</summary>
    string StrategyId { get; }

    /// <summary>Header names this signer writes that a cross-origin redirect must not replay.</summary>
    IReadOnlySet<string> SensitiveHeaders { get; }

    /// <summary>Query parameter names this signer writes that a diagnostic must not echo.</summary>
    IReadOnlySet<string> SensitiveQueryParameters { get; }

    /// <summary>Signs <paramref name="request"/> in place.</summary>
    ValueTask SignAsync(
        SignableRequest request,
        RequestSigningMaterial material,
        RequestSigningAttempt attempt,
        CancellationToken cancellationToken);
}
