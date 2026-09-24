namespace MCPiler.Engine.Authentication.OAuth1;

/// <summary>
/// Closed method-specific OAuth 1.0a signer material, resolved from the manifest-declared
/// credentials a profile references. A signer receives exactly the slots its method requires;
/// nothing here travels through the generic one-key-id/one-secret request-signing shape.
/// </summary>
public abstract record OAuth1SigningMaterial
{
    /// <summary>The non-secret consumer key.</summary>
    public required string ConsumerKey { get; init; }

    /// <summary>The token identifier, treated as sensitive throughout resolution.</summary>
    public required string Token { get; init; }

    private OAuth1SigningMaterial()
    {
    }

    /// <summary>HMAC and PLAINTEXT material: consumer and token secrets.</summary>
    public sealed record SharedSecretMaterial : OAuth1SigningMaterial
    {
        /// <summary>The consumer secret.</summary>
        public required string ConsumerSecret { get; init; }

        /// <summary>The token secret.</summary>
        public required string TokenSecret { get; init; }
    }

    /// <summary>RSA-SHA1 material: private-key content instead of shared secrets.</summary>
    public sealed record RsaMaterial : OAuth1SigningMaterial
    {
        /// <summary>The RSA private key in PEM form.</summary>
        public required string PrivateKeyPem { get; init; }
    }
}
