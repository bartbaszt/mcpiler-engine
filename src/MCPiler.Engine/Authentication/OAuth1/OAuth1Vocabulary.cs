namespace MCPiler.Engine.Authentication.OAuth1;

/// <summary>
/// The closed OAuth 1.0a runtime vocabulary: reviewed signature methods, protocol-parameter
/// transports, and credential slots. Engine is the authority for what it can execute, so the
/// lists are stated here rather than inferred from what a manifest happens to declare.
/// </summary>
internal static class OAuth1Vocabulary
{
    public const string HmacSha1 = "HMAC-SHA1";
    public const string RsaSha1 = "RSA-SHA1";
    public const string Plaintext = "PLAINTEXT";
    public const string HmacSha256 = "HMAC-SHA256";

    public static readonly string[] SignatureMethods = [HmacSha1, RsaSha1, Plaintext, HmacSha256];

    public const string AuthorizationHeaderTransport = "authorization-header";
    public const string QueryTransport = "query";
    public const string FormBodyTransport = "form-body";

    public static readonly string[] ParameterTransports =
        [AuthorizationHeaderTransport, QueryTransport, FormBodyTransport];

    public static readonly string[] SensitiveProtocolParameters =
    [
        "oauth_consumer_key",
        "oauth_token",
        "oauth_signature_method",
        "oauth_timestamp",
        "oauth_nonce",
        "oauth_version",
        "oauth_signature",
    ];

    public const string ConsumerSecretSlot = "consumerSecret";
    public const string RsaPrivateKeySlot = "rsaPrivateKey";
    public const string TokenSlot = "oauthToken";
    public const string TokenSecretSlot = "oauthTokenSecret";

    public static readonly string[] CredentialSlots =
        [ConsumerSecretSlot, RsaPrivateKeySlot, TokenSlot, TokenSecretSlot];

    /// <summary>
    /// The exact credential slots a signature method requires. HMAC and PLAINTEXT signing
    /// receive the consumer and token secrets; RSA-SHA1 receives the private key instead and
    /// never an unrelated secret merely to fit an older material shape.
    /// </summary>
    public static bool TryGetRequiredSlots(string? signatureMethod, out string[] slots)
    {
        slots = signatureMethod switch
        {
            HmacSha1 or HmacSha256 or Plaintext => [ConsumerSecretSlot, TokenSlot, TokenSecretSlot],
            RsaSha1 => [RsaPrivateKeySlot, TokenSlot],
            _ => [],
        };
        return slots.Length > 0;
    }
}
