namespace MCPiler.Engine.Execution;

/// <summary>
/// Raised when a destination is outside the governing allowed-origin set, either for the first
/// request or for a redirect target.
/// </summary>
/// <remarks>
/// A refused origin is never contacted. The message names the destination because an operator
/// diagnosing a perimeter needs to know which one was refused; it carries nothing else.
/// </remarks>
public sealed class OriginPolicyViolationException(Uri uri, string? detail = null)
    : Exception($"The request to '{uri}' is not allowed by the governing origin policy{(detail is null ? "." : ": " + detail)}")
{
    /// <summary>The destination that was refused.</summary>
    public Uri Uri { get; } = uri;
}

/// <summary>
/// Raised when a response claimed a redirect and named no destination.
/// </summary>
/// <remarks>
/// This is deliberately a separate type from an origin refusal rather than a flag on one. The
/// two share the property that no response comes back to compare, and nothing else: reporting a
/// malformed redirect as a policy refusal would tell an operator their allow-list rejected a
/// destination the upstream never stated.
/// </remarks>
public sealed class MalformedRedirectException(Uri uri)
    : Exception($"The response to '{uri}' carried a redirect status without a Location header.")
{
    /// <summary>The URI whose response was malformed.</summary>
    public Uri Uri { get; } = uri;
}

/// <summary>Raised when the redirect chain exceeds the governing hop limit.</summary>
public sealed class RedirectLimitException(int hopLimit)
    : Exception($"The request exceeded the configured redirect hop limit of {hopLimit}.")
{
    /// <summary>The limit that was exceeded.</summary>
    public int HopLimit { get; } = hopLimit;
}

/// <summary>Raised when a resolved destination address is refused by outbound containment.</summary>
/// <remarks>
/// The address is carried as text so this type stays usable from the host-free core. What
/// matters to a caller is which address was refused, not a parsed representation of it.
/// </remarks>
public sealed class AddressPolicyViolationException(string host, string address)
    : Exception($"Outbound connection to '{host}' resolved to denied address {address}.")
{
    /// <summary>The host as it was addressed.</summary>
    public string Host { get; } = host;

    /// <summary>The refused address.</summary>
    public string Address { get; } = address;
}

/// <summary>Raised when a host resolves to no usable address.</summary>
public sealed class HostResolutionException(string host, Exception? inner = null)
    : Exception($"Host '{host}' resolved to no usable address.", inner)
{
    /// <summary>The host that could not be resolved.</summary>
    public string Host { get; } = host;
}

/// <summary>
/// Raised when an exchange failed below the HTTP semantics the classification describes:
/// connection reset, TLS failure, protocol error.
/// </summary>
/// <remarks>
/// The adapter wraps every transport fault it does not recognize into this type rather than
/// letting a framework exception escape. That is what lets the classifier name a closed set of
/// Engine types and lets a test prove the set is complete: a catch-all over an open universe of
/// framework exceptions could not be shown to be a floor rather than the answer.
/// </remarks>
public sealed class UpstreamTransportException(string message, Exception? inner = null)
    : Exception(message, inner);

/// <summary>
/// Raised when a credential a request needs cannot be obtained or applied.
/// </summary>
/// <remarks>
/// The message names the reference kind and the reference name and never the resolved value,
/// the content of a referenced file, or any part of either. A diagnostic that leaked a fragment
/// of a secret in order to explain why it could not be read would defeat the reason the
/// reference exists.
/// </remarks>
public sealed class CredentialUnavailableException(string credentialId, string message)
    : Exception($"Credential '{credentialId}': {message}")
{
    /// <summary>The credential slot that could not be resolved or applied.</summary>
    public string CredentialId { get; } = credentialId;
}

/// <summary>
/// Raised when the file runtime refuses to take a payload: too large, a media type that
/// contradicts the content signature under a rejecting policy, a blocking scan verdict, or an
/// unusable store.
/// </summary>
public sealed class FileRuntimeException(string message, Exception? inner = null)
    : Exception(message, inner);
