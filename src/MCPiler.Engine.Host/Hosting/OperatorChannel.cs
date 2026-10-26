using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// The transport rule every Engine operator channel applies to a request.
/// </summary>
/// <remarks>
/// <para>
/// HTTPS is required unless the request genuinely originates on loopback. The scheme the caller
/// passes is read after the forwarded-headers middleware, which only honours headers from configured
/// proxies, so a remote client cannot present <c>X-Forwarded-Proto: https</c> and be believed unless
/// the operator already trusted the address that set it.
/// </para>
/// <para>
/// Shared by both operator channels rather than restated in each, because two answers to "may a
/// credential travel on this request" is exactly the drift a second copy would produce.
/// </para>
/// </remarks>
internal static class OperatorChannel
{
    /// <summary>
    /// Whether an operator channel may be used over a request observed as
    /// <paramref name="isHttps"/> from <paramref name="remote"/>.
    /// </summary>
    internal static bool IsTransportAcceptable(bool isHttps, IPAddress? remote)
        => isHttps || (remote is not null && IPAddress.IsLoopback(remote));

    /// <summary>
    /// Whether an operator credential may be sent to <paramref name="endpoint"/> at all.
    /// </summary>
    /// <remarks>
    /// The client half of the same rule: HTTPS, or a loopback address where the traffic never leaves
    /// this machine. Without it a client configured with a remote <c>http</c> endpoint would send the
    /// operator secret in cleartext to a server that only refuses it after it has already arrived.
    /// Both halves read the rule from here rather than restating it, because two answers to "may this
    /// credential travel on this connection" is exactly the drift a second copy would produce.
    /// </remarks>
    internal static bool IsEndpointTransportAcceptable(Uri endpoint)
        => endpoint.Scheme == Uri.UriSchemeHttps || endpoint.IsLoopback;
}

/// <summary>
/// Compares a presented bearer value against one configured operator secret.
/// </summary>
/// <remarks>
/// <para>
/// The comparison hashes both sides before comparing, so it is fixed-time with respect to content
/// and does not disclose the secret's length through the comparison. A presented value is never
/// written to a log or a response by this type or by any caller of it.
/// </para>
/// <para>
/// One instance per channel per process. The secret is already resident because startup read and
/// kept it; copying it per request would put a second copy of a live credential in memory for the
/// lifetime of the request.
/// </para>
/// </remarks>
internal sealed class OperatorChannelCredential
{
    /// <summary>The scheme an operator credential is presented under.</summary>
    internal const string Scheme = "Bearer";

    private readonly byte[] _expected;

    /// <summary>Hashes the configured secret once.</summary>
    /// <param name="secret">The operator secret, already read and non-empty.</param>
    internal OperatorChannelCredential(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        _expected = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        Fingerprint = Convert.ToHexString(_expected);
    }

    /// <summary>Whether the request presents exactly this credential.</summary>
    /// <param name="request">The request whose <c>Authorization</c> header is read.</param>
    internal bool IsAuthorized(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        string? header = request.Headers.Authorization;

        if (string.IsNullOrEmpty(header)
            || !header.StartsWith(Scheme + " ", StringComparison.Ordinal))
        {
            return false;
        }

        string presented = header[(Scheme.Length + 1)..].Trim();

        if (presented.Length == 0)
        {
            return false;
        }

        byte[] candidate = SHA256.HashData(Encoding.UTF8.GetBytes(presented));
        return CryptographicOperations.FixedTimeEquals(_expected, candidate);
    }

    /// <summary>
    /// A stable, non-secret identity for the configured credential, so a bound operation can be tied
    /// to the credential that started it without keeping a second copy of the credential.
    /// </summary>
    /// <remarks>
    /// It is the same digest the comparison already computes, rendered as hex. It is not reversible
    /// into the secret, and it is never rendered in a response: it exists so an operation opened by
    /// one operator credential cannot be completed by a different one.
    /// </remarks>
    internal string Fingerprint { get; }
}
