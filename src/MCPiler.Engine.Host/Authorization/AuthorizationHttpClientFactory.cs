using System.Net;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// Creates the HTTP client used for authorization trust traffic.
/// </summary>
/// <remarks>
/// Authorization endpoint policy is evaluated before a URI is used. Following a redirect here
/// would make that check apply only to the first hop, so every trust client deliberately refuses
/// redirects instead of allowing an issuer to widen its effective destination. Plain HTTP is only
/// allowed for loopback destinations, so those requests also bypass the ambient proxy. Otherwise a
/// system proxy could become the effective plaintext destination after the URI policy accepted it.
/// </remarks>
internal static class AuthorizationHttpClientFactory
{
    internal static HttpClient Create(TimeSpan timeout, IWebProxy? proxy = null)
    {
        HttpClientHandler handler = new()
        {
            AllowAutoRedirect = false,
            // Keep the existing system/default proxy behavior for HTTPS trust endpoints, but make
            // the loopback HTTP exception an actual direct connection. The optional argument is a
            // deterministic test seam; production callers use HttpClient.DefaultProxy.
            UseProxy = true,
            Proxy = new LoopbackHttpProxy(proxy ?? HttpClient.DefaultProxy),
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = timeout,
        };
    }

    private sealed class LoopbackHttpProxy(IWebProxy? inner) : IWebProxy
    {
        public ICredentials? Credentials
        {
            get => inner?.Credentials;
            set
            {
                if (inner is not null)
                {
                    inner.Credentials = value;
                }
            }
        }

        public Uri GetProxy(Uri destination)
        {
            ArgumentNullException.ThrowIfNull(destination);
            return IsDirectLoopbackHttp(destination) || inner is null
                ? destination
                : inner.GetProxy(destination) ?? destination;
        }

        public bool IsBypassed(Uri host)
        {
            ArgumentNullException.ThrowIfNull(host);
            return IsDirectLoopbackHttp(host) || inner is null || inner.IsBypassed(host);
        }

        private static bool IsDirectLoopbackHttp(Uri destination)
            => destination.IsLoopback
                && string.Equals(destination.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
    }
}
