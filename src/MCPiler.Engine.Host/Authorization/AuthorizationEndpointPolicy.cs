namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// The one trust-endpoint scheme rule shared by host binding, discovery preflight and runtime
/// endpoint resolution.
/// </summary>
internal static class AuthorizationEndpointPolicy
{
    /// <summary>
    /// HTTPS is required unless the endpoint is an HTTP loopback address owned by this host.
    /// </summary>
    internal static bool IsAllowed(Uri endpoint)
        => string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || string.Equals(endpoint.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) && endpoint.IsLoopback;
}
