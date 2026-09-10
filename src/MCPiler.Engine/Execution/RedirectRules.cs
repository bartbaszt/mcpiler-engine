namespace MCPiler.Engine.Execution;

/// <summary>
/// What a redirect means: which statuses are redirects, what method and body the next request
/// carries, which headers must not cross an origin, and whether two destinations share one.
/// </summary>
/// <remarks>
/// <para>
/// These are the decisions a redirect chain is made of, and they are stated here — with no
/// transport in reach — rather than inside the component that owns the socket. A rule expressed
/// over a status code and a method name is checkable by itself; the same rule expressed over a
/// live exchange is only observable by performing one.
/// </para>
/// <para>
/// Statuses and methods are an integer and a string rather than transport types on purpose. The
/// numbers are the wire contract, and depending on a transport's spelling of them would move
/// this file into the layer it exists to stay out of.
/// </para>
/// </remarks>
public static class RedirectRules
{
    /// <summary>
    /// Headers that are credential-bearing whatever a contract says, and therefore never
    /// replayed to a different origin.
    /// </summary>
    public static IReadOnlyList<string> AlwaysSensitiveHeaders { get; } =
    [
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
    ];

    /// <summary>The header that must never survive a redirect, because it names the old target.</summary>
    public const string HostHeader = "Host";

    /// <summary>True when <paramref name="statusCode"/> is a redirect this path follows.</summary>
    public static bool IsRedirect(int statusCode)
        => statusCode is 301 or 302 or 303 or 307 or 308;

    /// <summary>
    /// The method and body disposition of the request that follows
    /// <paramref name="statusCode"/> from a request that used <paramref name="currentMethod"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// 303 rewrites to GET except from HEAD, which stays HEAD: the point of 303 is "fetch the
    /// result elsewhere", and turning a metadata request into a body request would fetch more
    /// than was asked for.
    /// </para>
    /// <para>
    /// 301 and 302 rewrite POST to GET, which is what every deployed client does and what the
    /// upstream expects; 307 and 308 exist precisely to say "do not". Every other case preserves
    /// the method, and preserving the method means preserving the body.
    /// </para>
    /// </remarks>
    public static (string Method, bool PreserveBody) NextRequest(int statusCode, string currentMethod)
    {
        ArgumentException.ThrowIfNullOrEmpty(currentMethod);

        if (statusCode == 303)
        {
            return IsMethod(currentMethod, "HEAD") ? ("HEAD", false) : ("GET", false);
        }

        if (statusCode is 301 or 302 && IsMethod(currentMethod, "POST"))
        {
            return ("GET", false);
        }

        return (currentMethod, true);
    }

    /// <summary>
    /// True when a header of <paramref name="headerName"/> must be dropped when following a
    /// redirect from <paramref name="sameOrigin"/>.
    /// </summary>
    /// <param name="headerName">The header name as it was sent.</param>
    /// <param name="sameOrigin">Whether the redirect target shares the current origin.</param>
    /// <param name="sensitiveHeaders">
    /// Header names the contract marked credential-bearing, in addition to
    /// <see cref="AlwaysSensitiveHeaders"/>.
    /// </param>
    /// <remarks>
    /// <see cref="HostHeader"/> is dropped unconditionally: it names the destination of the
    /// request that has already been answered, and carrying it forward would address the new
    /// destination under the old name.
    /// </remarks>
    public static bool IsDroppedOnRedirect(
        string headerName,
        bool sameOrigin,
        IReadOnlyCollection<string> sensitiveHeaders)
    {
        ArgumentException.ThrowIfNullOrEmpty(headerName);
        ArgumentNullException.ThrowIfNull(sensitiveHeaders);

        if (string.Equals(headerName, HostHeader, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (sameOrigin)
        {
            return false;
        }

        return IsSensitive(headerName, sensitiveHeaders);
    }

    /// <summary>
    /// True when <paramref name="headerName"/> is credential-bearing, either unconditionally or
    /// because the contract said so.
    /// </summary>
    /// <remarks>
    /// Comparison is by whole name and case-insensitive. A name that merely contains a
    /// sensitive one — <c>X-Authorization-Scheme</c> — is a different header, and treating it as
    /// sensitive would silently strip something a same-origin contract depends on while
    /// suggesting a protection that was never asked for.
    /// </remarks>
    public static bool IsSensitive(string headerName, IReadOnlyCollection<string> sensitiveHeaders)
    {
        ArgumentException.ThrowIfNullOrEmpty(headerName);
        ArgumentNullException.ThrowIfNull(sensitiveHeaders);

        foreach (var known in AlwaysSensitiveHeaders)
        {
            if (string.Equals(headerName, known, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        foreach (var declared in sensitiveHeaders)
        {
            if (string.Equals(headerName, declared, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when <paramref name="left"/> and <paramref name="right"/> are the same origin:
    /// scheme, ASCII host and effective port.
    /// </summary>
    /// <remarks>
    /// The ASCII host is compared rather than the authored one, so an internationalized name and
    /// its punycode form are one origin. This is the same normalization the allow-list applies,
    /// for the same reason: two spellings of one destination must not be two answers.
    /// </remarks>
    public static bool IsSameOrigin(Uri left, Uri right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        return string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase)
            && left.Port == right.Port;
    }

    /// <summary>
    /// The absolute destination a <c>Location</c> value denotes, relative to the request it
    /// answered.
    /// </summary>
    /// <remarks>
    /// A relative <c>Location</c> is legal and common. Resolving it against the current request
    /// is what makes the perimeter check meaningful: the check is on the absolute destination,
    /// and a relative value that resolves outside the perimeter must be refused rather than
    /// treated as local by virtue of its spelling.
    /// </remarks>
    public static Uri ResolveLocation(Uri current, Uri location)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(location);

        return location.IsAbsoluteUri ? location : new Uri(current, location);
    }

    private static bool IsMethod(string candidate, string method)
        => string.Equals(candidate, method, StringComparison.OrdinalIgnoreCase);
}
