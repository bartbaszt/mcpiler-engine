namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// Renders one address for an operator-facing report as its origin alone.
/// </summary>
/// <remarks>
/// <para>
/// Every address the readiness report shows is either operator-configured or published by an
/// untrusted issuer document. A URL's userinfo, path, query and fragment can each carry a
/// credential, an access token or an operator-specific secret, so no part of the spelling beyond
/// the origin - scheme, host and port - is ever echoed. The withheld parts are named as fixed
/// categories, which stays diagnostic: an operator can see that a configured issuer carries
/// credentials or a query string without the report printing either one.
/// </para>
/// <para>
/// A value that is not an absolute URI is not echoed at all. Printing it "as-is" would reintroduce
/// exactly the leak this type exists to prevent, and a value that cannot be parsed as a URL cannot
/// be classified into safe parts.
/// </para>
/// </remarks>
internal static class SafeUriDisplay
{
    /// <summary>The fixed phrase shown in place of a value that is not an absolute URI.</summary>
    internal const string UnparsableAddress = "(a value that is not an absolute URL)";

    /// <summary>
    /// Renders one address that was received as text, such as a configuration setting or a member
    /// of an untrusted metadata document.
    /// </summary>
    internal static string Origin(string address)
        => Uri.TryCreate(address, UriKind.Absolute, out Uri? parsed)
            ? Origin(parsed)
            : UnparsableAddress;

    /// <summary>Renders one already-parsed address.</summary>
    internal static string Origin(Uri address)
    {
        ArgumentNullException.ThrowIfNull(address);

        string origin = address.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped);

        List<string> withheld = [];

        if (address.UserInfo.Length > 0)
        {
            withheld.Add("credentials");
        }

        if (address.AbsolutePath.Length > 1)
        {
            withheld.Add("path");
        }

        if (address.Query.Length > 0)
        {
            withheld.Add("query");
        }

        if (address.Fragment.Length > 0)
        {
            withheld.Add("fragment");
        }

        return withheld.Count == 0
            ? origin
            : $"{origin} [{string.Join(", ", withheld)} withheld]";
    }
}
