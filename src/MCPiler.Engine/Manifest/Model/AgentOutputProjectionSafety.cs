namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The unconditional hard-denied response-header set of the output-projection mechanisms.
/// </summary>
/// <remarks>
/// <para>
/// This is a deliberate mirror of the Platform authoring-time validator: Engine must build and
/// run from a standalone checkout, so the constant is declared here rather than referenced from
/// the Platform. The two copies are kept in step by the shared response-projection corpus and
/// the Manifest parity tests.
/// </para>
/// <para>
/// The set is unconditional by design. An operator selects a source explicitly, but a selected
/// credential, cookie or authentication-challenge header is never agent-visible, and no
/// projection or pagination policy may override that.
/// </para>
/// </remarks>
public static class AgentOutputProjectionSafety
{
    /// <summary>
    /// The hard-denied header names, canonical lower-case ASCII, ordinal.
    /// </summary>
    public static readonly IReadOnlySet<string> HardDeniedHeaders =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "set-cookie2",
            "www-authenticate",
            "proxy-authenticate",
            "authentication-info",
            "proxy-authentication-info",
        };

    /// <summary>True when the canonical header name is hard-denied.</summary>
    public static bool IsHardDenied(string canonicalName)
        => HardDeniedHeaders.Contains(canonicalName);
}
