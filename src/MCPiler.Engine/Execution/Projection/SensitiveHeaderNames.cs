using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution.Projection;

/// <summary>
/// The response headers a connector's own configuration classifies as credential-bearing.
/// </summary>
/// <remarks>
/// <para>
/// The hard-denied set covers the well-known families unconditionally. This adds the
/// connector-specific half: a credential the reviewed Manifest places in a header or cookie is
/// sensitive in that connector, whatever its name, and a projection referencing it is refused
/// exactly as if it had named <c>Authorization</c>.
/// </para>
/// <para>
/// The classification is derived from the same declaration the redirect rules use, so a header
/// that must not survive a redirect cannot become agent-visible either. A connector that reuses
/// a well-known slot widens the set rather than narrowing it: both halves are unioned.
/// </para>
/// </remarks>
internal static class SensitiveHeaderNames
{
    /// <summary>The canonical names implied by a resolved credential set.</summary>
    internal static IReadOnlySet<string> For(IReadOnlyList<ResolvedCredential> credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (ResolvedCredential credential in credentials)
        {
            ManifestCredential declaration = credential.Declaration;

            if (!declaration.IsRedirectSensitiveHeader)
            {
                continue;
            }

            names.Add(declaration.EffectiveLocation switch
            {
                CredentialLocation.Header => Canonical(declaration.Slot),

                // A basic or bearer credential reaches the wire through the Authorization
                // header whatever its slot is called, and a cookie credential's slot is not a
                // response header name at all, so the well-known name is the sensitive fact.
                CredentialLocation.Cookie => "cookie",
                _ => "authorization",
            });
        }

        return names;
    }

    private static string Canonical(string name) => name.Trim().ToLowerInvariant();
}
