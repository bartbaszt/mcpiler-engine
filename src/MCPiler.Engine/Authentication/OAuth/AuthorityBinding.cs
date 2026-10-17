using System.Security.Cryptography;
using System.Text;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.OAuth;

/// <summary>
/// The non-secret identities a committed local authority decision is bound to.
/// </summary>
/// <remarks>
/// <para>
/// A durable authorized successor is minted for one exact declaration and one exact validated
/// configuration. If either changes, the successor is stale: the provider that issued it was
/// reached through a different client identity, scope set or token endpoint than the deployment
/// now declares, so reusing it would present a credential to a destination it was never minted
/// for. The fingerprints are the compare tokens that make that binding checkable without storing
/// any secret.
/// </para>
/// <para>
/// Both the writer (an authorize operation) and the reader (token acquisition) compute these
/// from the same place, so the two sides cannot disagree about what "the same declaration"
/// means. The values are opaque, non-secret digests; they carry no credential material and are
/// safe to persist in the authenticated authority record.
/// </para>
/// </remarks>
public static class AuthorityBinding
{
    /// <summary>
    /// Binds the declaration the credential was minted under: the profile identity, its strategy
    /// kind and its scope fingerprint. A different declaration cannot consume the successor.
    /// </summary>
    public static string Declaration(AuthenticationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var material = string.Join('\u001f',
            "authority-declaration-v1",
            profile.Id,
            profile.Kind.ToString(),
            profile.ScopeFingerprint ?? string.Empty);

        return Digest(material);
    }

    /// <summary>
    /// Binds the validated OAuth configuration the credential was minted under: the client, the
    /// endpoints, and the scope/resource/audience projection. A changed client or endpoint must
    /// not silently consume a successor obtained under the previous configuration.
    /// </summary>
    public static string Configuration(OAuthStrategyConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var material = string.Join('\u001f',
            "authority-configuration-v1",
            configuration.ClientId,
            configuration.TokenEndpoint.AbsoluteUri,
            configuration.AuthorizationEndpoint?.AbsoluteUri ?? string.Empty,
            configuration.RevocationEndpoint?.AbsoluteUri ?? string.Empty,
            configuration.TokenAuthMethod,
            configuration.ScopeResourceKey);

        return Digest(material);
    }

    private static string Digest(string material)
        => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
}
