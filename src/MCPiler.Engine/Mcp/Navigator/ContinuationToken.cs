using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Canonical;

namespace MCPiler.Engine.Mcp.Navigator;

/// <summary>
/// The opaque token that continues one ranked page into the next.
/// </summary>
/// <remarks>
/// <para>
/// A position and the identity of the list it is a position in. The position alone would be
/// enough to page correctly only for a caller that repeats the query exactly; handed back with
/// a different query it would address an offset into a list that was never computed, and the
/// caller would receive results that skip some operations and repeat others with nothing
/// saying so. Carrying the identity turns "no duplication and no skipping" from an expectation
/// about caller behaviour into something this code enforces.
/// </para>
/// <para>
    /// The identity covers the query, the surface, the index fingerprint and the query vector,
    /// so a token issued on one surface is not redeemable on another, one issued against a
    /// Manifest is not redeemable after it changes, and one issued against a vector-assisted
    /// ranking is not redeemable against a lexical-only one. It is a digest, so the token
    /// discloses none of the four.
    /// </para>
/// <para>
/// Opaque to a caller and not encrypted: the honest claim is that a caller must not read or
/// construct one, not that it cannot. Everything inside is already something the caller
/// supplied or a digest of what it just queried, so there is nothing here to keep from it.
/// </para>
/// </remarks>
internal static class ContinuationToken
{
    /// <summary>How much of the identity digest travels in a token.</summary>
    /// <remarks>
    /// Sixty-four bits of a SHA-256 digest. Enough that two live pagings colliding is not a
    /// thing that happens, and short enough that the token stays a token rather than a
    /// paragraph. A collision costs a caller a wrong page, not a disclosure.
    /// </remarks>
    private const int IdentityLength = 16;

    /// <summary>The version marker every token carries.</summary>
    /// <remarks>
    /// So that a token issued by a build whose encoding differs is rejected rather than
    /// silently misread as an offset.
    /// </remarks>
    private const string Version = "v1";

    private const char Separator = ':';

    /// <summary>Digests the list a position refers to.</summary>
    /// <param name="query">The query text, absent or empty meaning "everything".</param>
    /// <param name="surface">The surface slug whose exposure table filtered the ranking.</param>
    /// <param name="index">The fingerprint of the index that was ranked.</param>
    /// <param name="vector">
    /// A digest of the query vector the ranking used, or <c>null</c> when it used none. Two
    /// rankings of one query that differ in their semantic half are two lists, and a position
    /// in one is not a position in the other.
    /// </param>
    internal static string Identify(string? query, string surface, string index, string? vector)
        => CanonicalJson.Hash(new JsonObject
        {
            ["query"] = query ?? string.Empty,
            ["surface"] = surface,
            ["index"] = index,
            ["vector"] = vector,
        })[..IdentityLength];

    /// <summary>Issues a token for the next position in an identified list.</summary>
    internal static string Issue(int offset, string identity)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Create(
                CultureInfo.InvariantCulture,
                $"{Version}{Separator}{offset}{Separator}{identity}")))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    /// <summary>
    /// Reads a token back, refusing one that does not belong to this list.
    /// </summary>
    /// <param name="token">The token a caller returned.</param>
    /// <param name="identity">The identity of the list being paged now.</param>
    /// <param name="offset">The position to resume from.</param>
    /// <returns>Whether the token is usable.</returns>
    internal static bool TryRedeem(string token, string identity, out int offset)
    {
        offset = 0;

        string decoded;

        try
        {
            string padded = token.Replace('-', '+').Replace('_', '/');
            padded += (padded.Length % 4) switch
            {
                2 => "==",
                3 => "=",
                _ => string.Empty,
            };

            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
        }
        catch (Exception failure) when (failure is FormatException or DecoderFallbackException)
        {
            return false;
        }

        string[] parts = decoded.Split(Separator);

        if (parts.Length != 3
            || !string.Equals(parts[0], Version, StringComparison.Ordinal)
            || !string.Equals(parts[2], identity, StringComparison.Ordinal))
        {
            return false;
        }

        // A negative position would index backwards into a list the caller has already been
        // given, which is the duplication this token exists to prevent.
        return int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out offset)
            && offset >= 0;
    }
}
