using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.OAuth;

/// <summary>
/// The runtime shape of an OAuth strategy profile: the non-secret configuration a manifest
/// already validated, projected into the values the token client needs.
/// </summary>
/// <remarks>
/// <para>
/// The manifest reader is the validation authority for this configuration. It admits only
/// closed member sets, bounded endpoints and bounded values, so this projection re-states
/// what execution consumes rather than re-validating the document. Where a value is absent
/// the documented default applies.
/// </para>
/// <para>
/// Unlike the Platform authoring record this type carries no connector, profile or status
/// identity: a manifest profile is the whole scope, and a bearer token acquired under it is
/// keyed by the manifest-local identity plus the non-secret scope key below.
/// </para>
/// </remarks>
public sealed record OAuthStrategyConfiguration
{
    /// <summary>Where the token endpoint lives. Required.</summary>
    public required Uri TokenEndpoint { get; init; }

    /// <summary>The browser authorization endpoint; present for the authorization-code kind.</summary>
    public Uri? AuthorizationEndpoint { get; init; }

    /// <summary>The optional revocation endpoint.</summary>
    public Uri? RevocationEndpoint { get; init; }

    /// <summary>The public client identity.</summary>
    public required string ClientId { get; init; }

    /// <summary>Requested scopes, distinct and ordinally ordered.</summary>
    public IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>The optional RFC 8707 resource indicator.</summary>
    public string? Resource { get; init; }

    /// <summary>The optional audience parameter.</summary>
    public string? Audience { get; init; }

    /// <summary>
    /// How the client authenticates at the token and revocation endpoints:
    /// <c>client_secret_post</c>, <c>client_secret_basic</c> or <c>none</c>.
    /// </summary>
    public string TokenAuthMethod { get; init; } = "client_secret_post";

    /// <summary>The safety skew subtracted from a token's lifetime before reacquisition.</summary>
    public TimeSpan AccessTokenSafetySkew { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Extra authorization-request parameters the profile declares.</summary>
    public IReadOnlyDictionary<string, string> AuthorizationParameters { get; init; }
        = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// The non-secret identity of what a token is for: scopes and audience, independent of any
    /// token value. Two acquisitions for different scopes cannot share a cache entry, and a
    /// token acquired for one scope can never be presented for another.
    /// </summary>
    public string ScopeResourceKey
    {
        get
        {
            var material = string.Join('\n',
                string.Join('\u001f', Scopes.OrderBy(value => value, StringComparer.Ordinal)),
                Resource ?? string.Empty,
                Audience ?? string.Empty);
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
        }
    }

    /// <summary>Projects the already-validated configuration object.</summary>
    /// <param name="configuration">The profile's closed configuration object.</param>
    /// <param name="authorizationCodeRequired">Whether the kind is authorization-code.</param>
    public static OAuthStrategyConfiguration FromConfiguration(
        JsonObject configuration,
        bool authorizationCodeRequired)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var clientId = ReadString(configuration, "clientId")
            ?? ReadInput(configuration, "clientId")
            ?? throw Invalid("OAuth client id is missing.");

        var tokenEndpoint = ParseEndpoint(
            ReadString(configuration, "tokenEndpoint") ?? throw Invalid("OAuth token endpoint is missing."),
            "token endpoint");
        var authorizationEndpoint = ReadString(configuration, "authorizationEndpoint") is { } authorization
            ? ParseEndpoint(authorization, "authorization endpoint")
            : null;
        if (authorizationCodeRequired && authorizationEndpoint is null)
        {
            throw Invalid("OAuth authorization endpoint is required for authorization-code authentication.");
        }

        var revocationEndpoint = ReadString(configuration, "revocationEndpoint") is { } revocation
            ? ParseEndpoint(revocation, "revocation endpoint")
            : null;

        var scopes = ReadStringArray(configuration, "scopes")
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static value => value, StringComparer.Ordinal)
            .ToArray();

        var skew = ReadInt(configuration, "accessTokenSafetySkewSeconds") ?? 30;

        return new OAuthStrategyConfiguration
        {
            TokenEndpoint = tokenEndpoint,
            AuthorizationEndpoint = authorizationEndpoint,
            RevocationEndpoint = revocationEndpoint,
            ClientId = clientId,
            Scopes = scopes,
            Resource = ReadString(configuration, "resource"),
            Audience = ReadString(configuration, "audience"),
            TokenAuthMethod = ReadString(configuration, "tokenAuthMethod") ?? "client_secret_post",
            AccessTokenSafetySkew = TimeSpan.FromSeconds(skew),
            AuthorizationParameters = ReadAuthorizationParameters(configuration),
        };
    }

    private static AuthenticationPlanException Invalid(string message)
        => new("oauth", message);

    private static string? ReadInput(JsonObject configuration, string name)
        => configuration["inputs"] is JsonObject inputs ? ReadString(inputs, name) : null;

    private static string? ReadString(JsonObject configuration, string name)
        => configuration[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static int? ReadInt(JsonObject configuration, string name)
        => configuration[name] is JsonValue value && value.TryGetValue<int>(out var number) ? number : null;

    private static IReadOnlyList<string> ReadStringArray(JsonObject configuration, string name)
        => configuration[name] is JsonArray array
            ? [.. array.OfType<JsonValue>().Select(static item =>
                item.TryGetValue<string>(out var text) ? text : string.Empty)]
            : [];

    private static IReadOnlyDictionary<string, string> ReadAuthorizationParameters(JsonObject configuration)
    {
        var parameters = new SortedDictionary<string, string>(StringComparer.Ordinal);
        if (configuration["authorizationParameters"] is not JsonObject declared)
        {
            return parameters;
        }

        foreach (var (name, value) in declared)
        {
            if (value is JsonValue item && item.TryGetValue<string>(out var text))
            {
                parameters[name] = text;
            }
        }

        return parameters;
    }

    private static Uri ParseEndpoint(string value, string label)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && uri.Scheme is "https" or "http"
            && !string.IsNullOrEmpty(uri.Host)
            && string.IsNullOrEmpty(uri.UserInfo)
            ? uri
            : throw Invalid($"OAuth {label} is invalid.");
}

/// <summary>Protocol-level bounds and helpers shared by the OAuth runtime.</summary>
public static class OAuthProtocol
{
    /// <summary>The largest token or revocation response this runtime will read.</summary>
    public const int MaximumTokenResponseBytes = 64 * 1024;

    /// <summary>The longest access-token lifetime a provider response may declare.</summary>
    public static TimeSpan MaximumAccessTokenLifetime { get; } = TimeSpan.FromDays(30);

    /// <summary>Base64url-encodes without padding.</summary>
    public static string Base64Url(ReadOnlySpan<byte> bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Creates an unguessable token of the requested byte length.</summary>
    public static string CreateRandomToken(int bytes)
        => Base64Url(RandomNumberGenerator.GetBytes(bytes));

    /// <summary>Parses <c>expires_in</c>, numerically or as an invariant string of seconds.</summary>
    public static TimeSpan ParseExpiresIn(JsonElement root)
    {
        if (!root.TryGetProperty("expires_in", out var element))
        {
            throw new AuthenticationPlanException("oauth", "OAuth token response did not include a usable expiry.");
        }

        long seconds;
        if (element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out seconds))
        {
            // Read directly.
        }
        else if (element.ValueKind == JsonValueKind.String
                 && long.TryParse(element.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out seconds))
        {
            // Some providers state the value as a string; the parse stays structural.
        }
        else
        {
            throw new AuthenticationPlanException("oauth", "OAuth token response contained an invalid expiry.");
        }

        var lifetime = TimeSpan.FromSeconds(seconds);
        if (seconds <= 0 || lifetime > MaximumAccessTokenLifetime)
        {
            throw new AuthenticationPlanException("oauth", "OAuth token response contained an out-of-range expiry.");
        }

        return lifetime;
    }

    /// <summary>
    /// Refuses an endpoint whose origin is outside the profile's reviewed authentication scope.
    /// A token request reveals a client secret, so an endpoint outside the declared origins is
    /// refused before any credential is read.
    /// </summary>
    public static void RequireAuthenticationOrigin(Uri endpoint, IReadOnlyList<string> authenticationOrigins)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(authenticationOrigins);

        var allowed = new OriginAllowList(authenticationOrigins);
        if (!allowed.IsAllowed(endpoint))
        {
            throw new CredentialUnavailableException(
                "oauth",
                "OAuth endpoint is outside the reviewed authentication scope.");
        }
    }
}
