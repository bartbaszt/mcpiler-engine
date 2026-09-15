using System.Text;
using System.Text.Json;
using MCPiler.Engine.Execution;

namespace MCPiler.Engine.Authentication.OAuth;

/// <summary>The outcome of one token-endpoint exchange.</summary>
public sealed record OAuthTokenEndpointResult
{
    /// <summary>The acquired access token.</summary>
    public required string AccessToken { get; init; }

    /// <summary>When the access token stops being usable, from the provider's own declaration.</summary>
    public required DateTimeOffset ExpiresAtUtc { get; init; }

    /// <summary>A replacement refresh token, when the provider rotated one.</summary>
    public string? RefreshToken { get; init; }
}

/// <summary>A token endpoint rejected the request with a bounded provider error code.</summary>
public sealed class OAuthTokenEndpointException(string errorCode, string message)
    : Exception(message)
{
    /// <summary>The provider's own error code, bounded and structural.</summary>
    public string ErrorCode { get; } = errorCode;
}

/// <summary>
/// The OAuth token endpoint client: one form-post exchange per acquisition, over the same
/// transport seam every other outbound request uses.
/// </summary>
/// <remarks>
/// <para>
/// A token request carries the client secret, so the endpoint is re-checked against the
/// profile's reviewed authentication origins before any credential is read, and the request is
/// sent under a perimeter of exactly that origin. Redirects are bounded by the profile's own
/// destination policy only in the sense that a token endpoint that moved is a different
/// endpoint: the transport's hop limit is zero and a redirect is therefore a failure rather
/// than a retry against an unreviewed host.
/// </para>
/// <para>
/// The response is bounded before parsing. A provider that returns a huge body must not
/// become a memory primitive merely because the acquisition path reads it.
/// </para>
/// </remarks>
public sealed class OAuthTokenEndpointClient(IUpstreamTransport transport, TimeProvider timeProvider)
{
    /// <summary>Exchanges form values for an access token.</summary>
    /// <param name="configuration">The profile configuration.</param>
    /// <param name="authenticationOrigins">The profile's reviewed authentication origins.</param>
    /// <param name="formValues">The grant parameters, without client authentication.</param>
    /// <param name="clientSecret">The client secret, absent for the <c>none</c> method.</param>
    /// <param name="cancellationToken">The whole-exchange deadline.</param>
    public async Task<OAuthTokenEndpointResult> ExchangeAsync(
        OAuthStrategyConfiguration configuration,
        IReadOnlyList<string> authenticationOrigins,
        IReadOnlyDictionary<string, string> formValues,
        string? clientSecret,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(authenticationOrigins);
        ArgumentNullException.ThrowIfNull(formValues);

        OAuthProtocol.RequireAuthenticationOrigin(configuration.TokenEndpoint, authenticationOrigins);

        var values = new Dictionary<string, string>(formValues, StringComparer.Ordinal)
        {
            ["client_id"] = configuration.ClientId,
        };

        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var sensitive = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        switch (configuration.TokenAuthMethod)
        {
            case "client_secret_post":
                values["client_secret"] = RequireClientSecret(clientSecret, "token");
                break;

            case "client_secret_basic":
                var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                    $"{configuration.ClientId}:{RequireClientSecret(clientSecret, "token")}"));
                headers["Authorization"] = ["Basic " + basic];
                sensitive.Add("Authorization");
                break;

            case "none":
                break;

            default:
                throw new AuthenticationPlanException(
                    "oauth",
                    "OAuth token authentication method is not supported.");
        }

        var body = Encoding.UTF8.GetBytes(SerializeForm(values));
        var request = new UpstreamRequest
        {
            Method = "POST",
            Uri = configuration.TokenEndpoint,
            Headers = headers,
            Body = body,
            BodyMediaType = "application/x-www-form-urlencoded",
            SensitiveHeaders = sensitive,
        };

        var origin = new OriginAllowList([OriginOf(configuration.TokenEndpoint)]);

        await using var response = await SendAsync(request, origin, cancellationToken);
        var bytes = await ReadBoundedAsync(response, cancellationToken);

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(bytes);
        }
        catch (JsonException ex)
        {
            throw new CredentialUnavailableException(
                "oauth",
                "OAuth token endpoint returned an invalid JSON response.",
                ex);
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new CredentialUnavailableException("oauth", "OAuth token endpoint returned an invalid response shape.");
            }

            if (response.StatusCode is < 200 or > 299)
            {
                throw new OAuthTokenEndpointException(
                    ReadBoundedErrorCode(root) ?? "token-endpoint-rejected",
                    "OAuth token endpoint rejected the request.");
            }

            var accessToken = ReadRequiredSecret(root, "access_token");
            if (root.TryGetProperty("token_type", out var typeElement)
                && (typeElement.ValueKind != JsonValueKind.String
                    || !string.Equals(typeElement.GetString(), "Bearer", StringComparison.OrdinalIgnoreCase)))
            {
                throw new CredentialUnavailableException("oauth", "OAuth token endpoint returned an unsupported token type.");
            }

            var lifetime = OAuthProtocol.ParseExpiresIn(root);

            string? refreshToken = null;
            if (root.TryGetProperty("refresh_token", out var refreshElement))
            {
                if (refreshElement.ValueKind != JsonValueKind.String
                    || string.IsNullOrEmpty(refreshElement.GetString())
                    || refreshElement.GetString()!.Length > 16_384)
                {
                    throw new CredentialUnavailableException("oauth", "OAuth token endpoint returned an invalid refresh token.");
                }

                refreshToken = refreshElement.GetString();
            }

            return new OAuthTokenEndpointResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresAtUtc = timeProvider.GetUtcNow().Add(lifetime),
            };
        }
    }

    /// <summary>Best-effort revocation of a refresh token, bounded to the revocation endpoint.</summary>
    public async Task RevokeRefreshTokenAsync(
        OAuthStrategyConfiguration configuration,
        IReadOnlyList<string> authenticationOrigins,
        string refreshToken,
        string? clientSecret,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(authenticationOrigins);

        var endpoint = configuration.RevocationEndpoint
            ?? throw new AuthenticationPlanException("oauth", "OAuth revocation endpoint is not configured.");
        OAuthProtocol.RequireAuthenticationOrigin(endpoint, authenticationOrigins);

        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["token"] = refreshToken,
            ["token_type_hint"] = "refresh_token",
            ["client_id"] = configuration.ClientId,
        };

        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var sensitive = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        switch (configuration.TokenAuthMethod)
        {
            case "client_secret_post":
                values["client_secret"] = RequireClientSecret(clientSecret, "revocation");
                break;

            case "client_secret_basic":
                var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                    $"{configuration.ClientId}:{RequireClientSecret(clientSecret, "revocation")}"));
                headers["Authorization"] = ["Basic " + basic];
                sensitive.Add("Authorization");
                break;

            case "none":
                break;

            default:
                throw new AuthenticationPlanException(
                    "oauth",
                    "OAuth revocation authentication method is not supported.");
        }

        var request = new UpstreamRequest
        {
            Method = "POST",
            Uri = endpoint,
            Headers = headers,
            Body = Encoding.UTF8.GetBytes(SerializeForm(values)),
            BodyMediaType = "application/x-www-form-urlencoded",
            SensitiveHeaders = sensitive,
        };

        await using var response = await SendAsync(request, new OriginAllowList([OriginOf(endpoint)]), cancellationToken);
        if (response.StatusCode is < 200 or > 299)
        {
            throw new CredentialUnavailableException("oauth", "OAuth provider revocation endpoint rejected the request.");
        }
    }

    private async Task<UpstreamResponse> SendAsync(
        UpstreamRequest request,
        OriginAllowList origin,
        CancellationToken cancellationToken)
    {
        try
        {
            return await transport.SendAsync(
                request,
                new UpstreamSendPolicy(origin, OAuthOutboundLimits),
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is OriginPolicyViolationException or UpstreamTransportException)
        {
            throw new CredentialUnavailableException(
                "oauth",
                "OAuth endpoint request failed within the reviewed network policy.",
                ex);
        }
    }

    /// <summary>
    /// A token endpoint is one exact host: a redirect would send the client secret somewhere the
    /// profile did not review, so the exchange does not follow one.
    /// </summary>
    private static OutboundLimits OAuthOutboundLimits { get; } =
        new(TimeSpan.FromSeconds(10), MaxConnectionsPerServer: 2, RedirectHopLimit: 0);

    private static string RequireClientSecret(string? secret, string purpose)
        => string.IsNullOrEmpty(secret)
            ? throw new CredentialUnavailableException(
                "oauth",
                $"OAuth client secret is required by the configured {purpose} authentication method.")
            : secret;

    private static string OriginOf(Uri uri) => uri.GetLeftPart(UriPartial.Authority);

    private static string SerializeForm(IReadOnlyDictionary<string, string> values)
        => string.Join('&', values.Select(static pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));

    private static async Task<byte[]> ReadBoundedAsync(UpstreamResponse response, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];

        while (true)
        {
            var read = await response.Body.ReadAsync(chunk, cancellationToken);
            if (read == 0)
            {
                return buffer.ToArray();
            }

            if (buffer.Length + read > OAuthProtocol.MaximumTokenResponseBytes)
            {
                throw new CredentialUnavailableException(
                    "oauth",
                    "OAuth token endpoint response exceeded the allowed size.");
            }

            buffer.Write(chunk, 0, read);
        }
    }

    private static string ReadRequiredSecret(JsonElement root, string member)
    {
        if (!root.TryGetProperty(member, out var element)
            || element.ValueKind != JsonValueKind.String
            || string.IsNullOrEmpty(element.GetString())
            || element.GetString()!.Length > 16_384)
        {
            throw new CredentialUnavailableException(
                "oauth",
                $"OAuth token response did not include a usable {member.Replace('_', ' ')}.");
        }

        return element.GetString()!;
    }

    private static string? ReadBoundedErrorCode(JsonElement root)
        => !root.TryGetProperty("error", out var element)
            || element.ValueKind != JsonValueKind.String
            || element.GetString() is not { } value
            || value.Length is 0 or > 100
            || value.Any(static character => !(char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.'))
                ? null
                : value;
}
