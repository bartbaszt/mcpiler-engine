using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.Exchange;

/// <summary>Acquired session material together with the destination it authorises.</summary>
/// <param name="Credential">The credential the operation request carries.</param>
/// <param name="DestinationAuthority">
/// The authority a response-derived destination named, when the exchange declared one. The
/// operation request is rebound onto it before it is sent.
/// </param>
/// <param name="ExpiresAtUtc">When the material stops being usable.</param>
public sealed record TokenSessionAcquisition(
    ResolvedCredential Credential,
    Uri? DestinationAuthority,
    DateTimeOffset ExpiresAtUtc);

/// <summary>
/// Acquires reviewed token/session material from a declared endpoint.
/// </summary>
/// <remarks>
/// <para>
/// The exchange is declarative all the way down: the endpoint, the method, the body and header
/// mappings, the response selectors and the injection point all come from the validated profile
/// configuration. This class therefore contains no protocol knowledge beyond "send what the
/// profile says and read what it says to read".
/// </para>
/// <para>
/// A response-derived destination is the one place the exchange can widen where an authenticated
/// request goes, so it must fall inside BOTH the reviewed destination list the exchange itself
/// declares and the profile's destination origins. That double check is what keeps a compromised
/// or malformed token endpoint from redirecting an operation to an origin nobody reviewed.
/// </para>
/// </remarks>
public sealed class TokenSessionExchangeService
{
    private const int MaximumResponseBytes = 64 * 1024;
    internal const int MaximumMaterialLength = 16_384;

    private static readonly OutboundLimits ExchangeLimits =
        new(TimeSpan.FromSeconds(10), MaxConnectionsPerServer: 2, RedirectHopLimit: 0);

    private readonly IUpstreamTransport _transport;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates the service.</summary>
    /// <param name="transport">The one outbound port.</param>
    /// <param name="timeProvider">The clock expiry is measured against.</param>
    public TokenSessionExchangeService(IUpstreamTransport transport, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _transport = transport;
        _timeProvider = timeProvider;
    }

    /// <summary>Acquires session material for one exchange profile.</summary>
    /// <param name="profile">The validated profile.</param>
    /// <param name="credentials">The profile's already-resolved secret slots.</param>
    /// <param name="cancellationToken">The whole-exchange deadline.</param>
    /// <exception cref="UnsupportedAuthenticationStrategyException">
    /// The profile is not a token/session exchange profile.
    /// </exception>
    /// <exception cref="CredentialUnavailableException">
    /// The endpoint refused the request, the response carried no usable material, or the
    /// configured origin/destination constraints were not met.
    /// </exception>
    public async ValueTask<TokenSessionAcquisition> AcquireAsync(
        AuthenticationProfile profile,
        IReadOnlyList<ResolvedCredential> credentials,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(credentials);

        if (profile.Kind != AuthenticationKind.TokenSessionExchange)
        {
            throw new UnsupportedAuthenticationStrategyException(
                $"Authentication profile '{profile.Id}' is not a token/session exchange profile.");
        }

        var definition = TokenSessionExchangeDefinition.FromConfiguration(profile.Configuration);

        RequireReviewedOrigin(definition.Endpoint, profile.AuthenticationOrigins);

        var request = BuildRequest(profile, definition, credentials);
        UpstreamResponse response;

        try
        {
            response = await _transport.SendAsync(
                request,
                new UpstreamSendPolicy(
                    new OriginAllowList([OriginOf(definition.Endpoint)]),
                    ExchangeLimits),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OriginPolicyViolationException
            or UpstreamTransportException
            or AddressPolicyViolationException
            or HostResolutionException
            or MalformedRedirectException
            or RedirectLimitException)
        {
            throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange request failed within the reviewed network policy.",
                exception);
        }

        await using (response.ConfigureAwait(false))
        {
            if (response.StatusCode is < 200 or > 299)
            {
                throw new CredentialUnavailableException(
                    "exchange",
                    "Token/session exchange endpoint rejected the authentication request.");
            }

            return await ReadAcquisitionAsync(profile, definition, response, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Whether a response status means the acquired session was rejected upstream.
    /// </summary>
    /// <param name="profile">The validated profile.</param>
    /// <param name="statusCode">The observed status.</param>
    public static bool IsAuthenticationFailure(AuthenticationProfile profile, int statusCode)
    {
        ArgumentNullException.ThrowIfNull(profile);

        return profile.Kind == AuthenticationKind.TokenSessionExchange
            && TokenSessionExchangeDefinition
                .FromConfiguration(profile.Configuration)
                .AuthenticationFailureStatusCodes
                .Contains(statusCode);
    }

    /// <summary>
    /// Re-anchors a request URI onto a response-derived destination authority, preserving the
    /// request's path and query.
    /// </summary>
    /// <param name="requestUri">The request as it was compiled.</param>
    /// <param name="destinationAuthority">The authority the response named.</param>
    public static Uri RebindUri(Uri requestUri, Uri destinationAuthority)
    {
        ArgumentNullException.ThrowIfNull(requestUri);
        ArgumentNullException.ThrowIfNull(destinationAuthority);

        var authority = destinationAuthority.GetLeftPart(UriPartial.Authority);
        var pathAndQuery = requestUri.GetComponents(UriComponents.PathAndQuery, UriFormat.UriEscaped);

        return new Uri(
            authority + (string.IsNullOrEmpty(pathAndQuery) ? "/" : pathAndQuery),
            UriKind.Absolute);
    }

    private static UpstreamRequest BuildRequest(
        AuthenticationProfile profile,
        TokenSessionExchangeDefinition definition,
        IReadOnlyList<ResolvedCredential> credentials)
    {
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var sensitiveHeaders = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (name, mapping) in definition.Headers)
        {
            headers[name] = [ResolveValue(profile, definition, mapping, credentials)];

            if (mapping.Kind == ExchangeValueSourceKind.Secret)
            {
                sensitiveHeaders.Add(name);
            }
        }

        if (definition.BasicAuthentication is { } basic)
        {
            var username = ResolveValue(profile, definition, basic.Username, credentials);
            var password = ResolveValue(profile, definition, basic.Password, credentials);
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
            headers["Authorization"] = ["Basic " + encoded];
            sensitiveHeaders.Add("Authorization");
        }

        var (body, mediaType) = BuildBody(profile, definition, credentials);

        return new UpstreamRequest
        {
            Method = definition.Method,
            Uri = definition.Endpoint,
            Headers = headers,
            Body = body,
            BodyMediaType = mediaType,
            SensitiveHeaders = sensitiveHeaders,
        };
    }

    private static (byte[]? Body, string? MediaType) BuildBody(
        AuthenticationProfile profile,
        TokenSessionExchangeDefinition definition,
        IReadOnlyList<ResolvedCredential> credentials)
    {
        if (definition.Fields.Count == 0)
        {
            return (null, null);
        }

        var fields = definition.Fields.ToDictionary(
            pair => pair.Key,
            pair => ResolveValue(profile, definition, pair.Value, credentials),
            StringComparer.Ordinal);

        return definition.MediaType switch
        {
            "application/json" => (
                JsonSerializer.SerializeToUtf8Bytes(fields),
                "application/json"),
            "application/x-www-form-urlencoded" => (
                Encoding.UTF8.GetBytes(SerializeForm(fields)),
                "application/x-www-form-urlencoded"),
            _ => throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange request media type is not supported."),
        };
    }

    private async ValueTask<TokenSessionAcquisition> ReadAcquisitionAsync(
        AuthenticationProfile profile,
        TokenSessionExchangeDefinition definition,
        UpstreamResponse response,
        CancellationToken cancellationToken)
    {
        var needsJson = definition.TokenSelector.Kind == ExchangeSelectorKind.JsonPointer
            || definition.Expiry?.Selector.Kind == ExchangeSelectorKind.JsonPointer
            || definition.Destination?.Selector.Kind == ExchangeSelectorKind.JsonPointer;

        byte[]? jsonBytes = null;

        if (needsJson)
        {
            try
            {
                jsonBytes = await ReadBoundedAsync(response.Body, cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException exception)
            {
                throw new CredentialUnavailableException(
                    "exchange",
                    "Token/session exchange endpoint response exceeded the allowed size.",
                    exception);
            }
        }

        JsonNode? json = null;

        if (jsonBytes is not null)
        {
            try
            {
                json = CanonicalJson.Parse(jsonBytes);
            }
            catch (JsonException exception)
            {
                throw new CredentialUnavailableException(
                    "exchange",
                    "Token/session exchange endpoint returned invalid JSON.",
                    exception);
            }
        }

        var token = ReadSelectorValue(profile, definition.TokenSelector, response, json, allowNumber: false);

        if (token.Length is 0 or > MaximumMaterialLength)
        {
            throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange response did not include usable session material.");
        }

        var now = _timeProvider.GetUtcNow();
        var expiresAt = definition.Expiry is null
            ? now.Add(definition.DefaultLifetime)
            : ParseExpiry(
                ReadSelectorValue(
                    profile,
                    definition.Expiry.Selector,
                    response,
                    json,
                    allowNumber: true),
                definition.Expiry.Kind,
                now);

        var destination = definition.Destination is null
            ? null
            : NormalizeDestination(
                ReadSelectorValue(
                    profile,
                    definition.Destination.Selector,
                    response,
                    json,
                    allowNumber: false),
                definition.Destination.AllowedOrigins,
                profile.DestinationOrigins);

        return new TokenSessionAcquisition(
            definition.Injection.CreateCredential(token),
            destination,
            expiresAt);
    }

    private static string ResolveValue(
        AuthenticationProfile profile,
        TokenSessionExchangeDefinition definition,
        ExchangeValueSource mapping,
        IReadOnlyList<ResolvedCredential> credentials)
        => mapping.Kind switch
        {
            ExchangeValueSourceKind.Input => definition.Inputs.TryGetValue(mapping.Slot!, out var input)
                ? input
                : throw new CredentialUnavailableException(
                    "exchange",
                    $"Token/session exchange input '{mapping.Slot}' is not declared by the profile configuration."),
            ExchangeValueSourceKind.Secret => credentials.FirstOrDefault(credential =>
                    credential.Declaration.Scheme == CredentialScheme.TokenSessionExchange
                    && string.Equals(credential.Declaration.Slot, mapping.Slot, StringComparison.Ordinal))?.Value
                ?? throw new CredentialUnavailableException(
                    "exchange",
                    "Token/session exchange references a secret slot the profile did not resolve."),
            ExchangeValueSourceKind.Static => mapping.StaticValue!,
            _ => throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange contains an unsupported value mapping."),
        };

    private static string ReadSelectorValue(
        AuthenticationProfile profile,
        ExchangeSelector selector,
        UpstreamResponse response,
        JsonNode? json,
        bool allowNumber)
    {
        switch (selector.Kind)
        {
            case ExchangeSelectorKind.JsonPointer:
                if (!TokenSessionExchangeDefinition.TrySelectJsonPointer(json, selector.Selector, out var selected))
                {
                    throw new CredentialUnavailableException(
                        "exchange",
                        "Token/session exchange response is missing the configured JSON Pointer value.");
                }

                if (selected is JsonValue value && value.TryGetValue<string>(out var text))
                {
                    return text;
                }

                if (allowNumber && selected is JsonValue numeric && numeric.TryGetValue<decimal>(out var number))
                {
                    return number.ToString(CultureInfo.InvariantCulture);
                }

                throw new CredentialUnavailableException(
                    "exchange",
                    allowNumber
                        ? "Token/session exchange JSON Pointer did not select a string or numeric expiry value."
                        : "Token/session exchange JSON Pointer did not select a string value.");

            case ExchangeSelectorKind.Header:
                return ReadHeader(selector.Selector, response);

            case ExchangeSelectorKind.Cookie:
                return ReadCookie(selector.Selector, response);

            default:
                throw new CredentialUnavailableException(
                    "exchange",
                    "Token/session exchange response selector is unsupported.");
        }
    }

    private static string ReadHeader(string headerName, UpstreamResponse response)
    {
        if (!response.Headers.TryGetValue(headerName, out var values))
        {
            throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange response is missing the configured header value.");
        }

        if (values.Length != 1 || values[0].Length is 0 or > MaximumMaterialLength)
        {
            throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange response header value is ambiguous or invalid.");
        }

        return values[0];
    }

    private static string ReadCookie(string cookieName, UpstreamResponse response)
    {
        if (!response.Headers.TryGetValue("Set-Cookie", out var values))
        {
            throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange response is missing the configured cookie value.");
        }

        string? found = null;

        foreach (var header in values)
        {
            var pair = header.Split(';', 2)[0];
            var equals = pair.IndexOf('=', StringComparison.Ordinal);

            if (equals <= 0 || !string.Equals(pair[..equals].Trim(), cookieName, StringComparison.Ordinal))
            {
                continue;
            }

            if (found is not null)
            {
                throw new CredentialUnavailableException(
                    "exchange",
                    "Token/session exchange response cookie value is ambiguous.");
            }

            var value = pair[(equals + 1)..].Trim();

            if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
            {
                value = value[1..^1]
                    .Replace("\\\"", "\"", StringComparison.Ordinal)
                    .Replace("\\\\", "\\", StringComparison.Ordinal);
            }

            found = value;
        }

        if (string.IsNullOrEmpty(found) || found.Length > MaximumMaterialLength)
        {
            throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange response is missing the configured cookie value.");
        }

        return found;
    }

    private static DateTimeOffset ParseExpiry(string value, ExchangeExpiryKind kind, DateTimeOffset now)
    {
        DateTimeOffset expiresAt;

        switch (kind)
        {
            case ExchangeExpiryKind.RelativeSeconds:
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
                    || seconds <= 0
                    || seconds > (long)TokenSessionExchangeDefinition.MaximumSessionLifetime.TotalSeconds)
                {
                    throw new CredentialUnavailableException(
                        "exchange",
                        "Token/session exchange response contained an invalid relative expiry.");
                }

                expiresAt = now.AddSeconds(seconds);
                break;

            case ExchangeExpiryKind.UnixSeconds:
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var unixSeconds)
                    || unixSeconds < -62_135_596_800
                    || unixSeconds > 253_402_300_799)
                {
                    throw new CredentialUnavailableException(
                        "exchange",
                        "Token/session exchange response contained an invalid absolute expiry.");
                }

                expiresAt = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
                break;

            case ExchangeExpiryKind.AbsoluteUtc:
                if (!DateTimeOffset.TryParse(
                        value,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out expiresAt))
                {
                    throw new CredentialUnavailableException(
                        "exchange",
                        "Token/session exchange response contained an invalid absolute expiry.");
                }

                break;

            default:
                throw new CredentialUnavailableException(
                    "exchange",
                    "Token/session exchange response expiry kind is unsupported.");
        }

        var lifetime = expiresAt - now;

        if (lifetime <= TimeSpan.Zero || lifetime > TokenSessionExchangeDefinition.MaximumSessionLifetime)
        {
            throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange response expiry is outside the allowed range.");
        }

        return expiresAt;
    }

    private static Uri NormalizeDestination(
        string value,
        IReadOnlyList<string> reviewedOrigins,
        IReadOnlyList<string> profileOrigins)
    {
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps
            || string.IsNullOrEmpty(uri.Host)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || uri.AbsolutePath is not ("" or "/")
            || Uri.CheckHostName(uri.IdnHost) is UriHostNameType.IPv4 or UriHostNameType.IPv6)
        {
            throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange response contained an invalid dynamic destination.");
        }

        try
        {
            var authority = new Uri(uri.GetLeftPart(UriPartial.Authority), UriKind.Absolute);

            if (!new OriginAllowList(reviewedOrigins).IsAllowed(authority)
                || !new OriginAllowList(profileOrigins).IsAllowed(authority))
            {
                throw new CredentialUnavailableException(
                    "exchange",
                    "Token/session exchange response destination is outside the reviewed origin scope.");
            }

            return authority;
        }
        catch (ArgumentException exception)
        {
            throw new CredentialUnavailableException(
                "exchange",
                "Token/session exchange destination origin metadata is invalid.",
                exception);
        }
    }

    private static void RequireReviewedOrigin(Uri endpoint, IReadOnlyList<string> authenticationOrigins)
    {
        if (new OriginAllowList(authenticationOrigins).IsAllowed(endpoint))
        {
            return;
        }

        throw new CredentialUnavailableException(
            "exchange",
            "Token/session exchange endpoint origin is outside the reviewed authentication scope.");
    }

    private static string OriginOf(Uri uri) => uri.GetLeftPart(UriPartial.Authority);

    private static string SerializeForm(IReadOnlyDictionary<string, string> values)
    {
        var builder = new StringBuilder();

        foreach (var (name, value) in values)
        {
            if (builder.Length > 0)
            {
                builder.Append('&');
            }

            builder.Append(Uri.EscapeDataString(name));
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(value));
        }

        return builder.ToString();
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];

        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                return buffer.ToArray();
            }

            if (buffer.Length + read > MaximumResponseBytes)
            {
                throw new InvalidOperationException(
                    "Token/session exchange response exceeded the configured size limit.");
            }

            buffer.Write(chunk, 0, read);
        }
    }
}
