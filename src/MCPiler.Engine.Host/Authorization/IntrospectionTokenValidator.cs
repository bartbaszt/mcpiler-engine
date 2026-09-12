using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// Validates tokens by asking the trusted issuer, per RFC 7662.
/// </summary>
/// <remarks>
/// <para>
/// Introspection is chosen when revocation has to be immediate: the issuer's answer names
/// the token's standing at the moment of the request, not at the moment it was signed. The
/// cost is one round trip per request, accepted by configuration rather than by accident.
/// </para>
/// <para>
/// Fail-closed is the whole shape of the error handling. An unreachable issuer, a malformed
/// response, a missing <c>active</c> member: each is an inactive token. A resource server
/// that fell open when its authorization server was down would protect nothing exactly when
/// protecting is hardest to verify.
/// </para>
/// </remarks>
internal sealed class IntrospectionTokenValidator : ITokenValidator
{
    private readonly HttpClient _client;
    private readonly string _issuer;
    private readonly string? _endpointOverride;

    private string? _endpoint;

    internal IntrospectionTokenValidator(HttpClient client, string issuer, string? endpointOverride)
    {
        _client = client;
        _issuer = issuer;
        _endpointOverride = endpointOverride;
    }

    public async Task<TokenVerification> ValidateAsync(string token, CancellationToken cancellationToken)
    {
        string? endpoint = await ResolveEndpointAsync(cancellationToken).ConfigureAwait(false);

        if (endpoint is null)
        {
            return TokenVerification.Inactive;
        }

        using HttpRequestMessage request = new(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = token,
            }),
        };

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        try
        {
            using HttpResponseMessage response = await _client
                .SendAsync(request, cancellationToken)
                .ConfigureAwait(false);

            if (response.StatusCode != HttpStatusCode.OK)
            {
                return TokenVerification.Inactive;
            }

            using JsonDocument document = await JsonDocument.ParseAsync(
                await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false),
                cancellationToken: cancellationToken).ConfigureAwait(false);

            JsonElement root = document.RootElement;

            if (root.ValueKind is not JsonValueKind.Object
                || !root.TryGetProperty("active", out JsonElement active)
                || active.ValueKind is not JsonValueKind.True)
            {
                return TokenVerification.Inactive;
            }

            return new TokenVerification(
                Active: true,
                Audience: ReadString(root, "aud"),
                Scopes: ReadScopes(root));
        }
        catch (Exception failure) when (failure is HttpRequestException or JsonException or TaskCanceledException)
        {
            // Unreachable issuer, slow issuer, malformed body: all of them mean "this token
            // is not known to be active", which is the only safe answer.
            return TokenVerification.Inactive;
        }
    }

    /// <summary>
    /// Resolves the introspection endpoint once, then reuses the answer. Discovery that ran
    /// per request would add a round trip an operator never agreed to, and one that fails
    /// whenever the issuer is slow rather than whenever the token is wrong.
    /// </summary>
    private async Task<string?> ResolveEndpointAsync(CancellationToken cancellationToken)
    {
        if (_endpoint is not null || _endpointOverride is not null)
        {
            return _endpoint ?? _endpointOverride;
        }

        JsonElement? metadata;

        try
        {
            metadata = await IssuerMetadata.DiscoverAsync(
                _client,
                _issuer,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is HttpRequestException or TaskCanceledException)
        {
            return null;
        }

        if (metadata is not { } discovered
            || !discovered.TryGetProperty("introspection_endpoint", out JsonElement endpoint)
            || endpoint.ValueKind is not JsonValueKind.String
            || endpoint.GetString() is not { } address
            || !Uri.TryCreate(address, UriKind.Absolute, out Uri? resolved)
            || resolved.Scheme is not ("http" or "https"))
        {
            return null;
        }

        return _endpoint = address;
    }

    /// <summary>
    /// Reads the audience, tolerating the multi-valued form the claim is allowed to take.
    /// </summary>
    /// <remarks>
    /// RFC 7662 declares <c>aud</c> a string, but the JWT claim it mirrors is defined as an
    /// array, and at least one major issuer sends the array through introspection. The
    /// byte-exact binding compares one name, so a multi-valued audience is one that names no
    /// single resource and is refused — but reading it as a string array and taking none of
    /// them is the same refusal without the parse failure.
    /// </remarks>
    private static string? ReadString(JsonElement root, string member)
    {
        if (!root.TryGetProperty(member, out JsonElement value))
        {
            return null;
        }

        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                return value.GetString();

            case JsonValueKind.Array when value.EnumerateArray().Any(static item => item.ValueKind is JsonValueKind.String):
                return null;

            default:
                return null;
        }
    }

    private static IReadOnlyList<string> ReadScopes(JsonElement root)
    {
        if (!root.TryGetProperty("scope", out JsonElement scope)
            || scope.ValueKind is not JsonValueKind.String
            || scope.GetString() is not { } declared)
        {
            return [];
        }

        return [.. declared.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
    }
}