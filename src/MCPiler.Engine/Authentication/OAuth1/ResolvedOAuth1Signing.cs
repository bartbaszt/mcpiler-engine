using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Authentication.Signing;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.OAuth1;

/// <summary>
/// An OAuth 1.0a profile bound to its material and destination scope, ready to sign hops.
/// </summary>
/// <remarks>
/// <para>
/// Each hop is signed independently with a fresh nonce and timestamp taken at the hop, never
/// inherited from an exchange-wide attempt: a redirected request is a new authenticated
/// request with a different base string, and reusing freshness values would replay the
/// previous hop's identity to a nonce-tracking upstream.
/// </para>
/// <para>
/// Signer-owned OAuth values never become ordinary input to the next hop. The unsigned
/// semantic request is preserved between sends: query OAuth parameters from a previous hop
/// are stripped and regenerated, form bodies are rebuilt from the original entity, and a
/// caller-supplied OAuth parameter on the original request fails closed instead.
/// </para>
/// </remarks>
public sealed class ResolvedOAuth1Signing
{
    /// <summary>OAuth protocol parameters version marker sent on every request.</summary>
    internal const string OAuthVersion = "1.0";

    private static readonly IReadOnlyCollection<string> SensitiveQueryNames =
        Array.AsReadOnly(OAuth1Vocabulary.SensitiveProtocolParameters);

    private static readonly Encoding StrictUtf8 = Encoding.GetEncoding(
        "utf-8",
        EncoderFallback.ExceptionFallback,
        DecoderFallback.ExceptionFallback);

    private readonly string _profileId;
    private readonly string _signatureMethod;
    private readonly string _parameterTransport;
    private readonly OAuth1SigningMaterial _material;
    private readonly OriginAllowList _destinations;
    private readonly TimeProvider _timeProvider;
    private KeyValuePair<string, string>[] _previousQueryOAuthParameters = [];
    private KeyValuePair<string, string>[] _previousFormOAuthParameters = [];
    private string? _previousAuthorization;

    /// <summary>
    /// OAuth protocol query names that must be redacted from transport diagnostics, including
    /// the original URI before the first hop is signed.
    /// </summary>
    public static IReadOnlyCollection<string> SensitiveQueryParameters
        => SensitiveQueryNames;

    /// <summary>Creates the per-hop signing closure state. Prefer <see cref="Create"/>.</summary>
    public ResolvedOAuth1Signing(
        string profileId,
        string signatureMethod,
        string parameterTransport,
        OAuth1SigningMaterial material,
        OriginAllowList destinations,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(profileId);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(destinations);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if (!OAuth1Vocabulary.TryGetRequiredSlots(signatureMethod, out _))
        {
            throw new UnsupportedAuthenticationStrategyException(
                $"Authentication profile '{profileId}' declares signature method '{signatureMethod}', which this Engine build cannot execute. " +
                $"Reviewed methods: {string.Join(", ", OAuth1Vocabulary.SignatureMethods)}.");
        }

        if (string.IsNullOrEmpty(parameterTransport)
            || !OAuth1Vocabulary.ParameterTransports.Contains(parameterTransport, StringComparer.Ordinal))
        {
            throw new UnsupportedAuthenticationStrategyException(
                $"Authentication profile '{profileId}' declares parameter transport '{parameterTransport}', which this Engine build cannot execute. " +
                $"Reviewed transports: {string.Join(", ", OAuth1Vocabulary.ParameterTransports)}.");
        }

        _profileId = profileId;
        _signatureMethod = signatureMethod;
        _parameterTransport = parameterTransport;
        _material = material;
        _destinations = destinations;
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// Binds a profile's runtime configuration to resolved material. Unknown methods and
    /// transports are refused here, before any request is built, rather than at signing time.
    /// </summary>
    public static ResolvedOAuth1Signing Create(
        AuthenticationProfile profile,
        OAuth1SigningMaterial material,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(timeProvider);

        ValidateConfiguration(profile);

        string? method = profile.Configuration["signatureMethod"] is JsonValue methodValue
            && methodValue.TryGetValue<string>(out string? methodText)
                ? methodText
                : null;

        string? transport = profile.Configuration["parameterTransport"] is JsonValue transportValue
            && transportValue.TryGetValue<string>(out string? transportText)
                ? transportText
                : null;

        return new ResolvedOAuth1Signing(
            profile.Id,
            method!,
            transport!,
            material,
            new OriginAllowList(profile.DestinationOrigins),
            timeProvider);
    }

    /// <summary>
    /// Refuses unsupported OAuth1 profile configuration before runtime resolves any credential
    /// values. Manifest readers already enforce this contract, but execution keeps the boundary
    /// closed for profiles constructed by another trusted in-process caller.
    /// </summary>
    internal static void ValidateConfiguration(AuthenticationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        string? method = profile.Configuration["signatureMethod"] is JsonValue methodValue
            && methodValue.TryGetValue<string>(out string? methodText)
                ? methodText
                : null;
        if (!OAuth1Vocabulary.TryGetRequiredSlots(method, out _))
        {
            throw new UnsupportedAuthenticationStrategyException(
                $"Authentication profile '{profile.Id}' declares signature method '{method}', which this Engine build cannot execute. " +
                $"Reviewed methods: {string.Join(", ", OAuth1Vocabulary.SignatureMethods)}.");
        }

        string? transport = profile.Configuration["parameterTransport"] is JsonValue transportValue
            && transportValue.TryGetValue<string>(out string? transportText)
                ? transportText
                : null;
        if (string.IsNullOrEmpty(transport)
            || !OAuth1Vocabulary.ParameterTransports.Contains(transport, StringComparer.Ordinal))
        {
            throw new UnsupportedAuthenticationStrategyException(
                $"Authentication profile '{profile.Id}' declares parameter transport '{transport}', which this Engine build cannot execute. " +
                $"Reviewed transports: {string.Join(", ", OAuth1Vocabulary.ParameterTransports)}.");
        }
    }

    /// <summary>Checks the initial destination against profile scope before secret resolution.</summary>
    internal static void ValidateDestinationScope(AuthenticationProfile profile, Uri destination)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(destination);

        OriginAllowList allowed;
        try
        {
            allowed = new OriginAllowList(profile.DestinationOrigins);
        }
        catch (ArgumentException ex)
        {
            throw new AuthenticationPlanException(
                profile.Id,
                "OAuth 1.0a profile declares an invalid destination scope.",
                ex);
        }

        if (!allowed.IsAllowed(destination))
        {
            throw new CredentialUnavailableException(
                profile.Id,
                "OAuth 1.0a signing was refused because the initial destination is outside the stored authentication scope.");
        }
    }

    /// <summary>
    /// Validates the compiled ordinary request before any OAuth credential references are
    /// resolved. This keeps an ineligible body, pre-supplied OAuth parameter, or unsupported URI
    /// from causing secret material to be revealed for a request the signer must refuse.
    /// </summary>
    internal static async ValueTask ValidateRequestShapeAsync(
        AuthenticationProfile profile,
        UpstreamRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(request);

        ValidateConfiguration(profile);

        try
        {
            _ = OAuth1Canonicalizer.BaseStringUri(request.Uri);
            var queryPairs = OAuth1Canonicalizer.ParseQueryPairs(request.Uri);
            OAuth1Canonicalizer.ThrowOnConflictingOAuthParameters(queryPairs, "URI query");

            ValidateBodySources(request);

            var signable = new SignableRequest(request.Method, request.Uri, request.Headers);
            string? authorization = signable.Header("Authorization");
            if (authorization is not null
                && authorization.StartsWith("OAuth ", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "OAuth1 signing refused Authorization: the request already carries OAuth protocol parameters.");
            }

            bool formMediaType = OAuth1Canonicalizer.IsFormUrlEncodedContentType(request.BodyMediaType);
            byte[]? body = request.Body;
            if (body is null && formMediaType && request.BodySource is { } source)
            {
                using var buffer = new MemoryStream();
                await source.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
                body = buffer.ToArray();
            }

            bool formEligible = body is not null && formMediaType;
            if (string.Equals(
                    ReadTransport(profile),
                    OAuth1Vocabulary.FormBodyTransport,
                    StringComparison.Ordinal)
                && !formEligible)
            {
                throw new InvalidOperationException(
                    "OAuth1 body transport requires an eligible application/x-www-form-urlencoded entity.");
            }

            if (formEligible)
            {
                var formPairs = OAuth1Canonicalizer.ParseFormEncodedPairs(StrictUtf8.GetString(body!));
                OAuth1Canonicalizer.ThrowOnConflictingOAuthParameters(formPairs, "form body");
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or DecoderFallbackException)
        {
            throw new CredentialUnavailableException(
                profile.Id,
                $"OAuth 1.0a signing refused the request shape: {ex.Message}",
                ex);
        }
    }

    /// <summary>
    /// Signs one hop after re-checking that its destination is inside the scope. The check runs
    /// before credential material is attached, so a redirect outside the profile's scope is
    /// refused without transmitting anything derived from a secret.
    /// </summary>
    public async ValueTask<UpstreamRequest> SignAsync(
        UpstreamRequest request,
        int hop,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_destinations.IsAllowed(request.Uri))
        {
            throw new CredentialUnavailableException(
                _profileId,
                "OAuth 1.0a signing was refused because the destination is outside the stored authentication scope.");
        }

        try
        {
            return await SignHopAsync(request, hop, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidOperationException or DecoderFallbackException)
        {
            // The inner shaping failures name parameter names and structural causes only,
            // never values, so surfacing the reason keeps the refusal actionable without
            // leaking anything the reference boundary keeps out of diagnostics.
            throw new CredentialUnavailableException(
                _profileId,
                $"OAuth 1.0a signing refused the request shape: {ex.Message}",
                ex);
        }
    }

    private async ValueTask<UpstreamRequest> SignHopAsync(
        UpstreamRequest request,
        int hop,
        CancellationToken cancellationToken)
    {
        ValidateBodySources(request);

        if (hop == 0)
        {
            // One resolved signing closure may be reused for an independent retry. A hop-zero
            // request starts a new chain, so no values from the preceding chain own its inputs.
            _previousQueryOAuthParameters = [];
            _previousFormOAuthParameters = [];
            _previousAuthorization = null;
        }

        string nonce = Base64Url(RandomNumberGenerator.GetBytes(16));
        string timestamp = _timeProvider.GetUtcNow().ToUnixTimeSeconds()
            .ToString(System.Globalization.CultureInfo.InvariantCulture);

        var signable = new SignableRequest(request.Method, request.Uri, request.Headers)
        {
            ReadBodyAsync = BodyReader(request),
        };

        List<KeyValuePair<string, string>> queryPairs = [.. OAuth1Canonicalizer.ParseQueryPairs(signable.Uri)];
        RemoveOwnedParameters(queryPairs, _previousQueryOAuthParameters);
        OAuth1Canonicalizer.ThrowOnConflictingOAuthParameters(queryPairs, "URI query");

        string? authorization = signable.Header("Authorization");
        if (authorization is not null
            && authorization.StartsWith("OAuth ", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(authorization, _previousAuthorization, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "OAuth1 signing refused Authorization: the request already carries OAuth protocol parameters.");
        }

        byte[]? bodyBytes = signable.ReadBodyAsync is { } readBody
            ? await readBody(cancellationToken).ConfigureAwait(false)
            : null;

        List<KeyValuePair<string, string>> formPairs = [];
        bool hasBody = bodyBytes is not null;
        bool formEligible = hasBody && OAuth1Canonicalizer.IsFormUrlEncodedContentType(request.BodyMediaType);
        if (formEligible)
        {
            formPairs = [.. OAuth1Canonicalizer.ParseFormEncodedPairs(StrictUtf8.GetString(bodyBytes!))];
            RemoveOwnedParameters(formPairs, _previousFormOAuthParameters);
            OAuth1Canonicalizer.ThrowOnConflictingOAuthParameters(formPairs, "form body");
        }
        else if (string.Equals(_parameterTransport, OAuth1Vocabulary.FormBodyTransport, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "OAuth1 body transport requires an eligible application/x-www-form-urlencoded entity.");
        }

        var oauth = new List<KeyValuePair<string, string>>
        {
            new("oauth_consumer_key", _material.ConsumerKey),
            new("oauth_token", _material.Token),
            new("oauth_signature_method", _signatureMethod),
            new("oauth_timestamp", timestamp),
            new("oauth_nonce", nonce),
            new("oauth_version", OAuthVersion),
        };

        string normalized = OAuth1Canonicalizer.NormalizeParameters([.. queryPairs, .. formPairs, .. oauth]);
        string baseStringUri = OAuth1Canonicalizer.BaseStringUri(signable.Uri);
        string baseString = OAuth1Canonicalizer.BuildSignatureBaseString(signable.Method, baseStringUri, normalized);
        string signature = OAuth1Signer.ComputeSignature(_material, _signatureMethod, baseString);
        var signed = new List<KeyValuePair<string, string>>(oauth)
        {
            new("oauth_signature", signature),
        };

        var sensitive = new HashSet<string>(request.SensitiveHeaders, StringComparer.OrdinalIgnoreCase)
        {
            "Authorization",
        };

        if (string.Equals(_parameterTransport, OAuth1Vocabulary.AuthorizationHeaderTransport, StringComparison.Ordinal))
        {
            signable.SetHeader("Authorization", "OAuth " + string.Join(", ", signed.Select(HeaderPair)));
            _previousAuthorization = signable.Header("Authorization");
            _previousQueryOAuthParameters = [];
            _previousFormOAuthParameters = [];
        }
        else if (string.Equals(_parameterTransport, OAuth1Vocabulary.QueryTransport, StringComparison.Ordinal))
        {
            var merged = new List<KeyValuePair<string, string>>(queryPairs);
            merged.AddRange(signed);
            signable.SetQuery(merged);
            _previousQueryOAuthParameters = [.. signed];
            _previousFormOAuthParameters = [];
            _previousAuthorization = null;
        }
        else
        {
            var merged = new List<KeyValuePair<string, string>>(formPairs);
            merged.AddRange(signed);
            _previousQueryOAuthParameters = [];
            _previousFormOAuthParameters = [.. signed];
            _previousAuthorization = null;

            return request with
            {
                Method = signable.Method,
                Uri = signable.Uri,
                Headers = new Dictionary<string, string[]>(signable.Headers, StringComparer.OrdinalIgnoreCase),
                Body = Encoding.UTF8.GetBytes(OAuth1Canonicalizer.SerializePairs(merged)),
                BodySource = null,
                BodyMediaType = "application/x-www-form-urlencoded",
                SensitiveHeaders = sensitive,
                SensitiveQueryParameters = SensitiveQueryNames,
            };
        }

        return request with
        {
            Method = signable.Method,
            Uri = signable.Uri,
            Headers = new Dictionary<string, string[]>(signable.Headers, StringComparer.OrdinalIgnoreCase),
            SensitiveHeaders = sensitive,
            SensitiveQueryParameters = SensitiveQueryNames,
        };
    }

    private static void ValidateBodySources(UpstreamRequest request)
    {
        if (request.Body is not null && request.BodySource is not null)
        {
            throw new InvalidOperationException(
                "OAuth1 signing refused a request that declares both materialized and replayable body sources.");
        }
    }

    private static Func<CancellationToken, ValueTask<byte[]>>? BodyReader(UpstreamRequest request)
    {
        if (request.Body is { } bytes)
        {
            return _ => ValueTask.FromResult(bytes);
        }

        if (request.BodySource is { } source)
        {
            return async token =>
            {
                using var buffer = new MemoryStream();
                await source.CopyToAsync(buffer, token).ConfigureAwait(false);
                return buffer.ToArray();
            };
        }

        return null;
    }

    private static string ReadTransport(AuthenticationProfile profile)
        => profile.Configuration["parameterTransport"] is JsonValue transportValue
            && transportValue.TryGetValue<string>(out string? transport)
                ? transport
                : string.Empty;

    private static void RemoveOwnedParameters(
        List<KeyValuePair<string, string>> candidates,
        IReadOnlyList<KeyValuePair<string, string>> owned)
    {
        foreach (KeyValuePair<string, string> previous in owned)
        {
            int index = candidates.FindIndex(candidate => candidate.Equals(previous));
            if (index >= 0)
            {
                candidates.RemoveAt(index);
            }
        }
    }

    private static string HeaderPair(KeyValuePair<string, string> pair)
        => $"{OAuth1Canonicalizer.Rfc3986Encode(pair.Key)}=\"{OAuth1Canonicalizer.Rfc3986Encode(pair.Value)}\"";

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
