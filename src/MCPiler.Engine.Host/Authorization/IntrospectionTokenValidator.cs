using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using MCPiler.Engine.Host.Configuration;

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
/// <para>
/// The endpoint is protected, so this server authenticates itself to it with the configured
/// client identity, using HTTP Basic (<c>client_secret_basic</c>). The secret is read from a file,
/// held in memory, and never appears in a log line, a diagnostic or a report.
/// </para>
/// </remarks>
internal sealed class IntrospectionTokenValidator : ITokenValidator
{
    private const int NegativeCacheSeconds = 5;

    /// <summary>The most distinct token introspections one process will coalesce at once.</summary>
    /// <remarks>
    /// Distinct in-flight keys are bounded independently of the result cache: without this a burst
    /// of distinct tokens would each add a permanent <c>_inFlight</c> entry and waiter, so the map
    /// and its retained task state would grow without bound even though the result cache is capped.
    /// A caller beyond the bound takes its own fresh fail-closed path rather than being retained.
    /// </remarks>
    internal const int MaximumInFlight = 512;

    /// <summary>The most bytes read from an introspection response body before it is refused.</summary>
    internal const int MaximumResponseBodyBytes = 256 * 1024;

    private readonly IntrospectionResultCache _cache = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<TokenVerification>> _inFlight = new(StringComparer.Ordinal);
    private readonly HttpClient _client;
    private readonly string _issuer;
    private readonly string? _endpointOverride;
    private readonly string? _clientId;
    private readonly string? _clientSecret;
    private readonly int _cacheTtlSeconds;
    private readonly TimeProvider _clock;

    private string? _endpoint;
    private int _admittedInFlight;

    /// <summary>The number of distinct tokens currently coalesced. For bounded-growth assertions.</summary>
    internal int InFlightCount => _inFlight.Count;

    /// <summary>The number of admission slots currently reserved. For bounded-growth assertions.</summary>
    internal int AdmittedInFlightCount => Volatile.Read(ref _admittedInFlight);

    internal IntrospectionTokenValidator(
        HttpClient client,
        string issuer,
        string? endpointOverride,
        string? clientId = null,
        string? clientSecret = null,
        int cacheTtlSeconds = 30,
        TimeProvider? clock = null)
    {
        _client = client;
        _issuer = issuer;
        _endpointOverride = endpointOverride;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _cacheTtlSeconds = cacheTtlSeconds < 0
            ? throw new ArgumentOutOfRangeException(nameof(cacheTtlSeconds))
            : cacheTtlSeconds;
        _clock = clock ?? TimeProvider.System;
    }

    public async Task<TokenVerification> ValidateAsync(string token, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        if (_cacheTtlSeconds == 0)
        {
            // Zero is the explicit "fresh issuer validation per request" mode. It disables
            // every form of result reuse, including transient per-token single-flight
            // coalescing between concurrent protected requests.
            return await ValidateFreshFailClosedAsync(token)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
        }

        string key = Digest(token);

        if (_cache.TryGet(key, _clock.GetUtcNow(), out TokenVerification? cached))
        {
            return cached!;
        }

        // A key already in flight always joins. A genuinely new key reserves an admission slot
        // atomically before it publishes a coalescing entry, so a concurrent burst cannot overshoot
        // the bound. A caller that cannot reserve is refused immediately and fail-closed: it makes
        // no HTTP call and is not retained as a waiter, so the map and its task state stay bounded.
        if (!_inFlight.TryGetValue(key, out TaskCompletionSource<TokenVerification>? existing))
        {
            if (Interlocked.Increment(ref _admittedInFlight) > MaximumInFlight)
            {
                Interlocked.Decrement(ref _admittedInFlight);
                return TokenVerification.Inactive;
            }

            TaskCompletionSource<TokenVerification> candidate = new(
                TaskCreationOptions.RunContinuationsAsynchronously);
            existing = _inFlight.GetOrAdd(key, candidate);

            if (ReferenceEquals(candidate, existing))
            {
                _ = CompleteSingleFlightAsync(key, token, candidate);
            }
            else
            {
                // Lost a race for the same key: join the existing flight and release the slot.
                Interlocked.Decrement(ref _admittedInFlight);
            }
        }

        return await existing.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task CompleteSingleFlightAsync(
        string key,
        string token,
        TaskCompletionSource<TokenVerification> completion)
    {
        try
        {
            TokenVerification verification = await ValidateFreshFailClosedAsync(token).ConfigureAwait(false);
            CacheIfAllowed(key, verification);
            completion.TrySetResult(verification);
        }
        catch
        {
            // Keep the shared authorization operation fail-closed even if local cache bookkeeping
            // fails unexpectedly; no waiter may be left pinned on an incomplete shared task.
            completion.TrySetResult(TokenVerification.Inactive);
        }
        finally
        {
            _inFlight.TryRemove(new KeyValuePair<string, TaskCompletionSource<TokenVerification>>(key, completion));
            Interlocked.Decrement(ref _admittedInFlight);
        }
    }

    private async Task<TokenVerification> ValidateFreshFailClosedAsync(string token)
    {
        try
        {
            return await ValidateFreshAsync(token, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is HttpRequestException or JsonException or TaskCanceledException)
        {
            // Transport/protocol failures are fail-closed and never reusable. The underlying
            // issuer operation is independent from a request waiter so one cancelled waiter does
            // not alter validation observed by another request.
            return TokenVerification.Inactive;
        }
        catch
        {
            // Validation is an authorization boundary: unexpected parser/client failures also
            // fail closed and remain non-cacheable.
            return TokenVerification.Inactive;
        }
    }

    private async Task<TokenVerification> ValidateFreshAsync(string token, CancellationToken cancellationToken)
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

        if (_clientId is { } clientId && _clientSecret is { } clientSecret)
        {
            // client_secret_basic: the two halves are form-urlencoded before they are base64'd,
            // which RFC 6749 §2.3.1 requires because either may contain characters that are not
            // valid in an HTTP header value.
            string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret)}"));

            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        }

        try
        {
            using HttpResponseMessage response = await _client
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            if (response.StatusCode != HttpStatusCode.OK)
            {
                return TokenVerification.Inactive;
            }

            byte[]? body = await ReadBoundedAsync(response, cancellationToken).ConfigureAwait(false);
            if (body is null)
            {
                return TokenVerification.Inactive;
            }

            using JsonDocument document = JsonDocument.Parse(body);

            JsonElement root = document.RootElement;

            if (root.ValueKind is not JsonValueKind.Object
                || !root.TryGetProperty("active", out JsonElement active)
                || active.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return TokenVerification.Inactive;
            }

            if (active.ValueKind is JsonValueKind.False)
            {
                return TokenVerification.Inactive with { IsAuthoritativeInactive = true };
            }

            return new TokenVerification(
                Active: true,
                Audience: ReadString(root, "aud"),
                Scopes: ReadScopes(root),
                ExpiresAt: ReadFutureExpiration(root, _clock.GetUtcNow()));
        }
        catch (Exception failure) when (failure is HttpRequestException or JsonException or TaskCanceledException)
        {
            // Unreachable issuer, slow issuer, malformed body: all of them mean "this token
            // is not known to be active", which is the only safe answer.
            return TokenVerification.Inactive;
        }
    }

    private void CacheIfAllowed(string key, TokenVerification verification)
    {
        if (_cacheTtlSeconds <= 0)
        {
            return;
        }

        DateTimeOffset now = _clock.GetUtcNow();
        DateTimeOffset? expiresAt = null;

        if (verification.Active && verification.ExpiresAt is { } issuerExpiry && issuerExpiry > now)
        {
            expiresAt = Min(issuerExpiry, now.AddSeconds(_cacheTtlSeconds));
        }
        else if (!verification.Active && verification.IsAuthoritativeInactive)
        {
            expiresAt = now.AddSeconds(Math.Min(NegativeCacheSeconds, _cacheTtlSeconds));
        }

        if (expiresAt is { } usable && usable > now)
        {
            _cache.Set(key, verification, usable, now);
        }
    }

    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right)
        => left <= right ? left : right;

    private static DateTimeOffset? ReadFutureExpiration(JsonElement root, DateTimeOffset now)
    {
        if (!root.TryGetProperty("exp", out JsonElement expiration)
            || expiration.ValueKind is not JsonValueKind.Number
            || !expiration.TryGetInt64(out long seconds))
        {
            return null;
        }

        try
        {
            DateTimeOffset value = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return value > now ? value : null;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static string Digest(string token)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>
    /// Reads an introspection body up to <see cref="MaximumResponseBodyBytes"/>, returning null when
    /// the body exceeds the bound. The length is enforced while streaming so an oversized or
    /// chunked response is never fully buffered before it is refused.
    /// </summary>
    private static async Task<byte[]?> ReadBoundedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is { } declared
            && declared > MaximumResponseBodyBytes)
        {
            return null;
        }

        await using Stream stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using MemoryStream buffer = new();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaximumResponseBodyBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// Resolves the introspection endpoint once, then reuses the answer. Discovery that ran
    /// per request would add a round trip an operator never agreed to, and one that fails
    /// whenever the issuer is slow rather than whenever the token is wrong.
    /// </summary>
    private async Task<string?> ResolveEndpointAsync(CancellationToken cancellationToken)
    {
        if (_endpoint is not null)
        {
            return _endpoint;
        }

        if (_endpointOverride is { } overrideEndpoint)
        {
            return Uri.TryCreate(overrideEndpoint, UriKind.Absolute, out Uri? configured)
                && AuthorizationEndpointPolicy.IsAllowed(configured)
                ? overrideEndpoint
                : null;
        }

        IssuerMetadataDiscovery metadata;

        try
        {
            metadata = await IssuerMetadata.DiscoverAsync(
                _client,
                _issuer,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            return null;
        }

        if (metadata.InvalidReason is not null
            || metadata.Document is not { } discovered
            || !discovered.TryGetProperty("introspection_endpoint", out JsonElement endpoint)
            || endpoint.ValueKind is not JsonValueKind.String
            || endpoint.GetString() is not { } address
            || !Uri.TryCreate(address, UriKind.Absolute, out Uri? resolved)
            || resolved.Scheme is not ("http" or "https")
            || !AuthorizationEndpointPolicy.IsAllowed(resolved))
        {
            return null;
        }

        return _endpoint = address;
    }

    /// <summary>
    /// Reads exactly one audience resource name from either the scalar or array claim form.
    /// </summary>
    /// <remarks>
    /// A singleton JSON array still names exactly one protected resource and is therefore
    /// equivalent to the scalar form. An empty array, a mixed array or a multi-valued array names
    /// no single resource for Engine's byte-exact binding and is refused by returning no audience.
    /// </remarks>
    private static string? ReadString(JsonElement root, string member)
    {
        if (!root.TryGetProperty(member, out JsonElement value))
        {
            return null;
        }

        if (value.ValueKind is JsonValueKind.String)
        {
            return value.GetString();
        }

        if (value.ValueKind is not JsonValueKind.Array)
        {
            return null;
        }

        JsonElement.ArrayEnumerator items = value.EnumerateArray();
        if (!items.MoveNext() || items.Current.ValueKind is not JsonValueKind.String)
        {
            return null;
        }

        string? audience = items.Current.GetString();
        return audience is not null && !items.MoveNext()
            ? audience
            : null;
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

/// <summary>
/// A bounded process-local cache of issuer token-standing facts. It never stores the bearer value.
/// </summary>
internal sealed class IntrospectionResultCache
{
    internal const int MaximumEntries = 4096;

    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    internal int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    internal bool TryGet(string key, DateTimeOffset now, out TokenVerification? verification)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out Entry? entry))
            {
                verification = null;
                return false;
            }

            if (entry.ExpiresAt <= now)
            {
                _entries.Remove(key);
                verification = null;
                return false;
            }

            verification = entry.Verification;
            return true;
        }
    }

    internal void Set(
        string key,
        TokenVerification verification,
        DateTimeOffset expiresAt,
        DateTimeOffset now)
    {
        lock (_gate)
        {
            foreach (string expired in _entries
                         .Where(pair => pair.Value.ExpiresAt <= now)
                         .Select(pair => pair.Key)
                         .ToArray())
            {
                _entries.Remove(expired);
            }

            if (!_entries.ContainsKey(key) && _entries.Count >= MaximumEntries)
            {
                string eviction = _entries
                    .OrderBy(pair => pair.Value.ExpiresAt)
                    .First()
                    .Key;
                _entries.Remove(eviction);
            }

            _entries[key] = new Entry(verification, expiresAt);
        }
    }

    private sealed record Entry(TokenVerification Verification, DateTimeOffset ExpiresAt);
}
