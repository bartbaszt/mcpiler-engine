using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// Deterministic local OAuth grant endpoint for real HTTP tests. Only request counts are
/// observable; codes, PKCE verifiers and issued credentials never appear in diagnostics.
/// </summary>
internal sealed class AuthorizationCodeProviderScenario(
    string registeredRedirectUri = "http://127.0.0.1:57431/oauth/callback")
{
    private const string RegisteredClientId = "test-client";
    private readonly ConcurrentDictionary<string, PendingCode> _codes = new(StringComparer.Ordinal);
    private int _authorizationRequests;
    private int _tokenRequests;
    private int _refreshRequests;
    private int _revocationRequests;

    internal string AccessToken { get; } = "CANARY-access-token-8d17";
    internal string RefreshToken { get; } = "CANARY-refresh-token-d53e";
    internal int AuthorizationRequests => Volatile.Read(ref _authorizationRequests);
    internal int TokenRequests => Volatile.Read(ref _tokenRequests);
    internal int RefreshRequests => Volatile.Read(ref _refreshRequests);
    internal int RevocationRequests => Volatile.Read(ref _revocationRequests);

    /// <summary>How the declared revocation endpoint answers, so a clear can be tested against each case.</summary>
    internal RevocationBehaviour Revocation { get; set; } = RevocationBehaviour.Succeed;

    /// <summary>
    /// How long the revocation endpoint withholds its answer. Zero answers at once; a test that
    /// wants to observe the bounded attempt cancels its own token instead of waiting it out.
    /// </summary>
    internal TimeSpan RevocationDelay { get; set; }

    internal async Task<bool> HandleAsync(HttpContext context)
    {
        if (context.Request.Path == "/revoke")
        {
            Interlocked.Increment(ref _revocationRequests);

            if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasFormContentType)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return true;
            }

            var revocation = await context.Request.ReadFormAsync(context.RequestAborted);

            // A revocation request names the token it retires; the fixture never echoes it back and
            // never records it, so a token cannot reach a diagnostic through this path.
            if (!OneNonEmpty(revocation, "token")
                || !ExactlyOne(revocation, "client_id", RegisteredClientId)
                || !ExactlyOne(revocation, "token_type_hint", "refresh_token"))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("{\"error\":\"invalid_request\"}", context.RequestAborted);
                return true;
            }

            if (RevocationDelay > TimeSpan.Zero)
            {
                await Task.Delay(RevocationDelay, context.RequestAborted);
            }

            if (Revocation == RevocationBehaviour.Reject)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("{\"error\":\"invalid_request\",\"error_description\":\"CANARY-revocation-secret-4a1f\"}", context.RequestAborted);
                return true;
            }

            context.Response.StatusCode = StatusCodes.Status200OK;
            return true;
        }

        if (context.Request.Path == "/authorize")
        {
            Interlocked.Increment(ref _authorizationRequests);
            var query = context.Request.Query;
            if (!ExactlyOne(query, "response_type", "code")
                || !ExactlyOne(query, "code_challenge_method", "S256")
                || !ExactlyOne(query, "client_id", RegisteredClientId)
                || !OneNonEmpty(query, "state")
                || !OneNonEmpty(query, "code_challenge")
                || !OneNonEmpty(query, "redirect_uri")
                || !Uri.TryCreate(query["redirect_uri"].ToString(), UriKind.Absolute, out Uri? redirect)
                || redirect.Scheme != Uri.UriSchemeHttp
                || !IsLoopbackHost(redirect.Host)
                || !string.Equals(redirect.AbsoluteUri, registeredRedirectUri, StringComparison.Ordinal)
                || !IsChallenge(query["code_challenge"].ToString()))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return true;
            }

            string code = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            _codes[code] = new PendingCode(
                query["client_id"].ToString(),
                redirect.AbsoluteUri,
                query["code_challenge"].ToString());
            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = redirect
                + (string.IsNullOrEmpty(redirect.Query) ? "?" : "&")
                + "code=" + Uri.EscapeDataString(code)
                + "&state=" + Uri.EscapeDataString(query["state"].ToString());
            return true;
        }

        if (context.Request.Path == "/token")
        {
            Interlocked.Increment(ref _tokenRequests);
            if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasFormContentType)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return true;
            }

            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            if (ExactlyOne(form, "grant_type", "refresh_token"))
            {
                Interlocked.Increment(ref _refreshRequests);
                if (!ExactlyOne(form, "client_id", RegisteredClientId)
                    || !ExactlyOne(form, "refresh_token", RefreshToken))
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("{\"error\":\"invalid_grant\"}", context.RequestAborted);
                    return true;
                }

                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    access_token = AccessToken,
                    token_type = "Bearer",
                    expires_in = 300,
                }), context.RequestAborted);
                return true;
            }

            if (!ExactlyOne(form, "grant_type", "authorization_code")
                || !OneNonEmpty(form, "client_id")
                || !OneNonEmpty(form, "code")
                || !OneNonEmpty(form, "redirect_uri")
                || !OneNonEmpty(form, "code_verifier")
                || !_codes.TryGetValue(form["code"].ToString(), out var pending)
                || pending.ClientId != form["client_id"].ToString()
                || pending.RedirectUri != form["redirect_uri"].ToString()
                || !string.Equals(pending.Challenge, Challenge(form["code_verifier"].ToString()), StringComparison.Ordinal)
                || !_codes.TryRemove(form["code"].ToString(), out _))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"error\":\"invalid_grant\"}", context.RequestAborted);
                return true;
            }

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(new
            {
                access_token = AccessToken,
                refresh_token = RefreshToken,
                token_type = "Bearer",
                expires_in = 300,
            }), context.RequestAborted);
            return true;
        }

        return false;
    }

    internal static string Challenge(string verifier)
        => Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool IsLoopbackHost(string host)
        => string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || System.Net.IPAddress.TryParse(host, out var ip) && System.Net.IPAddress.IsLoopback(ip);

    private static bool IsChallenge(string value)
        => value.Length == 43 && value.All(static ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_');

    private static bool ExactlyOne(IQueryCollection values, string key, string expected)
        => values.TryGetValue(key, out var found) && found.Count == 1 && found[0] == expected;
    private static bool OneNonEmpty(IQueryCollection values, string key)
        => values.TryGetValue(key, out var found) && found.Count == 1 && !string.IsNullOrWhiteSpace(found[0]);
    private static bool ExactlyOne(IFormCollection values, string key, string expected)
        => values.TryGetValue(key, out var found) && found.Count == 1 && found[0] == expected;
    private static bool OneNonEmpty(IFormCollection values, string key)
        => values.TryGetValue(key, out var found) && found.Count == 1 && !string.IsNullOrWhiteSpace(found[0]);

    private sealed record PendingCode(string ClientId, string RedirectUri, string Challenge);
}

/// <summary>How the fixture's declared revocation endpoint answers a bounded revocation attempt.</summary>
internal enum RevocationBehaviour
{
    /// <summary>Accept the request, as a provider that retired the token would.</summary>
    Succeed,

    /// <summary>Refuse the request with a secret-bearing body the Engine must never echo.</summary>
    Reject,
}
