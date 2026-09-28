using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// A loopback authorization server a test owns: RFC 8414 metadata, an RFC 7662 introspection
/// endpoint, and a JWKS. One handler answers all three, keyed on the request path.
/// </summary>
/// <remarks>
/// <para>
/// The engine under test is given this server's loopback address as the issuer, so discovery
/// runs against the real address and every document it names is one the test can also read.
/// The introspection endpoint answers with whatever standing the test declared; the JWKS
/// carries the key the test signs with.
/// </para>
/// <para>
/// Owned by the test that started it and stopped when that test disposes it, like every
/// listener in this suite.
/// </para>
/// </remarks>
internal sealed class FakeAuthorizationServer : IAsyncDisposable
{
    private static readonly TimeSpan ShutdownBudget = TimeSpan.FromSeconds(5);

    private readonly WebApplication _app;

    private FakeAuthorizationServer(
        WebApplication app,
        RSA signingKey,
        RsaSecurityKey parameters,
        bool active,
        Func<int> introspectionCalls)
    {
        _app = app;
        Key = signingKey;
        SigningParameters = parameters;
        Active = active;
        _introspectionCalls = introspectionCalls;
    }

    /// <summary>The loopback address the server bound, which is also the issuer identifier.</summary>
    public Uri Address { get; private init; } = null!;

    /// <summary>The RSA key tokens are signed with.</summary>
    public RSA Key { get; }

    /// <summary>The security-key form minting and the JWKS use.</summary>
    public RsaSecurityKey SigningParameters { get; }

    /// <summary>What the introspection endpoint answers for every presented token.</summary>
    public bool Active { get; }

    /// <summary>How many introspection requests this fake has received.</summary>
    public int IntrospectionCalls => _introspectionCalls();

    private readonly Func<int> _introspectionCalls;

    /// <summary>
    /// A deterministic barrier for an introspection request. It is intentionally owned by the
    /// test rather than by the fake server: the test decides exactly when validation may finish,
    /// which lets it place activation between request admission and downstream handling without
    /// relying on scheduler timing.
    /// </summary>
    public sealed class IntrospectionGate
    {
        private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _armed;

        /// <summary>Completes after a gated <c>/introspect</c> request has passed authentication.</summary>
        public Task Reached => _reached.Task;

        /// <summary>Releases the blocked introspection request.</summary>
        public void Release() => _release.TrySetResult();

        /// <summary>Arms the one test phase that must wait for an explicit release.</summary>
        public void Arm() => Volatile.Write(ref _armed, 1);

        internal async Task WaitAsync(HttpContext context)
        {
            if (Volatile.Read(ref _armed) == 0)
            {
                return;
            }

            _reached.TrySetResult();
            await _release.Task.WaitAsync(context.RequestAborted).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Starts an authorization server whose introspection endpoint demands client
    /// authentication when a credential is supplied, and accepts any caller when none is.
    /// </summary>
    /// <remarks>
    /// The credential is optional rather than always required because the two configurations
    /// are both legitimate and both need a server to talk to: a deployment may introspect
    /// anonymously, and RFC 7662 deployments authenticate. Making the fake always require a
    /// credential would leave the anonymous case untestable, and making it never require one
    /// would leave the authenticated case unprovable.
    /// </remarks>
    /// <param name="active">The standing the endpoint reports for every presented token.</param>
    /// <param name="cancellationToken">Cancels startup.</param>
    /// <param name="introspectionClientId">
    /// The client id the endpoint requires, or <c>null</c> to accept any caller.
    /// </param>
    /// <param name="introspectionClientSecret">
    /// The secret the endpoint requires. Required with <paramref name="introspectionClientId"/>.
    /// </param>
    /// <param name="publishesIntrospection">
    /// Whether the metadata document names an introspection endpoint at all. A real
    /// authorization server that answers only signature validation publishes no such member,
    /// and the engine is expected to refuse to start rather than reject every token.
    /// </param>
    /// <param name="introspectionGate">
    /// An optional test barrier that pauses an authenticated introspection request until released.
    /// </param>
    /// <param name="introspectionExpiresInSeconds">
    /// An optional future <c>exp</c> claim on successful introspection responses. Supplying it
    /// lets cache-boundary tests prove that an active response is eligible for positive caching.
    /// </param>
    public static async Task<FakeAuthorizationServer> StartAsync(
        bool active,
        CancellationToken cancellationToken,
        string? introspectionClientId = null,
        string? introspectionClientSecret = null,
        bool publishesIntrospection = true,
        IntrospectionGate? introspectionGate = null,
        int? introspectionExpiresInSeconds = null)
    {
        if (introspectionClientId is null ^ introspectionClientSecret is null)
        {
            throw new ArgumentException(
                "The introspection credential is one decision: supply both halves or neither.",
                introspectionClientSecret is null ? nameof(introspectionClientId) : nameof(introspectionClientSecret));
        }

        RSA signing = RSA.Create(2048);
        RsaSecurityKey parameters = new(signing.ExportParameters(true)) { KeyId = "test-key-1" };

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        WebApplication app = builder.Build();

        bool introspectionActive = active;
        string? requiredClientId = introspectionClientId;
        string? requiredSecret = introspectionClientSecret;
        bool advertisesIntrospection = publishesIntrospection;
        int? expirationSeconds = introspectionExpiresInSeconds;
        int introspectionCalls = 0;

        app.Run(async context =>
        {
            string path = context.Request.Path.Value ?? string.Empty;
            string host = context.Request.Host.Value ?? string.Empty;

            if (path.EndsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal))
            {
                // token_endpoint_auth_methods_supported is stated because a resource server that
                // has to authenticate needs to know the methods the issuer accepts, and a fake
                // that omitted it would not describe the real one.
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                string issuer = "http://" + host + "/";
                string metadata = advertisesIntrospection
                    ? "{\"issuer\":\"" + issuer
                        + "\",\"introspection_endpoint\":\"http://" + host
                        + "/introspect\",\"jwks_uri\":\"http://" + host
                        + "/jwks\",\"introspection_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}"
                    : "{\"issuer\":\"" + issuer
                        + "\",\"jwks_uri\":\"http://" + host + "/jwks\"}";

                await context.Response.WriteAsync(metadata, context.RequestAborted);
                return;
            }

            if (string.Equals(path, "/introspect", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref introspectionCalls);

                // A real introspection endpoint echoes the claims of the presented token.
                // The audience and scopes are read from the token itself, unverified: this
                // fake answers whatever standing the test declared about the token.
                if (!context.Request.HasFormContentType)
                {
                    context.Response.StatusCode = 400;
                    return;
                }

                if (requiredClientId is not null
                    && !Authenticates(context.Request, requiredClientId, requiredSecret!))
                {
                    // RFC 7662 requires the endpoint to be protected: a caller that cannot
                    // authenticate learns nothing about the token, not even whether it exists.
                    context.Response.StatusCode = 401;
                    return;
                }

                if (introspectionGate is not null)
                {
                    await introspectionGate.WaitAsync(context).ConfigureAwait(false);
                }

                string presented = context.Request.Form["token"].ToString();
                string audience = AudienceOf(presented);
                string scopes = ScopeOf(presented);
                string expiration = expirationSeconds is { } seconds
                    ? $", \"exp\": {DateTimeOffset.UtcNow.AddSeconds(seconds).ToUnixTimeSeconds()}"
                    : string.Empty;

                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    $$"""{ "active": {{introspectionActive.ToString().ToLowerInvariant()}}, "aud": "{{audience}}", "scope": "{{scopes}}"{{expiration}} }""",
                    context.RequestAborted);
                return;
            }

            if (string.Equals(path, "/jwks", StringComparison.Ordinal))
            {
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    Jwks(parameters),
                    context.RequestAborted);
                return;
            }

            context.Response.StatusCode = 404;
        });

        await app.StartAsync(cancellationToken);

        string bound = app.Urls.Single();

        return new FakeAuthorizationServer(
            app,
            signing,
            parameters,
            active,
            () => Volatile.Read(ref introspectionCalls))
        {
            Address = new Uri(bound, UriKind.Absolute),
        };
    }

    /// <summary>
    /// Signs a bearer token naming <paramref name="audience"/> and carrying
    /// <paramref name="scopes"/>, issued by this server.
    /// </summary>
    public string Mint(string audience, string scopes, DateTime? notAfter = null)
    {
        JsonWebTokenHandler handler = new();

        string token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Address.AbsoluteUri,
            Audience = audience,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "test-client",
                ["scope"] = scopes,
            },
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = notAfter ?? DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(SigningParameters, SecurityAlgorithms.RsaSha256),
        });

        return token;
    }

    /// <summary>
    /// Signs a bearer token that carries no optional identity claim.
    /// </summary>
    /// <remarks>
    /// A standards-compliant issuer is free to omit <c>sub</c> and <c>client_id</c>, and the
    /// authorization boundary must admit such a token: nothing in the protected-resource duties
    /// depends on either claim, and a boundary that required one would reject tokens it has no
    /// contract to reject. The audience and scopes are the facts the boundary is defined on.
    /// </remarks>
    /// <param name="audience">The resource the token is addressed to.</param>
    /// <param name="scopes">The scopes the token carries.</param>
    public string MintWithoutIdentityClaims(string audience, string scopes)
    {
        JsonWebTokenHandler handler = new();

        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Address.AbsoluteUri,
            Audience = audience,
            Claims = new Dictionary<string, object>
            {
                ["scope"] = scopes,
            },
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(SigningParameters, SecurityAlgorithms.RsaSha256),
        });
    }

    /// <summary>Serializes the public half of the signing key as a JWKS document.</summary>
    private static string Jwks(RsaSecurityKey parameters)
    {
        JsonWebKey key = JsonWebKeyConverter.ConvertFromRSASecurityKey(parameters);
        key.Kid ??= "test-key-1";

        return $$"""{ "keys": [ { "kty": "{{key.Kty}}", "kid": "{{key.Kid}}", "n": "{{key.N}}", "e": "{{key.E}}", "alg": "RS256", "use": "sig" } ] }""";
    }

    /// <summary>
    /// Whether the request carries exactly the expected <c>client_secret_basic</c> credential.
    /// </summary>
    /// <remarks>
    /// Both halves are compared, and the comparison is ordinal: an endpoint that accepted any
    /// client id or any secret would let the negative cases pass while proving nothing.
    /// </remarks>
    private static bool Authenticates(HttpRequest request, string clientId, string secret)
    {
        string header = request.Headers.Authorization.ToString();

        if (!header.StartsWith("Basic ", StringComparison.Ordinal))
        {
            return false;
        }

        string decoded;

        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..].Trim()));
        }
        catch (FormatException)
        {
            return false;
        }

        int separator = decoded.IndexOf(':', StringComparison.Ordinal);

        if (separator < 0)
        {
            return false;
        }

        string presentedId = Uri.UnescapeDataString(decoded[..separator]);
        string presentedSecret = Uri.UnescapeDataString(decoded[(separator + 1)..]);

        return string.Equals(presentedId, clientId, StringComparison.Ordinal)
            && string.Equals(presentedSecret, secret, StringComparison.Ordinal);
    }

    /// <summary>Reads the audience of a presented JWT without verifying it.</summary>
    private static string AudienceOf(string token)
    {
        // A JWE carries five segments and its claims are encrypted, so there is nothing to read.
        // The fake answers an empty audience for one, which the engine's byte-exact comparison
        // then refuses: the same refusal a real opaque token would earn.
        string[] parts = token.Split('.');

        if (parts.Length != 3)
        {
            return string.Empty;
        }

        string payload = Segment(token, 1);
        JsonNode? claims = JsonNode.Parse(payload);

        return claims?["aud"]?.GetValue<string>() ?? string.Empty;
    }

    /// <summary>Reads the scope claim of a presented JWT without verifying it.</summary>
    private static string ScopeOf(string token)
    {
        if (token.Split('.').Length != 3)
        {
            return string.Empty;
        }

        JsonNode? claims = JsonNode.Parse(Segment(token, 1));

        return claims?["scope"]?.GetValue<string>() ?? string.Empty;
    }

    /// <summary>
    /// Mints a token that is signed and then encrypted, the way an issuer with an encryption
    /// credential produces one.
    /// </summary>
    /// <remarks>
    /// A JWE is the shape a resource server using signature-only validation cannot read. The
    /// engine must contain that as a refusal, not as an unhandled failure: the difference is
    /// between a 401 a client can act on and a 500 that reads as a defect.
    /// </remarks>
    /// <param name="audience">The resource the token is addressed to.</param>
    /// <param name="scopes">The scopes the token carries.</param>
    public string MintEncrypted(string audience, string scopes)
    {
        using Aes encryption = Aes.Create();
        encryption.KeySize = 256;

        JsonWebTokenHandler handler = new();

        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Address.AbsoluteUri,
            Audience = audience,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "test-client",
                ["scope"] = scopes,
            },
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(SigningParameters, SecurityAlgorithms.RsaSha256),
            EncryptingCredentials = new EncryptingCredentials(
                new SymmetricSecurityKey(encryption.Key),
                SecurityAlgorithms.Aes256KW,
                SecurityAlgorithms.Aes128CbcHmacSha256),
        });
    }

    /// <summary>The URL-safe base64 segment at <paramref name="index"/> of a compact JWT.</summary>
    private static string Segment(string token, int index)
    {
        string[] parts = token.Split('.');
        byte[] bytes = Convert.FromBase64String(parts[index].PadRight(parts[index].Length + ((4 - (parts[index].Length % 4)) % 4), '='));
        return Encoding.UTF8.GetString(bytes);
    }

    public async ValueTask DisposeAsync()
    {
        using var shutdown = new CancellationTokenSource(ShutdownBudget);

        try
        {
            await _app.StopAsync(shutdown.Token);
        }
        finally
        {
            await _app.DisposeAsync();
            Key.Dispose();
        }
    }
}
