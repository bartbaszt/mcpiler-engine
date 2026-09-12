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

    private FakeAuthorizationServer(WebApplication app, RSA signingKey, RsaSecurityKey parameters, bool active)
    {
        _app = app;
        Key = signingKey;
        SigningParameters = parameters;
        Active = active;
    }

    /// <summary>The loopback address the server bound, which is also the issuer identifier.</summary>
    public Uri Address { get; private init; } = null!;

    /// <summary>The RSA key tokens are signed with.</summary>
    public RSA Key { get; }

    /// <summary>The security-key form minting and the JWKS use.</summary>
    public RsaSecurityKey SigningParameters { get; }

    /// <summary>What the introspection endpoint answers for every presented token.</summary>
    public bool Active { get; }

    /// <summary>Starts an authorization server whose introspection answers the fixed standing.</summary>
    public static async Task<FakeAuthorizationServer> StartAsync(
        bool active,
        CancellationToken cancellationToken)
    {
        RSA signing = RSA.Create(2048);
        RsaSecurityKey parameters = new(signing.ExportParameters(true)) { KeyId = "test-key-1" };

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        WebApplication app = builder.Build();

        bool introspectionActive = active;

        app.Run(async context =>
        {
            string path = context.Request.Path.Value ?? string.Empty;
            string host = context.Request.Host.Value ?? string.Empty;

            if (path.EndsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal))
            {
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    $$"""{ "issuer": "http://{{host}}", "introspection_endpoint": "http://{{host}}/introspect", "jwks_uri": "http://{{host}}/jwks" }""",
                    context.RequestAborted);
                return;
            }

            if (string.Equals(path, "/introspect", StringComparison.Ordinal))
            {
                // A real introspection endpoint echoes the claims of the presented token.
                // The audience and scopes are read from the token itself, unverified: this
                // fake answers whatever standing the test declared about the token.
                if (!context.Request.HasFormContentType)
                {
                    context.Response.StatusCode = 400;
                    return;
                }

                string presented = context.Request.Form["token"].ToString();
                string audience = AudienceOf(presented);
                string scopes = ScopeOf(presented);

                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    $$"""{ "active": {{introspectionActive.ToString().ToLowerInvariant()}}, "aud": "{{audience}}", "scope": "{{scopes}}" }""",
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

        return new FakeAuthorizationServer(app, signing, parameters, active)
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

    /// <summary>Serializes the public half of the signing key as a JWKS document.</summary>
    private static string Jwks(RsaSecurityKey parameters)
    {
        JsonWebKey key = JsonWebKeyConverter.ConvertFromRSASecurityKey(parameters);
        key.Kid ??= "test-key-1";

        return $$"""{ "keys": [ { "kty": "{{key.Kty}}", "kid": "{{key.Kid}}", "n": "{{key.N}}", "e": "{{key.E}}", "alg": "RS256", "use": "sig" } ] }""";
    }

    /// <summary>Reads the audience of a presented JWT without verifying it.</summary>
    private static string AudienceOf(string token)
    {
        string payload = Segment(token, 1);
        JsonNode? claims = JsonNode.Parse(payload);

        return claims?["aud"]?.GetValue<string>() ?? string.Empty;
    }

    /// <summary>Reads the scope claim of a presented JWT without verifying it.</summary>
    private static string ScopeOf(string token)
    {
        JsonNode? claims = JsonNode.Parse(Segment(token, 1));

        return claims?["scope"]?.GetValue<string>() ?? string.Empty;
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