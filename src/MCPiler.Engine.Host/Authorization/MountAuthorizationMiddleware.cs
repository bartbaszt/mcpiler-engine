using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// The authorization boundary of one serving process, applied per request.
/// </summary>
/// <remarks>
/// <para>
/// The boundary has two halves that must never be confused. Whether a request is required
/// to carry a token at all is mount state, decided by the library from the Manifest. Whether
/// a presented token authorizes the addressed surface — audience byte-identical to the
/// canonical resource identifier, declared scopes present — is decided here, per request,
/// against the address the request actually used.
/// </para>
/// <para>
/// Every refusal is byte-identical to the refusal for a mount that does not exist: the same
/// status, the same body, the same headers. A refusal that differs by one byte is an
/// existence oracle over mounts, surfaces and tokens, and the whole attack is getting that
/// one byte. The 401 challenge is the exception: it must point at the addressed surface's
/// protected-resource metadata, which an unknown resource also has, because a client that
/// cannot find the metadata cannot ever come back authorized.
/// </para>
/// <para>
/// No scheme other than the bearer token is admitted. A cookie, a shared secret, a header,
/// a source address — none of them substitute for a token where the mount requires one, and
/// none of them widen anything where it does not.
/// </para>
/// </remarks>
internal sealed class MountAuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ITokenValidator _tokens;

    /// <summary>
    /// The middleware constructor. Public because the middleware convention requires it; the
    /// validator is registered, the next delegate is supplied by the pipeline.
    /// </summary>
    public MountAuthorizationMiddleware(RequestDelegate next, ITokenValidator tokens)
    {
        _next = next;
        _tokens = tokens;
    }

    /// <summary>
    /// The request pipeline entry. Public because the middleware convention requires it; the
    /// decision inside is mount state and issuer configuration, nothing else.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<SurfaceEndpoint>() is not { } addressed)
        {
            // No surface metadata means the request matched no route, which routing already
            // answers. Nothing here can disclose what no route reached.
            await _next(context);
            return;
        }

        if (!addressed.Mount.RequiresAuthorization())
        {
            await _next(context);
            return;
        }

        TokenVerification verification = await VerifyAsync(context).ConfigureAwait(false);

        if (!verification.Active)
        {
            await ChallengeAsync(context).ConfigureAwait(false);
            return;
        }

        string canonical = MountAuthorization.CanonicalResource(
            context.Request.Scheme,
            context.Request.Host.Value ?? string.Empty,
            context.Request.Path.Value ?? "/");

        if (verification.Audience is null
            || !MountAuthorization.AudienceNames(verification.Audience, canonical))
        {
            await RefuseSilentlyAsync(context).ConfigureAwait(false);
            return;
        }

        foreach (string scope in addressed.Surface.RequiredScopes)
        {
            if (!verification.Scopes.Contains(scope, StringComparer.Ordinal))
            {
                await RefuseSilentlyAsync(context).ConfigureAwait(false);
                return;
            }
        }

        await _next(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the bearer token, admitting no other scheme, no other placement and no
    /// credentials that parse to nothing.
    /// </summary>
    private async Task<TokenVerification> VerifyAsync(HttpContext context)
    {
        string? header = context.Request.Headers.Authorization.ToString();

        if (header is null || !header.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            return TokenVerification.Inactive;
        }

        string token = header["Bearer ".Length..].Trim();

        if (token.Length == 0)
        {
            return TokenVerification.Inactive;
        }

        return await _tokens.ValidateAsync(token, context.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>
    /// The refusal for a request with no token the issuer will vouch for. Status 401, no
    /// body, the bearer challenge pointing at the addressed surface's protected-resource
    /// metadata — identical for an inactive token and no token at all. The challenge is the
    /// one exception to the byte-identical rule: it is the discovery step that lets a client
    /// ever come back authorized, and an unknown resource would answer with nothing, which is
    /// what "unknown" has to mean to a client that has not authenticated yet.
    /// </summary>
    private static Task ChallengeAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;

        // The resource_metadata URI mirrors the request path under the well-known prefix,
        // which is the SDK handler's own derivation and the address a client rediscovers
        // the metadata document at.
        string metadata = $"{context.Request.Scheme}://{context.Request.Host.Value}"
            + "/.well-known/oauth-protected-resource"
            + context.Request.Path.Value;

        context.Response.Headers.WWWAuthenticate = $"Bearer resource_metadata=\"{metadata}\"";

        return Task.CompletedTask;
    }

    /// <summary>
    /// The refusal for a token the issuer vouched for but that names another resource or
    /// carries too few scopes: 404, empty, no headers — byte-identical to the response for a
    /// route that was never mapped.
    /// </summary>
    /// <remarks>
    /// A 401 here would tell a caller that the addressed mount exists, which is the oracle
    /// the uniform-refusal requirement exists to close. The caller holds a valid token; the
    /// token just does not name this resource, and the answer is the same as for a resource
    /// that was never mounted.
    /// </remarks>
    private static Task RefuseSilentlyAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }
}

/// <summary>
/// Composes the per-process authorization machinery from the bound configuration.
/// </summary>
internal static class MountAuthorizationSetup
{
    /// <summary>
    /// The scheme name the SDK's MCP authentication handler forwards authenticate to.
    /// </summary>
    /// <remarks>
    /// The constant is the SDK's own convention ("Bearer", the JwtBearer scheme name it
    /// deliberately does not take a package reference to name). A handler registered under
    /// this name satisfies the forward; the actual per-request decisions live in the mount
    /// middleware, which runs before routing and sees every request.
    /// </remarks>
    internal const string BearerScheme = "Bearer";

    /// <summary>
    /// Whether the bound configuration authorizes anything: mounts that require tokens exist
    /// and an issuer is configured to validate them against.
    /// </summary>
    internal static bool IsConfigured(HostAuthorizationOptions? authorization)
        => authorization is not null;

    /// <summary>Builds the validator the configured validation mode selects.</summary>
    internal static ITokenValidator Validator(HostAuthorizationOptions options)
    {
        HttpClient client = new();

        return options.Validation switch
        {
            HostTokenValidation.Introspection => new IntrospectionTokenValidator(
                client,
                options.Issuer,
                options.IntrospectionEndpoint),
            HostTokenValidation.Jwks => new JwksTokenValidator(
                client,
                options.Issuer,
                options.JwksUri),
            _ => throw new InvalidOperationException(
                "The token validation configuration was validated at bind time; an unknown mode here is a bug."),
        };
    }
}