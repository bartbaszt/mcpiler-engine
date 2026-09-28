using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
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
/// <para>
/// Authorization resolves through the request admission made before this middleware, so the mount
/// state that decides whether a token is required and the surface whose scopes are checked both
/// come from the same immutable generation.
/// </para>
/// </remarks>
internal sealed class MountAuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ITokenValidator _tokens;
    private readonly CallerPartitionKey _partitions;

    /// <summary>
    /// The middleware constructor. Public because the middleware convention requires it; the
    /// validator and the partition key are registered and the next delegate is supplied by the
    /// pipeline.
    /// </summary>
    public MountAuthorizationMiddleware(
        RequestDelegate next,
        ITokenValidator tokens,
        CallerPartitionKey partitions)
    {
        _next = next;
        _tokens = tokens;
        _partitions = partitions;
    }

    /// <summary>
    /// The request pipeline entry. Public because the middleware convention requires it; the
    /// decision inside is mount state and issuer configuration, nothing else.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Features.Get<EngineRequestGenerationAdmission>() is not { } admission)
        {
            // Admission is installed before this middleware for every surface and transfer child.
            // A request without it is a non-surface host endpoint, so there is no mount decision
            // to make here.
            await _next(context);
            return;
        }

        SurfaceEndpoint route = context.GetEndpoint()?.Metadata.GetMetadata<SurfaceEndpoint>()
            ?? new SurfaceEndpoint(admission.Address, admission.Address);

        if (!string.Equals(
                admission.Address,
                RequestAddress.Resolve(context, route),
                StringComparison.Ordinal))
        {
            await RefuseSilentlyAsync(context).ConfigureAwait(false);
            return;
        }

        // Resolution address and authorization resource are deliberately different facts. Route
        // resolution may fold a trailing slash onto the mapped surface; authorization never does.
        // Transfer children already carry/inherit their exact parent resource in the admission.
        string resourcePath = admission.AuthorizationResourcePath;

        if (!admission.Resolution.Mount.RequiresAuthorization())
        {
            // An open mount states its identity explicitly rather than leaving a consumer to
            // infer one from an absence: every caller of this mount shares one public partition.
            admission.CallerPartition = CallerPartition.Public;
            await _next(context);
            return;
        }

        (TokenVerification verification, string? presented) = await VerifyAsync(context).ConfigureAwait(false);

        if (!verification.Active)
        {
            await ChallengeAsync(context, resourcePath).ConfigureAwait(false);
            return;
        }

        string canonical = admission.ResourceIdentity;

        if (verification.Audience is null
            || !MountAuthorization.AudienceNames(verification.Audience, canonical))
        {
            await RefuseSilentlyAsync(context).ConfigureAwait(false);
            return;
        }

        foreach (string scope in admission.Resolution.Surface.RequiredScopes)
        {
            if (!verification.Scopes.Contains(scope, StringComparer.Ordinal))
            {
                await RefuseSilentlyAsync(context).ConfigureAwait(false);
                return;
            }
        }

        // Derived here because this is the only place the authorization decision was made: the
        // presented token, the resource it was admitted for and the scopes it carried are all
        // available together, and nowhere else are they. A partition derived anywhere else would
        // be derived from facts some other component believed rather than from what was decided.
        admission.CallerPartition = new CallerPartition(
            CallerPartitionDerivation.Derive(presented!, canonical, verification.Scopes, _partitions.Value),
            IsCallerSpecific: true);

        await _next(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the bearer token, admitting no other scheme, no other placement and no
    /// credentials that parse to nothing.
    /// </summary>
    private async Task<(TokenVerification Verification, string? Presented)> VerifyAsync(HttpContext context)
    {
        string? header = context.Request.Headers.Authorization.ToString();

        if (header is null || !header.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            return (TokenVerification.Inactive, null);
        }

        string token = header["Bearer ".Length..].Trim();

        if (token.Length == 0)
        {
            return (TokenVerification.Inactive, null);
        }

        return (await _tokens.ValidateAsync(token, context.RequestAborted).ConfigureAwait(false), token);
    }

    /// <summary>
    /// The refusal for a request with no token the issuer will vouch for. Status 401, no
    /// body, the bearer challenge pointing at the addressed surface's protected-resource
    /// metadata — identical for an inactive token and no token at all. The challenge is the
    /// one exception to the byte-identical rule: it is the discovery step that lets a client
    /// ever come back authorized, and an unknown resource would answer with nothing, which is
    /// what "unknown" has to mean to a client that has not authenticated yet.
    /// </summary>
    private static Task ChallengeAsync(HttpContext context, string resourcePath)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;

        // The resource_metadata URI mirrors the request path under the well-known prefix,
        // except for transfer children, which inherit their parent MCP surface rather than
        // becoming protected resources of their own. The caller has already resolved that
        // parent path from request admission or endpoint metadata; no route is re-resolved here.
        string metadata = $"{context.Request.Scheme}://{context.Request.Host.Value}"
            + "/.well-known/oauth-protected-resource"
            + resourcePath;

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
    /// <remarks>
    /// <para>
    /// A configured introspection client reads its secret first, before any client is
    /// constructed, so an unusable file throws without leaving an undisposed <see cref="HttpClient"/>
    /// behind. The refusal names the path and never the value.
    /// </para>
    /// <para>
    /// The client's timeout is bounded well below the stock 100 seconds because this client sits
    /// on the request path of every protected call. A validator that waited the default would hold
    /// a client's connection open for over a minute while the issuer is unreachable, and the answer
    /// in that case is already known: the token cannot be established, so it is inactive. The
    /// validator's own catch turns the timeout into that inactive answer.
    /// </para>
    /// </remarks>
    internal static ITokenValidator Validator(HostAuthorizationOptions options)
    {
        string? secret = ReadIntrospectionSecret(options);
        HttpClient client = AuthorizationHttpClientFactory.Create(ValidationTimeout);

        return options.Validation switch
        {
            HostTokenValidation.Introspection => new IntrospectionTokenValidator(
                client,
                options.Issuer,
                options.IntrospectionEndpoint,
                options.IntrospectionClientId,
                secret,
                options.IntrospectionCacheTtlSeconds),
            HostTokenValidation.Jwks => new JwksTokenValidator(
                client,
                options.Issuer,
                options.JwksUri),
            _ => throw new InvalidOperationException(
                "The token validation configuration was validated at bind time; an unknown mode here is a bug."),
        };
    }

    /// <summary>
    /// Validates local authorization startup material without constructing the validator.
    /// </summary>
    /// <remarks>
    /// The same reader is used by <see cref="Validator"/>. Returning a structured refusal here
    /// lets <c>inspect</c> and <c>serve</c> agree about a missing, empty or unreadable
    /// introspection client secret before either path builds a web host.
    /// </remarks>
    internal static StartupRefusal? FindStartupRefusal(HostAuthorizationOptions options)
    {
        if (options.IntrospectionClientSecretFile is not { } path)
        {
            return null;
        }

        if (IntrospectionClientSecret.TryRead(path, out _, out string? refusal))
        {
            return null;
        }

        return new StartupRefusal(
            string.Empty,
            "auth/introspection-client-secret-unusable",
            $"The introspection client is configured but its secret is unusable: {refusal}")
        {
            Setting = HostConfiguration.IntrospectionClientSecretFileKey,
        };
    }

    /// <summary>
    /// How long validation waits on the issuer.
    /// </summary>
    /// <remarks>
    /// Chosen to sit inside the MCP request budget while still allowing a slow issuer on a
    /// congested link to answer. A timeout is not an error condition here: it produces the same
    /// inactive-token answer an unreachable issuer produces, because a token whose standing cannot
    /// be established is one no resource server may admit.
    /// </remarks>
    private static readonly TimeSpan ValidationTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The introspection client's secret, when one is configured.
    /// </summary>
    /// <remarks>
    /// An unreadable file throws, which the caller turns into a startup refusal: a resource server
    /// that started with an unusable credential would reject every token, and that is
    /// indistinguishable at the client from a misconfigured client.
    /// </remarks>
    private static string? ReadIntrospectionSecret(HostAuthorizationOptions options)
    {
        if (options.IntrospectionClientSecretFile is not { } path)
        {
            return null;
        }

        if (!IntrospectionClientSecret.TryRead(path, out string secret, out string? refusal))
        {
            throw new InvalidOperationException(
                $"The introspection client is configured but its secret is unusable: {refusal}");
        }

        return secret;
    }
}
