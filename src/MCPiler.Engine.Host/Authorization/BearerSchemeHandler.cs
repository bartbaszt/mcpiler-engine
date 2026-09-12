using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using System.Text.Encodings.Web;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// The authentication handler the SDK's MCP authentication handler forwards to.
/// </summary>
/// <remarks>
/// <para>
/// It answers nothing. The per-request authorization decisions — whether a token is required
/// on this mount, whether it is active, whether it names the addressed resource and carries
/// the declared scopes — are made by the mount middleware, which runs ahead of routing and
/// sees every request, authenticated or not.
/// </para>
/// <para>
/// The handler exists because the SDK's MCP authentication handler forwards authenticate to
/// the scheme named here, and an unregistered scheme is a 500 at the first authenticated
/// mount rather than a 401 the client can act on.
/// </para>
/// </remarks>
internal sealed class BearerSchemeHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public BearerSchemeHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        => Task.FromResult(AuthenticateResult.NoResult());
}