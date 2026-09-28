using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Files;
using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// Owns exactly one generation lease for each Engine surface or transfer HTTP request.
/// </summary>
/// <remarks>
/// This boundary is deliberately independent of authorization configuration. Open surfaces need the
/// same route/list/call/transfer consistency as protected surfaces, while health and unrelated host
/// endpoints do not address an Engine surface and therefore do not acquire a generation lease.
/// </remarks>
internal sealed class EngineRequestGenerationAdmissionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly EngineGenerationManager _generations;
    private readonly HostBinding _binding;

    public EngineRequestGenerationAdmissionMiddleware(
        RequestDelegate next,
        EngineGenerationManager generations,
        HostBinding binding)
    {
        _next = next;
        _generations = generations;
        _binding = binding;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        SurfaceEndpoint? route = context.GetEndpoint()?.Metadata.GetMetadata<SurfaceEndpoint>();

        if (!TryAddressOf(context, route, out string? address, out string authorizationResourcePath))
        {
            await RefuseSilentlyAsync(context).ConfigureAwait(false);
            return;
        }

        if (address is null)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!_generations.TryLease(out EngineGenerationLease? lease) || lease is null)
        {
            await RefuseSilentlyAsync(context).ConfigureAwait(false);
            return;
        }

        using (lease)
        {
            if (!lease.Generation.TryResolve(address, out SurfaceResolution? resolved)
                || resolved is null)
            {
                await RefuseSilentlyAsync(context).ConfigureAwait(false);
                return;
            }

            if (resolved.Mount.RequiresAuthorization()
                && (_binding.Authorization is null
                    || !AuthorityAllowed(context.Request.Host.Value, _binding.AllowedHosts)))
            {
                // Defense in depth for managed mode: a protected generation must never flow to
                // handlers when this listener was built without an authorization boundary, even
                // if a future activation bug admitted the generation.
                await RefuseSilentlyAsync(context).ConfigureAwait(false);
                return;
            }

            string resourceIdentity = MountAuthorization.CanonicalResource(
                context.Request.Scheme,
                context.Request.Host.Value ?? string.Empty,
                authorizationResourcePath);

            var admission = new EngineRequestGenerationAdmission(
                address,
                authorizationResourcePath,
                resourceIdentity,
                lease.Generation,
                resolved);

            if (!resolved.Mount.RequiresAuthorization())
            {
                // Public is a positive decision about an open mount, not the default identity of
                // a request whose authorization decision has not happened yet.
                admission.CallerPartition = CallerPartition.Public;
            }

            context.Features.Set(admission);

            try
            {
                await _next(context).ConfigureAwait(false);
            }
            finally
            {
                // The HttpContext is not reused as an admission source after the request, and
                // clearing the feature makes that lifetime boundary explicit for test hosts and
                // middleware that retain a context reference during teardown.
                context.Features.Set<EngineRequestGenerationAdmission>(null);
            }
        }
    }

    private static bool TryAddressOf(
        HttpContext context,
        SurfaceEndpoint? route,
        out string? address,
        out string authorizationResourcePath)
    {
        string decodedPath = context.Request.Path.Value ?? "/";

        if (TransferPath.TryParse(decodedPath, out _))
        {
            if (!RequestAddress.TryResolveCanonicalTransfer(
                    context,
                    out TransferPath decodedTransfer,
                    out TransferPath rawTransfer))
            {
                address = null;
                authorizationResourcePath = string.Empty;
                return false;
            }

            address = RequestAddress.NormalizeResolutionAddress(decodedTransfer.ParentAddress);
            authorizationResourcePath = rawTransfer.ParentAddress;
            return true;
        }

        if (route is null)
        {
            address = null;
            authorizationResourcePath = string.Empty;
            return true;
        }

        address = RequestAddress.Resolve(context, route);
        authorizationResourcePath = route.ResolveAuthorizationResourcePath(context);
        return true;
    }

    internal static bool AuthorityAllowed(string? authority, IReadOnlyList<string> allowed)
        => !string.IsNullOrEmpty(authority)
            && allowed.Any(candidate =>
                string.Equals(candidate, authority, StringComparison.OrdinalIgnoreCase));

    private static Task RefuseSilentlyAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }
}
