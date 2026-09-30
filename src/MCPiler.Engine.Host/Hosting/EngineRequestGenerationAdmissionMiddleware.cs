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

    public EngineRequestGenerationAdmissionMiddleware(
        RequestDelegate next,
        EngineGenerationManager generations)
    {
        _next = next;
        _generations = generations;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        string? address = AddressOf(context);

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

            string requestDerivedIdentity = MountAuthorization.CanonicalResource(
                context.Request.Scheme,
                context.Request.Host.Value ?? string.Empty,
                address);
            string resourceIdentity = lease.Generation.EffectiveResourceIdentity(
                resolved,
                requestDerivedIdentity);

            context.Features.Set(new EngineRequestGenerationAdmission(
                address,
                resourceIdentity,
                lease.Generation,
                resolved));

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

    private static string? AddressOf(HttpContext context)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<SurfaceEndpoint>() is { } route)
        {
            return RequestAddress.Resolve(context, route);
        }

        // A managed catch-all can receive a transfer child before the transfer dispatcher clears
        // the endpoint. Recognize it here so parent authorization and transfer execution share the
        // same admission even when endpoint routing exposes no SurfaceEndpoint metadata for the
        // child path.
        return TransferPath.TryParse(context.Request.Path.Value, out TransferPath transfer)
            ? transfer.ParentAddress
            : null;
    }

    private static Task RefuseSilentlyAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }
}
