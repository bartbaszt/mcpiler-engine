using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.Host.Files;

/// <summary>Maps the streaming file-transfer children of every HTTP MCP surface.</summary>
/// <remarks>
/// <para>
/// A transfer child is addressed relative to its parent MCP surface, so its metadata states the
/// parent address and the transfer handlers consume the request's generation admission. A file
/// handle is issued and redeemed against the same execution graph that serves the surface, which
/// is why the admission matters here as much as on the MCP routes themselves.
/// </para>
/// <para>
/// File mode maps one low-precedence catch-all fallback and recognises transfer children from
/// the request path at runtime. A literal ASP.NET route cannot represent the double slash that a
/// slash-terminated parent resource intentionally produces (for example
/// <c>/api/full//files/upload</c>). The fallback preserves that spelling without weakening the
/// parent-resource contract. Managed mode already has a catch-all MCP template and recognises the
/// same transfer path in middleware. Both paths reach the same handlers.
/// </para>
/// </remarks>
internal static class FileTransferEndpoints
{
    public static void Map(WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Specific MCP/health/operator routes outrank this catch-all. Unknown paths still end in a
        // normal 404; only paths recognised by TransferPath reach the transfer handlers.
        app.MapPost(McpRegistration.ManagedTemplate, FileModeFallbackAsync);
        app.MapGet(McpRegistration.ManagedTemplate, FileModeFallbackAsync);
    }

    private static async Task FileModeFallbackAsync(HttpContext context)
    {
        if (!await TryServeAsync(context).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
        }
    }

    /// <summary>
    /// Serves a transfer path recognised from the request, when the path is one.
    /// </summary>
    /// <remarks>
    /// Returns false for a path that is not a transfer child, so the caller can continue into the
    /// protocol handler. Used by the managed listener, whose single template also matches the
    /// children.
    /// </remarks>
    internal static async Task<bool> TryServeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!TransferPath.TryParse(context.Request.Path.Value, out TransferPath transfer))
        {
            return false;
        }

        SurfaceEndpoint route = new(transfer.ParentAddress, authorizationResourcePath: transfer.ParentAddress);
        context.SetEndpoint(null);

        if (transfer.Kind == TransferPathKind.Upload)
        {
            if (!HttpMethods.IsPost(context.Request.Method))
            {
                context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return true;
            }

            await UploadAsync(context, route).ConfigureAwait(false);
            return true;
        }

        if (!HttpMethods.IsGet(context.Request.Method))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return true;
        }

        await DownloadAsync(context, route, transfer.Capability!).ConfigureAwait(false);
        return true;
    }

    private static async Task UploadAsync(HttpContext context)
    {
        SurfaceEndpoint route = RequiredSurface(context);
        await UploadAsync(context, route).ConfigureAwait(false);
    }

    private static async Task DownloadAsync(HttpContext context)
    {
        SurfaceEndpoint route = RequiredSurface(context);
        string capability = context.Request.RouteValues["capability"]?.ToString() ?? string.Empty;
        await DownloadAsync(context, route, capability).ConfigureAwait(false);
    }

    private static async Task UploadAsync(HttpContext context, SurfaceEndpoint route)
    {
        if (context.Features.Get<EngineRequestGenerationAdmission>() is not { } admission)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        EngineExecution execution = admission.Generation.Execution;
        string resource = admission.ResourceIdentity;
        string? fileName = context.Request.Query["fileName"].FirstOrDefault();

        RuntimeFileUploadResult result = await execution
            .UploadFileAsync(
                context.Request.Body,
                fileName,
                context.Request.ContentType,
                resource,
                context.RequestAborted)
            .ConfigureAwait(false);

        if (!result.Succeeded)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(
                new { error = result.FailureReason },
                context.RequestAborted).ConfigureAwait(false);
            return;
        }

        await context.Response.WriteAsJsonAsync(
            new
            {
                handle = result.Capability,
                fileName = result.FileName,
                mediaType = result.MediaType,
                length = result.Length,
            },
            context.RequestAborted).ConfigureAwait(false);
    }

    private static async Task DownloadAsync(HttpContext context, SurfaceEndpoint route, string capability)
    {
        if (context.Features.Get<EngineRequestGenerationAdmission>() is not { } admission)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        EngineExecution execution = admission.Generation.Execution;
        string resource = admission.ResourceIdentity;

        await using RuntimeFileDownload download = await execution
            .OpenFileAsync(capability, resource, context.RequestAborted)
            .ConfigureAwait(false);

        if (download.Status == RuntimeFileDownloadStatus.Unknown)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (download.Status == RuntimeFileDownloadStatus.Expired)
        {
            context.Response.StatusCode = StatusCodes.Status410Gone;
            return;
        }

        if (download.Content is null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        context.Response.ContentType = download.MediaType ?? "application/octet-stream";
        context.Response.ContentLength = download.Length;
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Content-Disposition"] = "attachment";
        await StreamContentAsync(context, download.Content).ConfigureAwait(false);
    }

    /// <summary>
    /// Copies an admitted download directly to the response. Kept as one boundary so a regression
    /// that buffers the source before writing can be detected without replacing the real endpoint.
    /// </summary>
    internal static Task StreamContentAsync(HttpContext context, Stream content)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(content);
        return content.CopyToAsync(context.Response.Body, context.RequestAborted);
    }

    private static SurfaceEndpoint RequiredSurface(HttpContext context)
        => context.GetEndpoint()?.Metadata.GetMetadata<SurfaceEndpoint>()
            ?? throw new InvalidOperationException("A mapped transfer endpoint has no parent surface metadata.");

}
