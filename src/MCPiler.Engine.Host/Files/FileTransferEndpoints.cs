using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Host.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.Host.Files;

/// <summary>Maps the streaming file-transfer children of every HTTP MCP surface.</summary>
internal static class FileTransferEndpoints
{
    private const string UploadSuffix = "/files/upload";
    private const string DownloadSuffix = "/files/{capability}";

    public static void Map(WebApplication app, MountSet mounts)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(mounts);

        foreach (MountedSurfaceAddress address in mounts.Addresses)
        {
            MapSurface(app, address.Path, address.Mount, address.Surface);
        }
    }

    private static void MapSurface(
        WebApplication app,
        string parentPath,
        MountedManifest mount,
        MountedSurface surface)
    {
        SurfaceEndpoint metadata = new(
            mount,
            surface,
            parentPath,
            authorizationResourcePath: parentPath);

        app.MapPost(parentPath + UploadSuffix, UploadAsync).WithMetadata(metadata);
        app.MapGet(parentPath + DownloadSuffix, DownloadAsync).WithMetadata(metadata);
    }

    private static async Task UploadAsync(HttpContext context, EngineExecution execution)
    {
        SurfaceEndpoint addressed = RequiredSurface(context);
        string resource = CanonicalParent(context, addressed);
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

    private static async Task DownloadAsync(HttpContext context, EngineExecution execution)
    {
        SurfaceEndpoint addressed = RequiredSurface(context);
        string resource = CanonicalParent(context, addressed);
        string capability = context.Request.RouteValues["capability"]?.ToString() ?? string.Empty;

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

    private static string CanonicalParent(HttpContext context, SurfaceEndpoint addressed)
        => MountAuthorization.CanonicalResource(
            context.Request.Scheme,
            context.Request.Host.Value ?? string.Empty,
            addressed.AuthorizationResourcePath
                ?? throw new InvalidOperationException("A transfer endpoint has no parent resource path."));
}
