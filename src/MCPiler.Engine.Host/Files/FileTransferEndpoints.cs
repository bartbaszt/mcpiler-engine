using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

namespace MCPiler.Engine.Host.Files;

/// <summary>Serves the streaming file-transfer children of HTTP MCP surfaces.</summary>
/// <remarks>
/// <para>
/// A transfer child is addressed relative to its parent MCP surface. The request's generation
/// admission already names both the resolved surface and the exact protected parent resource, so a
/// file handle is issued and redeemed against the same execution graph and resource identity as
/// the MCP request that owns it.
/// </para>
/// <para>
/// Both deployment modes recognise transfer children in middleware from the request path. A
/// literal ASP.NET route cannot represent the double slash that a slash-terminated parent resource
/// intentionally produces (for example <c>/api/full//files/upload</c>). Runtime recognition
/// preserves that spelling without weakening the parent-resource contract.
/// </para>
/// </remarks>
internal static class FileTransferEndpoints
{
    /// <summary>
    /// Serves a transfer path recognised from the request, when the path is one.
    /// </summary>
    /// <remarks>
    /// Returns false for a path that is not a transfer child, so the caller can continue into the
    /// MCP endpoint routing. Admission and authorization run before this dispatcher.
    /// </remarks>
    internal static async Task<bool> TryServeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!TransferPath.TryParse(context.Request.Path.Value, out TransferPath transfer))
        {
            return false;
        }

        // The transfer child is dispatched by middleware rather than by an endpoint. Clear any
        // catch-all endpoint selected for managed MCP routing before producing the transfer result.
        context.SetEndpoint(null);

        if (transfer.Kind == TransferPathKind.Upload)
        {
            if (!HttpMethods.IsPost(context.Request.Method))
            {
                context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return true;
            }

            await UploadAsync(context).ConfigureAwait(false);
            return true;
        }

        if (!HttpMethods.IsGet(context.Request.Method))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return true;
        }

        await DownloadAsync(context, transfer.Capability!).ConfigureAwait(false);
        return true;
    }

    private static async Task UploadAsync(HttpContext context)
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

    private static async Task DownloadAsync(HttpContext context, string capability)
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
}
