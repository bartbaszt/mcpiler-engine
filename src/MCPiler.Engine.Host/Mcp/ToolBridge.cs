using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace MCPiler.Engine.Host.Mcp;

/// <summary>
/// Carries one call across the protocol boundary and renders the answer.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here resolves a name, judges an argument, or decides what a failure means. The
/// name a client sent goes across as sent and an outcome comes back already rendered, which is
/// what lets two refusals be byte-identical: a hidden tool and a name that never existed are
/// one component's single answer rather than two components agreeing to say the same thing.
/// </para>
/// <para>
/// The only work is shape. Protocol arguments arrive as a map of parsed elements and the seam
/// takes an object, so the map is rebuilt as one; a result carries content blocks and the seam
/// returns text, so the text becomes one block. Neither step can branch on a Manifest value.
/// </para>
/// </remarks>
internal static class ToolBridge
{
    private const string ErrorCodeMetaKey = "io.mcpiler/errorCode";

    /// <summary>Runs one call against the surface the request addressed.</summary>
    public static async ValueTask<CallToolResult> InvokeAsync(
        SurfaceEndpoint addressed,
        EngineExecution execution,
        DrainCoordinator drain,
        RequestContext<CallToolRequestParams> request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(addressed);
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(drain);
        ArgumentNullException.ThrowIfNull(request);

        string tool = request.Params?.Name ?? string.Empty;

        if (!drain.TryEnter(tool, cancellationToken, out DrainCoordinator.InvocationLease? lease))
        {
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = "Host shutdown is draining; this invocation was not accepted." }],
            };
        }

        using (DrainCoordinator.InvocationLease admitted = lease!)
        {
            ToolOutcome outcome = await execution
                .InvokeAsync(
                    addressed.Mount,
                    addressed.Surface,
                    addressed.ResourceIdentity,
                    tool,
                    Arguments(request.Params?.Arguments),
                    request.Server?.NegotiatedProtocolVersion,
                    admitted.CancellationToken)
                .ConfigureAwait(false);

            return new CallToolResult
            {
                // Set only when the call failed. A result carrying 'isError: false' and one
                // omitting it mean the same thing to a client, and the Studio omits it.
                IsError = outcome.IsError ? true : null,
                Content = [new TextContentBlock { Text = outcome.Text }],
                StructuredContent = outcome.StructuredContentJson is { } structured
                    ? JsonSerializer.Deserialize<JsonElement>(structured)
                    : null,
                Meta = outcome.ErrorCode is { } errorCode
                    ? new JsonObject { [ErrorCodeMetaKey] = errorCode }
                    : null,
            };
        }
    }

    /// <summary>Rebuilds the protocol's argument map as one object.</summary>
    /// <remarks>
    /// Each value is re-parsed from its own raw text, so a number keeps its written form and
    /// nothing passes through a converter that could round, widen or reorder it.
    /// </remarks>
    private static JsonObject Arguments(IDictionary<string, JsonElement>? supplied)
    {
        JsonObject arguments = [];

        if (supplied is null)
        {
            return arguments;
        }

        foreach ((string name, JsonElement value) in supplied)
        {
            arguments[name] = JsonNode.Parse(value.GetRawText());
        }

        return arguments;
    }
}
