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
/// <para>
/// HTTP calls use the generation admission of the current request rather than one captured at
/// session handshake. The current address/resource identity must still match the stateful session
/// binding, after which the already-resolved request surface is executed directly. Stdio continues
/// to use its fixed-generation lease source.
/// </para>
/// </remarks>
internal static class ToolBridge
{
    private const string ErrorCodeMetaKey = "io.mcpiler/errorCode";

    /// <summary>Runs one call against the surface the request addressed.</summary>
    public static async ValueTask<CallToolResult> InvokeAsync(
        string address,
        string resourceIdentity,
        GenerationLeaseSource leases,
        DrainCoordinator drain,
        RequestContext<CallToolRequestParams> request,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceIdentity);
        ArgumentNullException.ThrowIfNull(leases);
        ArgumentNullException.ThrowIfNull(drain);
        ArgumentNullException.ThrowIfNull(request);

        string tool = request.Params?.Name ?? string.Empty;

        if (!drain.TryEnter(tool, cancellationToken, out DrainCoordinator.InvocationLease? admitted))
        {
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = "Host shutdown is draining; this invocation was not accepted." }],
            };
        }

        using (DrainCoordinator.InvocationLease lease = admitted!)
        {
            if (leases() is not { } generation)
            {
                return NotServed();
            }

            using (generation)
            {
                return await ExecuteAsync(
                    address,
                    generation.Generation,
                    resourceIdentity,
                    tool,
                    request,
                    lease.CancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Runs one HTTP call against the admission belonging to the current request.</summary>
    internal static async ValueTask<CallToolResult> InvokeAsync(
        string address,
        string resourceIdentity,
        EngineRequestGenerationAdmissionAccessor admissions,
        DrainCoordinator drain,
        RequestContext<CallToolRequestParams> request,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceIdentity);
        ArgumentNullException.ThrowIfNull(admissions);
        ArgumentNullException.ThrowIfNull(drain);
        ArgumentNullException.ThrowIfNull(request);

        string tool = request.Params?.Name ?? string.Empty;

        if (admissions.Current is not { } admission
            || !admission.MatchesSession(address, resourceIdentity))
        {
            return NotServed();
        }

        if (admission.CallerPartition is not { } callerPartition)
        {
            // A protected request cannot reach execution until authorization has positively
            // settled a caller partition. Treating absence as Public would turn a missing
            // authorization decision into an anonymous execution identity.
            return NotServed();
        }

        if (!drain.TryEnter(tool, cancellationToken, out DrainCoordinator.InvocationLease? admitted))
        {
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = "Host shutdown is draining; this invocation was not accepted." }],
            };
        }

        using (DrainCoordinator.InvocationLease lease = admitted!)
        {
            return await ExecuteResolvedAsync(
                admission.Generation,
                admission.Resolution,
                admission.ResourceIdentity,
                tool,
                request,
                callerPartition,
                lease.CancellationToken).ConfigureAwait(false);
        }
    }

    private static async ValueTask<CallToolResult> ExecuteAsync(
        string address,
        EngineGeneration generation,
        string resourceIdentity,
        string tool,
        RequestContext<CallToolRequestParams> request,
        CancellationToken cancellationToken)
    {
        if (!generation.TryResolve(address, out SurfaceResolution? resolved)
            || resolved is null)
        {
            // The surface this session started against is no longer served: an activation removed
            // it. The answer is the same one a route that never existed gives.
            return NotServed();
        }

        return await ExecuteResolvedAsync(
            generation,
            resolved,
            resourceIdentity,
            tool,
            request,

            // A stdio session is not an HTTP-authorized caller: it is admitted by process
            // ownership rather than by a presented token, so every stdio caller shares the one
            // explicit public partition.
            CallerPartition.Public,
            cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<CallToolResult> ExecuteResolvedAsync(
        EngineGeneration generation,
        SurfaceResolution resolved,
        string resourceIdentity,
        string tool,
        RequestContext<CallToolRequestParams> request,
        CallerPartition callerPartition,
        CancellationToken cancellationToken)
    {
        ToolOutcome outcome = await generation.Execution
            .InvokeAsync(
                resolved.Mount,
                resolved.Surface,
                resourceIdentity,
                tool,
                Arguments(request.Params?.Arguments),
                request.Server?.NegotiatedProtocolVersion,
                cancellationToken,
                callerPartition)
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

    private static CallToolResult NotServed()
        => new()
        {
            IsError = true,
            Content = [new TextContentBlock { Text = "This address is no longer served by any active generation." }],
        };

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
