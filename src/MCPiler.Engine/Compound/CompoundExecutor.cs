using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Transform;

namespace MCPiler.Engine.Compound;

/// <summary>
/// Runs a workflow: one step after another, each through the same pipeline a direct call takes.
/// </summary>
/// <remarks>
/// <para>
/// Strictly sequential and fail-fast, with no retry anywhere. A workflow is a sequence the
/// author wrote because the steps depend on each other, so running two at once would change
/// what the second sees, and retrying one would repeat an effect the author never asked to
/// happen twice.
/// </para>
/// <para>
/// Every step re-enters <see cref="ExecutionService"/>. That is the requirement, not an
/// implementation shortcut: origin perimeter, credential scope, redirect policy, address
/// containment, response ceiling, file handling and the step's own transformations are all
/// decided by the same code that decides them for a direct invocation, so a step cannot reach
/// anywhere a direct call could not. Nothing here re-implements any of it, and nothing here
/// passes a step a credential its own binding does not scope.
/// </para>
/// <para>
/// Two bounds belong to the workflow rather than to any step: the wall clock and the aggregate
/// response budget. They are enforced here in addition to, never instead of, each step's own
/// ceiling — a hundred steps each inside the per-response limit are still a hundred times the
/// per-response limit.
/// </para>
/// </remarks>
internal static class CompoundExecutor
{
    /// <summary>The media type of an assembled workflow result.</summary>
    internal const string ResultMediaType = "application/json";

    /// <summary>The argument member carrying a request body.</summary>
    private const string BodyArgument = "body";

    /// <summary>Runs the workflow <paramref name="binding"/> declares.</summary>
    internal static async Task<EngineExecutionResult> ExecuteAsync(
        ExecutionService executions,
        FileHandleStore? files,
        ExecutionRequest request,
        CompoundBinding binding,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(executions);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(binding);

        var completed = new List<string>();

        if (!StepPlanResolver.TryResolve(request.Manifest, binding, out CompoundPlan? plan, out string? unresolved))
        {
            return Failed(request, null, CompoundStage.Plan, ExecutionFailureKind.Compilation, completed, unresolved);
        }

        using var workflow = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        if (plan.WorkflowTimeout > TimeSpan.Zero)
        {
            workflow.CancelAfter(plan.WorkflowTimeout);
        }

        var responses = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        var issued = new Dictionary<string, FileHandleReference>(StringComparer.Ordinal);
        long remaining = plan.MaxTotalResponseBytes;

        foreach (PlannedStep step in plan.Steps)
        {
            if (remaining <= 0)
            {
                return Failed(
                    request,
                    step.StepId,
                    CompoundStage.Workflow,
                    ExecutionFailureKind.ResponseSize,
                    completed,
                    Exhausted(plan.MaxTotalResponseBytes));
            }

            IReadOnlySet<string> slots = ExclusionValidation.FileArguments(step.Entry.InputSchema?.Object);

            if (!TryAssemble(request.Arguments, responses, step, out JsonObject document, out string? unmapped))
            {
                return Failed(
                    request, step.StepId, CompoundStage.Mapping, ExecutionFailureKind.Compilation, completed, unmapped);
            }

            if (step.InputProgram is { } program
                && !TransformStage.TryApply(
                    request.Manifest, program, slots, TransformDirection.Input, document, out document, out string? refused))
            {
                return Failed(
                    request,
                    step.StepId,
                    CompoundStage.Transformation,
                    ExecutionFailureKind.Transformation,
                    completed,
                    refused);
            }

            // No original arguments to carry reserved members across from: a workflow assembles
            // a step's request from mappings, and the caller's own arguments belong to the
            // compound rather than to any step inside it.
            JsonObject arguments = PartsDocument.Arguments(step.Operation, document, slots, new JsonObject());

            var carried = new Dictionary<string, ExecutionFile>(StringComparer.Ordinal);

            string? unreadable = await TryCarryAsync(
                    files, issued, arguments, carried, workflow.Token)
                .ConfigureAwait(false);

            if (unreadable is not null)
            {
                return Failed(
                    request, step.StepId, CompoundStage.Mapping, ExecutionFailureKind.FileRuntime, completed, unreadable);
            }

            EngineExecutionResult outcome;

            try
            {
                outcome = await executions
                    .ExecuteAsync(
                        new ExecutionRequest(request.Manifest, step.Slug, arguments)
                        {
                            Scope = request.Scope,
                            Files = carried,

                            // The caller identity the host proved for this invocation. A workflow
                            // step runs under the same caller as the workflow: a step that
                            // dropped it would let two different callers share one step's
                            // cached response while their workflows stayed separate.
                            CallerPartition = request.CallerPartition,

                            // What is left of the workflow's budget, so the aggregate is a
                            // bound on what arrives rather than a sum checked afterwards. A
                            // step is still separately bounded by the policy's own ceiling;
                            // this only ever narrows.
                            ResponseSizeLimitBytes = remaining,
                        },
                        workflow.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (Expired(workflow, cancellationToken))
            {
                return Failed(
                    request,
                    step.StepId,
                    CompoundStage.Workflow,
                    ExecutionFailureKind.Timeout,
                    completed,
                    Elapsed(plan.WorkflowTimeout));
            }

            if (!outcome.Succeeded)
            {
                // A step's own classification, unchanged. Reclassifying a refused origin as a
                // workflow failure would send an operator to read this file instead of the
                // allow-list that actually refused the request.
                return Failed(
                    request,
                    step.StepId,
                    CompoundStage.Execution,
                    outcome.Failure,
                    completed,
                    outcome.FailureReason);
            }

            remaining -= outcome.ResponseBody?.LongLength ?? outcome.ResponseFile?.Length ?? 0;

            if (outcome.ResponseFile is { } stored)
            {
                if (outcome.ResponseFileHandle is not { Length: > 0 } wireHandle)
                {
                    return Failed(
                        request,
                        step.StepId,
                        CompoundStage.Execution,
                        ExecutionFailureKind.FileRuntime,
                        completed,
                        "The stored response has no transferable file capability.");
                }

                issued[wireHandle] = stored;
            }

            responses[step.StepId] = PartsDocument.Response(outcome);
            completed.Add(step.StepId);
        }

        return Select(request, plan, responses, completed);
    }

    /// <summary>Builds the workflow's result from the completed steps.</summary>
    private static EngineExecutionResult Select(
        ExecutionRequest request,
        CompoundPlan plan,
        IReadOnlyDictionary<string, JsonObject> responses,
        List<string> completed)
    {
        var result = new JsonObject();

        if (plan.Output is { } selection)
        {
            foreach (CompoundOutputEntry entry in selection.Entries)
            {
                if (!TryWrite(result, entry.Target, Resolve(request.Arguments, responses, entry.Source), out string? failure))
                {
                    return Failed(
                        request, null, CompoundStage.Selection, ExecutionFailureKind.Compilation, completed, failure);
                }
            }

            if (selection.OutputProgram is { } program
                && !TransformStage.TryApply(
                    request.Manifest, program, EmptySlots, TransformDirection.Output, result, out result, out string? refused))
            {
                return Failed(
                    request,
                    null,
                    CompoundStage.Selection,
                    ExecutionFailureKind.Transformation,
                    completed,
                    refused);
            }
        }

        return new EngineExecutionResult
        {
            ResponseMediaType = ResultMediaType,
            ResponseBody = Encoding.UTF8.GetBytes(TransformEvaluator.Serialize(result)),
        };
    }

    /// <summary>Assembles one step's request document from its mappings.</summary>
    /// <remarks>
    /// A source that addresses nothing writes nothing. Writing an explicit null would send a
    /// declared empty where the caller sent no value at all, and refusing would make every
    /// optional argument of every step mandatory the moment a mapping mentions it.
    /// </remarks>
    private static bool TryAssemble(
        JsonObject arguments,
        IReadOnlyDictionary<string, JsonObject> responses,
        PlannedStep step,
        out JsonObject document,
        out string? failure)
    {
        document = new JsonObject
        {
            [Member(ManifestPointerRoots.Path)] = new JsonObject(),
            [Member(ManifestPointerRoots.Query)] = new JsonObject(),
            [Member(ManifestPointerRoots.Headers)] = new JsonObject(),
            [Member(ManifestPointerRoots.Cookies)] = new JsonObject(),
            [Member(ManifestPointerRoots.Parts)] = new JsonObject(),
        };

        foreach (StepInputMapping mapping in step.Mappings)
        {
            if (Resolve(arguments, responses, mapping.Source) is not { } value)
            {
                continue;
            }

            if (!TryWrite(document, mapping.Target, value, out failure))
            {
                return false;
            }
        }

        failure = null;
        return true;
    }

    /// <summary>Reads one mapping source.</summary>
    private static JsonNode? Resolve(
        JsonObject arguments,
        IReadOnlyDictionary<string, JsonObject> responses,
        MappingSource source)
    {
        if (source.IsArgument)
        {
            return JsonPointerNodes.Read(arguments, source.Argument!)?.DeepClone();
        }

        if (source.IsStepOutput)
        {
            return responses.TryGetValue(source.FromStep!, out JsonObject? response)
                ? JsonPointerNodes.Read(response, source.Response!)?.DeepClone()
                : null;
        }

        return source.Constant?.DeepClone();
    }

    /// <summary>
    /// Turns a handle a mapping carried forward back into the bytes it stands for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the whole of how a file crosses between steps. A binary response was stored
    /// rather than materialized, the response document carries its handle in its wire form, and
    /// a mapping moves that handle into a later step's request. The store resolves the wire form
    /// back to what it refers to and a replayable source is handed to the compiler. The content
    /// is opened only while the later step's outbound request is serialized.
    /// </para>
    /// <para>
    /// Only an identifier this workflow issued is recognised. Treating any well-formed
    /// identifier as a reference would mean a caller's own opaque string either became a file or
    /// failed the step, and neither is what the argument said. Because the set is what the
    /// workflow issued, the scope and the lifetime are this invocation's own and there is no
    /// cross-tenant handle to refuse.
    /// </para>
    /// </remarks>
    private static async Task<string?> TryCarryAsync(
        FileHandleStore? files,
        IReadOnlyDictionary<string, FileHandleReference> issued,
        JsonObject arguments,
        Dictionary<string, ExecutionFile> carried,
        CancellationToken cancellationToken)
    {
        if (issued.Count == 0)
        {
            return null;
        }

        foreach ((string member, JsonNode? value) in Carriers(arguments))
        {
            if (value is not JsonValue text
                || text.GetValueKind() != JsonValueKind.String
                || text.GetValue<string>() is not { } wire
                || !issued.TryGetValue(wire, out FileHandleReference? reference))
            {
                continue;
            }

            if (files is null)
            {
                return $"Step argument '{member}' names a stored file, and this runtime has no file store configured.";
            }

            FileHandleLookup lookup = await files
                .DescribeAsync(reference.Id, cancellationToken)
                .ConfigureAwait(false);

            if (lookup.Status != FileHandleStatus.Available)
            {
                return $"Step argument '{member}' names a stored file that is no longer available.";
            }

            carried[member] = new ExecutionFile(
                wire,
                reference.FileName,
                reference.MediaType,
                reference.Length,
                new StoreBackedBodySource(files, reference));
        }

        return null;
    }

    /// <summary>
    /// The places a file may sit in a compiled request, keyed as the compiler keys them.
    /// </summary>
    /// <remarks>
    /// The body's own members, because that is what a multipart writer turns into parts and
    /// what the file dictionaries are keyed by; and the top-level arguments, so a parameter
    /// carrying a file is reached by the same walk rather than by a second rule.
    /// </remarks>
    private static IEnumerable<KeyValuePair<string, JsonNode?>> Carriers(JsonObject arguments)
    {
        if (arguments[BodyArgument] is JsonObject body)
        {
            foreach (KeyValuePair<string, JsonNode?> part in body)
            {
                yield return part;
            }
        }

        foreach (KeyValuePair<string, JsonNode?> argument in arguments)
        {
            if (argument.Key != BodyArgument)
            {
                yield return argument;
            }
        }
    }

    private static bool TryWrite(JsonObject document, string target, JsonNode? value, out string? failure)
        => JsonPointerNodes.TryWrite(document, target, value, static () => { }, out failure);

    private static EngineExecutionResult Failed(
        ExecutionRequest request,
        string? step,
        string stage,
        ExecutionFailureKind code,
        IReadOnlyList<string> completed,
        string? reason) => new()
        {
            Failure = code,
            FailureReason = reason,
            FailureDetail = CompoundFailure.Body(request.Slug, step, stage, code, completed),
        };

    private static string Exhausted(long budget)
        => string.Create(
            CultureInfo.InvariantCulture,
            $"The workflow exhausted its total response budget of {budget} bytes.");

    private static string Elapsed(TimeSpan budget)
        => string.Create(CultureInfo.InvariantCulture, $"The workflow exceeded its time budget of {budget}.");

    /// <summary>
    /// True when the workflow's own deadline fired rather than the caller abandoning the call.
    /// </summary>
    private static bool Expired(CancellationTokenSource workflow, CancellationToken caller)
        => workflow.IsCancellationRequested && !caller.IsCancellationRequested;

    private static string Member(string root) => root[1..];

    private static readonly IReadOnlySet<string> EmptySlots = new HashSet<string>(StringComparer.Ordinal);
}
