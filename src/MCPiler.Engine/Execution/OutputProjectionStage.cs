using System.Globalization;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime.Projection;
using MCPiler.Engine.Transform;

namespace MCPiler.Engine.Execution;

/// <summary>
/// Where a declared output projection meets the body that arrived.
/// </summary>
/// <remarks>
/// <para>
/// One dispatcher for the three output kinds, for the same reason the binding dispatcher is one
/// place: selection must be made once, from the effective binding, so no second site can decide
/// differently. Passthrough is the absence of a projection rather than a fourth kind.
/// </para>
/// <para>
/// The JMESPath arm is the only one that leaves the serving process. It checks eligibility and
/// input bounds before asking the confined-worker port to evaluate; it never falls back to the
/// unprojected body. A binary/file result remains under the existing response classification and
/// is refused before any worker sees it.
/// </para>
/// <para>
/// A refusal is a failure of the projection, not of the upstream: the exchange succeeded and its
/// status and headers survive on the result. No arm falls back to the untransformed body, because
/// a fallback would mean the projection is advisory and the caller cannot tell which of two
/// documents it received.
/// </para>
/// </remarks>
internal static class OutputProjectionStage
{
    /// <summary>Applies the binding's output projection to an arrived body.</summary>
    internal static async Task<OutputProjectionResult> ApplyAsync(
        ManifestDocument manifest,
        AgentOperationEntry entry,
        ManifestOperation operation,
        EngineExecutionResult result,
        IProjectionWorker? worker,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(result);

        if (ManifestBindingDispatcher.TryResolveOutputProjection(entry.Binding) is not { } projection)
        {
            return OutputProjectionResult.Unchanged(result.ResponseBody);
        }

        switch (projection)
        {
            case ManifestOutputProjection.TransformProgramVariant:
                return TransformOutput(manifest, entry, result);

            case ManifestOutputProjection.JmesPathVariant jmesPath:
                return await JmesPathOutputAsync(
                    manifest,
                    operation,
                    result,
                    jmesPath,
                    worker,
                    cancellationToken).ConfigureAwait(false);

            default:
                return OutputProjectionResult.Refused(
                    ExecutionFailureKind.Transformation,
                    result.ResponseBody,
                    "The operation declares an output projection kind this runtime does not implement.");
        }
    }

    /// <summary>The existing TransformProgram path, delegated without changing its behavior.</summary>
    private static OutputProjectionResult TransformOutput(
        ManifestDocument manifest,
        AgentOperationEntry entry,
        EngineExecutionResult result)
    {
        if (TransformStage.TryOutput(
                manifest,
                entry,
                result,
                out byte[]? body,
                out string? failure))
        {
            return OutputProjectionResult.UnchangedOrProduced(result.ResponseBody, body);
        }

        // Preserve existing TransformProgram semantics, including the arrived body on a refused
        // program. The JMESPath no-raw-fallback rule is enforced by its own arm below.
        return OutputProjectionResult.Refused(
            ExecutionFailureKind.Transformation,
            result.ResponseBody,
            failure!);
    }

    private static async Task<OutputProjectionResult> JmesPathOutputAsync(
        ManifestDocument manifest,
        ManifestOperation operation,
        EngineExecutionResult result,
        ManifestOutputProjection.JmesPathVariant projection,
        IProjectionWorker? worker,
        CancellationToken cancellationToken)
    {
        if (result.ResponseFile is not null
            || ResponseClassification.IsBinaryResponse(
                operation,
                result.StatusCode ?? 0,
                result.ResponseMediaType))
        {
            return JmesPathRefusal(
                result,
                new JmesPathFailure(
                    JmesPathFailureClass.InputFileOrBinary,
                    "A binary/file response is not an inline JSON value and cannot be projected."));
        }

        if (projection.LanguageVersion != JmesPathProfile.SupportedLanguageVersion)
        {
            return JmesPathRefusal(
                result,
                new JmesPathFailure(
                    JmesPathFailureClass.InternalEvaluatorDefect,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"Unsupported languageVersion={projection.LanguageVersion} reached execution despite the load gate.")));
        }

        if (!projection.Limits.IsPositive)
        {
            return JmesPathRefusal(
                result,
                new JmesPathFailure(
                    JmesPathFailureClass.InternalEvaluatorDefect,
                    "Non-positive JMESPath limits reached execution despite the load gate."));
        }

        if (result.ResponseBody is not { } responseBody)
        {
            return JmesPathRefusal(
                result,
                new JmesPathFailure(
                    JmesPathFailureClass.InputNotJson,
                    "The response has no inline JSON body to project."));
        }

        JmesPathLimits effective = EffectiveLimits(manifest.Policy, projection.Limits);

        int expressionBytes = JmesPathProfile.ExpressionByteCount(projection.Expression);
        if (expressionBytes > effective.MaxExpressionBytes)
        {
            return JmesPathRefusal(
                result,
                new JmesPathFailure(
                    JmesPathFailureClass.ExpressionTooManyBytes,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The expression is {expressionBytes} UTF-8 bytes, exceeding maxExpressionBytes={effective.MaxExpressionBytes}.")));
        }

        if (!JmesPathProfile.TryPrepareInput(
                responseBody,
                effective,
                out JmesPathPreparedInput? prepared,
                out JmesPathFailure? preparationFailure))
        {
            return JmesPathRefusal(result, preparationFailure!);
        }

        if (worker is null)
        {
            return JmesPathRefusal(
                result,
                new JmesPathFailure(
                    JmesPathFailureClass.OperationalConfinementUnavailable,
                    "The operation declares a JMESPath output projection, and this execution was not given a confined worker."));
        }

        JmesPathEvaluationResult evaluation;

        try
        {
            evaluation = await worker
                .EvaluateAsync(
                    projection.Expression,
                    prepared!.Json,
                    effective,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception workerFailure) when (
            workerFailure is IOException or ObjectDisposedException or InvalidOperationException)
        {
            return JmesPathRefusal(
                result,
                new JmesPathFailure(
                    JmesPathFailureClass.OperationalWorkerFailure,
                    $"The confined projection worker failed ({workerFailure.GetType().Name})."));
        }

        if (!evaluation.Succeeded)
        {
            return JmesPathRefusal(result, evaluation.Failure!);
        }

        if (!JmesPathProfile.TryVerifyResult(
                evaluation.Output!,
                effective,
                out byte[]? canonical,
                out _,
                out JmesPathFailure? verificationFailure))
        {
            return JmesPathRefusal(result, verificationFailure!);
        }

        return OutputProjectionResult.Produced(canonical!);
    }

    /// <summary>
    /// Narrows the projection's declared bounds to the manifest policy and the existing response
    /// ceiling. A selector must not raise either one.
    /// </summary>
    private static JmesPathLimits EffectiveLimits(PolicySection policy, JmesPathLimits declared)
    {
        JmesPathCeiling ceiling = policy.EffectiveJmesPathCeiling;

        return declared.ClampTo(new JmesPathLimits(
            ceiling.MaxExpressionBytes,
            ceiling.MaxInputNodes,
            ceiling.MaxInputDepth,
            ceiling.MaxResultNodes,
            ceiling.MaxResultDepth,
            Math.Min(ceiling.MaxOutputBytes, policy.EffectiveLimits.UpstreamResponseSizeLimitBytes),
            ceiling.MaxEvaluationMilliseconds));
    }

    private static OutputProjectionResult JmesPathRefusal(EngineExecutionResult result, JmesPathFailure failure)
        => OutputProjectionResult.JmesPathRefused(
            result.ResponseBody,
            Describe(failure),
            OutputProjectionStage.Detail(failure.FailureClass));

    private static string Describe(JmesPathFailure failure)
        => string.Create(
            CultureInfo.InvariantCulture,
            $"The JMESPath output projection failed ({failure.Code}): {failure.Message}");

    /// <summary>The stable failure document a projection refusal carries.</summary>
    /// <remarks>
    /// A caller branching on a projection outcome needs the class rather than the sentence, and
    /// a deadline or memory refusal has to be visibly distinct from a language failure. The
    /// document carries no payload, header, expression text or upstream content.
    /// </remarks>
    internal static JsonNode Detail(JmesPathFailureClass failureClass)
        => new JsonObject
        {
            ["kind"] = "jmespath",
            ["code"] = JmesPathFailure.CodeOf(failureClass),
            ["operational"] = failureClass >= JmesPathFailureClass.OperationalTimeout,
        };
}

/// <summary>The result of applying one output projection.</summary>
internal sealed record OutputProjectionResult(
    bool Succeeded,
    byte[]? Body,
    ExecutionFailureKind FailureKind,
    string? FailureReason,
    JsonNode? FailureDetail)
{
    internal static OutputProjectionResult Unchanged(byte[]? body)
        => new(true, body, ExecutionFailureKind.None, null, null);

    internal static OutputProjectionResult Produced(byte[] body)
        => new(true, body, ExecutionFailureKind.None, null, null);

    internal static OutputProjectionResult UnchangedOrProduced(byte[]? original, byte[]? projected)
        => ReferenceEquals(original, projected) ? Unchanged(original) : Produced(projected!);

    internal static OutputProjectionResult Refused(
        ExecutionFailureKind kind,
        byte[]? original,
        string reason)
        => new(false, original, kind, reason, null);

    internal static OutputProjectionResult JmesPathRefused(
        byte[]? original,
        string reason,
        JsonNode detail)
        => new(false, original, ExecutionFailureKind.Transformation, reason, detail);
}
