using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Transform;

/// <summary>
/// Where a declared transformation meets an execution.
/// </summary>
/// <remarks>
/// <para>
/// Both directions run inside the execution rather than above it. The input direction has to,
/// because a program that aborts must cost no upstream request and no credential read, and
/// only code that runs before those can promise it. The output direction has to for the
/// symmetric reason: the transformation is part of what the operation returns, so a caller
/// reaching the library directly must get the same value the MCP surface does.
/// </para>
/// <para>
/// Every program is validated again here, at every invocation, against the same Tier-1 gate
/// the load applied. That is not redundancy: the load gate belongs to the mount, and this
/// method can be reached with any manifest a caller assembled. A program that runs because
/// something else is believed to have checked it is a program nothing checked.
/// </para>
/// </remarks>
internal static class TransformStage
{
    /// <summary>
    /// Applies the input-direction program, yielding the arguments the compiler will read.
    /// </summary>
    /// <returns>False when the program is refused or aborts; nothing has been contacted.</returns>
    internal static bool TryInput(
        ManifestDocument manifest,
        PolicySection policy,
        AgentOperationEntry entry,
        ManifestOperation operation,
        JsonObject arguments,
        out JsonObject effective,
        [NotNullWhen(false)] out string? failure)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(arguments);

        effective = arguments;
        failure = null;

        if (ManifestBindingDispatcher.TryResolveInputProgram(entry.Binding) is not { } document)
        {
            return true;
        }

        IReadOnlySet<string> slots = ExclusionValidation.FileArguments(entry.InputSchema?.Object);
        TransformCeilingValues ceiling = Ceiling(policy);

        if (!TransformValidation.TryAccept(
                document,
                ceiling,
                slots,
                TransformDirection.Input,
                out TransformProgram? program,
                out IReadOnlyList<TransformFinding> findings))
        {
            failure = Refused("input", findings);
            return false;
        }

        TransformEvaluation evaluation = TransformEvaluator.Evaluate(
            program,
            PartsDocument.Request(operation, arguments, slots),
            ceiling);

        if (!evaluation.Succeeded)
        {
            failure = $"The input transformation failed: {evaluation.Describe()}";
            return false;
        }

        if (evaluation.Output is not JsonObject produced)
        {
            failure = "The input transformation did not produce an object document.";
            return false;
        }

        effective = PartsDocument.Arguments(operation, produced, slots, arguments);
        return true;
    }

    /// <summary>
    /// Applies the output-direction program, yielding the agent-facing body.
    /// </summary>
    /// <remarks>
    /// A stored binary response is never transformed. Its bytes were deliberately not
    /// materialized, and a program that could reach them would undo the only reason the handle
    /// exists.
    /// </remarks>
    /// <returns>False when the program is refused or aborts.</returns>
    internal static bool TryOutput(
        ManifestDocument manifest,
        PolicySection policy,
        AgentOperationEntry entry,
        EngineExecutionResult result,
        out byte[]? body,
        [NotNullWhen(false)] out string? failure)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(result);

        body = result.ResponseBody;
        failure = null;

        if (result.ResponseFile is not null
            || result.ResponseBody is null
            || ManifestBindingDispatcher.TryResolveOutputProgram(entry.Binding) is not { } document)
        {
            return true;
        }

        IReadOnlySet<string> slots = ExclusionValidation.FileArguments(entry.InputSchema?.Object);
        TransformCeilingValues ceiling = Bounded(Ceiling(policy), policy);

        if (!TransformValidation.TryAccept(
                document,
                ceiling,
                slots,
                TransformDirection.Output,
                out TransformProgram? program,
                out IReadOnlyList<TransformFinding> findings))
        {
            failure = Refused("output", findings);
            return false;
        }

        TransformEvaluation evaluation = TransformEvaluator.Evaluate(
            program,
            PartsDocument.Response(result),
            ceiling);

        if (!evaluation.Succeeded)
        {
            failure = $"The output transformation failed: {evaluation.Describe()}";
            return false;
        }

        body = Encoding.UTF8.GetBytes(TransformEvaluator.Serialize(evaluation.Output));
        return true;
    }

    /// <summary>
    /// Applies a program to a part-scoped document that a caller has already assembled.
    /// </summary>
    /// <remarks>
    /// A compound step's request is built from its mappings rather than from an argument
    /// object, so there is nothing to translate on the way in. The gate is the same one an
    /// operation's own program passes: validated again here against the same ceiling, because
    /// a program that runs because something else is believed to have checked it is a program
    /// nothing checked.
    /// </remarks>
    /// <returns>False when the program is refused or aborts.</returns>
    internal static bool TryApply(
        ManifestDocument manifest,
        PolicySection policy,
        JsonObject program,
        IReadOnlySet<string> slots,
        TransformDirection direction,
        JsonObject document,
        out JsonObject produced,
        [NotNullWhen(false)] out string? failure)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(slots);
        ArgumentNullException.ThrowIfNull(document);

        produced = document;
        TransformCeilingValues ceiling = direction == TransformDirection.Output
            ? Bounded(Ceiling(policy), policy)
            : Ceiling(policy);

        if (!TransformValidation.TryAccept(
                program,
                ceiling,
                slots,
                direction,
                out TransformProgram? accepted,
                out IReadOnlyList<TransformFinding> findings))
        {
            failure = Refused(Name(direction), findings);
            return false;
        }

        TransformEvaluation evaluation = TransformEvaluator.Evaluate(accepted, document, ceiling);

        if (!evaluation.Succeeded)
        {
            failure = $"The {Name(direction)} transformation failed: {evaluation.Describe()}";
            return false;
        }

        if (evaluation.Output is not JsonObject result)
        {
            failure = $"The {Name(direction)} transformation did not produce an object document.";
            return false;
        }

        produced = result;
        failure = null;
        return true;
    }

    private static string Name(TransformDirection direction)
        => direction == TransformDirection.Output ? "output" : "input";

    /// <summary>The manifest policy's transform ceiling as five plain numbers.</summary>
    private static TransformCeilingValues Ceiling(PolicySection policy)
    {
        TransformCeiling declared = policy.EffectiveTransformCeiling;

        return new TransformCeilingValues(
            declared.MaxSteps,
            declared.MaxDepth,
            declared.MaxNodes,
            declared.MaxOutputBytes,
            declared.MaxArrayFanout);
    }

    /// <summary>
    /// Narrows the produced-size ceiling to the policy's response ceiling.
    /// </summary>
    /// <remarks>
    /// A transformation may not raise a limit the policy declares. Without this a program
    /// could state a larger <c>maxOutputBytes</c> than the response ceiling and hand a caller
    /// a document the policy refused to let arrive — the same bytes, produced one step later.
    /// </remarks>
    private static TransformCeilingValues Bounded(TransformCeilingValues ceiling, PolicySection policy)
        => ceiling with
        {
            MaxOutputBytes = Math.Min(
                ceiling.MaxOutputBytes,
                policy.EffectiveLimits.UpstreamResponseSizeLimitBytes),
        };

    /// <summary>
    /// The refusal a caller is told, naming the first finding only.
    /// </summary>
    /// <remarks>
    /// One finding, because this is an invocation and the caller cannot repair the manifest.
    /// The full list is what the load-time refusal prints, where the audience can act on it.
    /// </remarks>
    private static string Refused(string direction, IReadOnlyList<TransformFinding> findings)
    {
        TransformFinding first = findings[0];

        return first.Step is { } step
            ? string.Create(
                CultureInfo.InvariantCulture,
                $"The operation's {direction} transformation is not valid ({first.Code} at step {step}): {first.Message}")
            : $"The operation's {direction} transformation is not valid ({first.Code}): {first.Message}";
    }
}
