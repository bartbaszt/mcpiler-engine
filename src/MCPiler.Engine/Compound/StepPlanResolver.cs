using System.Diagnostics.CodeAnalysis;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Compound;

/// <summary>
/// Turns a compound binding into a plan whose every reference has already resolved.
/// </summary>
/// <remarks>
/// <para>
/// Resolution happens once, before the first step runs. A workflow that discovers at step three
/// that step four names nothing would have already sent two requests it can never complete, and
/// an artifact defect would arrive at the caller as a partial execution.
/// </para>
/// <para>
/// Every question about the binding is put to <see cref="ManifestBindingDispatcher"/>: which
/// steps, which operation each step runs, which upstream key that operation executes. Nothing
/// here tests a binding's type.
/// </para>
/// </remarks>
internal static class StepPlanResolver
{
    /// <summary>Resolves <paramref name="binding"/> against the manifest that declares it.</summary>
    /// <returns>False when a step, an operation or a bound cannot be resolved.</returns>
    internal static bool TryResolve(
        ManifestDocument manifest,
        CompoundBinding binding,
        [NotNullWhen(true)] out CompoundPlan? plan,
        [NotNullWhen(false)] out string? failure)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(binding);

        plan = null;
        var steps = new List<PlannedStep>(binding.Steps.Count);

        foreach (CompoundStepEntry step in binding.Steps)
        {
            AgentOperationEntry? entry = manifest.AgentSurface.Operation(step.Operation);

            if (entry is null)
            {
                failure = $"Step '{step.StepId}' references operation '{step.Operation}', which this manifest does not declare.";
                return false;
            }

            // Through the seam, so a step whose own binding is a transformation resolves to the
            // key its base executes rather than to nothing.
            string? key = ManifestBindingDispatcher.TryResolveOperationKey(entry.Binding);
            ManifestOperation? operation = key is null ? null : manifest.Operations.Operation(key);

            if (operation is null)
            {
                failure = $"Step '{step.StepId}' references operation '{step.Operation}', which has no upstream binding this runtime can execute.";
                return false;
            }

            steps.Add(new PlannedStep(
                step.StepId,
                step.Operation,
                entry,
                operation,
                step.InputMappings,
                step.InputProgram));
        }

        CompoundBounds bounds = manifest.Policy.EffectiveCompound;

        plan = new CompoundPlan(
            steps,
            binding.OutputSelection,
            Narrowed(binding.MaxTotalResponseBytes, bounds.MaxTotalResponseBytes),
            Narrowed(binding.WorkflowTimeout, bounds.WorkflowTimeout));

        failure = null;
        return true;
    }

    /// <summary>
    /// The smaller of what the binding declares and what the policy permits.
    /// </summary>
    /// <remarks>
    /// A binding states its own budget and the policy states the ceiling, and a compiled policy
    /// may only ever be narrowed. Taking the declared value outright would let a workflow raise
    /// a bound the deployment lowered, which is the same widening the origin perimeter and the
    /// transform ceiling both already refuse.
    /// </remarks>
    private static long Narrowed(long? declared, long ceiling)
        => declared is { } value ? Math.Min(value, ceiling) : ceiling;

    private static TimeSpan Narrowed(TimeSpan? declared, TimeSpan ceiling)
        => declared is { } value && value < ceiling ? value : ceiling;
}
