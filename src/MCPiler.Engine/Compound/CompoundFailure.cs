using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;

namespace MCPiler.Engine.Compound;

/// <summary>Where in a workflow something went wrong.</summary>
/// <remarks>
/// A closed set, because it is part of what a caller is told. The stage says which part of the
/// workflow failed; the error code says what kind of failure it was, and comes from
/// <see cref="ExecutionFailureKind"/> rather than from a second vocabulary invented here.
/// </remarks>
internal static class CompoundStage
{
    /// <summary>A step reference could not be resolved before the workflow started.</summary>
    internal const string Plan = "plan";

    /// <summary>A step's request document could not be assembled from its mappings.</summary>
    internal const string Mapping = "mapping";

    /// <summary>A step's own input transformation was refused or aborted.</summary>
    internal const string Transformation = "transformation";

    /// <summary>A step ran and its own pipeline reported a failure.</summary>
    internal const string Execution = "execution";

    /// <summary>The workflow's result could not be assembled from the completed steps.</summary>
    internal const string Selection = "selection";

    /// <summary>A whole-workflow bound was reached.</summary>
    internal const string Workflow = "workflow";

    /// <summary>Every stage a failure may name.</summary>
    internal static IReadOnlySet<string> All { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        Plan,
        Mapping,
        Transformation,
        Execution,
        Selection,
        Workflow,
    };
}

/// <summary>The document a caller receives when a workflow does not complete.</summary>
/// <remarks>
/// <para>
/// Five members and no free text. A caller that wants to react to a failing workflow needs to
/// know which tool, which step, how far it got and what kind of failure it was; a sentence
/// explaining the upstream's behaviour is for an operator and travels separately, in the
/// failure reason, where rewording it breaks nothing.
/// </para>
/// <para>
/// <c>stepsCompleted</c> is the honest half of the contract: it names what actually happened
/// upstream before the workflow stopped. A workflow is one invocation from the caller's side
/// and several requests from the network's, and hiding the difference would leave a caller
/// unable to tell a workflow that changed nothing from one that changed three things.
/// </para>
/// </remarks>
internal static class CompoundFailure
{
    /// <summary>The tool the caller invoked.</summary>
    internal const string ToolMember = "tool";

    /// <summary>The step that failed, or null when no step had started.</summary>
    internal const string StepMember = "failedStepId";

    /// <summary>Which part of the workflow failed.</summary>
    internal const string StageMember = "stage";

    /// <summary>The execution failure classification.</summary>
    internal const string CodeMember = "errorCode";

    /// <summary>The steps that ran to completion, in order.</summary>
    internal const string CompletedMember = "stepsCompleted";

    /// <summary>Builds the error body.</summary>
    internal static JsonObject Body(
        string tool,
        string? failedStepId,
        string stage,
        ExecutionFailureKind code,
        IReadOnlyList<string> completed)
    {
        ArgumentNullException.ThrowIfNull(completed);

        var steps = new JsonArray();

        foreach (string step in completed)
        {
            steps.Add(step);
        }

        return new JsonObject
        {
            [ToolMember] = tool,
            [StepMember] = failedStepId,
            [StageMember] = stage,
            [CodeMember] = code.ToString(),
            [CompletedMember] = steps,
        };
    }
}
