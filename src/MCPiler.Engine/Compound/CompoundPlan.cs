using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Compound;

/// <summary>One step of a workflow, with everything its execution needs already resolved.</summary>
/// <param name="StepId">The identifier later mappings reference this step's response by.</param>
/// <param name="Slug">The agent operation the step runs.</param>
/// <param name="Entry">The resolved agent operation.</param>
/// <param name="Operation">The upstream operation its binding executes.</param>
/// <param name="Mappings">How the step's request document is assembled.</param>
/// <param name="InputProgram">A transformation applied to that document after mapping.</param>
/// <remarks>
/// The upstream operation is carried because assembling a request document and turning it back
/// into compiler arguments both need the parameter list, and resolving it twice would mean two
/// answers about which bucket a parameter belongs to.
/// </remarks>
internal sealed record PlannedStep(
    string StepId,
    string Slug,
    AgentOperationEntry Entry,
    ManifestOperation Operation,
    IReadOnlyList<StepInputMapping> Mappings,
    JsonObject? InputProgram);

/// <summary>A compound binding with every reference resolved and every bound settled.</summary>
/// <param name="Steps">The steps, in declaration order.</param>
/// <param name="Output">What the workflow returns, or null for an empty result.</param>
/// <param name="MaxTotalResponseBytes">The aggregate response budget across all steps.</param>
/// <param name="WorkflowTimeout">The whole-workflow budget.</param>
internal sealed record CompoundPlan(
    IReadOnlyList<PlannedStep> Steps,
    CompoundOutputSelection? Output,
    long MaxTotalResponseBytes,
    TimeSpan WorkflowTimeout);
