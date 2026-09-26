using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;

using MCPiler.Engine.Compound;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Compound;

/// <summary>
/// Resolving a workflow before any of it runs, and the body a caller is told when it stops.
/// </summary>
public sealed class CompoundPlanTests
{
    private static readonly Uri BaseUrl = new("https://api.example.com");

    [Fact]
    public void Every_step_resolves_to_the_operation_its_binding_executes()
    {
        Assert.True(TryResolve(Manifest(), Binding("list-pets"), out CompoundPlan? plan, out _));

        PlannedStep step = Assert.Single(plan!.Steps);

        Assert.Equal("s0", step.StepId);
        Assert.Equal("list-pets", step.Slug);
        Assert.Equal("GET /pets", step.Operation.Key);
    }

    /// <summary>
    /// A step whose own binding is a transformation resolves through its base.
    /// </summary>
    [Fact]
    public void A_transformed_step_resolves_through_the_seam()
    {
        ManifestDocument manifest = Manifest(
            new AgentOperationEntry(
                "wrapped",
                "Wrapped",
                new TransformedHttpBinding(new HttpBinding("GET /pets"))));

        Assert.True(TryResolve(manifest, Binding("wrapped"), out CompoundPlan? plan, out _));
        Assert.Equal("GET /pets", Assert.Single(plan!.Steps).Operation.Key);
    }

    [Fact]
    public void A_step_naming_no_declared_operation_refuses_the_plan()
    {
        Assert.False(TryResolve(Manifest(), Binding("ghost"), out _, out string? failure));

        Assert.Contains("s0", failure!, StringComparison.Ordinal);
        Assert.Contains("ghost", failure, StringComparison.Ordinal);
    }

    /// <summary>
    /// A step whose target is itself a workflow has no upstream key to execute.
    /// </summary>
    /// <remarks>
    /// Nesting is refused at load, so this is the floor rather than the usual answer. It is
    /// still resolved here because a plan is built from whatever manifest a caller assembled,
    /// and a plan that assumed the load gate ran is a plan nothing checked.
    /// </remarks>
    [Fact]
    public void A_step_with_no_upstream_binding_refuses_the_plan()
    {
        ManifestDocument manifest = Manifest(
            new AgentOperationEntry(
                "inner",
                "Inner",
                new CompoundBinding([new CompoundStepEntry("x", "list-pets")]),
                Kind: AgentOperationKind.Compound));

        Assert.False(TryResolve(manifest, Binding("inner"), out _, out string? failure));
        Assert.Contains("no upstream binding", failure!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, 4096L)]
    [InlineData(1024L, 1024L)]
    [InlineData(999999L, 4096L)]
    public void The_response_budget_is_the_smaller_of_the_binding_and_the_policy(long? declared, long expected)
    {
        Assert.True(
            TryResolve(
                Manifest(compound: new CompoundBounds(4096, TimeSpan.FromSeconds(30))),
                Binding("list-pets") with { MaxTotalResponseBytes = declared },
                out CompoundPlan? plan,
                out _));

        Assert.Equal(expected, plan!.MaxTotalResponseBytes);
    }

    [Theory]
    [InlineData(null, 30)]
    [InlineData(5, 5)]
    [InlineData(600, 30)]
    public void The_time_budget_is_the_smaller_of_the_binding_and_the_policy(int? declared, int expected)
    {
        Assert.True(
            TryResolve(
                Manifest(compound: new CompoundBounds(4096, TimeSpan.FromSeconds(30))),
                Binding("list-pets") with
                {
                    WorkflowTimeout = declared is { } seconds ? TimeSpan.FromSeconds(seconds) : null,
                },
                out CompoundPlan? plan,
                out _));

        Assert.Equal(TimeSpan.FromSeconds(expected), plan!.WorkflowTimeout);
    }

    /// <summary>
    /// The format's published defaults, so a manifest declaring nothing is still bounded.
    /// </summary>
    [Fact]
    public void A_workflow_declaring_no_bounds_takes_the_format_defaults()
    {
        Assert.True(TryResolve(Manifest(), Binding("list-pets"), out CompoundPlan? plan, out _));

        Assert.Equal(100L * 1024 * 1024, plan!.MaxTotalResponseBytes);
        Assert.Equal(TimeSpan.FromSeconds(120), plan.WorkflowTimeout);
    }

    // ---- the error body ------------------------------------------------------------------

    [Fact]
    public void The_error_body_carries_exactly_the_five_members_the_contract_names()
    {
        JsonObject body = CompoundFailure.Body(
            "flow", "two", CompoundStage.Execution, ExecutionFailureKind.OriginPolicy, ["one"]);

        Assert.Equal(
            ["errorCode", "failedStepId", "stage", "stepsCompleted", "tool"],
            body.Select(static member => member.Key).OrderBy(static name => name, StringComparer.Ordinal));
    }

    [Fact]
    public void The_error_body_states_what_actually_ran()
    {
        JsonObject body = CompoundFailure.Body(
            "flow", "three", CompoundStage.Execution, ExecutionFailureKind.Transport, ["one", "two"]);

        Assert.Equal("flow", (string?)body[CompoundFailure.ToolMember]);
        Assert.Equal("three", (string?)body[CompoundFailure.StepMember]);
        Assert.Equal("execution", (string?)body[CompoundFailure.StageMember]);
        Assert.Equal("Transport", (string?)body[CompoundFailure.CodeMember]);
        Assert.Equal(["one", "two"], ((JsonArray)body[CompoundFailure.CompletedMember]!).Select(s => (string?)s));
    }

    /// <summary>
    /// A failure before the first step names no step rather than naming the first one.
    /// </summary>
    [Fact]
    public void A_failure_outside_any_step_names_none()
    {
        JsonObject body = CompoundFailure.Body(
            "flow", null, CompoundStage.Plan, ExecutionFailureKind.Compilation, []);

        Assert.Null(body[CompoundFailure.StepMember]);
        Assert.Empty((JsonArray)body[CompoundFailure.CompletedMember]!);
    }

    /// <summary>
    /// The error code vocabulary is the execution classification, not a second one.
    /// </summary>
    /// <remarks>
    /// One published closed set instead of two overlapping ones. A caller already has to
    /// understand <see cref="ExecutionFailureKind"/> to react to a single call, and a workflow
    /// that answered in a private vocabulary would make the same failure look like two.
    /// </remarks>
    [Fact]
    public void Every_execution_classification_can_appear_as_an_error_code()
    {
        foreach (ExecutionFailureKind kind in Enum.GetValues<ExecutionFailureKind>())
        {
            JsonObject body = CompoundFailure.Body("flow", "one", CompoundStage.Execution, kind, []);

            Assert.Equal(kind.ToString(), (string?)body[CompoundFailure.CodeMember]);
        }
    }

    [Fact]
    public void The_stage_vocabulary_is_closed()
        => Assert.Equal(
            ["execution", "mapping", "plan", "selection", "transformation", "workflow"],
            CompoundStage.All.OrderBy(static stage => stage, StringComparer.Ordinal));

    // ---- fixtures ------------------------------------------------------------------------

    private static bool TryResolve(
        ManifestDocument manifest,
        CompoundBinding binding,
        out CompoundPlan? plan,
        out string? failure)
        => StepPlanResolver.TryResolve(manifest, manifest.Policy, binding, out plan, out failure);

    private static CompoundBinding Binding(string operation)
        => new([new CompoundStepEntry("s0", operation)]);

    private static ManifestDocument Manifest(
        AgentOperationEntry? extra = null,
        CompoundBounds? compound = null)
    {
        List<AgentOperationEntry> operations =
        [
            new("list-pets", "List pets", new HttpBinding("GET /pets")),
        ];

        if (extra is not null)
        {
            operations.Add(extra);
        }

        return new ManifestDocument(
            ManifestFormatSupport.Maximum,
            new ServerSection("Example API"),
            new PolicySection(BaseUrl, Compound: compound),
            new OperationsSection([new ManifestOperation("GET /pets", "GET", "/pets")]),
            new AgentSurfaceSection(operations));
    }
}
