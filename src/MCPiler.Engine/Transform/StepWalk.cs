using System.Globalization;

using MCPiler.Engine.Manifest.Loading;

namespace MCPiler.Engine.Transform;

/// <summary>
/// One step as the validators see it: the step itself, the top-level index it belongs to, its
/// location in the program document, and the document its pointers address.
/// </summary>
/// <param name="Step">The step.</param>
/// <param name="Index">The index of the top-level step this one is inside, or is.</param>
/// <param name="Location">A JSON Pointer to this step within the program document.</param>
/// <param name="Scope">Which document this step's pointers address.</param>
internal readonly record struct WalkedStep(
    TransformStep Step,
    int Index,
    string Location,
    PointerScope Scope);

/// <summary>
/// The single traversal of a program's step tree.
/// </summary>
/// <remarks>
/// <para>
/// Every Tier-1 check that looks at steps walks them the same way, so the walk is written
/// once. Three separate traversals would be three chances for one of them to stop short of a
/// nested list, and a check that silently skips the inside of a <c>mapArray</c> is worse than
/// no check, because it reports a pass.
/// </para>
/// <para>
/// The walk carries the top-level index rather than the nested one. That index is what every
/// other surface counts in, and a nested position reported bare would name a different,
/// innocent step.
/// </para>
/// </remarks>
internal static class StepWalk
{
    private const string StepsMember = "steps";
    private const string ElseStepsMember = "elseSteps";

    /// <summary>Yields every step in the tree, outermost first.</summary>
    internal static IEnumerable<WalkedStep> Descend(IReadOnlyList<TransformStep> steps)
    {
        ArgumentNullException.ThrowIfNull(steps);

        for (int index = 0; index < steps.Count; index++)
        {
            string location = JsonPointer.Build(StepsMember, Token(index));

            foreach (WalkedStep walked in Descend(steps[index], index, location, PointerScope.Program))
            {
                yield return walked;
            }
        }
    }

    private static IEnumerable<WalkedStep> Descend(
        TransformStep step,
        int index,
        string location,
        PointerScope scope)
    {
        yield return new WalkedStep(step, index, location, scope);

        // An iteration rebinds the document root to the item it iterates. A conditional does
        // not: its branches address whatever the conditional itself addressed.
        PointerScope inner = step is MapArrayStep or MapObjectStep ? PointerScope.Item : scope;

        foreach ((string member, IReadOnlyList<TransformStep> nested) in NestedListsOf(step))
        {
            for (int position = 0; position < nested.Count; position++)
            {
                string child = location + JsonPointer.Build(member, Token(position));

                foreach (WalkedStep walked in Descend(nested[position], index, child, inner))
                {
                    yield return walked;
                }
            }
        }
    }

    /// <summary>The nested step lists a step carries, with the member each one lives under.</summary>
    internal static IEnumerable<(string Member, IReadOnlyList<TransformStep> Steps)> NestedListsOf(
        TransformStep step)
        => step switch
        {
            MapArrayStep s => [(StepsMember, s.Steps)],
            MapObjectStep s => [(StepsMember, s.Steps)],
            WhenStep s => [(StepsMember, s.Steps), (ElseStepsMember, s.ElseSteps)],
            _ => [],
        };

    private static string Token(int index) => index.ToString(CultureInfo.InvariantCulture);
}
