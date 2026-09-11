using System.Globalization;

using MCPiler.Engine.Manifest.Loading;

namespace MCPiler.Engine.Transform;

/// <summary>
/// Measures a program's static worst case against the limits that will actually govern it.
/// </summary>
/// <remarks>
/// <para>
/// The mandatory per-step bounds are read by <see cref="TransformProgramReader"/>, which
/// refuses a program that declares none. What is left here is the consequence: the bounds are
/// multiplicative along a nesting path, so a program whose individual numbers all look modest
/// can still describe an evaluation that is not.
/// </para>
/// <para>
/// The estimate is measured against the <em>effective</em> limit, the smaller of the program's
/// declared value and the manifest policy's ceiling. Measuring against the declared value alone
/// would pass a program that the evaluator will abort on its first run, which moves a
/// deployment error to a caller.
/// </para>
/// <para>
/// This is an estimate, not a proof. Evaluation enforces the same limits again on real values,
/// and that enforcement does not depend on anything computed here.
/// </para>
/// </remarks>
internal static class BoundsValidation
{
    private const string LimitsMember = "limits";

    /// <summary>Reports every static estimate that exceeds its effective limit.</summary>
    /// <param name="program">The parsed program.</param>
    /// <param name="ceiling">The manifest policy's transform ceiling.</param>
    /// <param name="findings">Where findings accumulate.</param>
    internal static void Validate(
        TransformProgram program,
        TransformCeilingValues ceiling,
        ICollection<TransformFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(program);
        ArgumentNullException.ThrowIfNull(ceiling);
        ArgumentNullException.ThrowIfNull(findings);

        TransformLimits effective = program.Limits.ClampTo(ceiling);

        int steps = WorstCaseSteps(program.Steps);

        if (steps > effective.MaxSteps)
        {
            findings.Add(Exceeded(
                TransformCodes.StepLimit,
                "step count",
                steps,
                effective.MaxSteps,
                "maxSteps"));
        }

        int depth = WorstCaseDepth(program.Steps);

        if (depth > effective.MaxDepth)
        {
            findings.Add(Exceeded(
                TransformCodes.StaticDepth,
                "nesting depth",
                depth,
                effective.MaxDepth,
                "maxDepth"));
        }

        long fanout = WorstCaseFanout(program.Steps);

        if (fanout > effective.MaxArrayFanout)
        {
            findings.Add(Exceeded(
                TransformCodes.StaticFanout,
                "array fan-out",
                fanout,
                effective.MaxArrayFanout,
                "maxArrayFanout"));
        }
    }

    /// <summary>
    /// The largest number of step executions the program can describe.
    /// </summary>
    /// <remarks>
    /// A nested list inside an iteration runs once per item, so it is charged its bound times.
    /// A conditional's branches are exclusive at evaluation, and the worst case is the larger
    /// of the two rather than their sum.
    /// </remarks>
    private static int WorstCaseSteps(IReadOnlyList<TransformStep> steps)
    {
        int total = 0;

        foreach (TransformStep step in steps)
        {
            total = Saturating(total, 1);

            total = step switch
            {
                MapArrayStep s => Saturating(total, Multiply(WorstCaseSteps(s.Steps), s.MaxItems)),
                MapObjectStep s => Saturating(total, Multiply(WorstCaseSteps(s.Steps), s.MaxEntries)),
                WhenStep s => Saturating(total, Math.Max(WorstCaseSteps(s.Steps), WorstCaseSteps(s.ElseSteps))),
                _ => total,
            };
        }

        return total;
    }

    /// <summary>The deepest nesting of iteration and conditional steps.</summary>
    private static int WorstCaseDepth(IReadOnlyList<TransformStep> steps)
    {
        int deepest = 0;

        foreach (TransformStep step in steps)
        {
            foreach ((string _, IReadOnlyList<TransformStep> nested) in StepWalk.NestedListsOf(step))
            {
                deepest = Math.Max(deepest, Saturating(1, WorstCaseDepth(nested)));
            }
        }

        return deepest;
    }

    /// <summary>
    /// The product of the iteration bounds along the heaviest nesting path.
    /// </summary>
    /// <remarks>
    /// Computed in <see cref="long"/> so that a program declaring bounds whose product
    /// overflows an <see cref="int"/> is refused for being too large rather than accepted for
    /// having wrapped to a small number.
    /// </remarks>
    private static long WorstCaseFanout(IReadOnlyList<TransformStep> steps)
    {
        long heaviest = 1;

        foreach (TransformStep step in steps)
        {
            long here = step switch
            {
                MapArrayStep s => Saturating(s.MaxItems, WorstCaseFanout(s.Steps)),
                MapObjectStep s => Saturating(s.MaxEntries, WorstCaseFanout(s.Steps)),
                WhenStep s => Math.Max(WorstCaseFanout(s.Steps), WorstCaseFanout(s.ElseSteps)),
                _ => 1,
            };

            heaviest = Math.Max(heaviest, here);
        }

        return heaviest;
    }

    private static int Multiply(int steps, int bound)
        => steps == 0 ? 0 : (int)Math.Min(int.MaxValue, (long)steps * bound);

    private static int Saturating(int left, int right)
        => (int)Math.Min(int.MaxValue, (long)left + right);

    private static long Saturating(long left, long right)
    {
        if (left == 0 || right == 0)
        {
            return 0;
        }

        return right > long.MaxValue / left ? long.MaxValue : left * right;
    }

    private static TransformFinding Exceeded(
        string code,
        string what,
        long measured,
        long limit,
        string member)
        => new(
            code,
            string.Create(
                CultureInfo.InvariantCulture,
                $"The static worst-case {what} of {measured} exceeds the effective limit of {limit}. The effective limit is the smaller of the program's '{member}' and the manifest policy's transform ceiling."),
            Step: null,
            JsonPointer.Build(LimitsMember, member));
}
