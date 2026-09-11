namespace MCPiler.Engine.Transform;

/// <summary>Which half of a mapping pair a program is.</summary>
/// <remarks>
/// A pair is two independent documents. Nothing inverts one into the other, so a program is
/// only ever read in the direction it declares.
/// </remarks>
internal enum TransformDirection
{
    /// <summary>Agent arguments into an effective request.</summary>
    Input,

    /// <summary>An upstream response into an agent-facing value.</summary>
    Output,
}

/// <summary>What the target document holds before the first step runs.</summary>
internal enum TransformBase
{
    /// <summary>The deterministic default mapping for the operation.</summary>
    Passthrough,

    /// <summary>Nothing.</summary>
    Empty,
}

/// <summary>What a reading step does when its source does not resolve.</summary>
internal enum TransformOnMissing
{
    /// <summary>Leave the target untouched.</summary>
    Skip,

    /// <summary>Write a null.</summary>
    Null,

    /// <summary>Fail the evaluation.</summary>
    Error,
}

/// <summary>The types <c>convert</c> may coerce to.</summary>
/// <remarks>
/// This list is the entirety of the arithmetic the vocabulary admits. Widening it is a format
/// decision under a new <c>transformVersion</c>, not a configuration option.
/// </remarks>
internal enum TransformConvertType
{
    /// <summary>A JSON string.</summary>
    String,

    /// <summary>A JSON number.</summary>
    Number,

    /// <summary>A JSON boolean.</summary>
    Boolean,
}

/// <summary>
/// The resource bounds a program declares. Never absent and never unbounded.
/// </summary>
/// <param name="MaxSteps">Total steps one evaluation may execute.</param>
/// <param name="MaxDepth">Deepest nesting of iteration and conditional steps.</param>
/// <param name="MaxNodes">Total JSON nodes one evaluation may materialize.</param>
/// <param name="MaxOutputBytes">Size of the produced document.</param>
/// <param name="MaxArrayFanout">Product of the iteration bounds along one path.</param>
internal sealed record TransformLimits(
    int MaxSteps,
    int MaxDepth,
    int MaxNodes,
    long MaxOutputBytes,
    int MaxArrayFanout)
{
    /// <summary>
    /// Narrows every bound to the smaller of this program's value and <paramref name="ceiling"/>.
    /// </summary>
    /// <remarks>
    /// A program that declares more than the manifest's policy allows is not refused here. The
    /// delta assigns refusing an over-declared program to the producer, which knows the
    /// administrator's intent; a consumer's duty is that the transform never raises a limit the
    /// policy declares, and clamping is what discharges it. Refusing instead would make a
    /// manifest that runs safely under a tight policy fail to mount under that same policy.
    /// </remarks>
    internal TransformLimits ClampTo(TransformCeilingValues ceiling)
        => new(
            Math.Min(MaxSteps, ceiling.MaxSteps),
            Math.Min(MaxDepth, ceiling.MaxDepth),
            Math.Min(MaxNodes, ceiling.MaxNodes),
            Math.Min(MaxOutputBytes, ceiling.MaxOutputBytes),
            Math.Min(MaxArrayFanout, ceiling.MaxArrayFanout));
}

/// <summary>
/// The administrator ceiling a program is measured against, decoupled from the manifest model.
/// </summary>
/// <param name="MaxSteps">Step ceiling.</param>
/// <param name="MaxDepth">Depth ceiling.</param>
/// <param name="MaxNodes">Node ceiling.</param>
/// <param name="MaxOutputBytes">Output-size ceiling.</param>
/// <param name="MaxArrayFanout">Fan-out ceiling.</param>
/// <remarks>
/// Validation takes five numbers rather than the policy section so that a test can state a
/// ceiling without assembling a manifest, and so that the transform components stay readable
/// without the manifest model in scope.
/// </remarks>
internal sealed record TransformCeilingValues(
    int MaxSteps,
    int MaxDepth,
    int MaxNodes,
    long MaxOutputBytes,
    int MaxArrayFanout);

/// <summary>
/// One direction of a transformation: the closed envelope and its ordered steps.
/// </summary>
/// <param name="TransformVersion">The grammar version, gated before anything else is read.</param>
/// <param name="Direction">Which half of the pair this is.</param>
/// <param name="Base">What the target document starts as.</param>
/// <param name="Limits">The declared resource bounds.</param>
/// <param name="Steps">The steps, applied in array order.</param>
internal sealed record TransformProgram(
    int TransformVersion,
    TransformDirection Direction,
    TransformBase Base,
    TransformLimits Limits,
    IReadOnlyList<TransformStep> Steps)
{
    /// <summary>The only grammar version this build implements.</summary>
    internal const int SupportedVersion = 1;
}
