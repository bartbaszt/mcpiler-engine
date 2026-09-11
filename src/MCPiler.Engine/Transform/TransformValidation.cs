using System.Text.Json.Nodes;

namespace MCPiler.Engine.Transform;

/// <summary>
/// Tier 1 of transformation validation, in full, as a load-time gate.
/// </summary>
/// <remarks>
/// <para>
/// Tiers 2 and 3 are the producer's. Shape inference wants the upstream contract and dry-run
/// evidence wants a sample corpus and an authoring context, none of which a serving process
/// has; their absence from a manifest is not a defect in the manifest.
/// </para>
/// <para>
/// Tier 1 is not re-derivation. Every bound the evaluator will enforce is read out of members
/// that only this pass proves are present and well-formed, so skipping it would leave the
/// evaluator reading a limit that might not exist.
/// </para>
/// <para>
/// Order is deliberate. The version gate comes first because a later grammar may give an
/// existing member a different meaning. Everything after it runs against a parsed program, and
/// the three passes are independent: a program with a bad pointer and a missing bound reports
/// both, because a manifest author reading one finding per run is debugging by bisection.
/// </para>
/// </remarks>
internal static class TransformValidation
{
    /// <summary>Validates one program document.</summary>
    /// <param name="document">The program as it appears in the manifest.</param>
    /// <param name="ceiling">The manifest policy's transform ceiling.</param>
    /// <param name="fileArguments">The agent argument names declared as file slots.</param>
    /// <returns>Every reason the program is refused; empty when it is valid.</returns>
    internal static IReadOnlyList<TransformFinding> Validate(
        JsonObject document,
        TransformCeilingValues ceiling,
        IReadOnlySet<string> fileArguments)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(ceiling);
        ArgumentNullException.ThrowIfNull(fileArguments);

        (TransformProgram? program, IReadOnlyList<TransformFinding> parsed) =
            TransformProgramReader.Read(document);

        if (program is null)
        {
            return parsed;
        }

        List<TransformFinding> findings = [.. parsed];

        PointerValidation.Validate(program, findings);
        BoundsValidation.Validate(program, ceiling, findings);
        ExclusionValidation.Validate(program, fileArguments, findings);

        return findings;
    }
}
