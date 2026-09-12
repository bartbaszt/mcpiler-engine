using System.Globalization;
using System.Text.Json.Nodes;

namespace MCPiler.Engine.Transform;

/// <summary>
/// What one bounded evaluation produced, or why it stopped.
/// </summary>
/// <param name="Output">
/// The transformed document, present only on success. A failed evaluation carries none: a
/// partially applied document is not a shorter answer, it is a different one, and returning it
/// alongside a failure invites a caller to use it.
/// </param>
/// <param name="Code">The abort reason from <see cref="TransformCodes"/>, or <c>null</c> on success.</param>
/// <param name="Step">
/// The index of the <em>top-level</em> step that aborted, or <c>null</c> when the failure
/// belongs to the document rather than to a step.
/// </param>
/// <param name="Operation">The wire name of that step's operation, or <c>null</c> with no step.</param>
/// <param name="Message">An operator-facing explanation. Never contractual.</param>
internal sealed record TransformEvaluation(
    JsonNode? Output,
    string? Code,
    int? Step,
    string? Operation,
    string? Message)
{
    /// <summary>Whether the program ran to completion.</summary>
    internal bool Succeeded => Code is null;

    internal static TransformEvaluation Produced(JsonNode? output)
        => new(output, null, null, null, null);

    /// <summary>An abort attributable to one step.</summary>
    internal static TransformEvaluation Aborted(string code, int step, string operation, string message)
        => new(null, code, step, operation, message);

    /// <summary>
    /// An abort belonging to the document as a whole.
    /// </summary>
    /// <remarks>
    /// The produced document's size is the only such condition. Attributing it to the last step
    /// that ran would name a step that may have added nothing; the program is what exceeded the
    /// bound.
    /// </remarks>
    internal static TransformEvaluation AbortedWholly(string code, string message)
        => new(null, code, null, null, message);

    /// <summary>
    /// Re-attributes a failure raised inside a nested step list to the enclosing step.
    /// </summary>
    /// <remarks>
    /// The index every other surface counts in is the top-level one, so a nested abort reports
    /// the enclosing step and says where inside it the abort happened. Reporting the inner
    /// index alone would name step 0 for a failure in the first nested step of step 7.
    /// </remarks>
    internal TransformEvaluation Within(int step, string operation, string place)
        => new(null, Code, step, operation, string.Create(CultureInfo.InvariantCulture, $"{place}: {Message}"));

    /// <summary>The failure as one sentence naming the step index and the operation.</summary>
    internal string Describe()
        => Step is { } step && Operation is { } operation
            ? string.Create(CultureInfo.InvariantCulture, $"{Code} at step {step} ({operation}): {Message}")
            : string.Create(CultureInfo.InvariantCulture, $"{Code}: {Message}");
}
