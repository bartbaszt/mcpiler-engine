namespace MCPiler.Engine.Runtime.Projection;

/// <summary>
/// What one worker evaluation produced.
/// </summary>
/// <remarks>
/// <para>
/// This is what a caller gets instead of an exception, because every failure has to survive a
/// process and frame boundary: the unchanged evaluator raises one exception type for lexing,
/// parsing and evaluation alike, and the class — not the prose — is what Platform preview,
/// publication readiness and Engine invocation act on.
/// </para>
/// <para>
/// A successful result carries only the bytes. The metrics belong to whoever measured them,
/// and the parent re-measures the frame independently: a bound that only the child enforces is
/// a bound the child could forget, or could be made to forget by an upgrade.
/// </para>
/// </remarks>
/// <param name="Succeeded">Whether the expression produced a value.</param>
/// <param name="Output">The canonical serialized value, or null when the evaluation failed.</param>
/// <param name="Failure">The classified failure, or null when the evaluation succeeded.</param>
public sealed record JmesPathEvaluationResult(
    bool Succeeded,
    byte[]? Output,
    JmesPathFailure? Failure)
{
    /// <summary>A successful evaluation.</summary>
    public static JmesPathEvaluationResult Produced(byte[] output) => new(Succeeded: true, output, Failure: null);

    /// <summary>A classified failure.</summary>
    public static JmesPathEvaluationResult Failed(JmesPathFailure failure) => new(Succeeded: false, Output: null, failure);
}
