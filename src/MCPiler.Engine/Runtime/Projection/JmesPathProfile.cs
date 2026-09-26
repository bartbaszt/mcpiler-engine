using System.Globalization;

using MCPiler.Engine.JmesPath;

namespace MCPiler.Engine.Runtime.Projection;

/// <summary>
/// The library's whole surface for one profile-1 output projection.
/// </summary>
/// <remarks>
/// <para>
/// Both halves of an evaluation are here and neither of them calls the evaluator: a host on one
/// side of a process boundary prepares a body and validates a result, and the worker on the
/// other side evaluates. The split is the point — preparing and validating are pure functions
/// of the bytes and the declared limits, so every process can perform them, while evaluation is
/// the one operation that must not happen where the product answers.
/// </para>
/// <para>
/// Nothing here accepts an ambient service, a header, a credential, a Manifest or a file
/// handle, and there is no overload that takes one. An evaluation's inputs are an expression
/// and a JSON body; anything else would be a value the expression could reach that the
/// projection never declared.
/// </para>
/// </remarks>
public static class JmesPathProfile
{
    private const long CanonicalizationExpansionFactor = 6;
    private const long CanonicalizationEnvelopeBytes = 1024;

    /// <summary>
    /// Returns the maximum prepared input frame for a raw JSON input bound.
    /// </summary>
    public static long PreparedInputFrameLimitBytes(long rawInputBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rawInputBytes);

        return checked((rawInputBytes * CanonicalizationExpansionFactor) + CanonicalizationEnvelopeBytes);
    }

    /// <summary>The only JMESPath language version this profile implements.</summary>
    /// <remarks>
    /// The version is MCPiler's, not the evaluator package's. It selects the frozen language
    /// and function profile — the official compliance snapshot plus this product's authored
    /// fixtures — so a dependency upgrade cannot silently redefine what a stored projection
    /// means. An expression that claims a different version is refused rather than best-effort
    /// interpreted against this one.
    /// </remarks>
    public const int SupportedLanguageVersion = 1;

    /// <summary>
    /// Parses a body, measures it against the input bounds, and freezes its member order.
    /// </summary>
    /// <param name="body">The raw inline JSON body bytes.</param>
    /// <param name="limits">The effective limits.</param>
    /// <param name="prepared">The evaluator-ready body, or null when it was refused.</param>
    /// <param name="failure">The refusal when the body was rejected.</param>
    /// <returns>True when the body is eligible for evaluation.</returns>
    public static bool TryPrepareInput(
        ReadOnlyMemory<byte> body,
        JmesPathLimits limits,
        out JmesPathPreparedInput? prepared,
        out JmesPathFailure? failure)
    {
        ArgumentNullException.ThrowIfNull(limits);

        prepared = null;
        failure = null;

        if (!limits.IsPositive)
        {
            failure = new JmesPathFailure(
                JmesPathFailureClass.InternalEvaluatorDefect,
                "The effective limits are not all positive, so no evaluation can be bounded.");

            return false;
        }

        if (!JmesPathDocument.TryParse(body, out var document, out failure))
        {
            return false;
        }

        using (document)
        {
            // A frame is JSON text, not raw source: re-encoding can expand a multi-byte
            // character into escapes. The checked six-times source bound plus envelope is
            // the measured transport ceiling; the cap refuses rather than partially writes.
            long cap = PreparedInputFrameLimitBytes(body.Length);

            if (!JmesPathCanonicalizer.TryCanonicalize(
                    document.RootElement,
                    JmesPathBudget.Input,
                    limits.MaxInputNodes,
                    limits.MaxInputDepth,
                    cap,
                    out byte[]? canonical,
                    out JmesPathValueMetrics metrics,
                    out failure))
            {
                return false;
            }

            prepared = new JmesPathPreparedInput(canonical!, metrics);
            return true;
        }
    }

    /// <summary>
    /// Evaluates an expression against an already-prepared body.
    /// </summary>
    /// <remarks>
    /// This is the worker side. It re-measures the body it received rather than trusting the
    /// preparation that produced it: the bytes crossed a boundary, and a bound that is only
    /// enforced by the sender is a bound the sender can be wrong about.
    /// </remarks>
    /// <param name="preparedJson">The prepared body bytes.</param>
    /// <param name="expression">The authored expression.</param>
    /// <param name="limits">The effective limits.</param>
    public static JmesPathEvaluationResult EvaluatePrepared(
        ReadOnlyMemory<byte> preparedJson,
        string expression,
        JmesPathLimits limits)
    {
        ArgumentException.ThrowIfNullOrEmpty(expression);
        ArgumentNullException.ThrowIfNull(limits);

        try
        {
            return EvaluatePreparedCore(preparedJson, expression, limits);
        }
        catch (OutOfMemoryException)
        {
            // An allocation refused by the enforced limit is operational evidence wherever in
            // the pipeline it lands, including the re-parse and re-canonicalization that run
            // before the evaluator. Classifying it here keeps the child able to answer with a
            // precise class instead of dying without a frame.
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.OperationalMemoryExceeded,
                "The projection worker reached its enforced memory limit."));
        }
    }

    private static JmesPathEvaluationResult EvaluatePreparedCore(
        ReadOnlyMemory<byte> preparedJson,
        string expression,
        JmesPathLimits limits)
    {
        if (ExpressionByteCount(expression) > limits.MaxExpressionBytes)
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.ExpressionTooManyBytes,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The expression is longer than maxExpressionBytes={limits.MaxExpressionBytes} bytes.")));
        }

        if (!JmesPathDocument.TryParse(preparedJson, out var document, out JmesPathFailure? parseFailure))
        {
            return JmesPathEvaluationResult.Failed(parseFailure!);
        }

        using (document)
        {
            if (!JmesPathCanonicalizer.TryCanonicalize(
                    document.RootElement,
                    JmesPathBudget.Input,
                    limits.MaxInputNodes,
                    limits.MaxInputDepth,
                    PreparedInputFrameLimitBytes(preparedJson.Length),
                    out byte[]? normalized,
                    out _,
                    out JmesPathFailure? boundFailure))
            {
                return JmesPathEvaluationResult.Failed(boundFailure!);
            }

            return CorvusJmesPathRuntime.Evaluate(normalized!, expression, limits);
        }
    }

    /// <summary>
    /// Validates a worker's result frame and returns the canonical serialized value.
    /// </summary>
    /// <remarks>
    /// The parent performs this independently of the worker that produced it. Two things are
    /// established at once: the frame is JSON inside the completed-result bounds, and its bytes
    /// are already the canonical form. A mismatch means the worker and the validator disagree
    /// about the same value, which is a defect in one of them rather than something to paper
    /// over by accepting whichever arrived.
    /// </remarks>
    public static bool TryVerifyResult(
        ReadOnlyMemory<byte> payload,
        JmesPathLimits limits,
        out byte[]? canonical,
        out JmesPathValueMetrics metrics,
        out JmesPathFailure? failure)
    {
        ArgumentNullException.ThrowIfNull(limits);

        canonical = null;
        metrics = default;
        failure = null;

        if (!JmesPathDocument.TryParse(payload, out var document, out _))
        {
            failure = new JmesPathFailure(
                JmesPathFailureClass.OperationalWorkerFailure,
                "The worker's result frame is not valid JSON.");

            return false;
        }

        using (document)
        {
            if (!JmesPathCanonicalizer.TryCanonicalize(
                    document.RootElement,
                    JmesPathBudget.Result,
                    limits.MaxResultNodes,
                    limits.MaxResultDepth,
                    limits.MaxOutputBytes,
                    out byte[]? recanonicalized,
                    out metrics,
                    out failure))
            {
                return false;
            }

            if (!payload.Span.SequenceEqual(recanonicalized))
            {
                failure = new JmesPathFailure(
                    JmesPathFailureClass.OperationalWorkerFailure,
                    "The worker's result frame is not the canonical form of the value it reports.");

                return false;
            }

            canonical = recanonicalized;
            return true;
        }
    }

    /// <summary>The UTF-8 byte length of an expression, the only size profile 1 declares.</summary>
    /// <remarks>
    /// A character count would let a string of multi-byte text cross the declared bound by a
    /// factor of four, which is the direction that matters for a bound whose job is refusal.
    /// </remarks>
    public static int ExpressionByteCount(string expression)
    {
        ArgumentNullException.ThrowIfNull(expression);

        return System.Text.Encoding.UTF8.GetByteCount(expression);
    }
}
