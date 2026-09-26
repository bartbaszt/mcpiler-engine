namespace MCPiler.Engine.Runtime.Projection;

/// <summary>
/// The externally enforceable bounds of one JMESPath profile-1 output projection.
/// </summary>
/// <remarks>
/// <para>
/// Every value here is enforced by MCPiler outside the evaluator: expression bytes and input
/// tree metrics before an expression runs, completed-result metrics after it returns, and
/// serialized output bytes while the result is read back in. None of these is a claim about
/// the evaluator's internal work; the unchanged package exposes no such hooks, and it is
/// deliberately never run in a serving process at all. That is why <c>maxResultNodes</c> is
/// named <em>completed</em> result: an oversized intermediate tree is contained by the
/// worker's operating-system memory limit, not by a meter.
/// </para>
/// <para>
/// <c>MaxEvaluationMilliseconds</c> is the total wall budget for one worker call's launch,
/// confinement handshake, IPC and evaluation. The synchronous process-launch call itself is not
/// interruptible; after it returns, the deadline governs the remaining work. Mandatory kill/reap
/// after cancellation uses a separate bounded cleanup interval, and an unconfirmed reap keeps
/// capacity charged. It is an operational bound: two machines may reach different outcomes on the
/// same input, and a caller must not treat a timeout as a language result.
/// </para>
/// </remarks>
/// <param name="MaxExpressionBytes">UTF-8 byte length of the expression.</param>
/// <param name="MaxInputNodes">Maximum nodes in the parsed response body.</param>
/// <param name="MaxInputDepth">Maximum nesting depth of the parsed response body.</param>
/// <param name="MaxResultNodes">Maximum nodes in the completed result value.</param>
/// <param name="MaxResultDepth">Maximum nesting depth of the completed result value.</param>
/// <param name="MaxOutputBytes">Maximum bytes of the serialized projected result.</param>
/// <param name="MaxEvaluationMilliseconds">Total worker call wall budget.</param>
public sealed record JmesPathLimits(
    int MaxExpressionBytes,
    long MaxInputNodes,
    int MaxInputDepth,
    long MaxResultNodes,
    int MaxResultDepth,
    long MaxOutputBytes,
    int MaxEvaluationMilliseconds)
{
    /// <summary>The conservative values a new projection starts with.</summary>
    /// <remarks>
    /// These are ordinary authored values, not maximums. An author may explicitly raise any
    /// dimension up to the active administrator ceiling; the defaults exist so the ordinary
    /// path does not silently consume the ceiling's headroom.
    /// </remarks>
    public static JmesPathLimits AuthoringDefault { get; } = new(
        MaxExpressionBytes: 4096,
        MaxInputNodes: 100_000,
        MaxInputDepth: 64,
        MaxResultNodes: 8_192,
        MaxResultDepth: 32,
        MaxOutputBytes: 256L * 1024,
        MaxEvaluationMilliseconds: 10_000);

    /// <summary>The product-default ceilings an administrator policy may narrow.</summary>
    /// <remarks>
    /// The evaluation deadline is deliberately generous: a legitimate 10 000-element sort over
    /// the unchanged package measured just over one second on the calibration host, and a
    /// quadratic sort over a large array is meant to be terminated by this bound rather than to
    /// complete. Narrowing it is an operator decision; widening it beyond this value is refused.
    /// </remarks>
    public static JmesPathLimits AdministratorCeiling { get; } = new(
        MaxExpressionBytes: 16384,
        MaxInputNodes: 1_000_000,
        MaxInputDepth: 64,
        MaxResultNodes: 65_536,
        MaxResultDepth: 64,
        MaxOutputBytes: 1L * 1024 * 1024,
        MaxEvaluationMilliseconds: 60_000);

    /// <summary>Whether every dimension is strictly positive.</summary>
    public bool IsPositive =>
        MaxExpressionBytes > 0
        && MaxInputNodes > 0
        && MaxInputDepth > 0
        && MaxResultNodes > 0
        && MaxResultDepth > 0
        && MaxOutputBytes > 0
        && MaxEvaluationMilliseconds > 0;

    /// <summary>
    /// Names every dimension in which this value exceeds <paramref name="ceiling"/>.
    /// </summary>
    /// <returns>An empty list when this value fits entirely inside the ceiling.</returns>
    public IReadOnlyList<string> ExceedingDimensions(JmesPathLimits ceiling)
    {
        ArgumentNullException.ThrowIfNull(ceiling);

        var exceeding = new List<string>();

        if (MaxExpressionBytes > ceiling.MaxExpressionBytes)
        {
            exceeding.Add(nameof(MaxExpressionBytes));
        }

        if (MaxInputNodes > ceiling.MaxInputNodes)
        {
            exceeding.Add(nameof(MaxInputNodes));
        }

        if (MaxInputDepth > ceiling.MaxInputDepth)
        {
            exceeding.Add(nameof(MaxInputDepth));
        }

        if (MaxResultNodes > ceiling.MaxResultNodes)
        {
            exceeding.Add(nameof(MaxResultNodes));
        }

        if (MaxResultDepth > ceiling.MaxResultDepth)
        {
            exceeding.Add(nameof(MaxResultDepth));
        }

        if (MaxOutputBytes > ceiling.MaxOutputBytes)
        {
            exceeding.Add(nameof(MaxOutputBytes));
        }

        if (MaxEvaluationMilliseconds > ceiling.MaxEvaluationMilliseconds)
        {
            exceeding.Add(nameof(MaxEvaluationMilliseconds));
        }

        return exceeding;
    }

    /// <summary>The dimension-wise minimum of this value and <paramref name="ceiling"/>.</summary>
    public JmesPathLimits ClampTo(JmesPathLimits ceiling)
    {
        ArgumentNullException.ThrowIfNull(ceiling);

        return new JmesPathLimits(
            Math.Min(MaxExpressionBytes, ceiling.MaxExpressionBytes),
            Math.Min(MaxInputNodes, ceiling.MaxInputNodes),
            Math.Min(MaxInputDepth, ceiling.MaxInputDepth),
            Math.Min(MaxResultNodes, ceiling.MaxResultNodes),
            Math.Min(MaxResultDepth, ceiling.MaxResultDepth),
            Math.Min(MaxOutputBytes, ceiling.MaxOutputBytes),
            Math.Min(MaxEvaluationMilliseconds, ceiling.MaxEvaluationMilliseconds));
    }
}
