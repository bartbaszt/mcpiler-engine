using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.Host.ProjectionWorker;

/// <summary>
/// The load-time expression check, answered by the same confined worker every evaluation uses.
/// </summary>
/// <remarks>
/// <para>
/// A manifest is validated before a listener exists, so this runs a real worker with the
/// expression and a placeholder body and classifies what comes back. Compiling the expression
/// in the host process would be quicker and would break the one rule the whole design exists
/// for, so the wait is a process launch by design rather than by accident.
/// </para>
/// <para>
/// The call is synchronous because loading is. There is no synchronization context in a serving
/// or inspection process and every await on the worker path stays unbound, so waiting here
/// cannot deadlock; the worker's own total deadline is what bounds the wait.
/// </para>
/// <para>
/// The placeholder is an empty object and the expression is not asked to succeed on it — only
/// to compile. <c>keys(@)</c> and <c>sort(@)</c> fail it with a data-dependent family and are
/// valid projections; that distinction is why a runtime-family result maps to
/// <see cref="ProjectionExpressionValidityStatus.Valid"/>.
/// </para>
/// </remarks>
internal sealed class WorkerExpressionValidator : IProjectionExpressionValidator, IProjectionWorker, IDisposable
{
    /// <summary>The body an expression is compiled against. Never interpreted as a real body.</summary>
    private static readonly byte[] Placeholder = "{}"u8.ToArray();

    private readonly WorkerPoolOptions _options;
    private ProjectionWorkerHost? _workers;

    /// <summary>Creates a validator that confines on first use and allocates nothing before it.</summary>
    /// <remarks>
    /// Lazy deliberately. Most manifests carry no JMESPath projection at all, and a process that
    /// serves one of them must not pay for a worker pool it will never use. The pool appears the
    /// first time an expression actually needs classifying.
    /// </remarks>
    internal WorkerExpressionValidator(WorkerPoolOptions? options = null)
        => _options = options ?? WorkerPoolOptions.Default;

    private ProjectionWorkerHost Workers => _workers ??= new ProjectionWorkerHost(_options);

    /// <inheritdoc />
    public ProjectionExpressionValidity Validate(string expression, JmesPathLimits limits)
    {
        ArgumentNullException.ThrowIfNull(expression);
        ArgumentNullException.ThrowIfNull(limits);

        if (!JmesPathProfile.TryPrepareInput(
                Placeholder,
                limits,
                out JmesPathPreparedInput? prepared,
                out JmesPathFailure? refusal))
        {
            // The placeholder cannot cross the declared input bounds, which means the declared
            // bounds are unusable. That is a limit problem the ceiling check reports; here it is
            // an unavailable check rather than an invalid expression.
            return ProjectionExpressionValidity.Unavailable(
                refusal ?? new JmesPathFailure(
                    JmesPathFailureClass.OperationalConfinementUnavailable,
                    "The placeholder body could not be prepared under the declared limits."));
        }

        // VSTHRD002 is suppressed deliberately and locally. Manifest loading is synchronous by
        // design: it happens once, before a listener exists, on a thread with no synchronization
        // context, and the worker path everywhere else uses ConfigureAwait(false). Returning a
        // Task here instead would force every caller of the load path to become async to say
        // nothing about the manifest. The worker's own total deadline bounds the wait.
#pragma warning disable VSTHRD002
        JmesPathEvaluationResult result = Workers
            .EvaluateAsync(expression, prepared!.Json, limits, CancellationToken.None)
            .AsTask()
            .GetAwaiter()
            .GetResult();
#pragma warning restore VSTHRD002

        if (result.Succeeded)
        {
            return ProjectionExpressionValidity.Valid;
        }

        JmesPathFailure failure = result.Failure!;

        if (failure.IsOperational)
        {
            return ProjectionExpressionValidity.Unavailable(failure);
        }

        // A runtime family means the expression compiled. It failed against this placeholder,
        // which is not what the expression has to work on; only the compile families are
        // findings about the expression itself.
        return failure.FailureClass is
            JmesPathFailureClass.RuntimeInvalidType or JmesPathFailureClass.RuntimeInvalidValue
            ? ProjectionExpressionValidity.Valid
            : ProjectionExpressionValidity.Invalid(failure);
    }

    /// <summary>
    /// Answers the invocation side with the same pool the load side uses.
    /// </summary>
    /// <remarks>
    /// One pool, because the confinement is one mechanism: two pools would double the process
    /// budget an operator configured and would let load-time and invocation-time evaluations
    /// saturate each other's slots without either having said so. The pool is created on the
    /// first call from either direction.
    /// </remarks>
    public ValueTask<JmesPathEvaluationResult> EvaluateAsync(
        string expression,
        ReadOnlyMemory<byte> normalizedJson,
        JmesPathLimits limits,
        CancellationToken cancellationToken)
        => Workers.EvaluateAsync(expression, normalizedJson, limits, cancellationToken);

    /// <inheritdoc />
    public void Dispose() => _workers?.Dispose();
}
