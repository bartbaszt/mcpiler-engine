namespace MCPiler.Engine.Runtime.Projection;

/// <summary>
/// The only way a serving process evaluates an untrusted JMESPath expression.
/// </summary>
/// <remarks>
/// <para>
/// The library decides what a projection means; it cannot decide where the evaluator runs,
/// because running the unchanged package in the serving process is the one outcome this whole
/// design exists to prevent. So the parent side of the evaluation is a port: the library asks,
/// and whichever host is serving answers — in the shipped hosts, by a short-lived,
/// OS-confined worker process, never in process.
/// </para>
/// <para>
/// The implementation owns the operational classes. A host that cannot confine, cannot launch,
/// or has no capacity answers with the corresponding <see cref="JmesPathFailureClass"/>, and
/// the library's callers treat that exactly like any other projection refusal. There is no
/// fallback path a host could take instead.
/// </para>
/// </remarks>
public interface IProjectionWorker
{
    /// <summary>Evaluates one expression against one already-bounded, normalized body.</summary>
    /// <param name="expression">The authored expression.</param>
    /// <param name="normalizedJson">
    /// The body, already validated against the input bounds and with object members in the
    /// profile's canonical order, so the evaluator's enumeration is deterministic.
    /// </param>
    /// <param name="limits">The effective limits for this evaluation.</param>
    /// <param name="cancellationToken">
    /// Cancels admission and asynchronous worker work. A synchronous process launch cannot be
    /// interrupted; after it returns, the call performs bounded cleanup. If exit cannot be
    /// confirmed, capacity remains charged.
    /// </param>
    ValueTask<JmesPathEvaluationResult> EvaluateAsync(
        string expression,
        ReadOnlyMemory<byte> normalizedJson,
        JmesPathLimits limits,
        CancellationToken cancellationToken);
}
