namespace MCPiler.Engine.Runtime.Projection;

/// <summary>
/// The stable failure classes a JMESPath profile-1 evaluation can produce.
/// </summary>
/// <remarks>
/// <para>
/// The classes are MCPiler's, not the evaluator's. They exist so Platform preview, publication
/// readiness and Engine invocation can agree on what failed without agreeing on diagnostic
/// prose, and so a projection breach is distinguishable from an upstream HTTP failure and from
/// a schema-conformance signal.
/// </para>
/// <para>
/// Operational classes are grouped at the end and describe a machine-dependent outcome
/// (deadline, memory admission, saturation) rather than a language result. They must never be
/// presented as deterministic, and a host builds them without consulting the evaluator. The
/// order matters: <see cref="JmesPathFailure.IsOperational"/> is the range from
/// <see cref="OperationalTimeout"/> onward, and <see cref="InternalEvaluatorDefect"/> sits
/// before that range because a dependency defect is a bug report, not machine load.
/// </para>
/// </remarks>
public enum JmesPathFailureClass
{
    /// <summary>The expression is not valid: a compile-phase failure family.</summary>
    CompileSyntax,

    /// <summary>The expression names a function profile 1 does not define.</summary>
    CompileUnknownFunction,

    /// <summary>The expression calls a known function with the wrong argument count.</summary>
    CompileInvalidArity,

    /// <summary>The expression uses grammar the evaluator does not support.</summary>
    CompileUnsupportedNode,

    /// <summary>The expression exceeds the effective UTF-8 byte budget.</summary>
    ExpressionTooManyBytes,

    /// <summary>
    /// The expression compiled, but applying it to this input produced a standard
    /// <c>invalid-type</c> failure. This is not a validity finding.
    /// </summary>
    RuntimeInvalidType,

    /// <summary>
    /// The expression compiled, but applying it to this input produced a value the language
    /// refuses, such as a slice step of zero. Like a type failure this is data-dependent and is
    /// therefore not a validity finding.
    /// </summary>
    RuntimeInvalidValue,

    /// <summary>The parsed input exceeds the allowed node count.</summary>
    InputTooManyNodes,

    /// <summary>The parsed input exceeds the allowed depth.</summary>
    InputTooDeep,

    /// <summary>The input body is not inline JSON eligible for projection.</summary>
    InputNotJson,

    /// <summary>The response was classified as binary or a file.</summary>
    InputFileOrBinary,

    /// <summary>The completed result exceeds the allowed node count.</summary>
    ResultTooManyNodes,

    /// <summary>The completed result exceeds the allowed depth.</summary>
    ResultTooDeep,

    /// <summary>The serialized result exceeds the allowed byte count.</summary>
    OutputTooManyBytes,

    /// <summary>The evaluator failed in a family MCPiler does not recognise.</summary>
    InternalEvaluatorDefect,

    /// <summary>The worker exceeded its total wall budget.</summary>
    OperationalTimeout,

    /// <summary>The caller cancelled the wait before the worker's wall budget expired.</summary>
    OperationalCancelled,

    /// <summary>The worker's OS memory boundary rejected an allocation.</summary>
    OperationalMemoryExceeded,

    /// <summary>The worker could not establish OS memory confinement.</summary>
    OperationalConfinementUnavailable,

    /// <summary>The worker pool had no capacity within the admission budget.</summary>
    OperationalBusy,

    /// <summary>The worker crashed, overflowed a bounded stream, or broke the protocol.</summary>
    OperationalWorkerFailure,
}

/// <summary>
/// One classified projection failure: a stable class plus a human-readable summary.
/// </summary>
/// <param name="FailureClass">The stable class.</param>
/// <param name="Message">What happened, without payload content.</param>
public sealed record JmesPathFailure(JmesPathFailureClass FailureClass, string Message)
{
    /// <summary>Whether the class describes a machine-dependent operational outcome.</summary>
    public bool IsOperational => FailureClass >= JmesPathFailureClass.OperationalTimeout;

    /// <summary>A stable machine readable code, for diagnostics and tests.</summary>
    public string Code => CodeOf(FailureClass);

    /// <summary>The stable machine readable code of one class.</summary>
    public static string CodeOf(JmesPathFailureClass failureClass) => failureClass switch
    {
        JmesPathFailureClass.CompileSyntax => "jmespath-compile-syntax",
        JmesPathFailureClass.CompileUnknownFunction => "jmespath-compile-unknown-function",
        JmesPathFailureClass.CompileInvalidArity => "jmespath-compile-invalid-arity",
        JmesPathFailureClass.CompileUnsupportedNode => "jmespath-compile-unsupported-node",
        JmesPathFailureClass.ExpressionTooManyBytes => "jmespath-expression-too-many-bytes",
        JmesPathFailureClass.RuntimeInvalidType => "jmespath-runtime-invalid-type",
        JmesPathFailureClass.RuntimeInvalidValue => "jmespath-runtime-invalid-value",
        JmesPathFailureClass.InputTooManyNodes => "jmespath-input-too-many-nodes",
        JmesPathFailureClass.InputTooDeep => "jmespath-input-too-deep",
        JmesPathFailureClass.InputNotJson => "jmespath-input-not-json",
        JmesPathFailureClass.InputFileOrBinary => "jmespath-input-file-or-binary",
        JmesPathFailureClass.ResultTooManyNodes => "jmespath-result-too-many-nodes",
        JmesPathFailureClass.ResultTooDeep => "jmespath-result-too-deep",
        JmesPathFailureClass.OutputTooManyBytes => "jmespath-output-too-many-bytes",
        JmesPathFailureClass.OperationalTimeout => "jmespath-operational-timeout",
        JmesPathFailureClass.OperationalCancelled => "jmespath-operational-cancelled",
        JmesPathFailureClass.OperationalMemoryExceeded => "jmespath-operational-memory-exceeded",
        JmesPathFailureClass.OperationalConfinementUnavailable => "jmespath-operational-confinement-unavailable",
        JmesPathFailureClass.OperationalBusy => "jmespath-operational-busy",
        JmesPathFailureClass.OperationalWorkerFailure => "jmespath-operational-worker-failure",
        _ => "jmespath-internal-evaluator-defect",
    };

    /// <summary>
    /// Keeps message text single-line and bounded so diagnostics cannot smuggle payload.
    /// </summary>
    /// <remarks>
    /// This is part of the seam because both sides of the process boundary quote diagnostic text
    /// they did not author: the worker quotes evaluator messages and the parent quotes launch
    /// failures. One implementation means the bound cannot differ between them.
    /// </remarks>
    public static string Sanitize(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "(no message)";
        }

        string flattened = message.Replace('\r', ' ').Replace('\n', ' ').Trim();

        return flattened.Length <= 300 ? flattened : flattened[..300];
    }

    /// <summary>
    /// The class named by a stable code, as a code travels across a process boundary.
    /// </summary>
    /// <remarks>
    /// An unknown code maps to <see cref="JmesPathFailureClass.InternalEvaluatorDefect"/>: a
    /// worker that reported something this build cannot name is a defect to surface, not a
    /// language result to reinterpret.
    /// </remarks>
    public static JmesPathFailureClass ClassFromCode(string? code) => code switch
    {
        "jmespath-compile-syntax" => JmesPathFailureClass.CompileSyntax,
        "jmespath-compile-unknown-function" => JmesPathFailureClass.CompileUnknownFunction,
        "jmespath-compile-invalid-arity" => JmesPathFailureClass.CompileInvalidArity,
        "jmespath-compile-unsupported-node" => JmesPathFailureClass.CompileUnsupportedNode,
        "jmespath-expression-too-many-bytes" => JmesPathFailureClass.ExpressionTooManyBytes,
        "jmespath-runtime-invalid-type" => JmesPathFailureClass.RuntimeInvalidType,
        "jmespath-runtime-invalid-value" => JmesPathFailureClass.RuntimeInvalidValue,
        "jmespath-input-too-many-nodes" => JmesPathFailureClass.InputTooManyNodes,
        "jmespath-input-too-deep" => JmesPathFailureClass.InputTooDeep,
        "jmespath-input-not-json" => JmesPathFailureClass.InputNotJson,
        "jmespath-input-file-or-binary" => JmesPathFailureClass.InputFileOrBinary,
        "jmespath-result-too-many-nodes" => JmesPathFailureClass.ResultTooManyNodes,
        "jmespath-result-too-deep" => JmesPathFailureClass.ResultTooDeep,
        "jmespath-output-too-many-bytes" => JmesPathFailureClass.OutputTooManyBytes,
        "jmespath-operational-timeout" => JmesPathFailureClass.OperationalTimeout,
        "jmespath-operational-cancelled" => JmesPathFailureClass.OperationalCancelled,
        "jmespath-operational-memory-exceeded" => JmesPathFailureClass.OperationalMemoryExceeded,
        "jmespath-operational-confinement-unavailable" => JmesPathFailureClass.OperationalConfinementUnavailable,
        "jmespath-operational-busy" => JmesPathFailureClass.OperationalBusy,
        "jmespath-operational-worker-failure" => JmesPathFailureClass.OperationalWorkerFailure,
        _ => JmesPathFailureClass.InternalEvaluatorDefect,
    };
}
