namespace MCPiler.Engine.Execution;

/// <summary>The outcome of one execution, successful or not.</summary>
/// <remarks>
/// <para>
/// A failure is a value here rather than an exception that escaped. Every way an execution can
/// go wrong — a refused destination, an unresolvable credential, a body over the ceiling, a
/// store that would not take a payload — arrives as a <see cref="Failure"/> with a
/// <see cref="FailureReason"/>, so a caller handles one shape instead of a catalogue of
/// exception types it has to keep in step with this assembly.
/// </para>
/// <para>
/// <see cref="Failure"/> is what callers branch on. <see cref="FailureReason"/> is for a human,
/// and rewording it is not a behavioural change: any code that read the text to decide what
/// happened would break on a typo fix.
/// </para>
/// </remarks>
public sealed record EngineExecutionResult
{
    /// <summary>The compiled request, present once compilation succeeded.</summary>
    public CompiledRequest? Request { get; init; }

    /// <summary>The observed status code, present once a response arrived.</summary>
    public int? StatusCode { get; init; }

    /// <summary>Response and content headers together, present once a response arrived.</summary>
    public IReadOnlyDictionary<string, string[]>? ResponseHeaders { get; init; }

    /// <summary>The observed media type without parameters.</summary>
    public string? ResponseMediaType { get; init; }

    /// <summary>The response body, when it was read as a value.</summary>
    public byte[]? ResponseBody { get; init; }

    /// <summary>The issued handle, when the body was stored as a file.</summary>
    public FileHandleReference? ResponseFile { get; init; }

    /// <summary>A human-readable explanation of the failure, or null on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary>What kind of failure occurred, or <see cref="ExecutionFailureKind.None"/>.</summary>
    public ExecutionFailureKind Failure { get; init; } = ExecutionFailureKind.None;

    /// <summary>True when nothing failed.</summary>
    public bool Succeeded => Failure == ExecutionFailureKind.None;
}
