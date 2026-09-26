using System.Text.Json.Nodes;

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

    /// <summary>
    /// The URI of the final request in the redirect chain, when a response was observed.
    /// </summary>
    /// <remarks>
    /// Captured as an execution fact rather than derived later: a relative pagination link is
    /// only meaningful against the representation's own URL, and the transport is the only
    /// component that saw which request produced the response.
    /// </remarks>
    public Uri? ResponseEffectiveUri { get; init; }

    /// <summary>The response body, when it was read as a value.</summary>
    public byte[]? ResponseBody { get; init; }

    /// <summary>The issued handle, when the body was stored as a file.</summary>
    public FileHandleReference? ResponseFile { get; init; }

    /// <summary>
    /// The opaque bearer capability that may cross a protocol boundary for <see cref="ResponseFile"/>.
    /// </summary>
    /// <remarks>
    /// Kept separate from <see cref="FileHandleReference"/> so the internal file-reference contract
    /// remains independent of any protocol wire representation.
    /// </remarks>
    public string? ResponseFileHandle { get; init; }

    /// <summary>A human-readable explanation of the failure, or null on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// A structured description of the failure, for the failures that have one.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="FailureReason"/> because the two have opposite contracts. The
    /// reason is prose and rewording it breaks nothing; this is a document whose member names
    /// and values a caller may branch on, and changing one is a versioning event. A workflow
    /// produces one, naming which step failed and how far it got; a single exchange has nothing
    /// to say that the classification and the reason do not already say.
    /// </remarks>
    public JsonNode? FailureDetail { get; init; }

    /// <summary>What kind of failure occurred, or <see cref="ExecutionFailureKind.None"/>.</summary>
    public ExecutionFailureKind Failure { get; init; } = ExecutionFailureKind.None;

    /// <summary>
    /// Bounded metadata findings produced after the response arrived.
    /// </summary>
    /// <remarks>
    /// A projection or pagination refusal is not an execution failure: the body stays available
    /// and these explain what was withheld. They are carried on the result so the serving layer
    /// can attribute them to a mounted Manifest and surface, which are facts the execution does
    /// not own.
    /// </remarks>
    public IReadOnlyList<ExecutionDiagnostic> Diagnostics { get; init; } = [];
    /// <summary>
    /// A short fingerprint of the caller partition this execution ran under, for diagnostics.
    /// </summary>
    /// <remarks>
    /// Never the partition value itself: the fingerprint is a display aid for comparing two
    /// decisions, and anything longer would be material an operator surface has no use for.
    /// Absent when no partition was established, which is also when caching bypasses.
    /// </remarks>
    public string? CallerPartitionFingerprint { get; init; }

    /// <summary>
    /// A short fingerprint of the upstream authority this execution ran under, for diagnostics.
    /// </summary>
    /// <remarks>
    /// Absent when the authority could not be proven — a signing strategy, an unusable
    /// credential, or a failure that happened before credentials resolved. Absent is the signal
    /// that a cache would have bypassed, so it must never be replaced with a placeholder value.
    /// </remarks>
    public string? AuthorityFingerprint { get; init; }

    /// <summary>
    /// The earliest known expiry of the credential material this execution presented, when known.
    /// </summary>
    /// <remarks>
    /// A cached response must not outlive the authority that obtained it. The value is the
    /// ceiling a cache applies to its own policy TTL, so a response obtained with a token that
    /// expires in two minutes is not served for the authored hour.
    /// </remarks>
    public DateTimeOffset? AuthorityExpiresAtUtc { get; init; }

    /// <summary>Transport-internal fact used to exclude redirect-chain results from cache admission.</summary>
    internal bool ResponseWasRedirected { get; init; }

    /// <summary>True when nothing failed.</summary>
    public bool Succeeded => Failure == ExecutionFailureKind.None;
}
