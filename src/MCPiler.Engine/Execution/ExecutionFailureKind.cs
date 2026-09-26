namespace MCPiler.Engine.Execution;

/// <summary>
/// The CLOSED classification of why an execution failed. Every consumer that needs to know WHAT
/// went wrong reads this; no consumer parses the human-facing failure text, which carries no
/// contract and may be reworded without changing behaviour.
/// </summary>
/// <remarks>
/// A classification is a type rather than a message prefix because a prefix cannot be checked by
/// a compiler and cannot survive rewording. The requirement that an authentication failure stay
/// distinguishable from a network failure is not something free text can carry reliably: any
/// future message beginning with the same characters would be silently reclassified.
///
/// The set is closed on purpose. Adding a member is a deliberate edit here plus a new arm in
/// every exhaustive switch over it, which is what makes the addition visible in review. A kind
/// is never derived from an upstream message, status, header, or argument.
///
/// Members are ordered by where in an execution the failure becomes known: before a request is
/// built, before a connection is attempted, during the exchange, then while handling what came
/// back. The compiling host that produced the manifest declares the same vocabulary with one
/// exception: it has no <see cref="Transformation"/> member, because it evaluates a program
/// above its execution service rather than inside it, so the abort never reaches a
/// classification there. Every other member and their order are the same, and a reader
/// comparing the two sees one vocabulary rather than two dialects.
/// </remarks>
public enum ExecutionFailureKind
{
    /// <summary>The execution did not fail.</summary>
    None,

    /// <summary>
    /// The request could not be compiled from the operation and the supplied arguments. Nothing
    /// was contacted.
    /// </summary>
    Compilation,

    /// <summary>
    /// An output transformation program or projection declared on the operation was refused or
    /// aborted.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="Compilation"/> because the two send an operator to different
    /// places: compilation is about the arguments a caller supplied, a transformation or output
    /// projection is about a program the manifest author wrote. An input-direction abort
    /// contacted nothing; an output-direction abort happened after a complete, in-bounds
    /// response arrived, which is why a caller is told the declared operation failed rather than
    /// that the upstream did.
    /// </remarks>
    Transformation,

    /// <summary>
    /// A credential the request needs could not be obtained or used: a reference naming a value
    /// that does not resolve, or a resolved value the scheme cannot apply. No request left the
    /// process, authenticated or otherwise.
    /// </summary>
    Authentication,

    /// <summary>
    /// The destination origin is outside the allowed-origin set in the manifest policy, either
    /// for the first request or for a redirect target. That origin was never contacted.
    /// </summary>
    OriginPolicy,

    /// <summary>
    /// The destination resolved to an address outbound policy refuses, or the host could not be
    /// resolved at all. No connection to a refused address was opened.
    /// </summary>
    AddressPolicy,

    /// <summary>The redirect chain exceeded the hop limit in the manifest policy.</summary>
    RedirectLimit,

    /// <summary>
    /// The execution exceeded its total time budget. This covers the whole exchange including
    /// every redirect hop, not one request within it.
    /// </summary>
    Timeout,

    /// <summary>
    /// The response exceeded the decoded-byte limit in the manifest policy. A status existed;
    /// the body did not fit.
    /// </summary>
    ResponseSize,

    /// <summary>
    /// A binary response arrived but could not be turned into a file reference: the handle store
    /// refused it, or the store itself is unusable.
    /// </summary>
    FileRuntime,

    /// <summary>
    /// The exchange failed below the HTTP semantics this classification describes — connection
    /// reset, TLS failure, protocol error. No status was ever observed.
    /// </summary>
    Transport,
}
