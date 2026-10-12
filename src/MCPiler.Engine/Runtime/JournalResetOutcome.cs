namespace MCPiler.Engine.Runtime;

/// <summary>
/// The outcome of an operator reset of an integrity-failed confirmation journal (R15.12).
/// </summary>
/// <remarks>
/// This is a seam type: the deployable's <c>confirmed-revisions reset</c> verb reports the outcome and
/// the deployable may name only <see cref="MCPiler.Engine.Runtime"/>, not the library's execution
/// namespace. The value is produced by the library and received by the deployable, which is the direction
/// the seam permits.
/// </remarks>
public enum JournalResetOutcome
{
    /// <summary>No journal file existed; nothing to reset.</summary>
    Missing,

    /// <summary>
    /// Durable runtime state is not configured, so there is no confirmation journal to reset. This is
    /// distinct from <see cref="Missing"/>: a caller must never read "not configured" as "absent" (R17.3).
    /// </summary>
    NotConfigured,

    /// <summary>The journal is readable and valid; a reset is refused.</summary>
    RefusedValid,

    /// <summary>
    /// The journal exists but could not be read for a transient reason (I/O, permissions, a concurrent
    /// rename). It is not proven integrity-failed, so the reset is refused and the file is left in place
    /// (R16.4).
    /// </summary>
    Unreadable,

    /// <summary>The integrity-failed journal was moved aside; the store now starts fresh.</summary>
    Reset,

    /// <summary>The journal could not be moved aside; it is left in place.</summary>
    Failed,
}
