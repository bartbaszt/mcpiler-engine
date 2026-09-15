namespace MCPiler.Engine.Execution.RuntimeState;

/// <summary>
/// Raised when a durable runtime-state record exists but cannot be authenticated or interpreted.
/// </summary>
/// <remarks>
/// <para>
/// This is deliberately not "no record". A corrupt, truncated or wrongly-keyed record is
/// evidence that something durable is wrong, and treating it as absence would silently fall back
/// to a credential the provider may already have retired. The distinction is the whole reason the
/// exception exists: absent means "use the declared value", unreadable means "fail closed and tell
/// an operator".
/// </para>
/// <para>
/// The message names the profile, the slot and the defect. It never carries the record's bytes,
/// the key, or anything derived from either.
/// </para>
/// </remarks>
public sealed class RuntimeStateStoreException : Exception
{
    /// <summary>Creates a refusal naming the record that cannot be used.</summary>
    /// <param name="profileId">The manifest-local profile identity the record belongs to.</param>
    /// <param name="slot">The slot identity within the profile.</param>
    /// <param name="message">What is wrong with the record, without any value.</param>
    /// <param name="inner">The underlying cause, when the failure wraps one.</param>
    public RuntimeStateStoreException(
        string profileId,
        string slot,
        string message,
        Exception? inner = null)
        : base($"Runtime state for profile '{profileId}', slot '{slot}': {message}", inner)
    {
        ProfileId = profileId;
        Slot = slot;
    }

    /// <summary>The profile whose record could not be used.</summary>
    public string ProfileId { get; }

    /// <summary>The slot whose record could not be used.</summary>
    public string Slot { get; }
}
