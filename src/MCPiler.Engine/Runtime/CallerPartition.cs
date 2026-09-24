namespace MCPiler.Engine.Runtime;

/// <summary>
/// Who the current request was authorized as, in a form only this process can recognize.
/// </summary>
/// <remarks>
/// <para>
/// The value is a process-keyed digest, never the token, the resource or the scope list
/// themselves. It exists so that a cache key can separate two callers whose authorization
/// differed without any component in the key, a log line or an operator surface ever holding
/// the credential material that made them differ.
/// </para>
/// <para>
/// An unavailable partition is a bypass, not a shared partition. Two callers whose identity
/// could not be established must never be conflated, so a caller of the cache must pass
/// <see langword="null"/> rather than a substitute value, and the cache must refuse to store or
/// serve anything for that request.
/// </para>
/// <para>
/// <see cref="Public"/> is the explicit identity of a mount that requires no authorization. It
/// is distinguishable from an unavailable partition by construction: the host states it, rather
/// than leaving the decision to be inferred from an absence.
/// </para>
/// </remarks>
/// <param name="OpaqueValue">The process-keyed digest of the authorized caller scope.</param>
/// <param name="IsCallerSpecific">
/// True when the value separates individual authorized callers; false for the single public
/// partition of an unauthenticated mount.
/// </param>
public sealed record CallerPartition(string OpaqueValue, bool IsCallerSpecific)
{
    /// <summary>
    /// The partition of an unauthenticated mount or a non-HTTP caller, which is the same for
    /// every caller by design.
    /// </summary>
    public static CallerPartition Public { get; } = new("public", IsCallerSpecific: false);
}
