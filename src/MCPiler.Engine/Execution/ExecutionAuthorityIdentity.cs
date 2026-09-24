namespace MCPiler.Engine.Execution;

/// <summary>
/// Which upstream authority the current execution actually runs under, in opaque form.
/// </summary>
/// <remarks>
/// <para>
/// Two requests that look identical but are sent under different credential material, a
/// different destination authority or a different session must never share a cached response.
/// This record is how that fact reaches a cache key without the key, a diagnostic or an operator
/// surface ever carrying the secret that made the difference.
/// </para>
/// <para>
/// A <see langword="null"/> identity means the authority could not be proven — for example a
/// signing strategy whose per-attempt material no key can represent. Callers must treat that as
/// a bypass rather than as one shared identity.
/// </para>
/// <para>
/// <see cref="ExpiresAtUtc"/> is the earliest known expiry of the presented credential material
/// when one is known. A cached response must not outlive the authority that was used to obtain
/// it, so this caps entry lifetime rather than being reported for convenience.
/// </para>
/// </remarks>
/// <param name="OpaqueValue">The process-keyed digest of the resolved upstream authority.</param>
/// <param name="ExpiresAtUtc">
/// When the authority stops being usable, or null when the material has no known expiry.
/// </param>
public sealed record ExecutionAuthorityIdentity(string OpaqueValue, DateTimeOffset? ExpiresAtUtc);
