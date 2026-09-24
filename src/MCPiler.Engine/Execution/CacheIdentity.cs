using System.Security.Cryptography;
using System.Text;

namespace MCPiler.Engine.Execution;

/// <summary>
/// Length-delimited, process-keyed digests for cache-scoping identities.
/// </summary>
/// <remarks>
/// <para>
/// Every part is written as a four-byte big-endian length followed by its UTF-8 bytes. Without
/// the length, two different part lists could produce the same payload by moving a boundary:
/// a credential named "ab" applied to slot "c" and one named "a" applied to slot "bc" would
/// digest identically, and the cache would serve one caller's response to the other.
/// </para>
/// <para>
/// The digest is keyed with a per-instance random key, so an opaque value that escapes into a
/// log line, a diagnostic or an operator surface cannot be recomputed, matched or replayed by
/// anything outside the process that produced it. The key is never persisted and never
/// derived from configuration, which is what makes "process-keyed" a property rather than a
/// hope.
/// </para>
/// </remarks>
internal static class CacheIdentity
{
    /// <summary>A fresh 256-bit key for one process-lifetime owner.</summary>
    internal static byte[] NewKey() => RandomNumberGenerator.GetBytes(32);

    /// <summary>
    /// Digests the supplied parts under the key, returning lowercase hexadecimal.
    /// </summary>
    /// <param name="key">The owner's process-lifetime key.</param>
    /// <param name="parts">
    /// The parts in canonical order. A null part is distinct from an empty one, because a
    /// missing value and a value that happens to be empty are different facts about authority.
    /// </param>
    internal static string Derive(byte[] key, params string?[] parts)
        => Convert.ToHexStringLower(DeriveBytes(key, parts));

    /// <summary>
    /// Digests the supplied parts under the key, returning the raw 32-byte MAC.
    /// </summary>
    /// <remarks>
    /// The raw form exists for a caller that stores the digest as a lookup key rather than
    /// spells it into a document. A hexadecimal spelling is the same value, but a key held as
    /// 32 bytes cannot be accidentally truncated or case-normalized by whatever eventually
    /// carries it.
    /// </remarks>
    internal static byte[] DeriveBytes(byte[] key, params string?[] parts)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(parts);

        using var payload = new MemoryStream();

        foreach (string? part in parts)
        {
            if (part is null)
            {
                // -1 marks absence and can never collide with a length, because a length is
                // never negative.
                WriteInt32(payload, -1);
                continue;
            }

            byte[] bytes = Encoding.UTF8.GetBytes(part);
            WriteInt32(payload, bytes.Length);
            payload.Write(bytes);
        }

        return HMACSHA256.HashData(key, payload.GetBuffer().AsSpan(0, (int)payload.Length));
    }

    /// <summary>
    /// Digests one credential value under the owner's key, so a raw secret never enters an
    /// identity and two identities cannot be compared across processes.
    /// </summary>
    internal static string DeriveValue(byte[] key, string value)
        => Derive(key, "value", value);

    /// <summary>
    /// A short, stable fingerprint of an opaque value, for operator-facing display.
    /// </summary>
    /// <remarks>
    /// The input is already an opaque digest, so a further unkeyed digest reveals nothing that
    /// the opaque value did not already hide. Twelve hexadecimal characters is long enough to
    /// compare two decisions by eye and too short to be mistaken for the key itself.
    /// </remarks>
    internal static string Fingerprint(string opaqueValue)
    {
        ArgumentNullException.ThrowIfNull(opaqueValue);

        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(opaqueValue));

        return Convert.ToHexStringLower(digest.AsSpan(0, 6));
    }

    private static void WriteInt32(Stream target, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        target.Write(bytes);
    }
}
