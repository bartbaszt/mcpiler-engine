using System.Security.Cryptography;
using System.Text;

namespace MCPiler.Engine.Host.Authorization;

/// <summary>
/// The process-lifetime key every admitted caller partition is derived under.
/// </summary>
/// <remarks>
/// <para>
/// Generated once per host process and never persisted, so a partition that escapes into a
/// diagnostic, a telemetry event or an operator surface cannot be recomputed, matched or replayed
/// by anything outside the serving process. Two processes serving byte-identical manifests
/// therefore never produce interchangeable partitions, which is what makes "process-keyed" a
/// property rather than a hope.
/// </para>
/// <para>
/// Registered as a singleton because the derivation must be stable for the process's lifetime: a
/// partition derived under a new key would describe the same caller as a different one, and every
/// cached response for that caller would become unreachable.
/// </para>
/// </remarks>
internal sealed class CallerPartitionKey
{
    internal CallerPartitionKey()
    {
        Value = RandomNumberGenerator.GetBytes(32);
    }

    /// <summary>The 256-bit key.</summary>
    internal byte[] Value { get; }
}

/// <summary>
/// Derives the opaque partition one authorized request belongs to.
/// </summary>
/// <remarks>
/// <para>
/// The inputs are exactly the facts the authorization decision used: the token that was
/// validated, the canonical resource the token was admitted for, and the scopes the request
/// carried. Two requests land in the same partition only when all three agree, so a cache keyed
/// on the partition can never serve one caller's response to a caller whose authorization
/// differed.
/// </para>
/// <para>
/// The token itself never enters the partition. It is digested under the process key, and the
/// partition that leaves this class is already a one-way value: no component above it handles,
/// logs or stores the credential material that made two callers different.
/// </para>
/// <para>
/// Optional token claims are deliberately not inputs. A token without <c>sub</c> or
/// <c>client_id</c> is a valid bearer under this contract, and partition derivation that required
/// either would refuse a caller the authorization step admitted.
/// </para>
/// </remarks>
internal static class CallerPartitionDerivation
{
    /// <summary>The version tag, so a change to the inputs cannot collide with an old partition.</summary>
    private const string FormatTag = "caller-partition-1";

    /// <summary>Derives the partition for one authorized request.</summary>
    /// <param name="bearer">The presented token that the issuer validated.</param>
    /// <param name="canonicalResource">The canonical protected-resource identifier.</param>
    /// <param name="scopes">The scopes the presented token carried, in any order.</param>
    /// <param name="key">The process-lifetime key.</param>
    internal static string Derive(
        string bearer,
        string canonicalResource,
        IReadOnlyList<string> scopes,
        byte[] key)
    {
        ArgumentException.ThrowIfNullOrEmpty(bearer);
        ArgumentException.ThrowIfNullOrEmpty(canonicalResource);
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(key);

        // Sorted and de-duplicated, so two requests whose scope claims enumerate the same set in
        // a different order or with a repetition land in the same partition. The set is what the
        // authorization decision used; its presentation is not.
        string[] normalized = [.. scopes.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];

        using var payload = new MemoryStream();

        Write(payload, FormatTag);
        Write(payload, bearer);
        Write(payload, canonicalResource);

        foreach (string scope in normalized)
        {
            Write(payload, scope);
        }

        return Convert.ToHexStringLower(
            HMACSHA256.HashData(key, payload.GetBuffer().AsSpan(0, (int)payload.Length)));
    }

    /// <summary>
    /// Writes one part as a four-byte length followed by its UTF-8 bytes.
    /// </summary>
    /// <remarks>
    /// Length-delimited rather than concatenated: without the boundary, a token ending in one
    /// character and a resource beginning with another could compose the same payload as a
    /// different pair, and two callers would share a partition.
    /// </remarks>
    private static void Write(Stream target, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        target.Write(length);
        target.Write(bytes);
    }
}
