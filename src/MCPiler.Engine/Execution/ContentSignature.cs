namespace MCPiler.Engine.Execution;

/// <summary>
/// Compares a declared media type against the way the content actually begins.
/// </summary>
/// <remarks>
/// <para>
/// This is not a scanner and is not an extension point. It is a deterministic check the store
/// always performs, kept separate from scanning so that the two answers stay separate: a
/// signature conflict is a statement about a declaration, and a scan verdict is a statement
/// about content. A store that reported "clean" for a payload it had merely checked the first
/// five bytes of would be describing an examination that did not happen.
/// </para>
/// <para>
/// A media type with no defined signature yields <see cref="SignatureVerdict.Undefined"/>
/// rather than a match. There is nothing to compare, and saying so is what keeps the policy
/// that rejects conflicts from silently rejecting nothing.
/// </para>
/// </remarks>
public static class ContentSignature
{
    /// <summary>How many leading bytes are enough to judge every signature below.</summary>
    public const int ProbeLength = 512;

    private static readonly (string MediaType, byte[] Magic)[] Signatures =
    [
        ("application/pdf", [0x25, 0x50, 0x44, 0x46, 0x2D]),
        ("image/png", [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        ("image/jpeg", [0xFF, 0xD8, 0xFF]),
        ("image/gif", [0x47, 0x49, 0x46, 0x38]),
        ("application/zip", [0x50, 0x4B, 0x03, 0x04]),
        ("application/gzip", [0x1F, 0x8B]),
    ];

    /// <summary>
    /// The media type with its parameters removed and its case normalized.
    /// </summary>
    /// <remarks>
    /// A declared type arrives as <c>application/json; charset=utf-8</c> as often as bare, and
    /// the parameters say nothing about how the bytes begin. Comparing the whole header value
    /// would make the same content conflict or match depending on whether a charset was
    /// mentioned.
    /// </remarks>
    public static string Essence(string? mediaType)
    {
        if (string.IsNullOrWhiteSpace(mediaType))
        {
            return string.Empty;
        }

        var separator = mediaType.IndexOf(';', StringComparison.Ordinal);
        var bare = separator < 0 ? mediaType : mediaType[..separator];

        return bare.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Judges <paramref name="probe"/> — the leading bytes of the payload — against
    /// <paramref name="declaredMediaType"/>.
    /// </summary>
    public static SignatureVerdict Evaluate(string? declaredMediaType, ReadOnlySpan<byte> probe)
    {
        var essence = Essence(declaredMediaType);

        if (essence.Length == 0)
        {
            return SignatureVerdict.Undefined;
        }

        foreach (var (mediaType, magic) in Signatures)
        {
            if (string.Equals(essence, mediaType, StringComparison.Ordinal))
            {
                return probe.StartsWith(magic) ? SignatureVerdict.Match : SignatureVerdict.Conflict;
            }
        }

        if (IsTextual(essence))
        {
            // A textual type has no magic bytes, but it does have a shape: an embedded NUL is
            // not something a JSON, XML, YAML or text payload contains, so its presence
            // contradicts the declaration even though nothing about the first bytes does.
            return probe.IndexOf((byte)0) < 0 ? SignatureVerdict.Match : SignatureVerdict.Conflict;
        }

        // application/octet-stream and everything else declare nothing checkable. Reporting a
        // match would claim a comparison that had no content.
        return SignatureVerdict.Undefined;
    }

    private static bool IsTextual(string essence)
        => essence.StartsWith("text/", StringComparison.Ordinal)
            || essence.EndsWith("+json", StringComparison.Ordinal)
            || essence.EndsWith("+xml", StringComparison.Ordinal)
            || essence is "application/json"
                or "application/xml"
                or "application/yaml"
                or "application/x-yaml"
                or "application/javascript"
                or "application/x-www-form-urlencoded";
}
