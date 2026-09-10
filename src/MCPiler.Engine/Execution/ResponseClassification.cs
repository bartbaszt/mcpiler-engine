using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution;

/// <summary>
/// Whether a response body is a file or a value, and which of the contract's declarations
/// answers that for the response that actually arrived.
/// </summary>
/// <remarks>
/// <para>
/// The observed status is what the contract must be read at. An operation declaring
/// <c>application/pdf</c> on 200 and <c>application/problem+json</c> on 400 is one operation
/// with two body kinds, and a classifier that consulted the operation rather than the answer
/// would hand a caller an error document as a downloadable file — or, reading the declarations
/// in the other order, would try to parse a PDF as a problem report.
/// </para>
/// <para>
/// What the upstream actually said outranks what it promised. A contract is a claim made before
/// the request; a <c>Content-Type</c> is a statement about the bytes that followed it.
/// </para>
/// </remarks>
public static class ResponseClassification
{
    /// <summary>
    /// True when a media type denotes content that has no useful textual reading.
    /// </summary>
    /// <remarks>
    /// The textual cases are enumerated first and the binary ones second, because the
    /// interesting mistakes are all textual types that look binary: a
    /// <c>+json</c> suffix, a charset parameter, a vendor subtype. A default of "binary" with
    /// textual exceptions would turn every unrecognized structured type into a file download.
    /// </remarks>
    public static bool IsBinaryMediaType(string? mediaType)
    {
        var essence = ContentSignature.Essence(mediaType);

        if (essence.Length == 0)
        {
            return false;
        }

        if (essence.StartsWith("text/", StringComparison.Ordinal)
            || essence.EndsWith("+json", StringComparison.Ordinal)
            || essence.EndsWith("+xml", StringComparison.Ordinal)
            || essence is "application/json"
                or "application/x-json"
                or "application/xml"
                or "application/yaml"
                or "application/x-yaml"
                or "application/x-www-form-urlencoded"
                or "application/javascript")
        {
            return false;
        }

        return essence.StartsWith("image/", StringComparison.Ordinal)
            || essence.StartsWith("audio/", StringComparison.Ordinal)
            || essence.StartsWith("video/", StringComparison.Ordinal)
            || essence is "application/octet-stream"
                or "application/pdf"
                or "application/zip"
                or "application/gzip"
                or "application/x-tar"
                or "application/x-7z-compressed";
    }

    /// <summary>
    /// True when the response to <paramref name="operation"/> that arrived with
    /// <paramref name="statusCode"/> and <paramref name="observedMediaType"/> should become a
    /// file handle rather than a value.
    /// </summary>
    /// <remarks>
    /// Precedence is observed type, then the declaration for the observed status, then the
    /// <c>default</c> declaration. A declaration under an unrelated status is never consulted:
    /// it describes a response that did not happen.
    /// </remarks>
    public static bool IsBinaryResponse(ManifestOperation? operation, int statusCode, string? observedMediaType)
    {
        if (!string.IsNullOrWhiteSpace(observedMediaType))
        {
            return IsBinaryMediaType(observedMediaType);
        }

        if (operation is null)
        {
            return false;
        }

        var declared = DeclaredMediaTypes(operation, statusCode.ToString(System.Globalization.CultureInfo.InvariantCulture))
            ?? DeclaredMediaTypes(operation, ManifestOperation.DefaultResponseKey);

        return declared is not null && declared.Any(IsBinaryMediaType);
    }

    private static IReadOnlyList<string>? DeclaredMediaTypes(ManifestOperation operation, string key)
        => operation.Responses.TryGetValue(key, out var response) && response.Content is { Count: > 0 } content
            ? [.. content.Keys]
            : null;
}
