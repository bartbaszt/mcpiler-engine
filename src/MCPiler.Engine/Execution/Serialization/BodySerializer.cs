using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution.Serialization;

/// <summary>
/// Selects a body media type from the operation's declared content and writes the body bytes for it.
/// </summary>
/// <remarks>
/// <para>
/// Media-type parameters are ignored when deciding how to write: only the type and subtype select a
/// branch.
/// </para>
/// <para>
/// Writing a body can decide part of the media type, so the media type is returned rather than
/// assumed to equal the one that was asked for. Multipart is the case that forces this: the
/// delimiter is chosen while writing and is mandatory in the media type, so a caller that rebuilt
/// the media type from the selected key alone would send an unparseable request.
/// </para>
/// </remarks>
public static class BodySerializer
{
    /// <summary>
    /// Writes the body bytes for the selected media type and reports the media type to send, which
    /// is the selected one for every form except multipart, where it carries the delimiter used.
    /// </summary>
    public static (byte[] Body, string MediaType) Serialize(
        string mediaType,
        ManifestMediaType effective,
        JsonNode? value,
        IReadOnlyDictionary<string, byte[]>? files = null,
        IReadOnlyDictionary<string, string>? fileNames = null,
        IReadOnlyDictionary<string, string>? fileMediaTypes = null,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? partHeaderValues = null,
        IBoundaryProvider? boundaryProvider = null)
    {
        var normalized = mediaType.Split(';')[0].Trim().ToLowerInvariant();

        if (normalized == "application/x-www-form-urlencoded")
        {
            return (FormSerializer.Serialize(value), mediaType);
        }

        if (normalized.StartsWith("multipart/", StringComparison.Ordinal))
        {
            var provider = boundaryProvider ?? new RandomBoundaryProvider();

            var (body, boundary) = new MultipartSerializer(provider).Serialize(
                effective,
                value,
                files ?? new Dictionary<string, byte[]>(StringComparer.Ordinal),
                fileNames ?? new Dictionary<string, string>(StringComparer.Ordinal),
                fileMediaTypes ?? new Dictionary<string, string>(StringComparer.Ordinal),
                partHeaderValues);

            // The delimiter is mandatory here, and it is the one part of the media type the writer
            // rather than the contract decides.
            return (body, $"{mediaType}; boundary={boundary}");
        }

        if (normalized.StartsWith("text/", StringComparison.Ordinal))
        {
            var text = value switch
            {
                null => string.Empty,
                JsonValue v when v.TryGetValue<string>(out var s) => s,
                _ => value.ToJsonString(),
            };

            return (Encoding.UTF8.GetBytes(text), mediaType);
        }

        if (normalized is "application/json" or "application/octet-stream" or "application/zip" or "application/pdf")
        {
            // A raw binary type carries its payload as bytes in the arguments rather than as text.
            if (value is JsonValue binary && binary.TryGetValue<byte[]>(out var raw))
            {
                return (raw, mediaType);
            }

            return (value is null ? [] : Encoding.UTF8.GetBytes(value.ToJsonString()), mediaType);
        }

        if (normalized.EndsWith("+json", StringComparison.Ordinal))
        {
            return (Encoding.UTF8.GetBytes(value?.ToJsonString() ?? "null"), mediaType);
        }

        throw new UnsupportedBodyMediaTypeException(mediaType);
    }

    /// <summary>
    /// Picks a media type from the declared content.
    /// </summary>
    /// <remarks>
    /// One declared type is not a choice. Several are, and the arguments carry no media type, so the
    /// pick has to be deterministic and it has to be recorded: a JSON-shaped type when one is
    /// declared, otherwise the first. The ambiguity flag is what lets the caller say the choice was
    /// made for the operation rather than by it.
    /// </remarks>
    public static (string MediaType, bool Ambiguous) SelectMediaType(
        IReadOnlyDictionary<string, ManifestMediaType> content,
        JsonNode? value)
    {
        if (content.Count == 0)
        {
            throw new UnsupportedBodyMediaTypeException("(none)", "the operation declares no request body content.");
        }

        if (content.Count == 1)
        {
            return (content.Keys.First(), false);
        }

        if (value is not null && content.Keys.Any(static k => k.EndsWith("json", StringComparison.OrdinalIgnoreCase)))
        {
            return (content.Keys.First(static k => k.EndsWith("json", StringComparison.OrdinalIgnoreCase)), true);
        }

        return (content.Keys.First(), true);
    }
}
