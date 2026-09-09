using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution.Serialization;

/// <summary>
/// Writes an object value as <c>multipart/form-data</c> bytes, mixing field parts and file parts.
/// </summary>
/// <remarks>
/// <para>
/// Per-part media types and declared encoding metadata are honoured. A binary payload is appended
/// verbatim and never text-decoded, because decoding and re-encoding a byte sequence is not
/// round-trip safe for anything that is not valid text in the assumed encoding.
/// </para>
/// <para>
/// The delimiter comes from the injected provider rather than being generated here, so a compiled
/// body is byte-comparable.
/// </para>
/// <para>
/// The delimiter is returned alongside the bytes because it is mandatory in the media type the
/// caller sends, and a delimiter that exists only inside the bytes cannot be put there. Returning it
/// is what makes the media type recoverable rather than reconstructible by guesswork.
/// </para>
/// </remarks>
public sealed class MultipartSerializer(IBoundaryProvider boundaryProvider)
{
    /// <summary>Writes the body bytes for an object value and reports the delimiter used.</summary>
    /// <param name="mediaType">The declared media type, read for its per-part encoding metadata.</param>
    /// <param name="value">The body object; each member becomes one part.</param>
    /// <param name="files">Raw bytes per member name. A member present here becomes a file part.</param>
    /// <param name="fileNames">File name per member name, defaulting to the member name.</param>
    /// <param name="fileMediaTypes">Media type per member name, overriding the declared one.</param>
    /// <param name="partHeaderValues">
    /// Values for the headers a part declares, keyed by member name then header name. A declared
    /// header is written only when a value is supplied, because the contract declares the header's
    /// shape and not its content.
    /// </param>
    public (byte[] Body, string Boundary) Serialize(
        ManifestMediaType mediaType,
        JsonNode? value,
        IReadOnlyDictionary<string, byte[]> files,
        IReadOnlyDictionary<string, string> fileNames,
        IReadOnlyDictionary<string, string> fileMediaTypes,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? partHeaderValues = null)
    {
        if (value is not JsonObject obj)
        {
            throw new UnsupportedSerializationException("Multipart body requires an object value.");
        }

        var boundary = boundaryProvider.GetBoundary();
        var segments = new List<byte[]>();

        foreach (var kv in obj)
        {
            var isFile = files.TryGetValue(kv.Key, out var bytes) && bytes is not null;
            var encoding = mediaType.Encoding.TryGetValue(kv.Key, out var e) ? e : null;
            var partHeaders = partHeaderValues is not null && partHeaderValues.TryGetValue(kv.Key, out var ph)
                ? ph
                : null;

            var headers = new StringBuilder();
            headers.Append("--").Append(boundary).Append("\r\n");

            if (isFile)
            {
                var fileName = fileNames.TryGetValue(kv.Key, out var name) ? name : kv.Key;
                var partMediaType = fileMediaTypes.TryGetValue(kv.Key, out var mt)
                    ? mt
                    : encoding?.ContentType ?? "application/octet-stream";

                headers.Append("Content-Disposition: form-data; name=\"").Append(kv.Key)
                    .Append("\"; filename=\"").Append(Sanitize(fileName)).Append("\"\r\n");
                headers.Append("Content-Type: ").Append(partMediaType).Append("\r\n");
                AppendEncodingHeaders(headers, encoding, partHeaders);
                headers.Append("\r\n");

                segments.Add(Encoding.UTF8.GetBytes(headers.ToString()));
                segments.Add(bytes!);
                segments.Add(Encoding.UTF8.GetBytes("\r\n"));
            }
            else
            {
                var partMediaType = encoding?.ContentType ?? "text/plain";

                headers.Append("Content-Disposition: form-data; name=\"").Append(kv.Key).Append("\"\r\n");
                headers.Append("Content-Type: ").Append(partMediaType).Append("\r\n");
                AppendEncodingHeaders(headers, encoding, partHeaders);
                headers.Append("\r\n");
                headers.Append(ParameterSerializer.ScalarText(kv.Value)).Append("\r\n");

                segments.Add(Encoding.UTF8.GetBytes(headers.ToString()));
            }
        }

        segments.Add(Encoding.UTF8.GetBytes($"--{boundary}--\r\n"));

        var output = new byte[segments.Sum(static s => s.Length)];
        var offset = 0;

        foreach (var segment in segments)
        {
            Buffer.BlockCopy(segment, 0, output, offset, segment.Length);
            offset += segment.Length;
        }

        return (output, boundary);
    }

    // The declared header set names which headers a part may carry, not what they contain. Only the
    // declared ones are considered, and only those with a supplied value are written.
    private static void AppendEncodingHeaders(
        StringBuilder sb,
        ManifestEncoding? encoding,
        IReadOnlyDictionary<string, string>? partHeaders)
    {
        if (encoding?.Headers is not { Count: > 0 })
        {
            return;
        }

        foreach (var header in encoding.Headers)
        {
            if (partHeaders is not null && partHeaders.TryGetValue(header.Key, out var value))
            {
                sb.Append(header.Key).Append(": ").Append(value).Append("\r\n");
            }
        }
    }

    // A carriage return, a newline, or a quote in a file name would let the name close its own
    // header and inject another one.
    private static string Sanitize(string name)
        => name
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal)
            .Replace("\"", string.Empty, StringComparison.Ordinal);
}
