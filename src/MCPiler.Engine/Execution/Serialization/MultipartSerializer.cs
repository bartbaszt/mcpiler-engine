using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution.Serialization;

/// <summary>
/// Writes an object value as <c>multipart/form-data</c>, mixing field parts and file parts.
/// </summary>
/// <remarks>
/// <para>
/// Per-part media types and declared encoding metadata are honoured. File payloads stay as
/// replayable sources and are copied directly to the destination when the transport serializes
/// the request; they are never accumulated into one multipart byte array.
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
    /// <summary>Compiles an object value and reports the delimiter used.</summary>
    /// <param name="mediaType">The declared media type, read for its per-part encoding metadata.</param>
    /// <param name="value">The body object; each member becomes one part.</param>
    /// <param name="files">
    /// Replayable files keyed by their original agent-facing slot. A transformed member may also
    /// identify a file by carrying the same opaque wire handle through <c>fileRef</c>.
    /// </param>
    /// <param name="partHeaderValues">
    /// Values for the headers a part declares, keyed by member name then header name. A declared
    /// header is written only when a value is supplied, because the contract declares the header's
    /// shape and not its content.
    /// </param>
    public (byte[]? Body, ReplayableBodySource? BodySource, string Boundary) Serialize(
        ManifestMediaType mediaType,
        JsonNode? value,
        IReadOnlyDictionary<string, ExecutionFile> files,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? partHeaderValues = null)
    {
        if (value is not JsonObject obj)
        {
            throw new UnsupportedSerializationException("Multipart body requires an object value.");
        }

        var boundary = boundaryProvider.GetBoundary();
        var segments = new List<BodySegment>();
        var containsStreamingFile = false;

        foreach (var kv in obj)
        {
            ExecutionFile? file = FileFor(kv.Key, kv.Value, files);
            var encoding = mediaType.Encoding.TryGetValue(kv.Key, out var e) ? e : null;
            var partHeaders = partHeaderValues is not null && partHeaderValues.TryGetValue(kv.Key, out var ph)
                ? ph
                : null;

            var headers = new StringBuilder();
            headers.Append("--").Append(boundary).Append("\r\n");

            if (file is not null)
            {
                var fileName = file.FileName.Length == 0 ? kv.Key : file.FileName;
                var partMediaType = file.MediaType.Length == 0
                    ? encoding?.ContentType ?? "application/octet-stream"
                    : file.MediaType;

                headers.Append("Content-Disposition: form-data; name=\"").Append(kv.Key)
                    .Append("\"; filename=\"").Append(Sanitize(fileName)).Append("\"\r\n");
                headers.Append("Content-Type: ").Append(partMediaType).Append("\r\n");
                AppendEncodingHeaders(headers, encoding, partHeaders);
                headers.Append("\r\n");

                segments.Add(BodySegment.Buffered(Encoding.UTF8.GetBytes(headers.ToString())));
                if (file.Content.BufferedBytes is { } buffered)
                {
                    segments.Add(BodySegment.Buffered(buffered.ToArray()));
                }
                else
                {
                    containsStreamingFile = true;
                    segments.Add(BodySegment.Streamed(file.Content));
                }
                segments.Add(BodySegment.Buffered("\r\n"u8.ToArray()));
            }
            else
            {
                var partMediaType = encoding?.ContentType ?? "text/plain";

                headers.Append("Content-Disposition: form-data; name=\"").Append(kv.Key).Append("\"\r\n");
                headers.Append("Content-Type: ").Append(partMediaType).Append("\r\n");
                AppendEncodingHeaders(headers, encoding, partHeaders);
                headers.Append("\r\n");
                headers.Append(ParameterSerializer.ScalarText(kv.Value)).Append("\r\n");

                segments.Add(BodySegment.Buffered(Encoding.UTF8.GetBytes(headers.ToString())));
            }
        }

        segments.Add(BodySegment.Buffered(Encoding.UTF8.GetBytes($"--{boundary}--\r\n")));

        if (containsStreamingFile)
        {
            return (null, new SegmentedBodySource(segments), boundary);
        }

        var output = new byte[segments.Sum(static segment => segment.Bytes!.Length)];
        var offset = 0;

        foreach (var segment in segments)
        {
            byte[] bytes = segment.Bytes!;
            Buffer.BlockCopy(bytes, 0, output, offset, bytes.Length);
            offset += bytes.Length;
        }

        return (output, null, boundary);
    }

    private static ExecutionFile? FileFor(
        string member,
        JsonNode? value,
        IReadOnlyDictionary<string, ExecutionFile> files)
    {
        if (files.TryGetValue(member, out ExecutionFile? direct))
        {
            return direct;
        }

        if (value is not JsonValue scalar || !scalar.TryGetValue(out string? wire) || wire is null)
        {
            return null;
        }

        return files.Values.FirstOrDefault(
            file => string.Equals(file.WireHandle, wire, StringComparison.Ordinal));
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

    private sealed record BodySegment(byte[]? Bytes, ReplayableBodySource? Source)
    {
        public static BodySegment Buffered(byte[] bytes) => new(bytes, null);

        public static BodySegment Streamed(ReplayableBodySource source) => new(null, source);
    }

    private sealed class SegmentedBodySource(IReadOnlyList<BodySegment> segments) : ReplayableBodySource
    {
        public override long? Length
        {
            get
            {
                long total = 0;

                foreach (BodySegment segment in segments)
                {
                    if (segment.Bytes is { } bytes)
                    {
                        total += bytes.LongLength;
                        continue;
                    }

                    if (segment.Source?.Length is not { } length)
                    {
                        return null;
                    }

                    total += length;
                }

                return total;
            }
        }

        public override async ValueTask CopyToAsync(Stream destination, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(destination);

            foreach (BodySegment segment in segments)
            {
                if (segment.Bytes is { } bytes)
                {
                    await destination.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                }
                else if (segment.Source is { } source)
                {
                    await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        // The execution request owns the file sources referenced by these segments. This object
        // holds no stream between writes and therefore has nothing independent to release.
        public override ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
