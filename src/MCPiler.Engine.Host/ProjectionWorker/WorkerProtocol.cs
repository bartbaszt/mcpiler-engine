using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json;

using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.Host.ProjectionWorker;

/// <summary>
/// The frame protocol between a serving process and one short-lived projection worker.
/// </summary>
/// <remarks>
/// <para>
/// A frame is a 4-byte little-endian payload length followed by that many bytes. Both directions
/// are length-framed and both directions are bounded, because the untrusted side of this pipe is
/// the evaluator: a reader that waited for a terminator, or that read to the end of a stream,
/// would size its buffer from the child's output rather than from a declared limit.
/// </para>
/// <para>
/// The handshake precedes all framing. A child prints <c>READY &lt;limitBytes&gt;</c> once it has
/// applied and verified its memory confinement and proved it can still allocate; it prints
/// nothing else before the parent sends the request. The number it echoes lets the parent confirm
/// the child is confined to the same value the parent believes, rather than assuming a successful
/// spawn implies a successful limit.
/// </para>
/// <para>
/// The only payload is JSON and the expression, and nothing else ever crosses: no credential, no
/// header, no Manifest, no caller identity, no file handle. The worker has no way to reach those
/// objects, so their absence is a property of the design rather than a rule it must remember.
/// </para>
/// </remarks>
internal static class WorkerProtocol
{
    /// <summary>The argument that selects worker mode. Deliberately absent from the CLI usage.</summary>
    internal const string ModeArgument = "--projection-worker";

    /// <summary>The handshake prefix a confined child prints before reading anything.</summary>
    internal const string ReadyToken = "READY";

    /// <summary>The largest request or response header frame.</summary>
    internal const int MaxHeaderBytes = 64 * 1024;

    /// <summary>
    /// The largest body frame. The effective input bounds make a body this large unreachable in
    /// practice; the cap exists so the framing layer has a number even when the bounds do not.
    /// </summary>
    internal const int MaxBodyBytes = 64 * 1024 * 1024;

    /// <summary>Writes one length-framed payload.</summary>
    internal static async Task WriteFrameAsync(
        Stream stream,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        byte[] length = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(length, payload.Length);

        await stream.WriteAsync(length, cancellationToken).ConfigureAwait(false);

        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }

        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one length-framed payload, refusing one whose declared length exceeds the cap.
    /// </summary>
    /// <returns>The payload, or null when the stream ended cleanly before a frame began.</returns>
    internal static async Task<byte[]?> ReadFrameAsync(
        Stream stream,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 1);

        byte[] length = new byte[sizeof(int)];
        int first = await stream.ReadAsync(length.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);

        if (first == 0)
        {
            return null;
        }

        await stream.ReadExactlyAsync(length.AsMemory(1), cancellationToken).ConfigureAwait(false);

        int declared = BinaryPrimitives.ReadInt32LittleEndian(length);

        if (declared < 0)
        {
            throw new InvalidDataException("A frame declared a negative length.");
        }

        if (declared > maxBytes)
        {
            throw new InvalidDataException(string.Create(
                CultureInfo.InvariantCulture,
                $"A frame declared {declared} bytes, exceeding the {maxBytes}-byte cap."));
        }

        byte[] payload = new byte[declared];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);

        return payload;
    }

    /// <summary>Reads the ready line, bounded so a child cannot make the parent allocate.</summary>
    /// <returns>The echoed limit in bytes, or null when the child produced no usable line.</returns>
    internal static async Task<long?> ReadReadyAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var line = new StringBuilder(32);

        for (int index = 0; index < 64; index++)
        {
            byte[] single = new byte[1];
            int read = await stream.ReadAsync(single, cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                return null;
            }

            if (single[0] == (byte)'\n')
            {
                break;
            }

            if (single[0] != (byte)'\r')
            {
                line.Append((char)single[0]);
            }
        }

        string text = line.ToString();

        if (!text.StartsWith(ReadyToken, StringComparison.Ordinal))
        {
            // A stream that opened with something other than the handshake is not the protocol
            // this parent speaks, so there is nothing to salvage from it.
            throw new InvalidDataException("The worker did not open with the ready handshake.");
        }

        string remainder = text[ReadyToken.Length..].Trim();

        return long.TryParse(remainder, NumberStyles.None, CultureInfo.InvariantCulture, out long echoed)
            ? echoed
            : null;
    }

    /// <summary>Encodes an evaluation request header.</summary>
    internal static byte[] RequestHeader(string expression, JmesPathLimits limits, int bodyBytes)
    {
        ArgumentNullException.ThrowIfNull(expression);
        ArgumentNullException.ThrowIfNull(limits);

        return Encode(writer =>
        {
            writer.WriteString("kind", "evaluate");
            writer.WriteString("expression", expression);
            writer.WriteNumber("bodyBytes", bodyBytes);
            writer.WriteStartObject("limits");
            writer.WriteNumber("maxExpressionBytes", limits.MaxExpressionBytes);
            writer.WriteNumber("maxInputNodes", limits.MaxInputNodes);
            writer.WriteNumber("maxInputDepth", limits.MaxInputDepth);
            writer.WriteNumber("maxResultNodes", limits.MaxResultNodes);
            writer.WriteNumber("maxResultDepth", limits.MaxResultDepth);
            writer.WriteNumber("maxOutputBytes", limits.MaxOutputBytes);
            writer.WriteNumber("maxEvaluationMilliseconds", limits.MaxEvaluationMilliseconds);
            writer.WriteEndObject();
        });
    }

    /// <summary>Encodes a successful response header.</summary>
    internal static byte[] SuccessHeader(int outputBytes)
        => Encode(writer =>
        {
            writer.WriteString("kind", "ok");
            writer.WriteNumber("outputBytes", outputBytes);
        });

    /// <summary>Encodes a classified failure header.</summary>
    internal static byte[] FailureHeader(JmesPathFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);

        return Encode(writer =>
        {
            writer.WriteString("kind", "error");
            writer.WriteString("code", failure.Code);
            writer.WriteString("message", failure.Message);
        });
    }

    /// <summary>Parses a request header, refusing anything outside the closed shape.</summary>
    internal static bool TryReadRequestHeader(byte[] payload, out WorkerRequest? request, out string? refusal)
    {
        ArgumentNullException.ThrowIfNull(payload);

        request = null;
        refusal = null;

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException)
        {
            refusal = "The request header is not valid JSON.";
            return false;
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("kind", out JsonElement kind)
                || kind.ValueKind != JsonValueKind.String
                || !string.Equals(kind.GetString(), "evaluate", StringComparison.Ordinal)
                || !root.TryGetProperty("expression", out JsonElement expression)
                || expression.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("bodyBytes", out JsonElement bodyBytes)
                || bodyBytes.ValueKind != JsonValueKind.Number
                || !bodyBytes.TryGetInt32(out int bytes)
                || bytes <= 0
                || bytes > MaxBodyBytes
                || !root.TryGetProperty("limits", out JsonElement limits)
                || limits.ValueKind != JsonValueKind.Object)
            {
                refusal = "The request header is not an evaluation request.";
                return false;
            }

            if (!TryReadLimits(limits, out JmesPathLimits? effective))
            {
                refusal = "The request declares limits that are not seven positive numbers.";
                return false;
            }

            request = new WorkerRequest(expression.GetString()!, effective!, bytes);
            return true;
        }
    }

    /// <summary>Parses a response header from a worker.</summary>
    internal static bool TryReadResponseHeader(
        byte[] payload,
        out WorkerResponse? response,
        out string? refusal)
        => TryReadResponse(payload, out response, out refusal, out _);

    /// <summary>Parses a response header, preserving whether the failure code is known.</summary>
    internal static bool TryReadResponse(
        byte[] payload,
        out WorkerResponse? response,
        out string? refusal,
        out bool succeeded)
    {
        ArgumentNullException.ThrowIfNull(payload);

        response = null;
        refusal = null;
        succeeded = false;

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException)
        {
            refusal = "The response header is not valid JSON.";
            return false;
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("kind", out JsonElement kind)
                || kind.ValueKind != JsonValueKind.String)
            {
                refusal = "The response header carries no kind.";
                return false;
            }

            switch (kind.GetString())
            {
                case "ok":
                    if (!root.TryGetProperty("outputBytes", out JsonElement outputBytes)
                        || outputBytes.ValueKind != JsonValueKind.Number
                        || !outputBytes.TryGetInt32(out int bytes)
                        || bytes < 0
                        || bytes > MaxBodyBytes)
                    {
                        refusal = "A success response declares no usable output size.";
                        return false;
                    }

                    succeeded = true;
                    response = new WorkerResponse(bytes, null, null);
                    return true;

                case "error":
                    if (!root.TryGetProperty("code", out JsonElement code)
                        || code.ValueKind != JsonValueKind.String
                        || !root.TryGetProperty("message", out JsonElement message)
                        || message.ValueKind != JsonValueKind.String)
                    {
                        refusal = "An error response carries no code and message.";
                        return false;
                    }

                    response = new WorkerResponse(0, code.GetString()!, message.GetString()!);
                    return true;

                default:
                    refusal = "The response header names an unknown kind.";
                    return false;
            }
        }
    }

    /// <summary>The stable code a worker uses for a failure it could not classify as language.</summary>
    internal static string CodeOf(JmesPathFailureClass failureClass)
        => JmesPathFailure.CodeOf(failureClass);

    private static bool TryReadLimits(JsonElement limits, out JmesPathLimits? parsed)
    {
        parsed = null;

        if (!TryInt(limits, "maxExpressionBytes", out int expressionBytes)
            || !TryLong(limits, "maxInputNodes", out long inputNodes)
            || !TryInt(limits, "maxInputDepth", out int inputDepth)
            || !TryLong(limits, "maxResultNodes", out long resultNodes)
            || !TryInt(limits, "maxResultDepth", out int resultDepth)
            || !TryLong(limits, "maxOutputBytes", out long outputBytes)
            || !TryInt(limits, "maxEvaluationMilliseconds", out int milliseconds))
        {
            return false;
        }

        if (expressionBytes <= 0
            || inputNodes <= 0
            || inputDepth <= 0
            || resultNodes <= 0
            || resultDepth <= 0
            || outputBytes <= 0
            || milliseconds <= 0)
        {
            return false;
        }

        parsed = new JmesPathLimits(
            expressionBytes, inputNodes, inputDepth, resultNodes, resultDepth, outputBytes, milliseconds);

        return true;
    }

    private static bool TryInt(JsonElement parent, string name, out int value)
    {
        value = 0;

        return parent.TryGetProperty(name, out JsonElement element)
            && element.ValueKind == JsonValueKind.Number
            && element.TryGetInt32(out value);
    }

    private static bool TryLong(JsonElement parent, string name, out long value)
    {
        value = 0;

        return parent.TryGetProperty(name, out JsonElement element)
            && element.ValueKind == JsonValueKind.Number
            && element.TryGetInt64(out value);
    }

    private static byte[] Encode(Action<Utf8JsonWriter> body)
    {
        using var stream = new MemoryStream();

        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            body(writer);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    /// <summary>One parsed evaluation request.</summary>
    internal sealed record WorkerRequest(string Expression, JmesPathLimits Limits, int BodyBytes);

    /// <summary>One parsed response header.</summary>
    internal sealed record WorkerResponse(int OutputBytes, string? Code, string? Message);
}
