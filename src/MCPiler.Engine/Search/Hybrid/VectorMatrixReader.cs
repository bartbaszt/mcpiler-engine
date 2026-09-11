using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Search.Hybrid;

/// <summary>
/// Reads the packed embedding matrix a Manifest may carry and judges whether it describes
/// the operation set being served.
/// </summary>
/// <remarks>
/// <para>
/// The layout is a four-byte magic, a little-endian <see cref="int"/> header length, a UTF-8
/// JSON header, and then the row-major payload. The header states the format version, the
/// dimension, the vector count, the element type, the normalization and the ordered operation
/// identifiers; the payload holds exactly <c>count * dimension</c> values and nothing else.
/// </para>
/// <para>
/// Every disagreement between the header and the bytes, and every disagreement between the
/// header and the operations being served, refuses the whole matrix. Nothing here truncates,
/// pads, reorders or scores a subset: a matrix that half-describes an operation set produces
/// rankings that look ordinary and are wrong, which is worse than a matrix that is ignored.
/// </para>
/// <para>
/// Values are read little-endian rather than reinterpreted from memory. Reinterpreting costs
/// nothing on the architectures anyone runs this on and silently scores byte-swapped garbage
/// on the ones they do not.
/// </para>
/// </remarks>
internal static class VectorMatrixReader
{
    /// <summary>The only matrix layout this build understands.</summary>
    internal const int FormatVersion = 1;

    /// <summary>The only element type this build understands.</summary>
    internal const string ElementTypeFloat32 = "float32";

    /// <summary>The only normalization this build understands.</summary>
    internal const string NormalizationL2 = "l2";

    private const int LengthPrefixBytes = 4;
    private const int ElementBytes = 4;
    private const string FormatVersionMember = "formatVersion";
    private const string DimensionMember = "dimension";
    private const string CountMember = "count";
    private const string ElementTypeMember = "elementType";
    private const string NormalizationMember = "normalization";
    private const string OperationsMember = "ids";

    private static ReadOnlySpan<byte> Magic => "MVMX"u8;

    /// <summary>
    /// Reads <paramref name="payload"/> and decides whether it may be scored against
    /// <paramref name="operations"/>.
    /// </summary>
    /// <param name="payload">The bytes the Manifest's <c>vectors</c> section carried.</param>
    /// <param name="declared">
    /// The <c>vectors</c> index entry, whose dimension is a second declaration of the same
    /// fact and must agree with the header's.
    /// </param>
    /// <param name="operations">
    /// The operation slugs the accompanying lexical index documents, in its order. The
    /// matrix must list exactly these, in exactly this order.
    /// </param>
    internal static VectorMatrixResult Read(
        ReadOnlyMemory<byte> payload,
        VectorSectionMetadata? declared,
        IReadOnlyList<string> operations)
    {
        if (payload.IsEmpty)
        {
            return VectorMatrixResult.Absent;
        }

        ReadOnlySpan<byte> bytes = payload.Span;
        int headerStart = Magic.Length + LengthPrefixBytes;

        if (bytes.Length < headerStart || !bytes[..Magic.Length].SequenceEqual(Magic))
        {
            return Unreadable("The payload does not begin with a vector matrix header.");
        }

        int headerLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(Magic.Length, LengthPrefixBytes));

        if (headerLength <= 0 || bytes.Length - headerStart < headerLength)
        {
            return Unreadable(string.Create(
                CultureInfo.InvariantCulture,
                $"The header claims {headerLength} bytes, which the payload does not contain."));
        }

        JsonObject? header;

        try
        {
            header = JsonNode.Parse(Encoding.UTF8.GetString(bytes.Slice(headerStart, headerLength))) as JsonObject;
        }
        catch (JsonException)
        {
            return Unreadable("The header is not JSON.");
        }

        if (header is null)
        {
            return Unreadable("The header is not a JSON object.");
        }

        if (Integer(header, FormatVersionMember) is not FormatVersion)
        {
            return Unreadable(string.Create(
                CultureInfo.InvariantCulture,
                $"The header declares a format this build does not read; it reads version {FormatVersion}."));
        }

        if (Text(header, ElementTypeMember) is not ElementTypeFloat32)
        {
            return Unreadable(string.Create(
                CultureInfo.InvariantCulture,
                $"The header declares an element type this build does not read; it reads '{ElementTypeFloat32}'."));
        }

        if (Text(header, NormalizationMember) is not NormalizationL2)
        {
            return Unreadable(string.Create(
                CultureInfo.InvariantCulture,
                $"The header declares a normalization this build does not read; it reads '{NormalizationL2}'."));
        }

        if (Integer(header, DimensionMember) is not { } dimension || dimension <= 0)
        {
            return Unreadable("The header declares no positive dimension.");
        }

        if (Integer(header, CountMember) is not { } count || count <= 0)
        {
            return Unreadable("The header declares no positive vector count.");
        }

        if (header[OperationsMember] is not JsonArray listed)
        {
            return Unreadable("The header lists no operations.");
        }

        if (listed.Count != count)
        {
            return Unreadable(string.Create(
                CultureInfo.InvariantCulture,
                $"The header declares {count} vectors and lists {listed.Count} operations."));
        }

        // The index entry states the dimension a second time. Two declarations of one fact
        // that disagree mean the bundle was assembled from two different embedding runs, and
        // the bytes cannot be both.
        if (declared?.Dimension is { } indexed && indexed != dimension)
        {
            return VectorMatrixResult.Refused(
                VectorAvailability.DimensionMismatch,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The section index declares dimension {indexed} and the matrix header declares {dimension}."));
        }

        int payloadStart = headerStart + headerLength;
        long available = bytes.Length - payloadStart;
        long required = (long)count * dimension * ElementBytes;

        // Exact, not "at least". Trailing bytes mean the payload was written by something
        // that disagreed about the shape, and accepting them scores a matrix whose extent
        // nobody agrees on.
        if (available != required)
        {
            return VectorMatrixResult.Refused(
                VectorAvailability.DimensionMismatch,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The header describes {count} vectors of {dimension} values, needing {required} bytes; the payload carries {available}."));
        }

        string[] named = new string[count];

        for (int index = 0; index < count; index++)
        {
            if (listed[index] is not JsonValue value || !value.TryGetValue(out string? slug) || slug is null)
            {
                return Unreadable(string.Create(
                    CultureInfo.InvariantCulture,
                    $"The operation at position {index} is not a string."));
            }

            named[index] = slug;
        }

        if (Disagreement(named, operations) is { } disagreement)
        {
            return VectorMatrixResult.Refused(VectorAvailability.OperationMismatch, disagreement);
        }

        float[] values = new float[count * dimension];

        for (int index = 0; index < values.Length; index++)
        {
            values[index] = BinaryPrimitives.ReadSingleLittleEndian(
                bytes.Slice(payloadStart + (index * ElementBytes), ElementBytes));
        }

        return VectorMatrixResult.Ready(new VectorMatrix(dimension, named, values));
    }

    /// <summary>
    /// Names the first way the matrix's operation list differs from the served one, or
    /// <c>null</c> when they are the same list in the same order.
    /// </summary>
    /// <remarks>
    /// Order matters and is not a formality: the payload is row-major in this order, so a
    /// list that holds the same slugs in a different order addresses every row to the wrong
    /// operation while looking, to anything that only compares sets, entirely correct.
    /// </remarks>
    private static string? Disagreement(IReadOnlyList<string> matrix, IReadOnlyList<string> served)
    {
        if (matrix.Count != served.Count)
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"The matrix describes {matrix.Count} operations and this Manifest indexes {served.Count}.");
        }

        for (int index = 0; index < matrix.Count; index++)
        {
            if (!string.Equals(matrix[index], served[index], StringComparison.Ordinal))
            {
                return string.Create(
                    CultureInfo.InvariantCulture,
                    $"The matrix names '{matrix[index]}' at position {index} where this Manifest indexes '{served[index]}'.");
            }
        }

        return null;
    }

    private static VectorMatrixResult Unreadable(string detail)
        => VectorMatrixResult.Refused(VectorAvailability.Unreadable, detail);

    private static int? Integer(JsonObject header, string member)
        => header[member] is JsonValue value && value.TryGetValue(out int parsed) ? parsed : null;

    private static string? Text(JsonObject header, string member)
        => header[member] is JsonValue value && value.TryGetValue(out string? parsed) ? parsed : null;
}
