using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;

namespace MCPiler.Engine.UnitTests.Search;

/// <summary>
/// Writes packed vector matrices the way a Manifest producer would, and the way one never
/// would.
/// </summary>
/// <remarks>
/// Deliberately independent of the reader: composing the bytes here from the layout the
/// format states, rather than round-tripping through a production writer, is what lets these
/// tests assert that the reader accepts the format instead of asserting that it agrees with
/// itself. <see cref="Compose"/> takes any header at all, because most of what the reader has
/// to refuse is a header no correct producer emits.
/// </remarks>
internal static class PackedMatrix
{
    internal const string Magic = "MVMX";

    /// <summary>A well-formed matrix over unit-length rows.</summary>
    internal static byte[] Write(IReadOnlyList<string> operations, IReadOnlyList<float[]> rows)
    {
        var dimension = rows[0].Length;
        var values = new List<float>(rows.Count * dimension);

        foreach (var row in rows)
        {
            var norm = MathF.Sqrt(row.Sum(value => value * value));
            values.AddRange(norm > 0f ? row.Select(value => value / norm) : row);
        }

        return Compose(Header(dimension, rows.Count, operations), Payload(values));
    }

    /// <summary>The header a correct producer writes for this shape.</summary>
    internal static JsonObject Header(int dimension, int count, IReadOnlyList<string> operations) => new()
    {
        ["formatVersion"] = 1,
        ["dimension"] = dimension,
        ["count"] = count,
        ["elementType"] = "float32",
        ["normalization"] = "l2",
        ["ids"] = new JsonArray([.. operations.Select(slug => JsonValue.Create(slug))]),
    };

    /// <summary>Little-endian float32 values, row-major, with nothing around them.</summary>
    internal static byte[] Payload(IEnumerable<float> values)
    {
        using var buffer = new MemoryStream();
        Span<byte> element = stackalloc byte[4];

        foreach (var value in values)
        {
            BinaryPrimitives.WriteSingleLittleEndian(element, value);
            buffer.Write(element);
        }

        return buffer.ToArray();
    }

    /// <summary>Magic, length prefix, header and payload, with no agreement enforced between them.</summary>
    internal static byte[] Compose(JsonObject header, byte[] payload)
        => Compose(Encoding.UTF8.GetBytes(header.ToJsonString()), payload, declaredHeaderLength: null);

    /// <summary>The same, with a length prefix that may lie about the header.</summary>
    internal static byte[] Compose(byte[] header, byte[] payload, int? declaredHeaderLength)
    {
        using var buffer = new MemoryStream();
        buffer.Write(Encoding.ASCII.GetBytes(Magic));

        Span<byte> prefix = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, declaredHeaderLength ?? header.Length);
        buffer.Write(prefix);

        buffer.Write(header);
        buffer.Write(payload);
        return buffer.ToArray();
    }
}
