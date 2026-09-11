using System;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Search.Hybrid;
using Xunit;

namespace MCPiler.Engine.UnitTests.Search;

/// <summary>
/// Reading a Manifest's embedding matrix and deciding whether it describes the operation set
/// being served.
/// </summary>
/// <remarks>
/// The refusals matter more than the acceptance. A matrix that half-describes an operation
/// set produces rankings that look ordinary and are wrong, so every disagreement between the
/// header, the bytes and the index has to end the same way: nothing scored, and a sentence
/// naming what disagreed.
/// </remarks>
public sealed class VectorMatrixReaderTests
{
    private static readonly string[] Served = ["add-pet", "list-pets"];

    [Fact]
    public void A_manifest_carrying_no_payload_is_not_an_error()
    {
        var result = VectorMatrixReader.Read(default, null, Served);

        Assert.Equal(VectorAvailability.Absent, result.State);
        Assert.Null(result.Matrix);

        // No detail, because there is nothing to say. A line every start-up about a
        // configuration that is supported teaches an operator to skip the line.
        Assert.Null(result.Detail);
    }

    [Fact]
    public void A_payload_that_is_not_a_matrix_is_unreadable()
    {
        var result = VectorMatrixReader.Read(Encoding.UTF8.GetBytes("not a matrix at all"), null, Served);

        Assert.Equal(VectorAvailability.Unreadable, result.State);
    }

    [Fact]
    public void A_payload_truncated_before_its_header_is_unreadable()
    {
        var whole = PackedMatrix.Write(Served, [[1f, 0f], [0f, 1f]]);

        var result = VectorMatrixReader.Read(whole.AsMemory(0, 6), null, Served);

        Assert.Equal(VectorAvailability.Unreadable, result.State);
    }

    [Fact]
    public void A_header_claiming_more_bytes_than_the_payload_holds_is_unreadable()
    {
        var bytes = PackedMatrix.Compose(
            Encoding.UTF8.GetBytes(PackedMatrix.Header(2, 2, Served).ToJsonString()),
            PackedMatrix.Payload([1f, 0f, 0f, 1f]),
            declaredHeaderLength: 1 << 20);

        var result = VectorMatrixReader.Read(bytes, null, Served);

        Assert.Equal(VectorAvailability.Unreadable, result.State);
    }

    [Fact]
    public void A_header_that_is_not_json_is_unreadable()
    {
        var bytes = PackedMatrix.Compose(
            Encoding.UTF8.GetBytes("{ this is not json"),
            PackedMatrix.Payload([1f, 0f, 0f, 1f]),
            declaredHeaderLength: null);

        var result = VectorMatrixReader.Read(bytes, null, Served);

        Assert.Equal(VectorAvailability.Unreadable, result.State);
    }

    [Theory]
    [InlineData("formatVersion", 2)]
    [InlineData("dimension", 0)]
    [InlineData("count", 0)]
    public void A_header_number_this_build_does_not_read_is_unreadable(string member, int value)
    {
        var header = PackedMatrix.Header(2, 2, Served);
        header[member] = value;

        var result = VectorMatrixReader.Read(
            PackedMatrix.Compose(header, PackedMatrix.Payload([1f, 0f, 0f, 1f])),
            null,
            Served);

        Assert.Equal(VectorAvailability.Unreadable, result.State);
    }

    [Theory]
    [InlineData("elementType", "float16")]
    [InlineData("normalization", "none")]
    public void A_header_encoding_this_build_does_not_read_is_unreadable(string member, string value)
    {
        // Not a dimension mismatch: the shape is right and the numbers agree. What this build
        // cannot do is interpret the values, and an operator sent to check the dimension
        // would find nothing wrong with it.
        var header = PackedMatrix.Header(2, 2, Served);
        header[member] = value;

        var result = VectorMatrixReader.Read(
            PackedMatrix.Compose(header, PackedMatrix.Payload([1f, 0f, 0f, 1f])),
            null,
            Served);

        Assert.Equal(VectorAvailability.Unreadable, result.State);
    }

    [Fact]
    public void A_header_counting_more_vectors_than_it_names_is_unreadable()
    {
        var header = PackedMatrix.Header(2, 3, Served);

        var result = VectorMatrixReader.Read(
            PackedMatrix.Compose(header, PackedMatrix.Payload([1f, 0f, 0f, 1f, 0f, 0f])),
            null,
            Served);

        Assert.Equal(VectorAvailability.Unreadable, result.State);
    }

    [Fact]
    public void A_header_naming_something_that_is_not_an_operation_is_unreadable()
    {
        var header = PackedMatrix.Header(2, 2, Served);
        header["ids"] = new JsonArray(JsonValue.Create("add-pet"), JsonValue.Create(7));

        var result = VectorMatrixReader.Read(
            PackedMatrix.Compose(header, PackedMatrix.Payload([1f, 0f, 0f, 1f])),
            null,
            Served);

        Assert.Equal(VectorAvailability.Unreadable, result.State);
    }

    [Fact]
    public void A_payload_shorter_than_the_header_describes_is_a_dimension_mismatch()
    {
        var bytes = PackedMatrix.Compose(
            PackedMatrix.Header(2, 2, Served),
            PackedMatrix.Payload([1f, 0f, 0f]));

        var result = VectorMatrixReader.Read(bytes, null, Served);

        Assert.Equal(VectorAvailability.DimensionMismatch, result.State);
        Assert.Null(result.Matrix);
    }

    [Fact]
    public void A_payload_longer_than_the_header_describes_is_a_dimension_mismatch()
    {
        // Trailing bytes are refused rather than ignored. Accepting them would score a matrix
        // whose extent the header and the producer disagree about, and the disagreement is
        // exactly what says one of them is wrong.
        var bytes = PackedMatrix.Compose(
            PackedMatrix.Header(2, 2, Served),
            PackedMatrix.Payload([1f, 0f, 0f, 1f, 0f]));

        var result = VectorMatrixReader.Read(bytes, null, Served);

        Assert.Equal(VectorAvailability.DimensionMismatch, result.State);
    }

    [Fact]
    public void A_section_index_dimension_disagreeing_with_the_header_is_a_dimension_mismatch()
    {
        // Two declarations of one fact. The bundle was assembled from two embedding runs and
        // the bytes cannot be both, whichever of the two is the correct one.
        var bytes = PackedMatrix.Write(Served, [[1f, 0f], [0f, 1f]]);

        var result = VectorMatrixReader.Read(bytes, new VectorSectionMetadata("m", 1536), Served);

        Assert.Equal(VectorAvailability.DimensionMismatch, result.State);
    }

    [Fact]
    public void A_matrix_naming_other_operations_is_an_operation_mismatch()
    {
        var bytes = PackedMatrix.Write(["get-pet", "list-pets"], [[1f, 0f], [0f, 1f]]);

        var result = VectorMatrixReader.Read(bytes, null, Served);

        Assert.Equal(VectorAvailability.OperationMismatch, result.State);
        Assert.Null(result.Matrix);
    }

    [Fact]
    public void A_matrix_naming_the_same_operations_in_another_order_is_an_operation_mismatch()
    {
        // The trap a set comparison walks into. Every slug is present, so nothing looks
        // missing, and every row is addressed to the wrong operation.
        var bytes = PackedMatrix.Write(["list-pets", "add-pet"], [[1f, 0f], [0f, 1f]]);

        var result = VectorMatrixReader.Read(bytes, null, Served);

        Assert.Equal(VectorAvailability.OperationMismatch, result.State);
    }

    [Fact]
    public void A_matrix_describing_more_operations_than_the_index_is_an_operation_mismatch()
    {
        var bytes = PackedMatrix.Write(
            ["add-pet", "get-pet", "list-pets"],
            [[1f, 0f], [0f, 1f], [1f, 1f]]);

        var result = VectorMatrixReader.Read(bytes, null, Served);

        Assert.Equal(VectorAvailability.OperationMismatch, result.State);
    }

    [Fact]
    public void A_matrix_describing_the_index_is_usable()
    {
        var bytes = PackedMatrix.Write(Served, [[1f, 0f], [0f, 1f]]);

        var result = VectorMatrixReader.Read(bytes, new VectorSectionMetadata("m", 2), Served);

        Assert.Equal(VectorAvailability.Usable, result.State);
        Assert.Null(result.Detail);

        var matrix = Assert.IsType<VectorMatrix>(result.Matrix);
        Assert.Equal(2, matrix.Dimension);
        Assert.Equal(2, matrix.Count);
        Assert.Equal(Served, matrix.Operations);
        Assert.Equal([1f, 0f], matrix.Row(0).ToArray());
        Assert.Equal([0f, 1f], matrix.Row(1).ToArray());
    }

    [Fact]
    public void Values_are_read_little_endian_rather_than_reinterpreted()
    {
        // 1.0f is 0x3F800000, so little-endian is 00 00 80 3F. Asserting the bytes rather
        // than round-tripping through the writer is the only way this test would notice a
        // reader that reinterprets host memory and agrees with itself on every machine
        // anyone happens to run it on.
        byte[] payload = [0x00, 0x00, 0x80, 0x3F, 0x00, 0x00, 0x00, 0xC0];

        var result = VectorMatrixReader.Read(
            PackedMatrix.Compose(PackedMatrix.Header(1, 2, Served), payload),
            null,
            Served);

        var matrix = Assert.IsType<VectorMatrix>(result.Matrix);
        Assert.Equal(1f, matrix.Row(0)[0]);
        Assert.Equal(-2f, matrix.Row(1)[0]);
    }

    [Fact]
    public void Every_refusal_carries_a_reason_and_no_matrix()
    {
        // One test over all three rather than a theory, because the parameter would be the
        // internal enum and the assertion is the same sentence in every case: a refused
        // matrix is never handed back, and never handed back without saying why.
        VectorMatrixResult[] refusals =
        [
            VectorMatrixReader.Read(Encoding.UTF8.GetBytes("rubbish"), null, Served),
            VectorMatrixReader.Read(
                PackedMatrix.Compose(PackedMatrix.Header(2, 2, Served), PackedMatrix.Payload([1f])),
                null,
                Served),
            VectorMatrixReader.Read(PackedMatrix.Write(["other"], [[1f, 0f]]), null, Served),
        ];

        Assert.Equal(
            [VectorAvailability.Unreadable, VectorAvailability.DimensionMismatch, VectorAvailability.OperationMismatch],
            refusals.Select(refusal => refusal.State));

        Assert.All(refusals, refusal =>
        {
            Assert.Null(refusal.Matrix);
            Assert.False(string.IsNullOrWhiteSpace(refusal.Detail));
        });
    }
}
