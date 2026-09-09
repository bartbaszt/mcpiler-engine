using System.Text;
using System.Text.Json.Nodes;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Serialization;
using MCPiler.Engine.Manifest.Model;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Covers multipart part assembly, including the declared-header branch that has exactly one corpus
/// case and no production caller. Rows 9 and 12 of the change's adversarial matrix.
/// </summary>
public sealed class MultipartSerializerTests
{
    private const string Boundary = "TEST-BOUNDARY";

    private static readonly IReadOnlyDictionary<string, byte[]> NoFiles =
        new Dictionary<string, byte[]>(StringComparer.Ordinal);

    private static readonly IReadOnlyDictionary<string, string> NoStrings =
        new Dictionary<string, string>(StringComparer.Ordinal);

    private static ManifestMediaType MediaType(params ManifestEncoding[] encodings)
        => new(
            "multipart/form-data",
            Encoding: encodings.ToDictionary(e => e.PropertyName, e => e, StringComparer.Ordinal));

    private static ManifestEncoding Encoding_(
        string propertyName,
        string? contentType = null,
        params string[] headerNames)
        => new(
            propertyName,
            contentType,
            Headers: headerNames.ToDictionary(
                n => n,
                _ => ManifestSchema.From(JsonNode.Parse("""{"type":"string"}""")!),
                StringComparer.OrdinalIgnoreCase));

    private static string Write(
        ManifestMediaType mediaType,
        string bodyJson,
        IReadOnlyDictionary<string, byte[]>? files = null,
        IReadOnlyDictionary<string, string>? fileNames = null,
        IReadOnlyDictionary<string, string>? fileMediaTypes = null,
        IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? partHeaderValues = null)
        => System.Text.Encoding.UTF8.GetString(
            new MultipartSerializer(new FixedBoundaryProvider(Boundary)).Serialize(
                mediaType,
                JsonNode.Parse(bodyJson),
                files ?? NoFiles,
                fileNames ?? NoStrings,
                fileMediaTypes ?? NoStrings,
                partHeaderValues).Body);

    [Fact]
    public void Every_member_becomes_one_part_and_the_body_ends_with_the_closing_delimiter()
    {
        var body = Write(MediaType(), """{"a":"x","b":"y"}""");

        // A non-file part carries an explicit text/plain content type rather than relying on the
        // recipient's default, which is what the recorded golden shows.
        Assert.Equal(
            "--TEST-BOUNDARY\r\n"
            + "Content-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain\r\n\r\nx\r\n"
            + "--TEST-BOUNDARY\r\n"
            + "Content-Disposition: form-data; name=\"b\"\r\nContent-Type: text/plain\r\n\r\ny\r\n"
            + "--TEST-BOUNDARY--\r\n",
            body);
    }

    [Fact]
    public void Part_order_is_the_body_s_member_order()
    {
        var forward = Write(MediaType(), """{"a":"x","b":"y"}""");
        var reversed = Write(MediaType(), """{"b":"y","a":"x"}""");

        Assert.NotEqual(forward, reversed);
        Assert.StartsWith("--TEST-BOUNDARY\r\nContent-Disposition: form-data; name=\"b\"", reversed, StringComparison.Ordinal);
    }

    [Fact]
    public void A_member_present_in_the_file_map_becomes_a_file_part()
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal) { ["doc"] = [1, 2, 3] };
        var names = new Dictionary<string, string>(StringComparer.Ordinal) { ["doc"] = "report.pdf" };
        var types = new Dictionary<string, string>(StringComparer.Ordinal) { ["doc"] = "application/pdf" };

        var body = Write(MediaType(), """{"doc":""}""", files, names, types);

        Assert.Contains(
            "Content-Disposition: form-data; name=\"doc\"; filename=\"report.pdf\"\r\nContent-Type: application/pdf\r\n",
            body,
            StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_part_without_a_supplied_name_falls_back_to_the_member_name()
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal) { ["doc"] = [1] };

        var body = Write(MediaType(), """{"doc":""}""", files);

        Assert.Contains("filename=\"doc\"", body, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_part_without_a_supplied_media_type_uses_the_declared_one()
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal) { ["doc"] = [1] };

        var body = Write(MediaType(Encoding_("doc", "image/png")), """{"doc":""}""", files);

        Assert.Contains("Content-Type: image/png", body, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_part_with_neither_a_supplied_nor_a_declared_media_type_falls_back_to_octet_stream()
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal) { ["doc"] = [1] };

        var body = Write(MediaType(), """{"doc":""}""", files);

        Assert.Contains("Content-Type: application/octet-stream", body, StringComparison.Ordinal);
    }

    [Fact]
    public void A_supplied_media_type_overrides_the_declared_one()
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal) { ["doc"] = [1] };
        var types = new Dictionary<string, string>(StringComparer.Ordinal) { ["doc"] = "text/csv" };

        var body = Write(MediaType(Encoding_("doc", "image/png")), """{"doc":""}""", files, null, types);

        Assert.Contains("Content-Type: text/csv", body, StringComparison.Ordinal);
        Assert.DoesNotContain("image/png", body, StringComparison.Ordinal);
    }

    [Fact]
    public void A_declared_header_is_written_only_when_a_value_is_supplied()
    {
        // The contract declares a header's shape, not its content, so a declaration alone must not
        // emit an empty header. Nothing in production supplies these values today, which is why this
        // branch needs a test of its own rather than relying on a corpus case.
        var mediaType = MediaType(Encoding_("note", null, "X-Note-Version"));

        var without = Write(mediaType, """{"note":"n"}""");
        var with = Write(
            mediaType,
            """{"note":"n"}""",
            partHeaderValues: new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal)
            {
                ["note"] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["X-Note-Version"] = "2.1",
                },
            });

        Assert.DoesNotContain("X-Note-Version", without, StringComparison.Ordinal);
        Assert.Contains("X-Note-Version: 2.1\r\n", with, StringComparison.Ordinal);
    }

    [Fact]
    public void A_supplied_header_that_the_part_does_not_declare_is_not_written()
    {
        var body = Write(
            MediaType(Encoding_("note", null, "X-Note-Version")),
            """{"note":"n"}""",
            partHeaderValues: new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal)
            {
                ["note"] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["X-Undeclared"] = "v",
                },
            });

        Assert.DoesNotContain("X-Undeclared", body, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_name_carrying_a_quote_or_a_newline_cannot_break_out_of_the_header()
    {
        // The property that matters is that no injected CRLF survives, because a surviving one would
        // let a caller-supplied file name append headers or an entire part. The sanitiser strips the
        // quote and the line breaks and keeps the remaining text, so the injected words stay inside
        // the quoted file name where they are inert.
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal) { ["doc"] = [1] };
        var names = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["doc"] = "a\"b\r\nContent-Type: text/html",
        };

        var body = Write(MediaType(), """{"doc":""}""", files, names);

        var disposition = body.Split("\r\n")[1];

        Assert.Equal(
            "Content-Disposition: form-data; name=\"doc\"; filename=\"abContent-Type: text/html\"",
            disposition);
        Assert.DoesNotContain("\r\nContent-Type: text/html", body, StringComparison.Ordinal);

        // Two delimiters and no more: the injected text produced neither an extra part nor an extra
        // header line.
        Assert.Equal(2, body.Split("--TEST-BOUNDARY").Length - 1);
        // The injected words survive as text inside the file name, so counting the bare token would
        // find two. What must be one is the number of places the token begins a header line.
        Assert.Equal(1, body.Split("\r\nContent-Type:").Length - 1);
    }

    [Fact]
    public void An_empty_body_object_produces_only_the_closing_delimiter()
        => Assert.Equal("--TEST-BOUNDARY--\r\n", Write(MediaType(), "{}"));

    [Theory]
    [InlineData("[1,2]")]
    [InlineData("\"text\"")]
    [InlineData("null")]
    public void A_body_that_is_not_an_object_is_refused(string json)
        => Assert.Throws<UnsupportedSerializationException>(() => Write(MediaType(), json));

    [Fact]
    public void The_boundary_provider_decides_every_delimiter_in_the_body()
    {
        var first = Write(MediaType(), """{"a":"x"}""");
        var second = new MultipartSerializer(new FixedBoundaryProvider("OTHER")).Serialize(
            MediaType(),
            JsonNode.Parse("""{"a":"x"}"""),
            NoFiles,
            NoStrings,
            NoStrings);

        Assert.Equal(
            first.Replace(Boundary, "OTHER", StringComparison.Ordinal),
            System.Text.Encoding.UTF8.GetString(second.Body));
    }

    [Fact]
    public void The_returned_boundary_is_the_one_the_body_uses()
    {
        // The caller has to put this value into the media type, so a returned boundary that did not
        // match the body would produce a message no server could split. Nothing else in the serializer
        // exposes the delimiter, which is exactly why it was missing from the header before.
        var written = new MultipartSerializer(new FixedBoundaryProvider(Boundary)).Serialize(
            MediaType(),
            JsonNode.Parse("""{"a":"x"}"""),
            NoFiles,
            NoStrings,
            NoStrings);

        Assert.Equal(Boundary, written.Boundary);

        var body = System.Text.Encoding.UTF8.GetString(written.Body);
        Assert.StartsWith($"--{written.Boundary}\r\n", body, StringComparison.Ordinal);
        Assert.EndsWith($"--{written.Boundary}--\r\n", body, StringComparison.Ordinal);
    }

    [Fact]
    public void A_generated_boundary_is_returned_as_well()
    {
        // Production injects no fixed provider, so the returned value must track a random delimiter too.
        var written = new MultipartSerializer(new RandomBoundaryProvider()).Serialize(
            MediaType(),
            JsonNode.Parse("""{"a":"x"}"""),
            NoFiles,
            NoStrings,
            NoStrings);

        Assert.NotEmpty(written.Boundary);
        Assert.StartsWith(
            $"--{written.Boundary}\r\n",
            System.Text.Encoding.UTF8.GetString(written.Body),
            StringComparison.Ordinal);
    }

    [Fact]
    public void A_random_provider_yields_a_different_boundary_each_time_it_is_asked()
    {
        var provider = new RandomBoundaryProvider();

        Assert.NotEqual(provider.GetBoundary(), provider.GetBoundary());
    }
}
