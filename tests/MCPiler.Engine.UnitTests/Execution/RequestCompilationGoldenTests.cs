using System.Text;
using System.Text.Json.Nodes;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Serialization;
using MCPiler.Engine.Manifest.Model;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Compiles every case of the shared corpus from a manifest operation section and compares the
/// result against the committed expectation.
/// </summary>
/// <remarks>
/// <para>
/// Each test names the same case file as its counterpart on the producing side, so the two suites can
/// be read as one table. The arguments are identical too: an argument object is part of the case, not
/// of the implementation, and changing one here to make a test pass would silently redefine the case.
/// </para>
/// <para>
/// Compiling a request never reads an environment variable, opens a socket, or resolves a credential.
/// That is why this suite can assert the whole wire shape of a request while the repository still has
/// no transport: the request is a value, and the value is complete before anything is sent.
/// </para>
/// </remarks>
public sealed class RequestCompilationGoldenTests
{
    private static readonly Uri Api = new("https://api.example.com");
    private static readonly Uri ApiV2 = new("https://api.example.com/v2");

    /// <summary>
    /// The multipart case's arguments, including the reserved <c>partHeaders</c> member. The part
    /// header value is stated here rather than passed to the serializer directly because arguments
    /// are the only source the compiler reads, so a golden built from this asserts a request a real
    /// caller can produce. The Platform suite states the identical literal.
    /// </summary>
    private const string MultipartArguments =
        """{"body":{"meta":"abc","file":"","note":"remember"},"partHeaders":{"note":{"X-Note-Version":"2.1"}}}""";
    private static readonly Uri Shop = new("https://shop.example.com");

    // -- parameter location and style ---------------------------------------

    [Fact]
    public void Path_simple_primitive_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", Api,
            JsonNode.Parse("""{"petId":42}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-simple-primitive.txt"), actual);
    }

    [Fact]
    public void Path_prefixed_base_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", ApiV2,
            JsonNode.Parse("""{"petId":42}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("basepath-simple-primitive.txt"), actual);
    }

    [Fact]
    public void Path_prefixed_base_preserves_encoded_path_and_query_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", ApiV2,
            JsonNode.Parse("""{"petId":"a/b c","fields":["a b","c/d"]}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("basepath-encoded-query.txt"), actual);
    }

    [Theory]
    [InlineData("https://api.example.com/v2", "https://api.example.com/v2/pets/42")]
    [InlineData("https://api.example.com/v2/", "https://api.example.com/v2/pets/42")]
    [InlineData("https://api.example.com/services/foo", "https://api.example.com/services/foo/pets/42")]
    [InlineData("https://api.example.com", "https://api.example.com/pets/42")]
    [InlineData("https://api.example.com/", "https://api.example.com/pets/42")]
    public void Base_path_join_normalizes_only_the_join_boundary(string baseUrl, string expected)
    {
        var compiled = RequestCompiler.Compile(
            GoldenCorpus.Operation("params-simple-form", "GET /pets/{petId}"),
            new Uri(baseUrl),
            JsonNode.Parse("""{"petId":42}""")!.AsObject());

        Assert.Equal(expected, compiled.ExactUrl);
    }

    [Fact]
    public void Operation_path_with_or_without_leading_slash_is_equivalent()
    {
        var operation = GoldenCorpus.Operation("params-simple-form", "GET /pets/{petId}");
        var variant = operation with { Path = operation.Path.TrimStart('/') };
        var arguments = JsonNode.Parse("""{"petId":42}""")!.AsObject();

        var canonical = RequestCompiler.Compile(operation, ApiV2, arguments);
        var trimmed = RequestCompiler.Compile(variant, ApiV2, arguments);

        Assert.Equal(canonical.ExactUrl, trimmed.ExactUrl);
    }

    [Fact]
    public void Root_operation_path_is_appended_after_base_prefix()
    {
        var operation = GoldenCorpus.Operation("params-simple-form", "GET /pets/{petId}") with
        {
            Path = "/",
            Parameters = [],
        };

        var compiled = RequestCompiler.Compile(
            operation, new Uri("https://api.example.com/v2/"), new JsonObject());

        Assert.Equal("https://api.example.com/v2/", compiled.ExactUrl);
    }

    [Fact]
    public void Query_form_array_explode_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", Api,
            JsonNode.Parse("""{"petId":42,"fields":["a","b"]}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-form-array-explode.txt"), actual);
    }

    [Fact]
    public void Query_form_array_nonexplode_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", Api,
            JsonNode.Parse("""{"petId":42,"tags":["x","y"]}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-form-array-nonexplode.txt"), actual);
    }

    [Fact]
    public void Header_and_cookie_match_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", Api,
            JsonNode.Parse("""{"petId":42,"X-Trace":"t-1","session":"s1"}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-header-cookie.txt"), actual);
    }

    [Fact]
    public void Query_deepobject_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", Api,
            JsonNode.Parse("""{"petId":42,"filter":{"color":"red","size":"m"}}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-deepobject.txt"), actual);
    }

    [Fact]
    public void Query_allow_reserved_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", Api,
            JsonNode.Parse("""{"petId":42,"limit":"7/8"}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-reserved.txt"), actual);
    }

    [Fact]
    public void Path_matrix_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-matrix-label", "GET /matrix/{id}{coords}", Api,
            JsonNode.Parse("""{"id":"abc"}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-matrix.txt"), actual);
    }

    [Fact]
    public void Path_label_array_explode_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-matrix-label", "GET /matrix/{id}{coords}", Api,
            JsonNode.Parse("""{"id":"abc","coords":[1,2,3]}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-label-array.txt"), actual);
    }

    [Fact]
    public void Query_space_delimited_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-space-pipe", "GET /list", Api,
            JsonNode.Parse("""{"ids":[1,2,3]}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-space.txt"), actual);
    }

    [Fact]
    public void Query_pipe_delimited_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-space-pipe", "GET /list", Api,
            JsonNode.Parse("""{"names":["a","b"]}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-pipe.txt"), actual);
    }

    [Fact]
    public void Query_object_form_nonexplode_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-object", "GET /object-param", Api,
            JsonNode.Parse("""{"filter":{"color":"red","size":"m"}}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-object-form.txt"), actual);
    }

    [Fact]
    public void Cookie_object_form_nonexplode_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-object", "GET /object-param", Api,
            JsonNode.Parse("""{"meta":{"a":"x","b":"y"}}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-object-cookie.txt"), actual);
    }

    // The neighbouring case declares explode explicitly; this one declares neither style nor explode,
    // so both defaults are resolved from the vocabulary. It is the case that exposed a divergence
    // between the two implementations, because a writer omits a value equal to the default and the two
    // sides disagreed about what a cookie parameter's default explode was.
    [Fact]
    public void Cookie_object_form_inherited_explode_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("params-object", "GET /object-param-inherited", Api,
            JsonNode.Parse("""{"meta":{"a":"x","b":"y"}}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-object-cookie-inherited.txt"), actual);
    }

    // A content-typed parameter declares a media type instead of a style, so nothing about the
    // style vocabulary decides its bytes. The query parameter states its own name and the header
    // one does not, which is the same asymmetry every other location already has.
    [Fact]
    public void Content_typed_parameters_encode_with_their_declared_media_type()
    {
        var actual = GoldenCorpus.CompileAndRender("params-object", "GET /content-param", Api,
            JsonNode.Parse("""{"filter":{"color":"red"},"X-Note":"hi"}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("params-content-typed.txt"), actual);
    }

    // -- body media types ----------------------------------------------------

    [Fact]
    public void Body_json_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("bodies-scalar", "POST /echo", Api,
            JsonNode.Parse("""{"body":{"name":"pal","count":3}}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("body-json.txt"), actual);
    }

    [Fact]
    public void Body_vnd_json_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("bodies-scalar", "POST /echo-vnd", Api,
            JsonNode.Parse("""{"body":{"sku":"A"}}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("body-vnd-json.txt"), actual);
    }

    [Fact]
    public void Body_text_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("bodies-scalar", "POST /echo-text", Api,
            JsonNode.Parse("""{"body":"hello world"}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("body-text.txt"), actual);
    }

    // The operation declares text/plain first and application/json second, so the JSON tie-break is
    // exercised rather than coinciding with declaration order. The recorded decision never reaches
    // the wire, so a golden cannot assert it and the compiled value has to be inspected directly.
    [Fact]
    public void An_ambiguous_body_media_type_selects_json_and_records_the_ambiguity()
    {
        var arguments = JsonNode.Parse("""{"body":{"name":"x"}}""")!.AsObject();
        var actual = GoldenCorpus.CompileAndRender("bodies-scalar", "POST /echo-ambiguous", Api, arguments);
        Assert.Equal(GoldenCorpus.Case("body-ambiguous-media-type.txt"), actual);

        var compiled = RequestCompiler.Compile(
            GoldenCorpus.Operation("bodies-scalar", "POST /echo-ambiguous"), Api, arguments);
        var decision = Assert.Single(compiled.Decisions, d => d.Location == "body");
        Assert.Equal("media-type", decision.Style);
        Assert.Equal("defaulted to application/json", decision.EncodedValue);
    }

    // The contrast that makes the assertion above mean something: an operation offering one media
    // type has nothing to disambiguate, so it must record nothing.
    [Fact]
    public void An_unambiguous_body_media_type_records_no_ambiguity()
    {
        var compiled = RequestCompiler.Compile(
            GoldenCorpus.Operation("bodies-scalar", "POST /echo"), Api,
            JsonNode.Parse("""{"body":{"name":"pal","count":3}}""")!.AsObject());
        Assert.DoesNotContain(compiled.Decisions, d => d.Location == "body");
    }

    [Fact]
    public void Body_form_urlencoded_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("bodies-scalar", "POST /echo-form", Api,
            JsonNode.Parse("""{"body":{"user":"alice","active":true}}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("body-form.txt"), actual);
    }

    // The golden pins the boundary parameter on the compiled Content-Type. It was absent for as long
    // as the delimiter lived only inside the body bytes, which made the body unparseable by a
    // conforming recipient even though the bytes themselves were correct. Returning the delimiter from
    // body serialization is what let the compiler state it. A golden alone would not keep it honest,
    // because it pins one literal and a header carrying a stale constant would still match; the
    // relationship between the header and the body is asserted separately below.
    [Fact]
    public void Body_multipart_mixed_matches_golden_with_injected_boundary()
    {
        var files = new Dictionary<string, byte[]> { ["file"] = Encoding.ASCII.GetBytes("%PDF-1.7") };
        var fileNames = new Dictionary<string, string> { ["file"] = "doc.pdf" };
        var fileMediaTypes = new Dictionary<string, string> { ["file"] = "application/pdf" };

        // The X-Note-Version part header arrives through the reserved partHeaders argument member, the
        // only source production reads. It used to be handed straight to the serializer, so the golden
        // asserted a header no caller could cause the product to emit.
        var actual = GoldenCorpus.CompileAndRender("bodies-multipart-binary", "POST /multipart", Api,
            JsonNode.Parse(MultipartArguments)!.AsObject(),
            files, fileNames, fileMediaTypes,
            new FixedBoundaryProvider("TEST-BOUNDARY"));

        Assert.Equal(GoldenCorpus.Case("body-multipart-mixed.txt"), actual);
    }

    // -- part-header gate ----------------------------------------------------
    //
    // These values arrive from a model, so the projection from arguments to part headers is a gate
    // rather than a copy. Everything below is refused before any byte is written: an unvalidated
    // value would let one argument append arbitrary headers to a part, and inside a multipart body
    // it would let that argument forge a delimiter and restructure the whole request.

    private static Exception CompileMultipart(string arguments)
        => Record.Exception(() => RequestCompiler.Compile(
            GoldenCorpus.Operation("bodies-multipart-binary", "POST /multipart"), Api,
            JsonNode.Parse(arguments)!.AsObject(),
            new Dictionary<string, byte[]> { ["file"] = Encoding.ASCII.GetBytes("%PDF-1.7") },
            new Dictionary<string, string> { ["file"] = "doc.pdf" },
            new Dictionary<string, string> { ["file"] = "application/pdf" },
            new FixedBoundaryProvider("TEST-BOUNDARY")))!;

    [Theory]
    // A header the encoding does not declare. Accepting it would make the contract advisory.
    [InlineData("""{"body":{"note":"remember"},"partHeaders":{"note":{"X-Injected":"1"}}}""")]
    // A part the media type declares no encoding for, so no header is declared for it either.
    [InlineData("""{"body":{"note":"remember"},"partHeaders":{"meta":{"X-Note-Version":"1"}}}""")]
    // A carriage return would close the header block and open attacker-chosen content.
    [InlineData("""{"body":{"note":"remember"},"partHeaders":{"note":{"X-Note-Version":"1\r\nX-Evil: y"}}}""")]
    // A bare line feed is the same escape; both terminators have to be refused, not just the pair.
    [InlineData("""{"body":{"note":"remember"},"partHeaders":{"note":{"X-Note-Version":"1\nX-Evil: y"}}}""")]
    // The member itself has to be an object keyed by part name.
    [InlineData("""{"body":{"note":"remember"},"partHeaders":"X-Note-Version: 1"}""")]
    // And each part's entry has to be an object keyed by header name.
    [InlineData("""{"body":{"note":"remember"},"partHeaders":{"note":"1"}}""")]
    public void A_part_header_that_is_not_declared_or_not_safe_is_refused(string arguments)
    {
        var error = CompileMultipart(arguments);
        var validation = Assert.IsType<ArgumentValidationException>(error);
        Assert.Equal(RequestCompiler.PartHeadersArgument, validation.ParameterName);
    }

    // The declared header is emitted only when a value is supplied. Absence is not an error, because
    // an encoding declares which headers a part may carry rather than which it must.
    [Fact]
    public void A_declared_part_header_with_no_supplied_value_is_omitted()
    {
        var actual = GoldenCorpus.CompileAndRender("bodies-multipart-binary", "POST /multipart", Api,
            JsonNode.Parse("""{"body":{"meta":"abc","file":"","note":"remember"}}""")!.AsObject(),
            new Dictionary<string, byte[]> { ["file"] = Encoding.ASCII.GetBytes("%PDF-1.7") },
            new Dictionary<string, string> { ["file"] = "doc.pdf" },
            new Dictionary<string, string> { ["file"] = "application/pdf" },
            new FixedBoundaryProvider("TEST-BOUNDARY"));

        Assert.DoesNotContain(Convert.ToHexString(Encoding.UTF8.GetBytes("X-Note-Version")).ToLowerInvariant(), actual);
    }

    [Fact]
    public void Body_raw_binary_matches_golden()
    {
        var raw = new byte[] { 0x00, 0xFF, 0x10, 0xAA };
        var arguments = new JsonObject { ["body"] = JsonValue.Create(raw) };
        var actual = GoldenCorpus.CompileAndRender("bodies-multipart-binary", "POST /binary-upload", Api, arguments);
        Assert.Equal(GoldenCorpus.Case("body-binary.txt"), actual);
    }

    // -- compound steps ------------------------------------------------------

    // The producing side reaches these cases through its compound mapping evaluator, which turns a
    // step's mapped input document into flat arguments. This stage has no evaluator, so the flat
    // arguments are stated directly. That is the whole point of the case: a mapped step must compile
    // to exactly what the direct path compiles for the equivalent flat arguments, so if the two ever
    // disagree the case stops matching on one side.
    [Fact]
    public void Compound_step_create_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("compound-commerce", "POST /orders", Shop,
            JsonNode.Parse("""{"body":{"customerId":"c-42"}}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("compound-step-create.txt"), actual);
    }

    [Fact]
    public void Compound_step_fetch_matches_golden()
    {
        var actual = GoldenCorpus.CompileAndRender("compound-commerce", "GET /orders/{orderId}", Shop,
            JsonNode.Parse("""{"orderId":"ord-77"}""")!.AsObject());
        Assert.Equal(GoldenCorpus.Case("compound-step-fetch.txt"), actual);
    }

    // -- determinism and refusals -------------------------------------------

    [Fact]
    public void Repeated_compilation_is_byte_identical()
    {
        var arguments = JsonNode.Parse("""{"petId":42,"fields":["a","b"]}""")!.AsObject();
        var first = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", Api, arguments);
        var second = GoldenCorpus.CompileAndRender("params-simple-form", "GET /pets/{petId}", Api, arguments);
        Assert.Equal(first, second);
    }

    [Fact]
    public void Repeated_multipart_compilation_differs_only_in_the_boundary()
    {
        var files = new Dictionary<string, byte[]> { ["file"] = Encoding.ASCII.GetBytes("%PDF-1.7") };
        var fileNames = new Dictionary<string, string> { ["file"] = "doc.pdf" };
        var fileMediaTypes = new Dictionary<string, string> { ["file"] = "application/pdf" };
        var arguments = JsonNode.Parse(MultipartArguments)!.AsObject();

        var first = GoldenCorpus.CompileAndRender("bodies-multipart-binary", "POST /multipart", Api,
            arguments, files, fileNames, fileMediaTypes, new FixedBoundaryProvider("ONE"));
        var second = GoldenCorpus.CompileAndRender("bodies-multipart-binary", "POST /multipart", Api,
            arguments, files, fileNames, fileMediaTypes, new FixedBoundaryProvider("TWO"));

        Assert.NotEqual(first, second);

        // The delimiter appears twice in the rendered form: verbatim in the Content-Type header and
        // hex-encoded inside the body. Substituting one for the other in both places must make the two
        // renderings identical, which says the boundary is the only thing that moved.
        var substituted = first
            .Replace("boundary=ONE", "boundary=TWO", StringComparison.Ordinal)
            .Replace(
                Convert.ToHexString(Encoding.ASCII.GetBytes("ONE")).ToLowerInvariant(),
                Convert.ToHexString(Encoding.ASCII.GetBytes("TWO")).ToLowerInvariant(),
                StringComparison.Ordinal);
        Assert.Equal(second, substituted);
    }

    [Fact]
    public void The_multipart_content_type_declares_the_body_delimiter()
    {
        // A golden pins one literal string, so on its own it cannot say whether the boundary in the
        // header is the boundary the body uses. This asserts the relationship RFC 2046 5.1.1 requires.
        var compiled = RequestCompiler.Compile(
            GoldenCorpus.Operation("bodies-multipart-binary", "POST /multipart"),
            Api,
            JsonNode.Parse("""{"body":{"meta":"abc","file":"","note":"remember"}}""")!.AsObject(),
            new Dictionary<string, byte[]> { ["file"] = Encoding.ASCII.GetBytes("%PDF-1.7") },
            new Dictionary<string, string> { ["file"] = "doc.pdf" },
            new Dictionary<string, string> { ["file"] = "application/pdf" },
            new FixedBoundaryProvider("TEST-BOUNDARY"));

        Assert.Equal("multipart/form-data; boundary=TEST-BOUNDARY", compiled.BodyMediaType);
        Assert.Equal(compiled.BodyMediaType, Assert.Single(compiled.Headers["Content-Type"]));

        var body = Encoding.ASCII.GetString(compiled.Body!);
        Assert.StartsWith("--TEST-BOUNDARY\r\n", body, StringComparison.Ordinal);
        Assert.EndsWith("--TEST-BOUNDARY--\r\n", body, StringComparison.Ordinal);
    }

    [Fact]
    public void A_generated_delimiter_reaches_the_content_type_too()
    {
        // Production injects no provider. If the header only carried the boundary under a test double,
        // every real upload would still be unparseable.
        var compiled = RequestCompiler.Compile(
            GoldenCorpus.Operation("bodies-multipart-binary", "POST /multipart"),
            Api,
            JsonNode.Parse("""{"body":{"meta":"abc","file":"","note":"remember"}}""")!.AsObject(),
            new Dictionary<string, byte[]> { ["file"] = Encoding.ASCII.GetBytes("%PDF-1.7") },
            new Dictionary<string, string> { ["file"] = "doc.pdf" },
            new Dictionary<string, string> { ["file"] = "application/pdf" });

        const string prefix = "multipart/form-data; boundary=";
        Assert.StartsWith(prefix, compiled.BodyMediaType, StringComparison.Ordinal);

        var declared = compiled.BodyMediaType![prefix.Length..];
        Assert.NotEmpty(declared);
        Assert.StartsWith($"--{declared}\r\n", Encoding.ASCII.GetString(compiled.Body!), StringComparison.Ordinal);
    }

    [Fact]
    public void A_non_multipart_body_declares_no_delimiter()
    {
        var compiled = RequestCompiler.Compile(
            GoldenCorpus.Operation("bodies-scalar", "POST /echo"),
            Api,
            JsonNode.Parse("""{"body":{"name":"widget"}}""")!.AsObject());

        Assert.Equal("application/json", compiled.BodyMediaType);
        Assert.DoesNotContain("boundary", compiled.BodyMediaType, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Missing_required_path_parameter_fails_compilation()
    {
        var operation = GoldenCorpus.Operation("params-simple-form", "GET /pets/{petId}");
        var error = Assert.Throws<ArgumentValidationException>(
            () => RequestCompiler.Compile(operation, Api, new JsonObject()));
        Assert.Equal("petId", error.ParameterName);
    }

    [Theory]
    [InlineData("https://api.example.com/v2?fixed=1")]
    [InlineData("https://api.example.com/v2#section")]
    [InlineData("https://api.example.com/v2?fixed=1#section")]
    public void Base_url_query_or_fragment_fails_with_configuration_diagnostic(string baseUrl)
    {
        var operation = GoldenCorpus.Operation("params-simple-form", "GET /pets/{petId}");
        var error = Assert.Throws<InvalidBaseUrlException>(() => RequestCompiler.Compile(
            operation, new Uri(baseUrl), JsonNode.Parse("""{"petId":42}""")!.AsObject()));

        Assert.Contains("Base URL", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("query", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fragment", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    // A location this vocabulary cannot express needs no refusal, but a style it can express in the
    // wrong place still does: matrix is a path style, and a header parameter declaring it has to be
    // refused rather than serialized as something else.
    [Fact]
    public void Unsupported_style_fails_compilation_with_diagnostic()
    {
        var operation = GoldenCorpus.Operation("params-object", "GET /object-param") with
        {
            Parameters =
            [
                new ManifestParameter("bad", ParameterLocation.Header, Required: true, Style: ParameterStyle.Matrix),
            ],
        };

        var error = Assert.Throws<UnsupportedSerializationException>(() => RequestCompiler.Compile(
            operation, Api, JsonNode.Parse("""{"bad":1}""")!.AsObject()));
        Assert.Contains("unsupported", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compiled_request_is_inspectable_before_send()
    {
        var compiled = RequestCompiler.Compile(
            GoldenCorpus.Operation("params-simple-form", "GET /pets/{petId}"),
            Api,
            JsonNode.Parse("""{"petId":42,"X-Trace":"t-1"}""")!.AsObject());

        Assert.Equal("GET", compiled.Method);
        Assert.Equal("https://api.example.com/pets/42", compiled.ExactUrl);
        Assert.Contains(compiled.Headers, kv => kv.Key.Equals("X-Trace", StringComparison.OrdinalIgnoreCase));
        Assert.True(compiled.Decisions.Count >= 2);
    }
}
