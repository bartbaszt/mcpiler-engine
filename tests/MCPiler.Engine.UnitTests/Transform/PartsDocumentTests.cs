using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Transform;

using Xunit;

namespace MCPiler.Engine.UnitTests.Transform;

/// <summary>
/// The translation between compiler arguments and the document a program addresses.
/// </summary>
/// <remarks>
/// The property that matters is the round trip. A transformation declared and left empty must
/// compile the request that no transformation would, so anything this type drops on the way out
/// and cannot rebuild on the way back is a request the author did not write.
/// </remarks>
public sealed class PartsDocumentTests
{
    private static readonly IReadOnlySet<string> NoFiles = new HashSet<string>(StringComparer.Ordinal);

    private static readonly ManifestOperation Operation = new(
        ManifestOperation.BuildKey("POST", "/pets/{petId}"),
        "POST",
        "/pets/{petId}",
        Parameters:
        [
            new ManifestParameter("petId", ParameterLocation.Path, Required: true),
            new ManifestParameter("status", ParameterLocation.Query),
            new ManifestParameter("optional", ParameterLocation.Query),
            new ManifestParameter("X-Trace", ParameterLocation.Header),
            new ManifestParameter("session", ParameterLocation.Cookie),
        ]);

    [Fact]
    public void A_round_trip_through_an_untouched_document_rebuilds_the_arguments()
    {
        var arguments = new JsonObject
        {
            ["petId"] = "p-7",
            ["status"] = "available",
            ["X-Trace"] = "abc",
            ["session"] = "s1",
            ["body"] = new JsonObject { ["name"] = "pico", ["weight"] = 1.0 },
        };

        JsonObject parts = PartsDocument.Request(Operation, arguments, NoFiles);
        JsonObject rebuilt = PartsDocument.Arguments(Operation, parts, NoFiles, arguments);

        Assert.Equal(JsonSerializer.Serialize(arguments), JsonSerializer.Serialize(rebuilt));
    }

    [Fact]
    public void An_absent_optional_parameter_does_not_come_back_as_null()
    {
        // A null in the arguments is a value the compiler serializes. Normalizing absence into
        // one would add a query parameter the caller never sent.
        var arguments = new JsonObject { ["petId"] = "p-7" };

        JsonObject parts = PartsDocument.Request(Operation, arguments, NoFiles);
        JsonObject rebuilt = PartsDocument.Arguments(Operation, parts, NoFiles, arguments);

        Assert.False(rebuilt.ContainsKey("optional"));
        Assert.False(rebuilt.ContainsKey("body"));
    }

    [Fact]
    public void Each_parameter_lands_in_the_bucket_its_location_names()
    {
        var arguments = new JsonObject
        {
            ["petId"] = "p-7",
            ["status"] = "available",
            ["X-Trace"] = "abc",
            ["session"] = "s1",
        };

        JsonObject parts = PartsDocument.Request(Operation, arguments, NoFiles);

        Assert.Equal("p-7", parts["path"]!["petId"]!.GetValue<string>());
        Assert.Equal("available", parts["query"]!["status"]!.GetValue<string>());
        Assert.Equal("abc", parts["headers"]!["X-Trace"]!.GetValue<string>());
        Assert.Equal("s1", parts["cookies"]!["session"]!.GetValue<string>());
    }

    [Fact]
    public void The_agent_document_is_the_root_so_a_source_can_read_an_argument_the_upstream_never_declared()
    {
        // The reason a transformation exists: an agent surface that takes 'term' and an upstream
        // that takes 'status'. With only the buckets at the root there would be nothing to read.
        var arguments = new JsonObject { ["term"] = "pico" };

        JsonObject parts = PartsDocument.Request(Operation, arguments, NoFiles);

        Assert.Equal("pico", parts["term"]!.GetValue<string>());
    }

    [Fact]
    public void An_agent_only_argument_is_not_rebuilt_into_the_compiler_arguments()
    {
        // It was an input to the program, not a value the request compiler knows what to do
        // with. Carrying it through would put an undeclared member in front of the compiler.
        var arguments = new JsonObject { ["term"] = "pico", ["petId"] = "p-7" };

        JsonObject parts = PartsDocument.Request(Operation, arguments, NoFiles);
        JsonObject rebuilt = PartsDocument.Arguments(Operation, parts, NoFiles, arguments);

        Assert.False(rebuilt.ContainsKey("term"));
        Assert.Equal("p-7", rebuilt["petId"]!.GetValue<string>());
    }

    [Fact]
    public void The_reserved_serialization_member_survives_although_no_pointer_addresses_it()
    {
        // partHeaders controls the multipart writer and has no pointer root. Dropping it would
        // make an empty passthrough program silently discard declared part headers.
        var headers = new JsonObject
        {
            ["file"] = new JsonObject { ["Content-Disposition"] = "inline" },
        };

        var arguments = new JsonObject
        {
            ["petId"] = "p-7",
            [RequestCompiler.PartHeadersArgument] = headers.DeepClone(),
        };

        JsonObject parts = PartsDocument.Request(Operation, arguments, NoFiles);
        JsonObject rebuilt = PartsDocument.Arguments(Operation, parts, NoFiles, arguments);

        Assert.False(parts.ContainsKey(RequestCompiler.PartHeadersArgument));
        Assert.Equal(
            JsonSerializer.Serialize(headers),
            JsonSerializer.Serialize(rebuilt[RequestCompiler.PartHeadersArgument]));
    }

    [Fact]
    public void A_file_slot_lands_in_parts_rather_than_in_its_declared_location()
    {
        IReadOnlySet<string> files = new HashSet<string>(StringComparer.Ordinal) { "status", "upload" };

        var arguments = new JsonObject
        {
            ["petId"] = "p-7",
            ["status"] = "handle-a",
            ["upload"] = "handle-b",
        };

        JsonObject parts = PartsDocument.Request(Operation, arguments, files);

        Assert.False(parts["query"]!.AsObject().ContainsKey("status"));
        Assert.Equal("handle-a", parts["parts"]!["status"]!.GetValue<string>());

        // A slot the operation never declared as a parameter is still a slot.
        Assert.Equal("handle-b", parts["parts"]!["upload"]!.GetValue<string>());

        JsonObject rebuilt = PartsDocument.Arguments(Operation, parts, files, arguments);

        Assert.Equal("handle-a", rebuilt["status"]!.GetValue<string>());
        Assert.Equal("handle-b", rebuilt["upload"]!.GetValue<string>());
    }

    [Fact]
    public void The_response_document_carries_the_status_one_header_value_and_a_parsed_body()
    {
        var result = new EngineExecutionResult
        {
            StatusCode = 201,
            ResponseHeaders = new Dictionary<string, string[]>(StringComparer.Ordinal)
            {
                ["X-Trace"] = ["first", "second"],
                ["X-Empty"] = [],
            },
            ResponseBody = "{\"id\":7}"u8.ToArray(),
        };

        JsonObject document = PartsDocument.Response(result);

        Assert.Equal(201, document["status"]!.GetValue<int>());
        Assert.Equal("first", document["headers"]!["X-Trace"]!.GetValue<string>());
        Assert.False(document["headers"]!.AsObject().ContainsKey("X-Empty"));
        Assert.Equal(7, document["body"]!["id"]!.GetValue<int>());
    }

    [Fact]
    public void A_response_body_that_is_not_json_arrives_as_text()
    {
        var result = new EngineExecutionResult
        {
            StatusCode = 200,
            ResponseBody = "plain text, not a document"u8.ToArray(),
        };

        JsonObject document = PartsDocument.Response(result);

        Assert.Equal("plain text, not a document", document["body"]!.GetValue<string>());
    }

    [Fact]
    public void A_response_with_no_body_and_no_status_still_has_the_three_members()
    {
        // A program addressing /status or /headers must not fail because the exchange was
        // empty; the shape of the document is the contract, not its contents.
        JsonObject document = PartsDocument.Response(new EngineExecutionResult());

        Assert.Equal(0, document["status"]!.GetValue<int>());
        Assert.Empty(document["headers"]!.AsObject());
        Assert.Null(document["body"]);
    }
}
