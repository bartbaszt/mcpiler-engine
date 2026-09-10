using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Mcp;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>
/// The two decisions a call makes without reaching anything: whether the arguments satisfy the
/// contract that was advertised, and what an outcome means.
/// </summary>
public sealed class ToolInvocationTests
{
    private static CatalogueTool Tool(string inputSchemaJson)
        => new(
            "list-pets",
            "list-pets",
            "Lists pets.",
            inputSchemaJson,
            ReadOnly: true,
            Destructive: false,
            Idempotent: true,
            OpenWorld: true)
        {
            Operation = "list-pets",
        };

    private static JsonObject Arguments(string json) => JsonNode.Parse(json)!.AsObject();

    // ---- validation ------------------------------------------------------------------

    [Fact]
    public void Arguments_that_satisfy_the_advertised_schema_are_accepted()
    {
        var schema = """{"type":"object","required":["status"],"properties":{"status":{"type":"string"}}}""";

        Assert.Null(ToolInvocation.Validate(Tool(schema), Arguments("""{"status":"available"}""")));
    }

    [Fact]
    public void A_missing_required_argument_is_refused_and_the_location_is_named()
    {
        var schema = """{"type":"object","required":["status"],"properties":{"status":{"type":"string"}}}""";

        var refusal = ToolInvocation.Validate(Tool(schema), Arguments("{}"));

        Assert.NotNull(refusal);
        Assert.Contains("advertised input schema", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void An_argument_of_the_wrong_type_is_refused_at_its_own_location()
    {
        var schema = """{"type":"object","properties":{"limit":{"type":"integer"}}}""";

        var refusal = ToolInvocation.Validate(Tool(schema), Arguments("""{"limit":"ten"}"""));

        Assert.NotNull(refusal);
        Assert.Contains("'/limit'", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void A_refusal_never_echoes_the_offending_value()
    {
        var schema = """{"type":"object","properties":{"token":{"type":"integer"}}}""";

        var refusal = ToolInvocation.Validate(Tool(schema), Arguments("""{"token":"hunter2"}"""));

        // An argument may be credential material. A message that quoted it to explain the
        // refusal would have put a secret into a log line.
        Assert.NotNull(refusal);
        Assert.DoesNotContain("hunter2", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void The_unconstrained_schema_accepts_whatever_arrives()
    {
        var tool = Tool(ToolSetProjection.UnconstrainedInputSchema);

        // A Manifest that declares no arguments constrains nothing, and validation must not
        // invent a prohibition the Manifest never stated.
        Assert.Null(ToolInvocation.Validate(tool, Arguments("""{"anything":[1,2,3]}""")));
    }

    [Fact]
    public void A_schema_annotation_the_dialect_does_not_know_does_not_refuse_the_call()
    {
        var schema =
            """
            {"type":"object","properties":{"upload":{"type":"string","x-mcp-file":true,"nullable":false}}}
            """;

        // 'x-mcp-file' is how a file slot is marked and it carries no assertion. A validator
        // that tripped over it would make every file operation uninvokable.
        Assert.Null(ToolInvocation.Validate(Tool(schema), Arguments("""{"upload":"handle"}""")));
    }

    [Fact]
    public void An_uninterpretable_schema_refuses_the_call_rather_than_skipping_the_check()
    {
        var refusal = ToolInvocation.Validate(Tool("not json at all"), Arguments("{}"));

        // Fail-closed. Skipping validation here would mean the contract hardest to satisfy is
        // the one nothing measures.
        Assert.NotNull(refusal);
        Assert.Contains("could not be interpreted", refusal, StringComparison.Ordinal);
        Assert.Contains("before any request", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void A_recursive_advertised_schema_validates_against_its_own_components()
    {
        var schema =
            """
            {
              "type": "object",
              "required": ["id"],
              "properties": {
                "id": { "type": "string" },
                "children": { "type": "array", "items": { "$ref": "#/$defs/Node" } }
              },
              "$defs": {
                "Node": {
                  "type": "object",
                  "required": ["id"],
                  "properties": {
                    "id": { "type": "string" },
                    "children": { "type": "array", "items": { "$ref": "#/$defs/Node" } }
                  }
                }
              }
            }
            """;

        // This is the shape derivation produces for a manifest-local reference, and it is the
        // reason containment relocates the target instead of leaving the pointer: a schema
        // that travelled alone with '#/components/schemas/Node' could not be evaluated here
        // and every call would have been refused.
        Assert.Null(ToolInvocation.Validate(
            Tool(schema),
            Arguments("""{"id":"a","children":[{"id":"b","children":[{"id":"c"}]}]}""")));

        Assert.NotNull(ToolInvocation.Validate(
            Tool(schema),
            Arguments("""{"id":"a","children":[{"children":[]}]}""")));
    }

    // ---- shaping ---------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(FailureKinds))]
    public void Every_failure_kind_is_rendered_as_a_stated_tool_error(ExecutionFailureKind failure)
    {
        var outcome = ToolInvocation.Shape(new EngineExecutionResult
        {
            Failure = failure,
            FailureReason = "the stated reason",
        });

        Assert.True(outcome.IsError);
        Assert.Equal("the stated reason", outcome.Text);
    }

    [Theory]
    [MemberData(nameof(FailureKinds))]
    public void A_failure_with_no_reason_is_still_explained(ExecutionFailureKind failure)
    {
        // The floor, not the expected answer. It exists so the mapping is total over the
        // closed classification instead of depending on an invariant held somewhere else.
        var outcome = ToolInvocation.Shape(new EngineExecutionResult { Failure = failure });

        Assert.True(outcome.IsError);
        Assert.Contains(failure.ToString(), outcome.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_successful_body_is_rendered_as_text()
    {
        var outcome = ToolInvocation.Shape(new EngineExecutionResult
        {
            StatusCode = 200,
            ResponseBody = "[{\"id\":1}]"u8.ToArray(),
        });

        Assert.False(outcome.IsError);
        Assert.Equal("[{\"id\":1}]", outcome.Text);
    }

    [Fact]
    public void An_empty_body_is_stated_rather_than_returned_as_nothing()
    {
        var outcome = ToolInvocation.Shape(new EngineExecutionResult { StatusCode = 204 });

        Assert.False(outcome.IsError);
        Assert.Equal(ToolInvocation.NoBody, outcome.Text);
    }

    [Fact]
    public void An_unsuccessful_upstream_status_is_not_a_tool_error()
    {
        var outcome = ToolInvocation.Shape(new EngineExecutionResult
        {
            StatusCode = 404,
            ResponseBody = """{"code":"not_found"}"""u8.ToArray(),
        });

        // The upstream answered. Reporting it as a tool error would tell a caller its request
        // was malformed when the request was fine and the resource was not there.
        Assert.False(outcome.IsError);
        Assert.Equal("""{"code":"not_found"}""", outcome.Text);
    }

    [Fact]
    public void A_stored_binary_response_is_rendered_as_a_reference_rather_than_as_bytes()
    {
        var outcome = ToolInvocation.Shape(new EngineExecutionResult
        {
            StatusCode = 200,
            ResponseFile = new FileHandleReference(
                "abc123",
                "report.pdf",
                "application/pdf",
                2048,
                "0f".PadRight(64, '0'),
                "ab/abc123.bin",
                "/api",
                null,
                FileScanVerdict.NotScanned,
                SignatureVerdict.Match),
        });

        Assert.False(outcome.IsError);
        Assert.Contains("abc123", outcome.Text, StringComparison.Ordinal);
        Assert.Contains("application/pdf", outcome.Text, StringComparison.Ordinal);
        Assert.Contains("2048", outcome.Text, StringComparison.Ordinal);

        // The content itself never becomes text.
        Assert.DoesNotContain("ab/abc123.bin", outcome.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_success_arm_is_reachable_for_no_failure()
    {
        // Guards the theories above: if 'None' were treated as a failure they would still
        // pass, because they assert what a failure looks like.
        Assert.False(ToolInvocation.Shape(new EngineExecutionResult()).IsError);
    }

    public static TheoryData<ExecutionFailureKind> FailureKinds()
    {
        var data = new TheoryData<ExecutionFailureKind>();

        foreach (var failure in Enum.GetValues<ExecutionFailureKind>())
        {
            if (failure != ExecutionFailureKind.None)
            {
                data.Add(failure);
            }
        }

        return data;
    }
}
