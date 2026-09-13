using System.Text.Json.Nodes;

using MCPiler.Engine.Transform;

using Xunit;

namespace MCPiler.Engine.UnitTests.Transform;

/// <summary>
/// One program per normatively excluded category, expressed as the most plausible attempt.
/// </summary>
/// <remarks>
/// <para>
/// The point of these is not that the categories are absent from the documentation. It is that
/// each attempt hits a stated refusal with a code, so the exclusion is closed rather than
/// merely unmentioned. A category nobody wrote a fixture for is a category nobody knows is
/// excluded.
/// </para>
/// <para>
/// Most are refused by the grammar itself, which is the stronger form: there is no member and
/// no vocabulary entry that could carry them, so nothing needed disabling.
/// </para>
/// </remarks>
public sealed class TransformExclusionTests
{
    [Fact]
    public void An_expression_string_in_an_operation_parameter_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "copy",
            ["source"] = "/name",
            ["target"] = "/query/name",
            ["expression"] = "name.toUpperCase()",
        })));

        Assert.Equal(TransformCodes.UnknownField, finding.Code);
        Assert.Equal(0, finding.Step);
    }

    [Fact]
    public void A_condition_expressed_as_a_string_is_refused()
    {
        // The most plausible expression escape: a condition that reads like one line of code.
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "when",
            ["condition"] = "status == 'active'",
            ["steps"] = new JsonArray(),
        })));

        Assert.Equal(TransformCodes.UnknownField, finding.Code);
        Assert.Equal("/steps/0/condition", finding.Pointer);
        Assert.Equal(0, finding.Step);
    }

    [Fact]
    public void A_predicate_carrying_an_unknown_member_is_refused()
    {
        // A member beside a recognised one looks operative and nothing would read it. That is
        // the shape an escape takes: a parameter some later implementation decides to honour.
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "when",
            ["condition"] = new JsonObject
            {
                ["eq"] = "active",
                ["pointer"] = "/status",
                ["transform"] = "lowercase",
            },
            ["steps"] = new JsonArray(),
        })));

        Assert.Equal(TransformCodes.UnknownField, finding.Code);
    }

    [Fact]
    public void A_connective_whose_operand_is_not_a_list_of_predicates_is_refused()
    {
        // Accepting this as an empty group would make the condition vacuously true, and a
        // conditional that always fires is a conditional nobody notices is broken.
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "when",
            ["condition"] = new JsonObject { ["and"] = "status" },
            ["steps"] = new JsonArray(),
        })));

        Assert.Equal(TransformCodes.UnknownField, finding.Code);
    }

    [Fact]
    public void A_regular_expression_operation_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "replace",
            ["source"] = "/name",
            ["target"] = "/query/name",
            ["pattern"] = "^(\\w+)$",
            ["replacement"] = "$1",
        })));

        Assert.Equal(TransformCodes.UnknownOperation, finding.Code);
        Assert.Equal(0, finding.Step);
    }

    [Fact]
    public void Arithmetic_beyond_type_coercion_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "add",
            ["source"] = "/count",
            ["target"] = "/query/count",
            ["value"] = 1,
        })));

        Assert.Equal(TransformCodes.UnknownOperation, finding.Code);
    }

    [Fact]
    public void A_host_registered_function_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "call",
            ["function"] = "tenant.resolveKey",
            ["target"] = "/headers/x-key",
        })));

        Assert.Equal(TransformCodes.UnknownOperation, finding.Code);
    }

    [Fact]
    public void An_eval_equivalent_operation_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "eval",
            ["script"] = "return args.name;",
            ["target"] = "/query/name",
        })));

        Assert.Equal(TransformCodes.UnknownOperation, finding.Code);
        Assert.Contains("eval", finding.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_culture_dependent_operation_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "sort",
            ["source"] = "/tags",
            ["target"] = "/query/tags",
            ["culture"] = "tr-TR",
        })));

        Assert.Equal(TransformCodes.UnknownOperation, finding.Code);
    }

    [Fact]
    public void An_ambient_source_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "now",
            ["target"] = "/headers/x-request-time",
        })));

        Assert.Equal(TransformCodes.UnknownOperation, finding.Code);
    }

    [Fact]
    public void An_ambient_source_smuggled_into_a_template_is_refused()
    {
        // The one pattern string in the vocabulary is where an ambient source would try to
        // arrive, so its admitted syntax is checked rather than assumed.
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "template",
            ["target"] = "/headers/x-trace",
            ["pattern"] = "req-{uuid()}",
            ["arguments"] = new JsonArray(),
            ["onMissing"] = "skip",
        })));

        Assert.Equal(TransformCodes.TemplatePattern, finding.Code);
        Assert.Equal(0, finding.Step);
        Assert.Equal("/steps/0/pattern", finding.Pointer);
    }

    [Fact]
    public void An_unterminated_placeholder_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(Template(
            "prefix-{name",
            new JsonObject { ["name"] = "name", ["pointer"] = "/name" }))));

        Assert.Equal(TransformCodes.TemplatePattern, finding.Code);
    }

    [Fact]
    public void A_bound_placeholder_is_admitted()
    {
        Assert.Empty(Programs.Validate(Programs.Input(Template(
            "pets/{name}/detail",
            new JsonObject { ["name"] = "name", ["pointer"] = "/name" }))));
    }

    [Fact]
    public void A_template_nested_inside_an_iteration_is_checked_too()
    {
        // A pattern scan that stopped at the top level would leave every nested template
        // unchecked while still reporting a pass for the program that contains it.
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "mapArray",
            ["source"] = "/rows",
            ["target"] = "/body/rows",
            ["maxItems"] = 4,
            ["onMissing"] = "skip",
            ["steps"] = new JsonArray(new JsonObject
            {
                ["op"] = "template",
                ["target"] = "/label",
                ["pattern"] = "{now()}",
                ["arguments"] = new JsonArray(),
                ["onMissing"] = "skip",
            }),
        })));

        Assert.Equal(TransformCodes.TemplatePattern, finding.Code);
        Assert.Equal(0, finding.Step);
        Assert.Equal("/steps/0/steps/0/pattern", finding.Pointer);
    }

    [Fact]
    public void A_literal_shaped_like_a_file_handle_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "setConstant",
            ["target"] = "/parts/upload",
            ["value"] = new string('a', 64),
        })));

        Assert.Equal(TransformCodes.FileHandle, finding.Code);
        Assert.Equal("/steps/0/value", finding.Pointer);
    }

    [Fact]
    public void A_literal_shaped_like_a_wire_file_handle_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "setConstant",
            ["target"] = "/parts/upload",
            ["value"] = new string('A', 43),
        })));

        Assert.Equal(TransformCodes.FileHandle, finding.Code);
        Assert.Equal("/steps/0/value", finding.Pointer);
    }

    [Fact]
    public void An_ordinary_literal_is_not_mistaken_for_a_handle()
    {
        Assert.Empty(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "setConstant",
            ["target"] = "/query/status",
            ["value"] = "available",
        })));
    }

    [Fact]
    public void Coercing_a_file_argument_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(
            Programs.Input(new JsonObject
            {
                ["op"] = "convert",
                ["source"] = "/upload",
                ["target"] = "/query/upload",
                ["to"] = "string",
                ["onMissing"] = "skip",
            }),
            "upload"));

        Assert.Equal(TransformCodes.FileHandle, finding.Code);
        Assert.Equal("/steps/0/source", finding.Pointer);
    }

    [Fact]
    public void Coercing_an_argument_that_is_not_a_file_is_permitted()
    {
        Assert.Empty(Programs.Validate(
            Programs.Input(new JsonObject
            {
                ["op"] = "convert",
                ["source"] = "/count",
                ["target"] = "/query/count",
                ["to"] = "string",
                ["onMissing"] = "skip",
            }),
            "upload"));
    }

    [Theory]
    [InlineData("/headers/content-type")]
    [InlineData("/headers/Content-Type")]
    [InlineData("/headers/CONTENT-TYPE")]
    public void Writing_the_content_type_is_refused(string target)
    {
        // Case matters here only in that it must not: a header name comparison that was
        // ordinal would let one capitalisation through and refuse the rest.
        TransformFinding finding = Programs.Only(Programs.Validate(
            Programs.Input(new JsonObject
            {
                ["op"] = "setConstant",
                ["target"] = target,
                ["value"] = "application/x-www-form-urlencoded",
            })));

        Assert.Equal(TransformCodes.ContentTypeReserved, finding.Code);
        Assert.Equal(0, finding.Step);
    }

    [Fact]
    public void Writing_a_header_whose_name_merely_starts_the_same_way_is_permitted()
    {
        Assert.Empty(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "setConstant",
            ["target"] = "/headers/content-type-hint",
            ["value"] = "json",
        })));
    }

    [Fact]
    public void The_vocabulary_is_fixed_at_nineteen_entries()
    {
        Assert.Equal(StepVocabulary.Size, StepVocabulary.Names.Count);
        Assert.Equal(StepVocabulary.Names.Count, StepVocabulary.Names.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void The_vocabulary_admits_no_operation_reading_an_ambient_source()
    {
        string[] ambient =
            ["now", "date", "time", "random", "uuid", "guid", "env", "environment", "caller", "identity", "session"];

        foreach (string name in ambient)
        {
            Assert.DoesNotContain(name, StepVocabulary.Names, StringComparer.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void The_vocabulary_is_matched_ordinally()
    {
        // A case-insensitive match would make two byte-different programs behave identically,
        // which the format's byte-identity rules depend on not happening.
        Assert.False(StepVocabulary.TryRead("SetConstant", out _));
        Assert.True(StepVocabulary.TryRead("setConstant", out _));
    }

    private static JsonObject Template(string pattern, params JsonObject[] arguments)
        => new()
        {
            ["op"] = "template",
            ["target"] = "/path/name",
            ["pattern"] = pattern,
            ["arguments"] = new JsonArray([.. arguments.Select(static argument => (JsonNode)argument)]),
            ["onMissing"] = "skip",
        };
}
