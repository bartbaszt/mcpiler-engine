using System.Text.Json.Nodes;

using MCPiler.Engine.Transform;

using Xunit;

namespace MCPiler.Engine.UnitTests.Transform;

/// <summary>
/// Tier 1, one case per reason code, each asserting the code and the step index.
/// </summary>
/// <remarks>
/// Every case starts from a program that is otherwise valid and breaks exactly one thing. A
/// fixture that is wrong in two ways can pass for the wrong reason, and a gate that refuses
/// for the wrong reason is indistinguishable from one that refuses everything.
/// </remarks>
public sealed class TransformTierOneTests
{
    [Fact]
    public void A_valid_program_produces_no_finding()
    {
        Assert.Empty(Programs.Validate(Programs.Input(Programs.Copy())));
    }

    [Fact]
    public void A_valid_program_needs_no_dry_run_evidence_in_the_manifest()
    {
        // Tiers 2 and 3 belong to the producer. Their absence is not a defect in the artifact,
        // and a consumer that treated it as one would refuse every hand-authored program.
        Assert.Empty(Programs.Validate(Programs.Output(new JsonObject
        {
            ["op"] = "copy",
            ["source"] = "/body/id",
            ["target"] = "/id",
            ["onMissing"] = "skip",
        })));
    }

    [Fact]
    public void An_unsupported_version_is_refused_before_anything_else_is_read()
    {
        JsonObject document = Programs.Input(new JsonObject { ["op"] = "eval" });
        document["transformVersion"] = 2;
        document["script"] = "whatever";

        TransformFinding finding = Programs.Only(Programs.Validate(document));

        // The unknown operation and the unknown envelope member are both present and neither is
        // reported. Under a grammar this build cannot read, a finding about a member's contents
        // would be a confident claim about a document nothing here understands.
        Assert.Equal(TransformCodes.UnsupportedVersion, finding.Code);
        Assert.Equal("/transformVersion", finding.Pointer);
        Assert.Null(finding.Step);
    }

    [Fact]
    public void An_unknown_envelope_member_names_its_path()
    {
        JsonObject document = Programs.Input(Programs.Copy());
        document["script"] = "return 1;";

        TransformFinding finding = Programs.Only(Programs.Validate(document));

        Assert.Equal(TransformCodes.UnknownField, finding.Code);
        Assert.Equal("/script", finding.Pointer);
    }

    [Fact]
    public void An_unknown_step_member_names_its_path_and_step()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(
            Programs.Copy(),
            new JsonObject
            {
                ["op"] = "copy",
                ["source"] = "/id",
                ["target"] = "/query/id",
                ["regex"] = "^a.*z$",
            })));

        Assert.Equal(TransformCodes.UnknownField, finding.Code);
        Assert.Equal("/steps/1/regex", finding.Pointer);
        Assert.Equal(1, finding.Step);
    }

    [Fact]
    public void An_operation_outside_the_vocabulary_names_the_step_and_the_value()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(
            Programs.Copy(),
            new JsonObject { ["op"] = "eval" })));

        Assert.Equal(TransformCodes.UnknownOperation, finding.Code);
        Assert.Equal(1, finding.Step);
        Assert.Contains("eval", finding.Message, StringComparison.Ordinal);
        Assert.Equal("/steps/1/op", finding.Pointer);
    }

    [Fact]
    public void An_operation_that_is_not_a_string_is_refused_rather_than_thrown()
    {
        // A program arrives inside an artifact this process did not author. Asking a number for
        // its string value would turn a validation result into a crash at load.
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(
            new JsonObject { ["op"] = 5 })));

        Assert.Equal(TransformCodes.UnknownOperation, finding.Code);
    }

    [Theory]
    [InlineData("direction")]
    [InlineData("base")]
    public void An_envelope_discriminator_that_is_not_a_string_is_refused_rather_than_thrown(string member)
    {
        JsonObject document = Programs.Input(Programs.Copy());
        document[member] = new JsonObject();

        TransformFinding finding = Programs.Only(Programs.Validate(document));

        Assert.Equal(TransformCodes.UnknownField, finding.Code);
        Assert.Equal("/" + member, finding.Pointer);
    }

    [Fact]
    public void A_program_declaring_no_limits_block_is_refused()
    {
        JsonObject document = Programs.Input(Programs.Copy());
        document.Remove("limits");

        TransformFinding finding = Programs.Only(Programs.Validate(document));

        Assert.Equal(TransformCodes.UnknownField, finding.Code);
        Assert.Equal("/limits", finding.Pointer);
    }

    [Theory]
    [InlineData("maxSteps")]
    [InlineData("maxDepth")]
    [InlineData("maxNodes")]
    [InlineData("maxOutputBytes")]
    [InlineData("maxArrayFanout")]
    public void A_program_declaring_no_bound_is_refused(string bound)
    {
        JsonObject document = Programs.Input(Programs.Copy());
        ((JsonObject)document["limits"]!).Remove(bound);

        TransformFinding finding = Programs.Only(Programs.Validate(document));

        Assert.Equal(TransformCodes.MissingBound, finding.Code);
        Assert.Equal("/limits/" + bound, finding.Pointer);
    }

    [Theory]
    [InlineData("mapArray", "maxItems")]
    [InlineData("mapObject", "maxEntries")]
    [InlineData("limitArray", "maxItems")]
    public void An_iteration_without_its_bound_is_refused_naming_the_step(string operation, string bound)
    {
        var step = new JsonObject
        {
            ["op"] = operation,
            ["source"] = "/rows",
            ["target"] = "/body/rows",
            ["onMissing"] = "skip",
        };

        if (operation != "limitArray")
        {
            step["steps"] = new JsonArray();
        }

        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(Programs.Copy(), step)));

        Assert.Equal(TransformCodes.MissingBound, finding.Code);
        Assert.Equal(1, finding.Step);
        Assert.Equal("/steps/1/" + bound, finding.Pointer);
    }

    [Fact]
    public void A_malformed_pointer_is_refused()
    {
        TransformFinding finding = Programs.Only(
            Programs.Validate(Programs.Input(Programs.Copy(source: "body/name"))));

        Assert.Equal(TransformCodes.PointerSyntax, finding.Code);
        Assert.Equal(0, finding.Step);
    }

    [Fact]
    public void A_pointer_whose_escape_is_malformed_is_refused()
    {
        TransformFinding finding = Programs.Only(
            Programs.Validate(Programs.Input(Programs.Copy(source: "/a~2b"))));

        Assert.Equal(TransformCodes.PointerSyntax, finding.Code);
    }

    [Fact]
    public void An_input_program_writing_to_the_response_status_is_refused()
    {
        TransformFinding finding = Programs.Only(
            Programs.Validate(Programs.Input(Programs.Copy(target: "/status"))));

        Assert.Equal(TransformCodes.PointerRoot, finding.Code);
        Assert.Equal(0, finding.Step);
        Assert.Contains("/status", finding.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_output_program_reading_from_the_request_parts_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Output(new JsonObject
        {
            ["op"] = "copy",
            ["source"] = "/parts/upload",
            ["target"] = "/upload",
            ["onMissing"] = "skip",
        })));

        Assert.Equal(TransformCodes.PointerRoot, finding.Code);
    }

    [Fact]
    public void An_input_program_reading_a_request_part_as_if_it_were_an_argument_is_refused()
    {
        // The input direction's source is the agent argument document. A part selector there is
        // not a narrower read of the same document, it is a different document the step has no
        // business seeing.
        TransformFinding finding = Programs.Only(
            Programs.Validate(Programs.Input(Programs.Copy(source: "/headers/authorization"))));

        Assert.Equal(TransformCodes.PointerRoot, finding.Code);
    }

    [Fact]
    public void An_argument_named_like_a_part_but_not_rooted_at_one_is_permitted()
    {
        // "/bodyguard" is an ordinary agent argument. Refusing it would make the root rule a
        // prefix match, which would silently forbid legitimate argument names.
        Assert.Empty(Programs.Validate(Programs.Input(Programs.Copy(source: "/bodyguard"))));
    }

    [Fact]
    public void A_nested_step_may_address_the_item_it_iterates()
    {
        // The evaluator rebinds the document root to the item, so an item-relative pointer is
        // the whole point of a nested step list. A rule that admitted only the empty pointer
        // would refuse every useful iteration while still reporting a pass for an empty one.
        Assert.Empty(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "mapArray",
            ["source"] = "/rows",
            ["target"] = "/body/rows",
            ["maxItems"] = 20,
            ["onMissing"] = "skip",
            ["steps"] = new JsonArray(new JsonObject
            {
                ["op"] = "move",
                ["source"] = "/raw",
                ["target"] = "/value",
                ["onMissing"] = "skip",
            }),
        })));
    }

    [Fact]
    public void A_nested_step_may_not_address_a_request_part()
    {
        // Inside an item there are no request parts. A step reading "/headers" there would be
        // reading whatever member the item happens to have, which is accidental agreement.
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(
            Programs.Copy(),
            new JsonObject
            {
                ["op"] = "mapArray",
                ["source"] = "/rows",
                ["target"] = "/body/rows",
                ["maxItems"] = 20,
                ["onMissing"] = "skip",
                ["steps"] = new JsonArray(new JsonObject
                {
                    ["op"] = "copy",
                    ["source"] = "/headers/authorization",
                    ["target"] = "/leak",
                    ["onMissing"] = "skip",
                }),
            })));

        Assert.Equal(TransformCodes.PointerRoot, finding.Code);
        Assert.Equal(1, finding.Step);
        Assert.Equal("/steps/1/steps/0", finding.Pointer);
    }

    [Fact]
    public void A_template_argument_pointer_is_root_checked_like_any_other_read()
    {
        // Template arguments are read exactly like a step source. Leaving them out would make
        // template the one operation whose reads nothing checks.
        TransformFinding finding = Programs.Only(Programs.Validate(Programs.Input(new JsonObject
        {
            ["op"] = "template",
            ["target"] = "/query/q",
            ["pattern"] = "{token}",
            ["onMissing"] = "skip",
            ["arguments"] = new JsonArray(new JsonObject
            {
                ["name"] = "token",
                ["pointer"] = "/headers/authorization",
            }),
        })));

        Assert.Equal(TransformCodes.PointerRoot, finding.Code);
    }

    [Fact]
    public void A_static_step_count_above_the_effective_limit_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(
            Programs.Input(Outer(maxItems: 50, Item())),
            Programs.Ceiling with { MaxSteps = 8 }));

        Assert.Equal(TransformCodes.StepLimit, finding.Code);
        Assert.Equal("/limits/maxSteps", finding.Pointer);
    }

    [Fact]
    public void A_static_depth_above_the_effective_limit_is_refused()
    {
        TransformFinding finding = Programs.Only(Programs.Validate(
            Programs.Input(Outer(maxItems: 2, Inner(maxItems: 2, Item()))),
            Programs.Ceiling with { MaxDepth = 1 }));

        Assert.Equal(TransformCodes.StaticDepth, finding.Code);
        Assert.Equal("/limits/maxDepth", finding.Pointer);
    }

    [Fact]
    public void A_static_fan_out_above_the_effective_limit_is_refused()
    {
        JsonObject document = Programs.Input(Outer(maxItems: 20, Inner(maxItems: 20, Item())));
        document["limits"] = Programs.Limits(steps: 1000);

        TransformFinding finding = Programs.Only(Programs.Validate(
            document,
            Programs.Ceiling with { MaxSteps = 1000, MaxArrayFanout = 32 }));

        // Neither bound is above the ceiling on its own; their product is. That is the whole
        // reason a static estimate exists rather than a per-step comparison.
        Assert.Equal(TransformCodes.StaticFanout, finding.Code);
        Assert.Contains("400", finding.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_effective_limit_is_the_smaller_of_the_program_and_the_policy()
    {
        JsonObject document = Programs.Input(Outer(maxItems: 20, Item()));

        // The program declares room for this fan-out and the policy does not. The smaller
        // governs, so the program is measured against the policy rather than against itself.
        Assert.Empty(Programs.Validate(document, Programs.Ceiling with { MaxArrayFanout = 20 }));

        TransformFinding finding = Programs.Only(
            Programs.Validate(document, Programs.Ceiling with { MaxArrayFanout = 19 }));

        Assert.Equal(TransformCodes.StaticFanout, finding.Code);
    }

    [Fact]
    public void A_program_declaring_more_than_the_policy_allows_is_clamped_rather_than_refused()
    {
        JsonObject document = Programs.Input(Programs.Copy());
        document["limits"] = Programs.Limits(fanout: 100_000);

        // Choosing the values and refusing an over-declared program is the producer's part.
        // The consumer's part is that a transform never raises a limit the policy declares,
        // and clamping discharges it. Refusing here would make a manifest that runs safely
        // under a tight policy fail to mount under that same policy.
        Assert.Empty(Programs.Validate(document, Programs.Ceiling with { MaxArrayFanout = 8 }));
    }

    /// <summary>A top-level iteration reading an argument array into the request body.</summary>
    private static JsonObject Outer(int maxItems, JsonObject nested)
        => Iteration("/rows", "/body/rows", maxItems, nested);

    /// <summary>An iteration nested inside another, addressing the item it was handed.</summary>
    private static JsonObject Inner(int maxItems, JsonObject nested)
        => Iteration("/cells", "/cells", maxItems, nested);

    /// <summary>A step addressing the item it is handed.</summary>
    private static JsonObject Item() => Programs.Copy(source: "/raw", target: "/value");

    private static JsonObject Iteration(string source, string target, int maxItems, JsonObject nested)
        => new()
        {
            ["op"] = "mapArray",
            ["source"] = source,
            ["target"] = target,
            ["maxItems"] = maxItems,
            ["onMissing"] = "skip",
            ["steps"] = new JsonArray(nested),
        };
}
