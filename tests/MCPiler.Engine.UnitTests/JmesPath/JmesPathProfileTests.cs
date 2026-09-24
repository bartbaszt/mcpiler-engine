using System.Text;

using MCPiler.Engine.JmesPath;
using MCPiler.Engine.Runtime.Projection;

using Xunit;

namespace MCPiler.Engine.UnitTests.JmesPath;

/// <summary>
/// The library's evaluation surface over the unchanged evaluator: what it accepts, what it
/// refuses, and the frozen enumeration order profile 1 promises.
/// </summary>
/// <remarks>
/// <para>
/// These tests call <see cref="JmesPathProfile.EvaluatePrepared"/> directly. That is the worker
/// side of the split and it is deliberately reachable from a unit test: the process boundary and
/// the OS confinement are integration facts, and what is being fixed here is the language and
/// serialization contract that both sides depend on.
/// </para>
/// <para>
/// The ordering fixtures are the measured unchanged-package behavior, independently authored.
/// An evaluator upgrade that changes any of them fails here rather than silently redefining
/// profile 1.
/// </para>
/// </remarks>
public sealed class JmesPathProfileTests
{
    private static readonly JmesPathLimits Limits = new(
        MaxExpressionBytes: 4096,
        MaxInputNodes: 65_536,
        MaxInputDepth: 64,
        MaxResultNodes: 65_536,
        MaxResultDepth: 64,
        MaxOutputBytes: 1024 * 1024,
        MaxEvaluationMilliseconds: 10_000);

    [Theory]
    [InlineData("@", """{"a":1}""", """{"a":1}""")]
    [InlineData("a", """{"a":1}""", "1")]
    [InlineData("a.b", """{"a":{"b":42}}""", "42")]
    [InlineData("a[1]", """{"a":[1,2,3]}""", "2")]
    [InlineData("length(@)", "[1,2,3]", "3")]
    [InlineData("[?a > `1`].a", """[{"a":1},{"a":2},{"a":3}]""", "[2,3]")]
    [InlineData("sort(@)", "[3,1,2]", "[1,2,3]")]
    [InlineData("max(@)", "[3,1,2]", "3")]
    [InlineData("join(',', @)", """["a","b"]""", "\"a,b\"")]
    [InlineData("starts_with(a, 'x')", """{"a":"xy"}""", "true")]
    [InlineData("contains(@, `2`)", "[1,2,3]", "true")]
    [InlineData("to_string(@)", "1", "\"1\"")]
    [InlineData("to_number(@)", "\"12\"", "12")]
    [InlineData("not_null(a, b)", """{"b":2}""", "2")]
    [InlineData("type(@)", "[1]", "\"array\"")]
    [InlineData("ceil(@)", "1.2", "2")]
    [InlineData("floor(@)", "1.8", "1")]
    [InlineData("abs(@)", "-3", "3")]
    public void A_standard_projection_produces_the_expected_value(
        string expression,
        string body,
        string expected)
    {
        JmesPathEvaluationResult result = Evaluate(expression, body);

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.Equal(expected, Encoding.UTF8.GetString(result.Output!));
    }

    [Fact]
    public void A_missing_member_resolves_to_json_null()
    {
        Assert.Equal("null", Output("missing", """{"a":1}"""));
        Assert.Equal("null", Output("@.missing", """{"a":1}"""));
    }

    [Fact]
    public void An_explicit_null_literal_is_json_null()
    {
        Assert.Equal("null", Output("`null`", "{}"));
    }

    [Fact]
    public void A_filter_over_an_empty_array_is_an_empty_array()
    {
        Assert.Equal("[]", Output("[?a]", "[]"));
    }

    [Theory]
    [InlineData("foo(")]
    [InlineData("[")]
    [InlineData("{")]
    [InlineData("\"unterminated")]
    [InlineData("a..b")]
    public void Invalid_syntax_is_a_compile_family_failure(string expression)
    {
        JmesPathEvaluationResult result = Evaluate(expression, "{}");

        Assert.False(result.Succeeded);
        Assert.True(
            JmesPathFailureClassifier.IsCompileFamily(result.Failure!.FailureClass),
            $"expected a compile family, got {result.Failure.FailureClass}");
    }

    [Fact]
    public void An_unknown_function_is_refused_rather_than_resolved_ambiently()
    {
        JmesPathEvaluationResult result = Evaluate("regex(@, 'x')", "\"abc\"");

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.CompileUnknownFunction, result.Failure!.FailureClass);
    }

    [Theory]
    [InlineData("env(@)")]
    [InlineData("filesystem(@)")]
    [InlineData("read_file('x')")]
    public void A_lookalike_extension_function_is_an_unknown_function(string expression)
    {
        JmesPathEvaluationResult result = Evaluate(expression, """{"a":1}""");

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.CompileUnknownFunction, result.Failure!.FailureClass);
    }

    [Fact]
    public void An_arity_failure_is_a_compile_family_failure()
    {
        JmesPathEvaluationResult result = Evaluate("sort_by(@)", "[1,2]");

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.CompileInvalidArity, result.Failure!.FailureClass);
    }

    [Fact]
    public void A_type_mismatch_at_runtime_is_not_a_compile_family_failure()
    {
        // The normative distinction: this expression is a valid program that needs an array.
        JmesPathEvaluationResult result = Evaluate("sort(@)", """{"a":1}""");

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.RuntimeInvalidType, result.Failure!.FailureClass);
        Assert.False(JmesPathFailureClassifier.IsCompileFamily(result.Failure.FailureClass));
    }

    [Fact]
    public void An_expression_over_the_declared_byte_budget_is_refused_as_an_expression_failure()
    {
        JmesPathLimits tight = Limits with { MaxExpressionBytes = 8 };

        Assert.True(JmesPathProfile.TryPrepareInput(Encoding.UTF8.GetBytes("{}"), tight, out JmesPathPreparedInput? prepared, out _));

        JmesPathEvaluationResult result = JmesPathProfile.EvaluatePrepared(
            prepared!.Json, "longer_than_eight", tight);

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.ExpressionTooManyBytes, result.Failure!.FailureClass);
    }

    [Fact]
    public void An_expression_at_the_byte_budget_is_accepted()
    {
        Assert.Equal("1", Output("a", """{"a":1}""", Limits with { MaxExpressionBytes = 1 }));
    }

    [Fact]
    public void A_multibyte_expression_is_measured_in_utf8_bytes_not_characters()
    {
        // One character, four bytes. A character count would let it cross a four-byte budget.
        string expression = "\uD83D\uDE00";

        Assert.Equal(4, JmesPathProfile.ExpressionByteCount(expression));

        JmesPathEvaluationResult result = Evaluate(expression, "{}", Limits with { MaxExpressionBytes = 3 });

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.ExpressionTooManyBytes, result.Failure!.FailureClass);
    }

    [Fact]
    public void Wildcard_enumeration_follows_the_canonical_input_order()
    {
        // The heart of the freeze: the unchanged package enumerates in the order it received, so
        // the same set of members reaches the evaluator in one order whatever the source said.
        Assert.Equal(
            "[2,3,1]",
            Output("values(@)", """{"a":2,"m":3,"z":1}"""));

        Assert.Equal(
            "[2,3,1]",
            Output("values(@)", """{"z":1,"a":2,"m":3}"""));

        Assert.Equal(
            "[2,3,1]",
            Output("*", """{"m":3,"z":1,"a":2}"""));
    }

    [Fact]
    public void Nested_wildcard_enumeration_is_deterministic_across_input_orders()
    {
        Assert.Equal(
            Output("obj.*.id", """{"obj":{"a":{"id":2},"z":{"id":1}}}"""),
            Output("obj.*.id", """{"obj":{"z":{"id":1},"a":{"id":2}}}"""));

        Assert.Equal("[2,1]", Output("obj.*.id", """{"obj":{"z":{"id":1},"a":{"id":2}}}"""));
    }

    [Fact]
    public void Keys_orders_by_utf8_bytes_as_the_unchanged_package_does()
    {
        // Measured: keys() sorts by unescaped UTF-8 bytes, so the supplementary-plane name sorts
        // after the BMP private-use name even though ordinal UTF-16 order would place it first.
        Assert.Equal(
            """["a","\uE000","\uD83D\uDE00"]""",
            Output("keys(@)", """{"\uD83D\uDE00":1,"\uE000":2,"a":3}"""));
    }

    [Fact]
    public void A_multiselect_hash_follows_expression_order_not_member_order()
    {
        // Measured unchanged-package behavior, frozen here: the evaluator builds the hash in
        // expression order and a wildcard over it observes that order.
        Assert.Equal("[9,8]", Output("{z2: z, a2: a}.*", """{"z":9,"a":8}"""));
    }

    [Fact]
    public void Merge_wildcard_follows_the_construction_order_the_evaluator_produces()
    {
        // JSON object literals in an expression are backtick-quoted; the expression is frozen
        // because the evaluator's merge enumerates from its last argument.
        Assert.Equal(
            "[3,1,2]",
            Output("""merge(`{"b":1,"a":2}`, `{"c":3}`).*""", "{}"));
    }

    [Fact]
    public void A_result_object_created_by_the_expression_is_serialized_canonically()
    {
        // The evaluator's own serialization follows construction order. Profile 1 canonicalizes
        // the completed result, so member order in the output is the author-visible order.
        Assert.Equal("""{"a":1,"b":2}""", Output("""{b: `2`, a: `1`}""", "{}"));
    }

    [Fact]
    public void Duplicate_members_reach_the_evaluator_and_its_behavior_is_frozen()
    {
        // The profile does not collapse duplicates: it preserves the upstream's member sequence
        // and the unchanged evaluator's handling of it is profile behavior.
        Assert.Equal("""{"a":1,"a":2}""", Output("@", """{"a":1,"a":2}"""));

        Assert.Equal("[1,2]", Output("values(@)", """{"a":1,"a":2}"""));
        Assert.Equal("""["a","a"]""", Output("keys(@)", """{"a":1,"a":2}"""));
    }

    [Fact]
    public void A_result_over_the_output_budget_is_refused_with_its_own_class()
    {
        JmesPathLimits tight = Limits with { MaxOutputBytes = 16 };

        Assert.True(JmesPathProfile.TryPrepareInput(
            Encoding.UTF8.GetBytes("""{"a":"a string longer than sixteen bytes"}"""),
            tight,
            out JmesPathPreparedInput? prepared,
            out _));

        JmesPathEvaluationResult result = JmesPathProfile.EvaluatePrepared(prepared!.Json, "@", tight);

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.OutputTooManyBytes, result.Failure!.FailureClass);
    }

    [Fact]
    public void A_result_over_the_node_budget_is_refused_with_its_own_class()
    {
        JmesPathLimits tight = Limits with { MaxResultNodes = 2 };

        Assert.True(JmesPathProfile.TryPrepareInput(
            Encoding.UTF8.GetBytes("[1,2,3]"), tight, out JmesPathPreparedInput? prepared, out _));

        JmesPathEvaluationResult result = JmesPathProfile.EvaluatePrepared(prepared!.Json, "@", tight);

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.ResultTooManyNodes, result.Failure!.FailureClass);
    }

    [Fact]
    public void Evaluate_prepared_rechecks_the_body_it_received()
    {
        // The worker re-measures rather than trusting the preparation: bytes crossed a boundary.
        JmesPathLimits tight = Limits with { MaxInputNodes = 2 };

        JmesPathEvaluationResult result = JmesPathProfile.EvaluatePrepared(
            Encoding.UTF8.GetBytes("[1,2,3,4]"), "@", tight);

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.InputTooManyNodes, result.Failure!.FailureClass);
    }

    [Fact]
    public void A_body_that_is_not_json_is_refused_before_evaluation()
    {
        Assert.False(JmesPathProfile.TryPrepareInput(
            Encoding.UTF8.GetBytes("not json"), Limits, out _, out JmesPathFailure? failure));
        Assert.Equal(JmesPathFailureClass.InputNotJson, failure!.FailureClass);
    }

    [Theory]
    [InlineData("{'a':1}")]
    [InlineData("{\"a\":1,}")]
    [InlineData("// comment\n{}")]
    public void An_almost_json_body_is_refused(string body)
    {
        Assert.False(JmesPathProfile.TryPrepareInput(
            Encoding.UTF8.GetBytes(body), Limits, out _, out JmesPathFailure? failure));
        Assert.Equal(JmesPathFailureClass.InputNotJson, failure!.FailureClass);
    }

    [Fact]
    public void Non_positive_limits_are_refused_before_anything_is_parsed()
    {
        JmesPathLimits broken = Limits with { MaxInputNodes = 0 };

        Assert.False(JmesPathProfile.TryPrepareInput(
            Encoding.UTF8.GetBytes("{}"), broken, out _, out JmesPathFailure? failure));
        Assert.Equal(JmesPathFailureClass.InternalEvaluatorDefect, failure!.FailureClass);
    }

    private static JmesPathEvaluationResult Evaluate(
        string expression,
        string body,
        JmesPathLimits? limits = null)
    {
        JmesPathLimits effective = limits ?? Limits;

        Assert.True(
            JmesPathProfile.TryPrepareInput(
                Encoding.UTF8.GetBytes(body), effective, out JmesPathPreparedInput? prepared, out JmesPathFailure? failure),
            failure?.Message);

        return JmesPathProfile.EvaluatePrepared(prepared!.Json, expression, effective);
    }

    private static string Output(
        string expression,
        string body,
        JmesPathLimits? limits = null)
    {
        JmesPathEvaluationResult result = Evaluate(expression, body, limits);

        Assert.True(result.Succeeded, result.Failure?.Message);

        return Encoding.UTF8.GetString(result.Output!);
    }
}
