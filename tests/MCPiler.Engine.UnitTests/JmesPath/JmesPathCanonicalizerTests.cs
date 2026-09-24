using System.Text;

using MCPiler.Engine.JmesPath;
using MCPiler.Engine.Runtime.Projection;

using Xunit;

namespace MCPiler.Engine.UnitTests.JmesPath;

/// <summary>
/// The profile's canonical form: member order, duplicates, lexical numbers and declared bounds.
/// </summary>
/// <remarks>
/// These are the properties the freeze depends on. Wildcard and <c>values()</c> enumeration is
/// observable, so two spellings of the same object must reach the evaluator in one order; a
/// number's spelling is part of the value a caller reads back, so it must survive; and a value
/// that does not fit a declared bound must be refused rather than truncated.
/// </remarks>
public sealed class JmesPathCanonicalizerTests
{
    private static readonly JmesPathLimits Bounds = new(
        MaxExpressionBytes: 4096,
        MaxInputNodes: 1024,
        MaxInputDepth: 16,
        MaxResultNodes: 1024,
        MaxResultDepth: 16,
        MaxOutputBytes: 64 * 1024,
        MaxEvaluationMilliseconds: 10_000);

    [Theory]
    [InlineData("""{"z":1,"a":2,"m":3}""", """{"a":2,"m":3,"z":1}""")]
    [InlineData("""{"a":2,"m":3,"z":1}""", """{"a":2,"m":3,"z":1}""")]
    [InlineData("""{"m":3,"z":1,"a":2}""", """{"a":2,"m":3,"z":1}""")]
    public void Object_members_are_emitted_in_ordinal_name_order(string body, string expected)
    {
        Assert.Equal(expected, Canonical(body));
    }

    [Fact]
    public void Member_order_is_ordinal_over_utf16_code_units()
    {
        // Ordinal comparison over UTF-16 code units places the supplementary-plane name before
        // the BMP private-use name, because its first surrogate (0xD83D) precedes 0xE000. This is
        // deliberately not the order keys() produces: the evaluator sorts keys by UTF-8 bytes.
        string body = """{"\uD83D\uDE00":1,"\uE000":2,"a":3}""";

        string canonical = Canonical(body);

        Assert.Equal("""{"a":3,"\uD83D\uDE00":1,"\uE000":2}""", canonical);

        int a = canonical.IndexOf("\"a\"", StringComparison.Ordinal);
        int supplementary = canonical.IndexOf("\"\\uD83D\\uDE00\"", StringComparison.Ordinal);
        int bmp = canonical.IndexOf("\"\\uE000\"", StringComparison.Ordinal);

        Assert.True(a < supplementary, "basic latin sorts first");
        Assert.True(supplementary < bmp, "the surrogate pair precedes U+E000 as UTF-16 code units");
    }

    [Fact]
    public void Array_order_is_preserved()
    {
        Assert.Equal("[3,1,2]", Canonical("[3,1,2]"));
    }

    [Fact]
    public void Nested_objects_are_reordered_at_every_depth()
    {
        Assert.Equal(
            """{"a":{"b":{"c":[{"d":1,"e":2}]}}}""",
            Canonical("""{"a":{"b":{"c":[{"e":2,"d":1}]}}}"""));
    }

    [Fact]
    public void Duplicate_member_names_are_preserved_in_source_relative_order()
    {
        // Two values with one name are not a value this pipeline may collapse: the upstream
        // sent both, and the evaluator's own duplicate handling is the profile's behavior.
        Assert.Equal("""{"a":1,"a":2,"b":3}""", Canonical("""{"a":1,"a":2,"b":3}"""));
    }

    [Theory]
    [InlineData("1", "1")]
    [InlineData("1.0", "1.0")]
    [InlineData("1e2", "1e2")]
    [InlineData("1E+2", "1E+2")]
    [InlineData("-0", "-0")]
    [InlineData("0.30000000000000004", "0.30000000000000004")]
    [InlineData("18446744073709551616", "18446744073709551616")]
    [InlineData("1e309", "1e309")]
    public void A_number_keeps_its_lexical_token(string body, string expected)
    {
        Assert.Equal(expected, Canonical(body));
    }

    [Fact]
    public void A_string_is_re_encoded_from_its_parsed_value()
    {
        // Two source spellings of one string are one value, and both produce the same bytes.
        Assert.Equal(Canonical("""{"k":"\u00e9"}"""), Canonical("""{"k":"é"}"""));
    }

    [Fact]
    public void Escaping_is_deterministic()
    {
        string canonical = Canonical("""{"u":"\u00e9\uD83D\uDE00","h":"<&>"}""");

        Assert.Contains(@"\u00E9", canonical, StringComparison.Ordinal);
        Assert.Contains(@"\uD83D\uDE00", canonical, StringComparison.Ordinal);
        Assert.Contains(@"\u003C", canonical, StringComparison.Ordinal);
        Assert.Contains(@"\u0026", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public void A_body_over_the_node_budget_is_refused_as_an_input_failure()
    {
        try
        {
            JmesPathLimits tight = Bounds with { MaxInputNodes = 3 };

            Assert.False(JmesPathProfile.TryPrepareInput(
                Encoding.UTF8.GetBytes("[1,2,3,4,5]"), tight, out _, out JmesPathFailure? failure));
            Assert.Equal(JmesPathFailureClass.InputTooManyNodes, failure!.FailureClass);
        }
        finally
        {
        }
    }

    [Fact]
    public void A_body_over_the_depth_budget_is_refused_as_an_input_failure()
    {
        JmesPathLimits tight = Bounds with { MaxInputDepth = 3 };

        Assert.False(JmesPathProfile.TryPrepareInput(
            Encoding.UTF8.GetBytes("[[[[1]]]]"), tight, out _, out JmesPathFailure? failure));
        Assert.Equal(JmesPathFailureClass.InputTooDeep, failure!.FailureClass);
    }

    [Fact]
    public void A_body_at_the_depth_budget_is_accepted()
    {
        // Three arrays and the scalar behind them: the scalar sits at depth four.
        JmesPathLimits exactly = Bounds with { MaxInputDepth = 4 };

        Assert.True(JmesPathProfile.TryPrepareInput(
            Encoding.UTF8.GetBytes("[[[1]]]"), exactly, out JmesPathPreparedInput? prepared, out JmesPathFailure? failure),
            failure?.Message);

        Assert.Equal(4, prepared!.Metrics.Depth);
    }

    [Fact]
    public void A_result_over_the_node_budget_is_refused_as_a_result_failure()
    {
        JmesPathLimits tight = Bounds with { MaxResultNodes = 2 };

        Assert.False(JmesPathProfile.TryVerifyResult(
            Encoding.UTF8.GetBytes("[1,2,3]"), tight, out _, out _, out JmesPathFailure? failure));
        Assert.Equal(JmesPathFailureClass.ResultTooManyNodes, failure!.FailureClass);
    }

    [Fact]
    public void A_result_over_the_byte_budget_is_refused_without_truncation()
    {
        JmesPathLimits tight = Bounds with { MaxOutputBytes = 8 };

        Assert.False(JmesPathProfile.TryVerifyResult(
            Encoding.UTF8.GetBytes("""{"longer":"than eight bytes"}"""),
            tight,
            out _,
            out _,
            out JmesPathFailure? failure));
        Assert.Equal(JmesPathFailureClass.OutputTooManyBytes, failure!.FailureClass);
    }

    [Fact]
    public void A_non_canonical_result_frame_is_a_worker_failure()
    {
        // The parent validates independence: a frame that is not the canonical form of the value
        // it reports means the two sides disagree about the same value.
        Assert.True(JmesPathProfile.TryVerifyResult(
            Encoding.UTF8.GetBytes("""{"a":1,"b":2}"""), Bounds, out _, out _, out _));

        Assert.False(JmesPathProfile.TryVerifyResult(
            Encoding.UTF8.GetBytes("""{"b":2,"a":1}"""), Bounds, out _, out _, out JmesPathFailure? failure));
        Assert.Equal(JmesPathFailureClass.OperationalWorkerFailure, failure!.FailureClass);
    }

    [Fact]
    public void A_result_frame_that_is_not_json_is_a_worker_failure()
    {
        Assert.False(JmesPathProfile.TryVerifyResult(
            Encoding.UTF8.GetBytes("not json"), Bounds, out _, out _, out JmesPathFailure? failure));
        Assert.Equal(JmesPathFailureClass.OperationalWorkerFailure, failure!.FailureClass);
    }

    [Fact]
    public void Metrics_count_nodes_and_depth_with_the_root_at_one()
    {
        Assert.True(JmesPathProfile.TryPrepareInput(
            Encoding.UTF8.GetBytes("""{"a":[1,2]}"""), Bounds, out JmesPathPreparedInput? prepared, out _));

        Assert.Equal(4, prepared!.Metrics.Nodes);
        Assert.Equal(3, prepared.Metrics.Depth);
    }

    [Fact]
    public void A_scalar_body_measures_one_node_and_depth_one()
    {
        Assert.True(JmesPathProfile.TryPrepareInput(
            Encoding.UTF8.GetBytes("1"), Bounds, out JmesPathPreparedInput? prepared, out _));

        Assert.Equal(1, prepared!.Metrics.Nodes);
        Assert.Equal(1, prepared.Metrics.Depth);
    }

    private static string Canonical(string body)
    {
        Assert.True(
            JmesPathProfile.TryPrepareInput(Encoding.UTF8.GetBytes(body), Bounds, out JmesPathPreparedInput? prepared, out JmesPathFailure? failure),
            failure?.Message);

        return Encoding.UTF8.GetString(prepared!.Json);
    }
}
