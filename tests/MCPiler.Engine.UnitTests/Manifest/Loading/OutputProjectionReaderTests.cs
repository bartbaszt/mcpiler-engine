using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Runtime.Projection;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Loading;

/// <summary>
/// Format 4 replaced the output program member with a closed projection union, and these are
/// the shapes the reader must accept, refuse and locate.
/// </summary>
/// <remarks>
/// The reader is the only component that decides what a projection's declared shape is, so the
/// union's closure is asserted here rather than inferred from the validator's behaviour: a
/// document that mixes a program and an expression must not reach a model that has to guess
/// which one it is.
/// </remarks>
public sealed class OutputProjectionReaderTests
{
    private static JmesPathLimits Limits { get; } = JmesPathLimits.AuthoringDefault;

    [Fact]
    public void A_jmespath_projection_carries_its_version_expression_and_seven_limits()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var section = SectionReader.ReadAgentSurface(Json(Projection(JmesPath())), diagnostics);

        Assert.DoesNotContain(diagnostics, static diagnostic => diagnostic.IsError);

        var binding = Assert.IsType<TransformedHttpBinding>(section!.Operations[0].Binding);
        var projection = Assert.IsType<ManifestOutputProjection.JmesPathVariant>(binding.Output);

        Assert.Equal(1, projection.LanguageVersion);
        Assert.Equal("@", projection.Expression);
        Assert.Equal(Limits, projection.Limits);
    }

    [Fact]
    public void A_transform_program_projection_carries_the_program_verbatim()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var section = SectionReader.ReadAgentSurface(
            Json(Projection("""{"kind": "transformProgram", "program": {"transformVersion": 1, "steps": []}}""")),
            diagnostics);

        Assert.DoesNotContain(diagnostics, static diagnostic => diagnostic.IsError);

        var binding = Assert.IsType<TransformedHttpBinding>(section!.Operations[0].Binding);
        var projection = Assert.IsType<ManifestOutputProjection.TransformProgramVariant>(binding.Output);

        Assert.Equal(1, projection.Program["transformVersion"]!.GetValue<int>());
    }

    [Fact]
    public void An_absent_projection_is_passthrough()
    {
        var diagnostics = new List<ManifestDiagnostic>();
        var section = SectionReader.ReadAgentSurface(
            Json(
                """
                {
                  "operations": [
                    {
                      "slug": "a", "name": "A",
                      "binding": { "type": "transformedHttp", "base": { "operation": "GET /pets" } }
                    }
                  ]
                }
                """),
            diagnostics);

        Assert.DoesNotContain(diagnostics, static diagnostic => diagnostic.IsError);

        var binding = Assert.IsType<TransformedHttpBinding>(section!.Operations[0].Binding);

        Assert.Null(binding.Output);
    }

    [Fact]
    public void A_mixed_projection_is_refused_by_the_closed_shape()
    {
        var diagnostics = new List<ManifestDiagnostic>();

        SectionReader.ReadAgentSurface(
            Json(Projection($$"""{"kind": "jmespath", "program": {"steps": []}, "languageVersion": 1, "expression": "@", "limits": {{LimitsObject()}}}""")),
            diagnostics);

        Assert.Contains(
            diagnostics,
            static diagnostic => diagnostic.Code == ManifestDiagnosticCodes.UnknownMember
                && diagnostic.Pointer!.Contains("program", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unknown_projection_kind_is_refused()
    {
        var diagnostics = new List<ManifestDiagnostic>();

        SectionReader.ReadAgentSurface(
            Json(Projection("""{"kind": "jq"}""")),
            diagnostics);

        Assert.Contains(
            diagnostics,
            static diagnostic => diagnostic.Code == ManifestDiagnosticCodes.BindingTypeUnknown
                && diagnostic.Pointer!.Contains("kind", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("maxExpressionBytes")]
    [InlineData("maxInputNodes")]
    [InlineData("maxInputDepth")]
    [InlineData("maxResultNodes")]
    [InlineData("maxResultDepth")]
    [InlineData("maxOutputBytes")]
    [InlineData("maxEvaluationMilliseconds")]
    public void A_missing_limit_is_refused_by_name(string member)
    {
        var limits = (JsonObject)JsonNode.Parse(LimitsObject())!;
        limits.Remove(member);

        var diagnostics = new List<ManifestDiagnostic>();

        SectionReader.ReadAgentSurface(
            Json(Projection($$"""{"kind": "jmespath", "languageVersion": 1, "expression": "@", "limits": {{limits.ToJsonString()}}}""")),
            diagnostics);

        Assert.Contains(
            diagnostics,
            diagnostic => diagnostic.Code == ManifestDiagnosticCodes.MemberRequired
                && diagnostic.Pointer!.EndsWith(member, StringComparison.Ordinal));
    }

    [Fact]
    public void A_non_positive_limit_is_refused()
    {
        var limits = (JsonObject)JsonNode.Parse(LimitsObject())!;
        limits["maxInputNodes"] = 0;

        var diagnostics = new List<ManifestDiagnostic>();

        SectionReader.ReadAgentSurface(
            Json(Projection($$"""{"kind": "jmespath", "languageVersion": 1, "expression": "@", "limits": {{limits.ToJsonString()}}}""")),
            diagnostics);

        Assert.Contains(
            diagnostics,
            diagnostic => diagnostic.Code == ManifestDiagnosticCodes.LimitOutOfRange
                && diagnostic.Pointer!.EndsWith("maxInputNodes", StringComparison.Ordinal));
    }

    [Fact]
    public void A_non_object_limits_member_is_refused_with_its_pointer()
    {
        var diagnostics = new List<ManifestDiagnostic>();

        SectionReader.ReadAgentSurface(
            Json(Projection("""{"kind": "jmespath", "languageVersion": 1, "expression": "@", "limits": 7}""")),
            diagnostics);

        Assert.Contains(
            diagnostics,
            diagnostic => diagnostic.Pointer!.Contains("limits", StringComparison.Ordinal));
    }

    private static string Projection(string projection)
        => $$"""
        {
          "operations": [
            {
              "slug": "a", "name": "A",
              "binding": {
                "type": "transformedHttp",
                "base": { "operation": "GET /pets" },
                "outputProjection": {{projection}}
              }
            }
          ]
        }
        """;

    private static string JmesPath()
        => $$"""{"kind": "jmespath", "languageVersion": 1, "expression": "@", "limits": {{LimitsObject()}}}""";

    private static string LimitsObject()
        => $$"""
        {
          "maxExpressionBytes": {{Limits.MaxExpressionBytes}},
          "maxInputNodes": {{Limits.MaxInputNodes}},
          "maxInputDepth": {{Limits.MaxInputDepth}},
          "maxResultNodes": {{Limits.MaxResultNodes}},
          "maxResultDepth": {{Limits.MaxResultDepth}},
          "maxOutputBytes": {{Limits.MaxOutputBytes}},
          "maxEvaluationMilliseconds": {{Limits.MaxEvaluationMilliseconds}}
        }
        """;

    private static JsonNode Json(string text) => JsonNode.Parse(text)!;
}
