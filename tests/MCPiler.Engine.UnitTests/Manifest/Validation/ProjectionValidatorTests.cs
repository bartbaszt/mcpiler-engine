using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Runtime.Projection;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest.Validation;

/// <summary>
/// A JMESPath projection is validated against the compiled ceiling and the profile, never
/// against a guess.
/// </summary>
/// <remarks>
/// <para>
/// The check has two independent refusals and both matter. A limit above the compiled
/// <c>jmesPathCeiling</c> is a widening attempt and is refused even though the expression itself
/// may be perfect; an expression validity check that cannot run in confinement is refused
/// rather than performed in process, because a manifest admitted without its expression ever
/// being compiled fails at the first call.
/// </para>
/// <para>
/// The validator port is supplied by the host that can confine the evaluation, so these tests
/// pass a stub that records what it was asked. What the real worker does with the expression is
/// the worker's own suite's subject.
/// </para>
/// </remarks>
public sealed class ProjectionValidatorTests
{
    private static readonly ManifestFormatVersion Version = new(0, 3);

    private static JmesPathLimits Declared() => JmesPathLimits.AuthoringDefault;

    [Fact]
    public void A_valid_projection_inside_the_ceiling_produces_no_diagnostic()
    {
        var diagnostics = ManifestValidator.Validate(Manifest(Declared()), Stub(ProjectionExpressionValidity.Valid));

        Assert.Empty(diagnostics);
    }

    [Fact]
    public void A_projection_with_no_validator_is_refused_rather_than_interpreted()
    {
        var codes = Codes(ManifestValidator.Validate(Manifest(Declared()), expressionValidator: null));

        Assert.Equal([ManifestDiagnosticCodes.ProjectionInvalid], codes);
    }

    [Fact]
    public void An_unavailable_validator_refuses_the_projection()
    {
        var diagnostics = ManifestValidator.Validate(
            Manifest(Declared()),
            Stub(ProjectionExpressionValidity.Unavailable(new JmesPathFailure(
                JmesPathFailureClass.OperationalConfinementUnavailable,
                "no confinement here"))));

        var diagnostic = Assert.Single(diagnostics);

        Assert.Equal(ManifestDiagnosticCodes.ProjectionInvalid, diagnostic.Code);
        Assert.Contains("no confinement here", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_invalid_expression_carries_the_profile_reason()
    {
        var diagnostics = ManifestValidator.Validate(
            Manifest(Declared()),
            Stub(ProjectionExpressionValidity.Invalid(new JmesPathFailure(
                JmesPathFailureClass.CompileSyntax,
                "Unexpected token at position 3."))));

        var diagnostic = Assert.Single(diagnostics);

        Assert.Equal(ManifestDiagnosticCodes.ProjectionInvalid, diagnostic.Code);
        Assert.Equal("jmespath-compile-syntax", diagnostic.ProgramCode);
        Assert.EndsWith("/outputProjection/expression", diagnostic.Pointer, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unsupported_language_version_is_refused_by_name()
    {
        var diagnostics = ManifestValidator.Validate(
            Manifest(Declared(), languageVersion: 2),
            Stub(ProjectionExpressionValidity.Valid));

        var diagnostic = Assert.Single(diagnostics);

        Assert.Equal(ManifestDiagnosticCodes.ProjectionVersionUnsupported, diagnostic.Code);
        Assert.Contains("version 2", diagnostic.Message, StringComparison.Ordinal);
        Assert.EndsWith("/outputProjection/languageVersion", diagnostic.Pointer, StringComparison.Ordinal);
    }

    [Fact]
    public void A_declared_limit_above_the_ceiling_is_refused_by_dimension()
    {
        // The input-node ceiling is narrowed below what the projection declares, so the two
        // disagree in exactly one dimension.
        var policy = new PolicySection(
            new Uri("https://api.example.com/v1"),
            JmesPathCeiling: JmesPathCeiling.Default with { MaxInputNodes = 10 });

        var diagnostics = ManifestValidator.Validate(
            Manifest(JmesPathLimits.AuthoringDefault, policy: policy),
            Stub(ProjectionExpressionValidity.Valid));

        var diagnostic = Assert.Single(diagnostics);

        Assert.Equal(ManifestDiagnosticCodes.ProjectionLimitOutOfRange, diagnostic.Code);
        Assert.Contains("MaxInputNodes", diagnostic.Message, StringComparison.Ordinal);
        Assert.EndsWith("/outputProjection/limits/MaxInputNodes", diagnostic.Pointer, StringComparison.Ordinal);
    }

    [Fact]
    public void A_limit_breach_is_reported_without_running_the_expression()
    {
        // Nothing about a widening attempt is a statement about the expression, so asking the
        // validator to compile it would be work whose answer the manifest already refuses.
        var policy = new PolicySection(
            new Uri("https://api.example.com/v1"),
            JmesPathCeiling: JmesPathCeiling.Default with { MaxExpressionBytes = 1 });

        RecordingValidator recorder = new(ProjectionExpressionValidity.Valid);

        ManifestValidator.Validate(Manifest(JmesPathLimits.AuthoringDefault, policy: policy), recorder);

        Assert.Equal(0, recorder.Calls);
    }

    [Fact]
    public void Every_exceeding_dimension_is_reported_not_only_the_first()
    {
        var policy = new PolicySection(
            new Uri("https://api.example.com/v1"),
            JmesPathCeiling: JmesPathCeiling.Default with
            {
                MaxInputNodes = 1,
                MaxResultNodes = 1,
            });

        var diagnostics = ManifestValidator.Validate(
            Manifest(JmesPathLimits.AuthoringDefault, policy: policy),
            Stub(ProjectionExpressionValidity.Valid));

        Assert.Equal(2, diagnostics.Count);
        Assert.All(diagnostics, diagnostic => Assert.Equal(ManifestDiagnosticCodes.ProjectionLimitOutOfRange, diagnostic.Code));
    }

    [Fact]
    public void A_transform_program_projection_is_not_sent_to_the_expression_validator()
    {
        // The union's two kinds are checked by different authorities: a program by the
        // transformation validator, an expression by the projection validator. Asking the
        // expression validator about a program would be a classification of something that is
        // not an expression.
        RecordingValidator recorder = new(ProjectionExpressionValidity.Valid);

        ManifestValidator.Validate(Manifest(Declared(), transformProgram: true), recorder);

        Assert.Equal(0, recorder.Calls);
    }

    private static ManifestDocument Manifest(
        JmesPathLimits limits,
        int languageVersion = 1,
        bool transformProgram = false,
        PolicySection? policy = null)
    {
        ManifestOutputProjection projection = transformProgram
            ? new ManifestOutputProjection.TransformProgramVariant(new System.Text.Json.Nodes.JsonObject
            {
                ["transformVersion"] = 1,
                ["direction"] = "output",
                ["base"] = "empty",
                ["steps"] = new System.Text.Json.Nodes.JsonArray(),
            })
            : new ManifestOutputProjection.JmesPathVariant(languageVersion, "@", limits);

        return new ManifestDocument(
            FormatVersion: Version,
            Server: new ServerSection(Name: "Example API"),
            Policy: policy ?? new PolicySection(new Uri("https://api.example.com/v1")),
            Operations: new OperationsSection([new ManifestOperation(Key: "GET /pets", Method: "GET", Path: "/pets")]),
            AgentSurface: new AgentSurfaceSection(
            [
                new AgentOperationEntry(
                    Slug: "list-pets",
                    Name: "list-pets",
                    Binding: new TransformedHttpBinding(new HttpBinding("GET /pets"), Output: projection)),
            ]));
    }

    private static IReadOnlyList<string> Codes(IReadOnlyList<ManifestDiagnostic> diagnostics)
        => [.. diagnostics.Select(static diagnostic => diagnostic.Code)];

    private static IProjectionExpressionValidator Stub(ProjectionExpressionValidity validity)
        => new RecordingValidator(validity);

    private sealed class RecordingValidator(ProjectionExpressionValidity validity) : IProjectionExpressionValidator
    {
        public int Calls { get; private set; }

        public ProjectionExpressionValidity Validate(string expression, JmesPathLimits limits)
        {
            Calls++;

            return validity;
        }
    }
}

