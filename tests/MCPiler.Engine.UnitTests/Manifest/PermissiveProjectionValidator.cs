using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// Classifies every expression as valid without evaluating it.
/// </summary>
/// <remarks>
/// The authoring corpus asserts what a manifest <em>declares</em> and whether it loads, which
/// needs the reader's validator seat filled rather than a real classification. Evaluating the
/// expression requires a confined worker, and one can only be started by a host; that obligation
/// belongs to the integration suites and to a real deployment, not to a unit corpus that would
/// otherwise have to interpret untrusted expressions in process. The fixture this stands in for
/// is compiler-generated and byte-pinned by the drift test, so its expression is not hand-edited
/// behind this double's back.
/// </remarks>
internal sealed class PermissiveProjectionValidator : IProjectionExpressionValidator
{
    /// <summary>The single instance; the type is stateless.</summary>
    internal static PermissiveProjectionValidator Instance { get; } = new();

    /// <inheritdoc />
    public ProjectionExpressionValidity Validate(string expression, JmesPathLimits limits)
        => ProjectionExpressionValidity.Valid;
}
