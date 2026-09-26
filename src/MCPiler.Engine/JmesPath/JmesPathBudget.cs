namespace MCPiler.Engine.JmesPath;

/// <summary>
/// Which declared bounds a canonicalization walk is charged against, and therefore which
/// failure classes it reports when one is crossed.
/// </summary>
/// <remarks>
/// The walk is the same code on both sides; only the names of the dimensions differ, because a
/// response body that is too large and a projected result that is too large are different
/// findings with different remedies. Naming the budget at the call site keeps that distinction
/// from being inferred from context.
/// </remarks>
internal enum JmesPathBudget
{
    /// <summary>Charged against the input node and depth bounds.</summary>
    Input,

    /// <summary>Charged against the completed-result node, depth and output byte bounds.</summary>
    Result,
}
