namespace MCPiler.Engine.Runtime.Projection;

/// <summary>
/// The structural size of one JSON value as profile 1 counts it.
/// </summary>
/// <remarks>
/// Node count includes the root and every array element and object member value; depth counts
/// structure levels with the root at one. Both sides of the split count the same way, so the
/// same document measures the same on each.
/// </remarks>
/// <param name="Nodes">The counted nodes.</param>
/// <param name="Depth">The structural depth with the root at one.</param>
public readonly record struct JmesPathValueMetrics(long Nodes, int Depth);
