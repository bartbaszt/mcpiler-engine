namespace MCPiler.Engine.Runtime.Projection;

/// <summary>
/// A body that passed the input bounds and became the deterministic form the evaluator reads.
/// </summary>
/// <remarks>
/// Preparation is separate from evaluation because the two happen in different processes and
/// the refusal has to be reachable without one. A body whose nodes or depth cross the input
/// bound is refused by whoever holds it, and no expression is ever sent anywhere: a bound that
/// is only checked next to the evaluator is a bound that costs a process launch to discover.
/// </remarks>
/// <param name="Json">The body with members in the profile's canonical order, as UTF-8 JSON.</param>
/// <param name="Metrics">The shape that was measured while preparing it.</param>
public sealed record JmesPathPreparedInput(byte[] Json, JmesPathValueMetrics Metrics);
