using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Execution;

/// <summary>
/// The transport-shaped subset of a manifest's execution limits.
/// </summary>
/// <remarks>
/// <para>
/// A manifest's <see cref="ExecutionLimits"/> carries six numbers, three of which describe a
/// socket and three of which describe how much of a response, a request or a chain the product
/// is willing to process. Only the first three mean anything to a client factory, and handing
/// the whole record to the adapter would put a manifest type inside a directory whose entire
/// justification is that it holds no manifest knowledge.
/// </para>
/// <para>
/// The projection is deliberately one-way and lives here, in the host-free half: the adapter
/// receives numbers it can act on and has no way to ask what else the policy said.
/// </para>
/// </remarks>
/// <param name="ConnectTimeout">
/// The per-connection dial budget. Distinct from the whole-exchange budget, which is a
/// cancellation token the caller owns.
/// </param>
/// <param name="MaxConnectionsPerServer">The connection pool ceiling for one destination.</param>
/// <param name="RedirectHopLimit">
/// How many redirects one exchange may follow. Zero means the first response is final.
/// </param>
public sealed record OutboundLimits(
    TimeSpan ConnectTimeout,
    int MaxConnectionsPerServer,
    int RedirectHopLimit)
{
    /// <summary>The limits that apply when a manifest states no policy of its own.</summary>
    public static OutboundLimits Default { get; } = From(ExecutionLimits.Default);

    /// <summary>Projects the transport-relevant members of a manifest's execution limits.</summary>
    /// <param name="limits">The governing limits.</param>
    public static OutboundLimits From(ExecutionLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);

        return new OutboundLimits(
            limits.UpstreamConnectTimeout,
            limits.Concurrency,
            limits.RedirectHopLimit);
    }
}
