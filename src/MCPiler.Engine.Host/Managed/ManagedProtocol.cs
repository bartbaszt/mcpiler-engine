namespace MCPiler.Engine.Host.Managed;

/// <summary>
/// The values the managed protocol pins on the Engine side.
/// </summary>
/// <remarks>
/// These are restated here rather than taken from the Platform assembly, which Engine never
/// references. The shared fixture is the contract; a value that drifted on one side alone would
/// fail the fixture tests rather than a deployment.
/// </remarks>
internal static class ManagedProtocol
{
    /// <summary>The protocol version this Engine speaks.</summary>
    public const int Version = 2;

    /// <summary>Platform-issued fencing epoch carried on accepted managed polls.</summary>
    public const string SessionEpochHeader = "X-MCPiler-Managed-Session-Epoch";

    /// <summary>The outcome spelling for a candidate that became active.</summary>
    public const string Active = "active";

    /// <summary>The outcome spelling for a candidate that was refused.</summary>
    public const string CandidateFailed = "candidate-failed";
}
