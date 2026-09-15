using System.Globalization;

namespace MCPiler.Engine.Host.Managed;

/// <summary>
/// Everything a managed deployment needs to reach its Platform and stay bounded.
/// </summary>
/// <remarks>
/// <para>
/// The deployment secret is named by file, never carried in the setting itself. A command line
/// is visible in a process listing and lands in a container's configuration; a file can be
/// mounted read-only with restrictive permissions and rotated without changing the process
/// arguments.
/// </para>
/// <para>
/// Both bounds matter. The poll bound stops a long poll from outliving the listener's shutdown
/// budget; the initial-sync bound stops a Platform that is reachable but not answering from
/// keeping the process from ever opening its listener or exiting with a diagnostic.
/// </para>
/// </remarks>
public sealed record ManagedSyncOptions
{
    /// <summary>The Platform endpoint serving the management protocol.</summary>
    public required Uri Endpoint { get; init; }

    /// <summary>The deployment this process synchronizes with.</summary>
    public required string DeploymentId { get; init; }

    /// <summary>The file holding the deployment-scoped bearer secret.</summary>
    public required string SecretFile { get; init; }

    /// <summary>How long the bounded initial synchronization may take before startup refuses.</summary>
    public TimeSpan InitialSyncBound { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long one long poll waits before the Platform answers "no change".</summary>
    public TimeSpan PollBound { get; init; } = TimeSpan.FromSeconds(25);

    /// <summary>The largest generation response this process will read.</summary>
    public long MaximumResponseBytes { get; init; } = 64L * 1024 * 1024;

    /// <summary>The largest poll request body this process will write.</summary>
    public long MaximumRequestBytes { get; init; } = 64 * 1024;

    /// <summary>How long a connection attempt may take before the worker backs off.</summary>
    public TimeSpan ConnectBound { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Whether the endpoint may use plain HTTP. Only ever true for a loopback address.
    /// </summary>
    /// <remarks>
    /// Managed synchronization carries provider secret values. A plain-HTTP channel to anything
    /// but the local process would put those values on the network in a form anyone on the path
    /// can read, so the exception is limited to loopback for tests and local diagnostics.
    /// </remarks>
    public bool AllowsLoopbackHttp => IsLoopback(Endpoint);

    /// <summary>True when the endpoint is a loopback address.</summary>
    public static bool IsLoopback(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return endpoint.IsLoopback || string.Equals(endpoint.Host, "localhost", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Renders the endpoint for a diagnostic without its query or user information.
    /// </summary>
    public string Describe() => string.Create(
        CultureInfo.InvariantCulture,
        $"{Endpoint.Scheme}://{Endpoint.Authority}");
}
