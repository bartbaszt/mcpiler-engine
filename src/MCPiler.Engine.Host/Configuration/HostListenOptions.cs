namespace MCPiler.Engine.Host.Configuration;

/// <summary>How a client reaches this process.</summary>
public enum HostTransport
{
    /// <summary>A network listener speaking MCP over Streamable HTTP.</summary>
    Http,
}

/// <summary>
/// The part of the configuration the listener reads and the library never sees.
/// </summary>
/// <remarks>
/// <para>
/// An address and a transport are facts about how this process is reached, not about what it
/// serves. They are kept apart from the runtime options for that reason: the sufficiency
/// argument in the specifications is that two deployments of one Manifest behave identically,
/// and a setting that reached the library would be a setting that could make them differ.
/// </para>
/// <para>
/// The default address is loopback. This is Engine's first inbound surface, and a process that
/// bound every interface because nobody said otherwise would publish a server as a
/// side effect of omitting a flag.
/// </para>
/// </remarks>
/// <param name="Listen">The address a network listener binds.</param>
/// <param name="Transport">The transport a client reaches this process through.</param>
public sealed record HostListenOptions(string Listen, HostTransport Transport)
{
    /// <summary>The address bound when configuration names none.</summary>
    public const string DefaultListen = "http://127.0.0.1:8080";

    /// <summary>The transport name accepted for <see cref="HostTransport.Http"/>.</summary>
    public const string HttpTransportName = "http";

    /// <summary>Every transport name this build accepts.</summary>
    /// <remarks>
    /// A local standard-stream transport is a separate capability with its own obligations,
    /// and it is absent from this list until it exists. Listing a name this build cannot serve
    /// would turn a missing capability into a runtime surprise.
    /// </remarks>
    public static IReadOnlyList<string> AcceptedTransports { get; } = [HttpTransportName];

    /// <summary>The settings a process is started with when nothing is configured.</summary>
    public static HostListenOptions Default { get; } = new(DefaultListen, HostTransport.Http);
}
