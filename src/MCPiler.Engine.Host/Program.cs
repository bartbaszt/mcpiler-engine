using System.Globalization;
using System.Reflection;

using MCPiler.Engine.Host.Cli;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host;

/// <summary>
/// The Engine executable.
/// </summary>
/// <remarks>
/// <para>
/// At this point the entry point does one thing: state which build it is and which
/// Manifest format versions it can read. That is not a placeholder. A Manifest is
/// portable and an Engine build inside a container is not identifiable by looking at it,
/// so a support conversation that cannot start with "which build, and can it read this
/// document" starts with guessing instead.
/// </para>
/// <para>
/// Everything this host grows - configuration, mounts, the listener, the transports -
/// arrives behind the rule that makes the split checkable: the library decides what to
/// serve, and this project decides how it is reached. A decision that lands here rather
/// than there is invisible to every guard the library carries.
/// </para>
/// <para>
/// The entry point itself holds no verb. It reads arguments, hands them to the command
/// runner and writes what comes back, so every verb is reachable from a test without a
/// process.
/// </para>
/// </remarks>
internal static class Program
{
    internal static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        CommandOutcome outcome = await HostCommands
            .RunAsync(args, Identity(), CancellationToken.None, Console.Error)
            .ConfigureAwait(false);

        // The serving progress stream is stderr because stdio owns stdout byte-for-byte while
        // the protocol is active. Returned command output is written only after a command has
        // completed or refused before serving, so it cannot interleave with protocol frames.
        Console.Out.Write(outcome.Output);

        return outcome.ExitCode;
    }

    /// <summary>The one fact this build can state about itself without reading anything.</summary>
    internal static string Identity()
        => string.Create(
            CultureInfo.InvariantCulture,
            $"mcpiler-engine {Version()} (manifest format {EngineRuntime.SupportedManifestFormatRange})");

    private static string Version()
        => typeof(Program).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
            ?? typeof(Program).Assembly.GetName().Version?.ToString()
            ?? "unknown";
}
