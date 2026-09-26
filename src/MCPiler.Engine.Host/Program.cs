using System.Globalization;
using System.Reflection;

using MCPiler.Engine.Host.Cli;
using MCPiler.Engine.Host.ProjectionWorker;
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
/// <para>
/// One argument is not a verb and is checked before the command runner sees the line: the
/// internal projection-worker mode. A worker is a short-lived child of the serving process
/// rather than a command an operator runs, and its one argument is deliberately not part of
/// the documented verb set.
/// </para>
/// </remarks>
internal static class Program
{
    internal static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Length > 0 && string.Equals(args[0], WorkerProtocol.ModeArgument, StringComparison.Ordinal))
        {
            return await ProjectionWorkerEntry
                .RunAsync(Console.OpenStandardInput(), Console.OpenStandardOutput(), Console.OpenStandardError(), WorkerLimitsFromEnvironment(), CancellationToken.None)
                .ConfigureAwait(false);
        }

        CommandOutcome outcome = await HostCommands
            .RunAsync(args, Identity(), CancellationToken.None, Console.Error)
            .ConfigureAwait(false);

        // The serving progress stream is stderr because stdio owns stdout byte-for-byte while
        // the protocol is active. Returned command output is written only after a command has
        // completed or refused before serving, so it cannot interleave with protocol frames.
        Console.Out.Write(outcome.Output);

        return outcome.ExitCode;
    }

    /// <summary>
    /// The confinement a worker applies to itself, taken from the parent's environment or from
    /// the calibrated defaults when the environment does not carry a value.
    /// </summary>
    /// <remarks>
    /// The defaults are the same numbers the parent uses, so a directly-launched worker is
    /// confined too. The parent passes its own values through the environment so a deployment
    /// that narrowed the policy narrows the child identically.
    /// </remarks>
    private static WorkerLimits WorkerLimitsFromEnvironment()
    {
        long committed = ReadLimit(WorkerResourceLimits.CommittedBytesVariable, WorkerResourceLimits.DefaultCommittedBytes);
        long addressSpace = ReadLimit(WorkerResourceLimits.AddressSpaceBytesVariable, WorkerResourceLimits.DefaultAddressSpaceBytes);
        long inputBody = ReadLimit(WorkerResourceLimits.InputBodyBytesVariable, WorkerResourceLimits.DefaultInputBodyLimitBytes);

        return new WorkerLimits(committed, addressSpace, inputBody);

        static long ReadLimit(string name, long fallback)
        {
            string? text = Environment.GetEnvironmentVariable(name);

            return long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long value) && value > 0
                ? value
                : fallback;
        }
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
