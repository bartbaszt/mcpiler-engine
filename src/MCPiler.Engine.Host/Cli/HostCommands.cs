using System.Globalization;
using System.Text;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;

namespace MCPiler.Engine.Host.Cli;

/// <summary>What a command produced.</summary>
/// <param name="ExitCode">The process exit code.</param>
/// <param name="Output">Everything the operator should read.</param>
public sealed record CommandOutcome(int ExitCode, string Output);

/// <summary>
/// Runs one verb.
/// </summary>
/// <remarks>
/// <para>
/// Every verb that touches a Manifest goes through the same startup the serving verb uses.
/// A second path would be a second answer to what a Manifest exposes, and the whole value of
/// an inspection verb is that its answer is the one that will be served.
/// </para>
/// <para>
/// Nothing here decides anything about a Manifest. It selects a verb, hands the library what
/// the operator supplied, and renders what comes back.
/// </para>
/// </remarks>
public static class HostCommands
{
    /// <summary>Runs the command described by <paramref name="args"/>.</summary>
    /// <param name="args">The process arguments.</param>
    /// <param name="identity">The build identity line.</param>
    /// <param name="cancellationToken">Cancels a store operation or a running listener.</param>
    /// <param name="progress">
    /// Where a verb that does not return writes what it has to say. The serving verb reports
    /// its startup and then blocks, so an operator who only saw the returned output would
    /// learn what happened at start only once the process had stopped.
    /// </param>
    public static async Task<CommandOutcome> RunAsync(
        IReadOnlyList<string> args,
        string identity,
        CancellationToken cancellationToken,
        TextWriter? progress = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentException.ThrowIfNullOrEmpty(identity);

        CommandLineResult parsed = CommandLine.Parse(args);

        if (!parsed.Valid)
        {
            StringBuilder text = new();

            foreach (string refusal in parsed.Refusals)
            {
                text.AppendLine(refusal);
            }

            text.AppendLine();
            text.AppendLine(CommandLine.Usage);

            return new CommandOutcome(ExitCodes.Usage, text.ToString());
        }

        return parsed.Verb switch
        {
            HostVerb.Version => new CommandOutcome(ExitCodes.Success, identity + Environment.NewLine),
            HostVerb.Serve => await ServeAsync(parsed, identity, progress, cancellationToken).ConfigureAwait(false),
            HostVerb.Inspect => Inspect(parsed, identity),
            _ => await FilesAsync(parsed, cancellationToken).ConfigureAwait(false),
        };
    }

    private static async Task<CommandOutcome> ServeAsync(
        CommandLineResult parsed,
        string identity,
        TextWriter? progress,
        CancellationToken cancellationToken)
    {
        if (!Bind(parsed, out HostBinding? binding, out CommandOutcome? refused))
        {
            return refused;
        }

        RuntimeStartResult result = EngineRuntime.Start(binding.Runtime);
        string report = identity + Environment.NewLine + StartupReport.Render(result);

        if (!result.Started)
        {
            return new CommandOutcome(StartupReport.ExitCode(result), report);
        }

        // Reported before the listener opens, not after it closes. Everything that could
        // refuse has already refused, so this line means the mounts an operator configured
        // are the mounts about to answer.
        progress?.Write(report);
        progress?.Flush();

        // Outlives the application deliberately: the pool it owns is closed after the
        // listener has stopped accepting, never by whichever container teardown ran first.
        using EngineExecution execution = EngineExecution.Create(
            result,
            diagnostic =>
            {
                progress?.WriteLine(diagnostic);
                progress?.Flush();
            });

        await using WebApplication app = EngineWebHost.Build(result, binding, execution);

        await app.StartAsync(cancellationToken).ConfigureAwait(false);
        await app.WaitForShutdownAsync(cancellationToken).ConfigureAwait(false);

        return new CommandOutcome(ExitCodes.Success, string.Empty);
    }

    private static CommandOutcome Inspect(CommandLineResult parsed, string identity)
    {
        if (!Bind(parsed, out HostBinding? binding, out CommandOutcome? refused))
        {
            return refused;
        }

        RuntimeStartResult result = EngineRuntime.Start(binding.Runtime);

        if (!result.Started)
        {
            return new CommandOutcome(
                StartupReport.ExitCode(result),
                identity + Environment.NewLine + StartupReport.Render(result));
        }

        StringBuilder text = new(identity);
        text.AppendLine();
        text.Append(StartupReport.Render(result));

        foreach (MountedManifest mount in result.Mounts)
        {
            foreach (MountedSurface surface in mount.Surfaces)
            {
                text.AppendLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"{mount.Prefix} surface {surface.Slug}{(surface.IsDefault ? " (default)" : string.Empty)} "
                    + $"tools={surface.ToolNames.Count} fingerprint={surface.Fingerprint}"));

                if (surface.RequiredScopes.Count > 0)
                {
                    text.AppendLine(string.Create(
                        CultureInfo.InvariantCulture,
                        $"{mount.Prefix} surface {surface.Slug} scopes={string.Join(' ', surface.RequiredScopes)}"));
                }

                foreach (string tool in surface.ToolNames)
                {
                    text.AppendLine(string.Create(
                        CultureInfo.InvariantCulture,
                        $"{mount.Prefix} surface {surface.Slug} tool {tool}"));
                }
            }
        }

        text.AppendLine("Nothing was served. This command opened no listener.");

        return new CommandOutcome(ExitCodes.Success, text.ToString());
    }

    private static async Task<CommandOutcome> FilesAsync(CommandLineResult parsed, CancellationToken cancellationToken)
    {
        if (!Bind(parsed, out HostBinding? binding, out CommandOutcome? refused))
        {
            return refused;
        }

        FileStoreInspection? store = FileStoreInspection.Open(binding.Runtime.FileStoreRoot, out StartupRefusal? unusable);

        if (store is null)
        {
            return new CommandOutcome(ExitCodes.Configuration, unusable!.Message + Environment.NewLine);
        }

        StringBuilder text = new();

        switch (parsed.Verb)
        {
            case HostVerb.FilesList:
                foreach (StoredHandle handle in await store.ListAsync(cancellationToken).ConfigureAwait(false))
                {
                    text.AppendLine(Describe(handle));
                }

                break;

            case HostVerb.FilesShow:
                StoredHandle? found = await store.ShowAsync(parsed.Operand!, cancellationToken).ConfigureAwait(false);

                if (found is null)
                {
                    text.AppendLine(string.Create(
                        CultureInfo.InvariantCulture,
                        $"No handle {parsed.Operand} is recorded."));

                    return new CommandOutcome(ExitCodes.Failure, text.ToString());
                }

                text.AppendLine(Describe(found));
                break;

            default:
                SweepOutcome swept = await store.SweepAsync(cancellationToken).ConfigureAwait(false);

                Reclaimed(text, "expired", swept.ExpiredHandles);
                Reclaimed(text, "unreadable-record", swept.UnreadableRecords);
                Reclaimed(text, "content-absent", swept.RecordsWithoutContent);
                Reclaimed(text, "orphan-content", swept.ReclaimedContent);

                text.AppendLine(string.Create(CultureInfo.InvariantCulture, $"reclaimed {swept.Total}"));
                break;
        }

        return new CommandOutcome(ExitCodes.Success, text.ToString());
    }

    private static void Reclaimed(StringBuilder text, string reason, IReadOnlyList<string> ids)
    {
        foreach (string id in ids)
        {
            text.AppendLine(string.Create(CultureInfo.InvariantCulture, $"reclaimed {id} {reason}"));
        }
    }

    /// <summary>Renders one handle. Metadata only; content is never printed.</summary>
    private static string Describe(StoredHandle handle)
        => string.Create(
            CultureInfo.InvariantCulture,
            $"{handle.Id} {handle.FileName} {handle.MediaType} {handle.Length}B sha256={handle.ContentHash} "
            + $"scope={handle.Scope} expires={handle.ExpiresAtUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "never"} "
            + $"scan={handle.ScanVerdict} signature={handle.SignatureVerdict} "
            + $"state={(handle.Expired ? "expired" : handle.ContentPresent ? "available" : "content-absent")}");

    private static bool Bind(
        CommandLineResult parsed,
        out HostBinding binding,
        out CommandOutcome refused)
    {
        if (HostConfiguration.TryBind(parsed.Mounts, parsed.Settings, out HostBinding? bound, out IReadOnlyList<string> refusals))
        {
            binding = bound;
            refused = null!;
            return true;
        }

        StringBuilder text = new();

        foreach (string refusal in refusals)
        {
            text.AppendLine(refusal);
        }

        binding = null!;
        refused = new CommandOutcome(ExitCodes.Configuration, text.ToString());
        return false;
    }
}
