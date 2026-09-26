using System.Globalization;
using System.Text;

using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Host.Managed;
using MCPiler.Engine.Host.ProjectionWorker;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Runtime.Managed;

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
            HostVerb.Compatibility => new CommandOutcome(
                ExitCodes.Success,
                CompatibilityDescriptor.EngineSupport().ToCanonicalJson()),
            HostVerb.Serve => await ServeAsync(parsed, identity, progress, cancellationToken).ConfigureAwait(false),
            HostVerb.Inspect => await InspectAsync(parsed, identity, cancellationToken).ConfigureAwait(false),
            _ => await FilesAsync(parsed, cancellationToken).ConfigureAwait(false),
        };
    }

    private static async Task<CommandOutcome> ServeAsync(
        CommandLineResult parsed,
        string identity,
        TextWriter? progress,
        CancellationToken cancellationToken)
    {
        // The mode is read before binding, because it decides whether a local mount is required at
        // all: a managed process is refused for naming one, and a file-mode process is refused for
        // omitting one. Checking the mount before the mode would report the wrong absence.
        bool managed = HostConfiguration.RequestsManagedMode(parsed.Settings);

        if (!managed && !HasManifestMount(parsed, out CommandOutcome? refused))
        {
            return refused;
        }

        if (!Bind(parsed, out HostBinding? binding, out refused))
        {
            return refused;
        }

        // Before either transport opens anything: a mode that needs an endpoint the issuer does
        // not publish can only ever reject every token, and an operator should read that as a
        // setting to change rather than as a client that cannot authenticate.
        if (await AuthorizationEndpointCheck
                .FindAsync(binding.Authorization, cancellationToken)
                .ConfigureAwait(false) is { } unusable)
        {
            return new CommandOutcome(
                ExitCodes.Configuration,
                identity + Environment.NewLine + StartupReport.RenderRefusal(unusable) + Environment.NewLine);
        }

        if (binding.Mode is HostDeploymentMode.Managed)
        {
            return await ServeManagedAsync(binding, identity, progress, cancellationToken).ConfigureAwait(false);
        }

        // A manifest carrying a JMESPath projection can only be validated by compiling the
        // expression in a confined worker, so the serving path supplies the one host that can.
        // The validator allocates nothing until an expression actually needs classifying, so a
        // deployment that serves no projection pays nothing for this.
        using WorkerExpressionValidator expressions = new();

        RuntimeStartResult result = EngineRuntime.Start(
            binding.Runtime with { ExpressionValidator = expressions, ProjectionWorker = expressions });
        string report = identity + Environment.NewLine + StartupReport.Render(result, binding.Authorization, binding.ResponseCacheOperatorSecret is not null);

        if (!result.Started)
        {
            return new CommandOutcome(StartupReport.ExitCode(result), report);
        }

        if (binding.Listener.Transport is HostTransport.Stdio
            && !StdioTransport.TrySelectSurface(result, out _, out string? stdioRefusal))
        {
            return new CommandOutcome(
                ExitCodes.Configuration,
                report + stdioRefusal + Environment.NewLine);
        }

        // Reported before the listener opens, not after it closes. Everything that could
        // refuse has already refused, so this line means the mounts an operator configured
        // are the mounts about to answer.
        progress?.Write(report);

        if (binding.Listener.Transport is HostTransport.Stdio)
        {
            progress?.WriteLine(StdioTransport.SecurityBoundaryStatement);
        }

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
        using DrainCoordinator drain = new();

        if (binding.Listener.Transport is HostTransport.Stdio)
        {
            DrainReport drainReport = await StdioTransport
                .RunAsync(result, execution, drain, binding.Lifecycle.DrainTimeout, cancellationToken)
                .ConfigureAwait(false);
            ReportDrain(progress, drainReport);
        }
        else
        {
            WebApplication app;
            try
            {
                app = EngineWebHost.Build(result, binding, execution, drain);
            }
            catch (InvalidOperationException refusal)
            {
                // The listener refuses before it exists: for example a mount that requires a
                // token while no issuer is configured. That is a configuration outcome, not a
                // crash, so it reports through the same refusal path every other startup
                // problem uses and exits with the configuration code.
                return new CommandOutcome(
                    ExitCodes.Configuration,
                    refusal.Message + Environment.NewLine);
            }

            await using (app.ConfigureAwait(false))
            {
                await app.StartAsync(cancellationToken).ConfigureAwait(false);
                await WaitForStoppingAsync(app, cancellationToken).ConfigureAwait(false);

                DrainReport drainReport = await drain
                    .ShutdownAsync(app, binding.Lifecycle.DrainTimeout)
                    .ConfigureAwait(false);
                ReportDrain(progress, drainReport);
            }
        }

        return new CommandOutcome(ExitCodes.Success, string.Empty);
    }

    /// <summary>
    /// Serves the desired state one Platform deployment delivers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The initial synchronization is bounded and happens before the listener exists. A managed
    /// process with no generation has nothing to serve, and opening a socket first would report
    /// readiness to an orchestrator while answering nothing: the refusal has to be a startup
    /// outcome, not a client-visible absence.
    /// </para>
    /// <para>
    /// The worker starts only after the listener is up, so the first activation cannot race the
    /// generation the listener was built around.
    /// </para>
    /// </remarks>
    private static async Task<CommandOutcome> ServeManagedAsync(
        HostBinding binding,
        string identity,
        TextWriter? progress,
        CancellationToken cancellationToken)
    {
        if (binding.Listener.Transport is HostTransport.Stdio)
        {
            return new CommandOutcome(
                ExitCodes.Configuration,
                "Managed synchronization serves a long-polled generation and cannot run over stdio. "
                + "Choose the http transport."
                + Environment.NewLine);
        }

        ManagedSyncOptions options = binding.Managed
            ?? throw new InvalidOperationException(
                "A managed binding without synchronization settings cannot serve. The configuration "
                + "layer refuses this shape, so reaching here means a caller built a binding by hand.");

        // Every generation this process activates is validated the same way a local mount is:
        // a JMESPath expression is compiled in a confined worker, or the generation is refused.
        using WorkerExpressionValidator expressions = new();

        if (!ManagedGenerationLoader.TryOpen(
                binding.Runtime with { ExpressionValidator = expressions, ProjectionWorker = expressions },
                out ManagedGenerationLoader? loader,
                out IReadOnlyList<StartupRefusal> loadRefusals))
        {
            return new CommandOutcome(
                ExitCodes.Configuration,
                identity + Environment.NewLine + Render(loadRefusals));
        }

        using ManagedGenerationLoader generationsLoader = loader!;
        using EngineGenerationManager generations = new(HostMode.Managed);
        using DrainCoordinator drain = new();
        using ManagedSyncWorker worker = new(
            options,
            generationsLoader,
            generations,
            EngineRuntime.SupportedManifestFormatRange,
            diagnostic =>
            {
                progress?.WriteLine(diagnostic);
                progress?.Flush();
            });

        ManagedInitialSync initial = await worker
            .SynchronizeInitialAsync(cancellationToken)
            .ConfigureAwait(false);

        if (!initial.Started)
        {
            string refusal = initial.Refusal is { } refusalValue
                ? StartupReport.RenderRefusal(refusalValue)
                : "Engine could not obtain an initial generation and will not open a listener."
                    + Environment.NewLine;

            return new CommandOutcome(ExitCodes.Configuration, identity + Environment.NewLine + refusal);
        }

        progress?.Write(identity + Environment.NewLine + StartupReport.RenderManaged(
            options.Describe(),
            initial.GenerationId!,
            generationsLoader.DurableRuntimeState,
            binding.Authorization,
            binding.Runtime.ResponseCache));
        progress?.Flush();

        await using WebApplication? app = BuildManagedOrRefuse(binding, drain, generations, out CommandOutcome? buildRefusal);
        if (app is null)
        {
            return buildRefusal!;
        }

        await app.StartAsync(cancellationToken).ConfigureAwait(false);

        // Started after the listener, because an activation that landed earlier would replace the
        // generation the listener was built around while nothing could yet serve it.
        worker.Start(cancellationToken);

        await WaitForStoppingAsync(app, cancellationToken).ConfigureAwait(false);

        DrainReport drainReport = await drain
            .ShutdownAsync(app, binding.Lifecycle.DrainTimeout)
            .ConfigureAwait(false);
        ReportDrain(progress, drainReport);

        return new CommandOutcome(ExitCodes.Success, string.Empty);

        static string Render(IReadOnlyList<StartupRefusal> refusals)
        {
            StringBuilder text = new();

            foreach (StartupRefusal refusal in refusals)
            {
                text.AppendLine(StartupReport.RenderRefusal(refusal));
            }

            return text.ToString();
        }
    }

    /// <summary>
    /// Builds the managed listener, or reports the startup refusal a configuration gap names.
    /// </summary>
    /// <remarks>
    /// The listener refuses before it exists when the active generation requires authorization and
    /// no issuer is configured. That is the same class of outcome as any other startup refusal, so
    /// it exits with the configuration code instead of escaping as an unhandled exception.
    /// </remarks>
    private static WebApplication? BuildManagedOrRefuse(
        HostBinding binding,
        DrainCoordinator drain,
        EngineGenerationManager generations,
        out CommandOutcome? refusal)
    {
        try
        {
            refusal = null;
            return EngineWebHost.BuildManaged(binding, drain, generations);
        }
        catch (InvalidOperationException unbuildable)
        {
            refusal = new CommandOutcome(
                ExitCodes.Configuration,
                unbuildable.Message + Environment.NewLine);
            return null;
        }
    }

    private static async Task WaitForStoppingAsync(
        WebApplication app,
        CancellationToken cancellationToken)
    {
        Task applicationStopping = Task.Delay(
            Timeout.InfiniteTimeSpan,
            app.Lifetime.ApplicationStopping);
        Task externalStopping = Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

        _ = await Task.WhenAny(applicationStopping, externalStopping).ConfigureAwait(false);
    }

    internal static void ReportDrain(TextWriter? progress, DrainReport report)
    {
        if (report.Completed)
        {
            return;
        }

        progress?.WriteLine(
            $"shutdown: abandoned {report.AbandonedTools.Count} invocation(s): "
            + string.Join(", ", report.AbandonedTools));
        progress?.Flush();
    }

    private static async Task<CommandOutcome> InspectAsync(
        CommandLineResult parsed,
        string identity,
        CancellationToken cancellationToken)
    {
        if (!HasManifestMount(parsed, out CommandOutcome? refused))
        {
            return refused;
        }

        if (!Bind(parsed, out HostBinding? binding, out refused))
        {
            return refused;
        }

        // Inspection must answer the question serving would: it stands up the same worker
        // validator, because a manifest refused at serve time must not inspect cleanly.
        using WorkerExpressionValidator expressions = new();

        RuntimeStartResult result = EngineRuntime.Start(
            binding.Runtime with { ExpressionValidator = expressions, ProjectionWorker = expressions });

        if (!result.Started)
        {
            return new CommandOutcome(
                StartupReport.ExitCode(result),
                identity + Environment.NewLine + StartupReport.Render(result, operatorChannelConfigured: binding.ResponseCacheOperatorSecret is not null));
        }

        StringBuilder text = new(identity);
        text.AppendLine();
        text.Append(StartupReport.Render(result, operatorChannelConfigured: binding.ResponseCacheOperatorSecret is not null));

        // Inspection runs the same mount path as serving and stops before the listener. The one
        // thing that path cannot report on its own is the host-side pairing rule, because it
        // depends on configuration rather than on the Manifest: a protected mount with no
        // configured issuer refuses to start. Reporting it here is the difference between an
        // inspection that answers "will this endpoint demand a token" and one that answers "will
        // this configuration run at all".
        if (AuthorizationRefusal.Find(result.Mounts, binding.Authorization) is { } unstartable)
        {
            text.Append(StartupReport.RenderUnstartable(unstartable));
        }

        // The other host-side pairing rule: a configured validation mode whose issuer publishes
        // no endpoint for it. Also invisible to the mount path, and also the difference between
        // "what would be exposed" and "whether this configuration would run".
        if (await AuthorizationEndpointCheck
                .FindAsync(binding.Authorization, cancellationToken)
                .ConfigureAwait(false) is { } unreachable)
        {
            text.Append(StartupReport.RenderUnstartable(unreachable));
        }

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

    private static bool HasManifestMount(CommandLineResult parsed, out CommandOutcome refused)
    {
        if (parsed.Mounts.Count > 0)
        {
            refused = null!;
            return true;
        }

        refused = new CommandOutcome(
            ExitCodes.Configuration,
            "At least one '--mount <prefix>=<dir>' is required. Engine serves configured Manifest mounts and does not start with an empty surface."
                + Environment.NewLine);
        return false;
    }
}
