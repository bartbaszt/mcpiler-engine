using System.Globalization;
using System.Text;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Host.ProjectionWorker;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host.Cli;

/// <summary>
/// Runs the file-mode <c>auth</c> verbs: interactive bootstrap (ST-1/ST-2), status (OPS-1), clear
/// (OPS-2), diagnostics (OPS-3) and the acknowledged destructive reset (OPS-2g).
/// </summary>
/// <remarks>
/// <para>
/// The workflow order is the safety property. Every mutating command takes the runtime-state-root
/// lease and finishes all validation before it opens the callback listener, reaches the provider
/// or writes anything, so a second owner or an unusable target is refused before any local or
/// upstream change.
/// </para>
/// <para>
/// Nothing here reads or writes an authority record itself. Each verb prepares the deployment and
/// hands the request to <see cref="StandaloneAuthorization"/>; the library owns every decision
/// about what an authority transition means.
/// </para>
/// </remarks>
internal static class OAuthAuthorizationCommands
{
    /// <summary>Runs <c>auth authorize &lt;mount&gt; &lt;profile&gt;</c>.</summary>
    internal static async Task<CommandOutcome> AuthorizeAsync(
        CommandLineResult parsed,
        string identity,
        TextWriter? progress,
        AuthorizationOutcomeLog outcomes,
        TimeProvider? timeProvider,
        CancellationToken cancellationToken)
    {
        if (!TryPrepare(parsed, identity, redirectRequired: true, out CommandOutcome refused, out PreparedAuthorization prepared))
        {
            return refused;
        }

        using (prepared)
        {
            string mount = parsed.Targets[0];
            string profileId = parsed.Targets[1];
            Uri redirect = prepared.Redirect!;

            StandaloneAuthorizationStart begun = await StandaloneAuthorization
                .BeginAsync(
                    prepared.Start,
                    new StandaloneAuthorizationTarget(mount, profileId, redirect),
                    timeProvider: timeProvider,
                    allowLoopbackAuthorization: prepared.Binding.AllowLoopbackAuthorization,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            if (!begun.Started || begun.Attempt is not { } attempt)
            {
                return Refuse(identity, ExitCodes.Configuration, RenderRefusals(begun.Refusals));
            }

            await using var listener = OAuthLoopbackCallbackListener.For(redirect);

            try
            {
                await listener.StartAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception bindFailure) when (bindFailure is IOException or InvalidOperationException)
            {
                // The attempt is already registered for this (mount, profile), so it has to be
                // terminal before this returns. A live attempt that can never receive a callback
                // would keep the process reporting 'authorizing' for that profile until its
                // lifetime elapsed, which is exactly the state an operator reads as progress.
                attempt.Cancel();

                return Refuse(
                    identity,
                    ExitCodes.Configuration,
                    $"The loopback callback listener could not bind {redirect.GetLeftPart(UriPartial.Authority)}. Another process may hold the port; choose a free loopback URI and register it with the provider. ({bindFailure.Message})");
            }

            attempt.Begin();

            if (progress is not null)
            {
                progress.WriteLine("Open this URL in a browser to authorize:");
                progress.WriteLine(attempt.AuthorizationUrl.AbsoluteUri);
                progress.WriteLine($"Waiting for the provider to redirect to {redirect.AbsoluteUri} ...");
                progress.WriteLine(
                    $"If the callback is not reachable from the browser, forward the callback port to this machine, for example: ssh -L {redirect.Port.ToString(CultureInfo.InvariantCulture)}:127.0.0.1:{redirect.Port.ToString(CultureInfo.InvariantCulture)} <host>");
                progress.Flush();
            }

            string? callbackQuery;

            try
            {
                callbackQuery = await listener.WaitAsync(attempt.ExpiresAtUtc, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                attempt.Cancel();
                return Record(
                    outcomes,
                    identity,
                    "authorize",
                    mount,
                    profileId,
                    "local",
                    "oauth/attempt-cancelled",
                    "The authorization attempt was cancelled before a callback arrived, so the profile is not authorized.",
                    new StandaloneAuthorizationOutcome(
                        false,
                        "oauth/attempt-cancelled",
                        "The authorization attempt was cancelled before a callback arrived, so the profile is not authorized.",
                        mount,
                        profileId,
                        0,
                        0));
            }

            StandaloneAuthorizationOutcome outcome;

            if (callbackQuery is null)
            {
                attempt.Cancel();
                outcome = new StandaloneAuthorizationOutcome(
                    false,
                    "oauth/attempt-expired",
                    "No callback arrived before the attempt expired, so the profile is not authorized.",
                    mount,
                    profileId,
                    0,
                    0);
            }
            else
            {
                outcome = await attempt.CompleteAsync(callbackQuery, cancellationToken).ConfigureAwait(false);
            }

            return Record(outcomes, identity, "authorize", mount, profileId, "local", outcome.Code, outcome.Message, outcome);
        }
    }

    /// <summary>Runs <c>auth status [&lt;mount&gt; &lt;profile&gt;]</c>.</summary>
    internal static async Task<CommandOutcome> StatusAsync(
        CommandLineResult parsed,
        string identity,
        AuthorizationOutcomeLog outcomes,
        CancellationToken cancellationToken)
    {
        if (HostConfiguration.RequestsManagedMode(parsed.Settings))
        {
            return ManagedStatus(parsed, identity);
        }

        if (!HostCommands.Bind(parsed, out HostBinding binding, out CommandOutcome refused))
        {
            return refused;
        }

        if (binding.Mode is HostDeploymentMode.Managed)
        {
            return ManagedStatus(parsed, identity);
        }

        // A read-only status still claims a coherent snapshot, so it holds the store-root lease for
        // the whole read: while the lease is held no other process can mutate the authority, and when
        // it cannot be taken the conflict is reported instead of a possibly stale read. Releasing
        // after a probe would leave exactly the window in which a concurrent mutation could land
        // between the probe and the read.
        IDisposable? owner = null;
        bool ownerElsewhere = false;

        if (!string.IsNullOrWhiteSpace(binding.Runtime.RuntimeStateRoot)
            && !EngineRuntime.TryAcquireRuntimeStateOwner(binding.Runtime.RuntimeStateRoot, out owner, out _))
        {
            ownerElsewhere = true;
        }

        try
        {
            using WorkerExpressionValidator expressions = new();

            RuntimeStartResult start = EngineRuntime.Start(
                binding.Runtime with { ExpressionValidator = expressions, ProjectionWorker = expressions });

            if (!start.Started)
            {
                return Refuse(identity, StartupReport.ExitCode(start), RenderRefusals(start.Refusals));
            }

            var status = await StandaloneAuthorizationOperations
                .DescribeAsync(
                    start,
                    parsed.Targets.Count == 2 ? parsed.Targets[0] : null,
                    parsed.Targets.Count == 2 ? parsed.Targets[1] : null,
                    ownerElsewhere,
                    cancellationToken)
                .ConfigureAwait(false);

            return new CommandOutcome(StatusExitCode(status), RenderStatus(identity, status));
        }
        finally
        {
            owner?.Dispose();
        }
    }

    /// <summary>Runs <c>auth clear &lt;mount&gt; &lt;profile&gt;</c>.</summary>
    internal static async Task<CommandOutcome> ClearAsync(
        CommandLineResult parsed,
        string identity,
        AuthorizationOutcomeLog outcomes,
        CancellationToken cancellationToken)
    {
        if (!TryPrepare(parsed, identity, redirectRequired: false, out CommandOutcome refused, out PreparedAuthorization prepared))
        {
            return refused;
        }

        using (prepared)
        {
            StandaloneClearOutcome outcome = await StandaloneAuthorizationOperations
                .ClearAsync(
                    prepared.Start,
                    parsed.Targets[0],
                    parsed.Targets[1],
                    allowLoopbackAuthorization: prepared.Binding.AllowLoopbackAuthorization,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            RecordClear(outcomes, parsed.Targets[0], parsed.Targets[1], outcome);

            StringBuilder text = new(identity);
            text.AppendLine();
            text.AppendLine($"{(outcome.Cleared ? "cleared" : "not-cleared " + outcome.LocalOutcome)} {outcome.MountPrefix} {outcome.ProfileId} {outcome.Code}");
            text.AppendLine(outcome.Message);

            if (outcome.Cleared)
            {
                text.AppendLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"local clear: {outcome.LocalOutcome}, authority epoch {outcome.AuthorityEpoch}, revision {outcome.RuntimeRevision}. The next acquisition and a restarted Engine use only this cleared floor."));
            }
            else
            {
                text.AppendLine("local clear: " + outcome.LocalOutcome + ".");
            }

            text.AppendLine(string.Create(
                CultureInfo.InvariantCulture,
                $"provider revocation: {outcome.ProviderOutcome} ({outcome.ProviderDetail}). Issued MCP caller tokens are not invalidated by a local clear and are outside this Engine's local authority."));

            if (!outcome.Cleared)
            {
                text.AppendLine("Nothing was changed.");
            }

            return new CommandOutcome(ClearExitCode(outcome), text.ToString());
        }
    }

    /// <summary>Runs <c>auth authority-reset &lt;mount&gt; &lt;profile&gt; [--acknowledge-irrecoverable]</c>.</summary>
    internal static async Task<CommandOutcome> ResetAsync(
        CommandLineResult parsed,
        string identity,
        AuthorizationOutcomeLog outcomes,
        CancellationToken cancellationToken)
    {
        if (!TryPrepare(parsed, identity, redirectRequired: false, out CommandOutcome refused, out PreparedAuthorization prepared))
        {
            return refused;
        }

        using (prepared)
        {
            StandaloneResetOutcome outcome = await StandaloneAuthorizationOperations
                .ResetAsync(
                    prepared.Start,
                    parsed.Targets[0],
                    parsed.Targets[1],
                    parsed.AcknowledgeReset,
                    cancellationToken)
                .ConfigureAwait(false);

            outcomes.Record(new AuthorizationOutcome(
                TimeProvider.System.GetUtcNow(),
                "authority-reset",
                parsed.Targets[0],
                parsed.Targets[1],
                "local",
                outcome.Code,
                outcome.Message));

            StringBuilder text = new(identity);
            text.AppendLine();
            text.AppendLine($"{(outcome.Reset ? "reset" : "not-reset")} {outcome.MountPrefix} {outcome.ProfileId} {outcome.Code}");
            text.AppendLine(outcome.Message);

            foreach (string slot in outcome.AffectedSlots)
            {
                text.AppendLine("affected slot: " + slot);
            }

            foreach (string result in outcome.Results)
            {
                text.AppendLine("result: " + result);
            }

            return new CommandOutcome(ResetExitCode(outcome), text.ToString());
        }
    }

    /// <summary>Runs <c>auth events</c>.</summary>
    internal static Task<CommandOutcome> EventsAsync(
        CommandLineResult parsed,
        string identity,
        AuthorizationOutcomeLog outcomes,
        CancellationToken cancellationToken)
    {
        _ = parsed;
        _ = cancellationToken;

        IReadOnlyList<AuthorizationOutcome> recent = outcomes.Recent(TimeProvider.System.GetUtcNow());
        StringBuilder text = new(identity);
        text.AppendLine();

        if (recent.Count == 0)
        {
            text.AppendLine("No recent authorization outcomes are available.");
            text.AppendLine(
                "This buffer is in-memory and belongs to one process: it is discarded when that process exits, it is not a durable audit history, and a separate invocation cannot see another process's outcomes.");
            return Task.FromResult(new CommandOutcome(ExitCodes.Success, text.ToString()));
        }

        text.AppendLine(string.Create(
            CultureInfo.InvariantCulture,
            $"recent authorization outcomes (in-memory, this process only, newest first, {recent.Count} retained)"));

        foreach (AuthorizationOutcome outcome in recent)
        {
            text.AppendLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{outcome.AtUtc.ToString("O", CultureInfo.InvariantCulture)} {outcome.Verb} {outcome.Mount} {outcome.Profile} {outcome.Category} {outcome.Code} {outcome.Message}"));
        }

        return Task.FromResult(new CommandOutcome(ExitCodes.Success, text.ToString()));
    }

    /// <summary>
    /// Runs the shared validation every auth verb needs, in the order that makes refusals safe.
    /// </summary>
    /// <remarks>
    /// Managed mode is refused before binding because a local bootstrap against Platform-managed
    /// authority would create a second, competing authority. The lease is taken before the runtime
    /// loads anything, so a running owner refuses this command before a provider is contacted or a
    /// local byte is written (ST-5a).
    /// </remarks>
    private static bool TryPrepare(
        CommandLineResult parsed,
        string identity,
        bool redirectRequired,
        out CommandOutcome refused,
        out PreparedAuthorization prepared)
    {
        prepared = null!;

        if (HostConfiguration.RequestsManagedMode(parsed.Settings))
        {
            refused = Refuse(
                identity,
                ExitCodes.Configuration,
                "This process is configured for managed mode. Upstream authorization is Platform-owned there: use Platform Connect/Reauthorize/Disconnect instead of a local 'auth' management command.");
            return false;
        }

        if (parsed.Targets.Count < 2)
        {
            refused = Refuse(identity, ExitCodes.Usage, "This command needs a mount prefix and a profile id.");
            return false;
        }

        Uri? redirect = null;

        if (redirectRequired)
        {
            if (parsed.OAuthRedirectUri is not { Length: > 0 } redirectText)
            {
                refused = Refuse(
                    identity,
                    ExitCodes.Configuration,
                    "'auth authorize' needs '--oauth-redirect-uri <uri>' naming the exact loopback callback URI the provider has registered.");
                return false;
            }

            if (!Uri.TryCreate(redirectText, UriKind.Absolute, out redirect))
            {
                refused = Refuse(
                    identity,
                    ExitCodes.Configuration,
                    $"'--oauth-redirect-uri' was given '{redirectText}', which is not an absolute URI.");
                return false;
            }
        }

        if (!HostCommands.Bind(parsed, out HostBinding binding, out CommandOutcome bindRefusal))
        {
            refused = bindRefusal;
            return false;
        }

        if (binding.Mode is HostDeploymentMode.Managed)
        {
            refused = Refuse(
                identity,
                ExitCodes.Configuration,
                "Managed mode makes the Platform deployment authoritative, so local 'auth' management is refused.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(binding.Runtime.RuntimeStateRoot)
            || string.IsNullOrWhiteSpace(binding.Runtime.RuntimeStateKeyFile))
        {
            refused = Refuse(
                identity,
                ExitCodes.Configuration,
                "Standalone authorization needs a durable runtime-state store so authorization survives a restart: pass '--runtime-state-root <directory>' and '--runtime-state-key-file <file>'.");
            return false;
        }

        if (!EngineRuntime.TryAcquireRuntimeStateOwner(
                binding.Runtime.RuntimeStateRoot, out IDisposable? owner, out string? ownerRefusal))
        {
            refused = new CommandOutcome(
                ExitCodes.Configuration,
                identity + Environment.NewLine + ownerRefusal + Environment.NewLine);
            return false;
        }

        WorkerExpressionValidator expressions = new();

        RuntimeStartResult start = EngineRuntime.Start(
            binding.Runtime with { ExpressionValidator = expressions, ProjectionWorker = expressions });

        prepared = new PreparedAuthorization(binding, start, redirect, owner, expressions);

        if (!start.Started)
        {
            prepared.Dispose();
            prepared = null!;
            refused = Refuse(identity, ExitCodes.Configuration, RenderRefusals(start.Refusals));
            return false;
        }

        refused = null!;
        return true;
    }

    private static CommandOutcome ManagedStatus(CommandLineResult parsed, string identity)
    {
        if (!HostCommands.Bind(parsed, out HostBinding binding, out CommandOutcome refused))
        {
            return refused;
        }

        StringBuilder text = new(identity);
        text.AppendLine();
        text.AppendLine("managed: upstream authorization is Platform-owned.");

        if (binding.Managed is { } managed)
        {
            text.AppendLine(managed.Describe());
        }

        text.AppendLine(
            "Only authoritative managed-state metadata is reported here. Use Platform Connect, Reauthorize and Disconnect for credential lifecycle; "
            + "local 'auth authorize', 'auth clear' and 'auth authority-reset' are refused in managed mode before any change.");
        return new CommandOutcome(ExitCodes.Success, text.ToString());
    }

    private static string RenderStatus(string identity, IReadOnlyList<StandaloneAuthorizationStatus> status)
    {
        StringBuilder text = new(identity);
        text.AppendLine();

        foreach (StandaloneAuthorizationStatus entry in status)
        {
            text.AppendLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{entry.MountPrefix} {entry.ProfileId} {entry.ProfileKind} {StateName(entry.State)} {entry.Code}"));

            text.AppendLine(entry.Message);

            if (entry.AuthorityEpoch > 0 || entry.RuntimeRevision > 0)
            {
                text.AppendLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"authority epoch {entry.AuthorityEpoch}, revision {entry.RuntimeRevision}"));
            }

            foreach (StandaloneAuthorizationSource source in entry.Sources)
            {
                string detail = source.Detail.Length > 0 ? " " + source.Detail : string.Empty;

                text.AppendLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"source {source.Id} scheme={source.Scheme} slot={source.Slot} {source.Reference} {source.Availability}{detail}"));
            }

            text.AppendLine("next: " + entry.NextAction);
        }

        return text.ToString();
    }

    private static string StateName(StandaloneAuthorizationState state)
        => StandaloneAuthorizationStateNames.Write(state);

    private static int StatusExitCode(IReadOnlyList<StandaloneAuthorizationStatus> status)
    {
        if (status.Any(static entry => entry.State is StandaloneAuthorizationState.Unavailable))
        {
            return ExitCodes.Configuration;
        }

        return status.Any(static entry => entry.State is StandaloneAuthorizationState.Faulted)
            ? ExitCodes.Failure
            : ExitCodes.Success;
    }

    private static int ClearExitCode(StandaloneClearOutcome outcome)
    {
        if (outcome.Cleared || outcome.Code is "oauth/already-cleared" or "oauth/nothing-to-clear")
        {
            return ExitCodes.Success;
        }

        return outcome.Code.StartsWith("standalone/", StringComparison.Ordinal)
            ? ExitCodes.Configuration
            : ExitCodes.Failure;
    }

    private static int ResetExitCode(StandaloneResetOutcome outcome)
    {
        if (outcome.Reset)
        {
            return ExitCodes.Success;
        }

        return outcome.Code switch
        {
            "oauth/reset-acknowledgement-required" => ExitCodes.Configuration,
            var code when code.StartsWith("standalone/", StringComparison.Ordinal) => ExitCodes.Configuration,
            _ => ExitCodes.Failure,
        };
    }

    private static void RecordClear(
        AuthorizationOutcomeLog outcomes,
        string mount,
        string profileId,
        StandaloneClearOutcome outcome)
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();

        outcomes.Record(new AuthorizationOutcome(
            now, "clear", mount, profileId, "local", outcome.Code, outcome.Message));

        outcomes.Record(new AuthorizationOutcome(
            now,
            "clear",
            mount,
            profileId,
            "provider",
            "oauth/revocation-" + outcome.ProviderOutcome,
            outcome.ProviderDetail));
    }

    private static CommandOutcome Record(
        AuthorizationOutcomeLog outcomes,
        string identity,
        string verb,
        string mount,
        string profileId,
        string category,
        string code,
        string message,
        StandaloneAuthorizationOutcome outcome)
    {
        outcomes.Record(new AuthorizationOutcome(
            TimeProvider.System.GetUtcNow(), verb, mount, profileId, category, code, message));

        return new CommandOutcome(
            outcome.Authorized ? ExitCodes.Success : ExitCodes.Failure,
            RenderOutcome(identity, outcome));
    }

    private static CommandOutcome Refuse(string identity, int exitCode, string message)
        => new(exitCode, identity + Environment.NewLine + message + Environment.NewLine);

    private static string RenderRefusals(IReadOnlyList<StartupRefusal> refusals)
    {
        StringBuilder text = new();

        foreach (StartupRefusal refusal in refusals)
        {
            text.AppendLine(StartupReport.RenderRefusal(refusal));
        }

        return text.ToString();
    }

    private static string RenderOutcome(string identity, StandaloneAuthorizationOutcome outcome)
    {
        StringBuilder text = new(identity);
        text.AppendLine();
        text.AppendLine(
            (outcome.Authorized ? "authorized " : "refused ")
            + outcome.MountPrefix + " " + outcome.ProfileId + " " + outcome.Code);
        text.AppendLine(outcome.Message);

        if (outcome.Authorized)
        {
            text.AppendLine(
                $"authority epoch {outcome.AuthorityEpoch.ToString(CultureInfo.InvariantCulture)}, revision {outcome.RuntimeRevision.ToString(CultureInfo.InvariantCulture)}. The serving Engine uses this credential after a restart.");
        }
        else
        {
            text.AppendLine("Nothing was changed. Fix the cause and run 'auth authorize' again.");
        }

        return text.ToString();
    }

    /// <summary>
    /// Everything a validated, leased auth invocation holds, released together when the verb ends.
    /// </summary>
    private sealed class PreparedAuthorization(
        HostBinding binding,
        RuntimeStartResult start,
        Uri? redirect,
        IDisposable? owner,
        WorkerExpressionValidator expressions) : IDisposable
    {
        /// <summary>The resolved configuration the command runs under.</summary>
        internal HostBinding Binding { get; } = binding;

        /// <summary>The started runtime the library seam is handed.</summary>
        internal RuntimeStartResult Start { get; } = start;

        /// <summary>The validated loopback callback URI, when the verb takes one.</summary>
        internal Uri? Redirect { get; } = redirect;

        public void Dispose()
        {
            // The lease is released before the validator, mirroring the take order in reverse.
            // Unconfigured runtime state needs no lease, so the owner is legitimately absent there.
            owner?.Dispose();
            expressions.Dispose();
        }
    }
}
