using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Runtime.Managed;

namespace MCPiler.Engine.Host.Managed;

/// <summary>
/// Keeps one managed deployment's active generation converged with the Platform's desired one.
/// </summary>
/// <remarks>
/// <para>
/// The worker owns the whole managed lifecycle: a bounded initial synchronization that produces
/// the generation the listener opens with, then an endless long-poll that activates replacements.
/// Both paths run through the same load-then-activate sequence, so the generation a process
/// starts with and the generation it later swaps to are produced by one rule.
/// </para>
/// <para>
/// The worker never stops the process. A Platform outage leaves the active generation serving,
/// which is the distributed-system behaviour the protocol was chosen for: the last complete
/// generation is the only thing a client can be served, and it is already loaded.
/// </para>
/// <para>
/// Loaded generations are owned by the manager, not by the worker. Activation hands the manager
/// the candidate and lets retirement dispose the superseded one after its leases drain; a worker
/// that disposed a generation itself would be deciding when a leased request stops executing.
/// </para>
/// </remarks>
internal sealed class ManagedSyncWorker : IDisposable
{
    private readonly ManagedSyncOptions _options;
    private readonly ManagedSyncClient _client;
    private readonly ManagedGenerationLoader _loader;
    private readonly EngineGenerationManager _generations;
    private readonly ManagedSyncBackoff _backoff;
    private readonly Action<string>? _diagnostics;
    private readonly string _engineVersion;
    private readonly PendingReconciliationQueue _reconciliations = new();

    /// <summary>
    /// Minted once per process. The Platform stores it with every report so it can order the
    /// reports of one process monotonically, which is what lets a delayed poll be refused instead
    /// of recorded over a newer observation.
    /// </summary>
    private readonly string _instanceId = Guid.NewGuid().ToString("N");

    private long _reportSequence;
    private long? _sessionEpoch;

    private string? _activeGenerationId;
    private string? _deliveredGenerationId;
    private string? _lastCandidateOutcome;
    private string? _lastCandidateCode;
    private string? _lastCandidateMessage;
    private Task? _running;
    private CancellationTokenSource? _stopping;
    private bool _disposed;

    /// <summary>Creates a worker for one deployment.</summary>
    /// <param name="options">Where the Platform is, which deployment, and every bound.</param>
    /// <param name="loader">The library loader a delivered generation is decoded by.</param>
    /// <param name="generations">The manager activations swap the pointer through.</param>
    /// <param name="engineVersion">This build's identity, reported to the Platform.</param>
    /// <param name="diagnostics">Where worker-level messages an operator should see are written.</param>
    /// <param name="client">The sync client, or null to create the production one.</param>
    /// <param name="backoff">
    /// The backoff sequence, or null to use the production initial/maximum delays. Supplied by
    /// tests so a bounded wait does not spend the real retry schedule.
    /// </param>
    public ManagedSyncWorker(
        ManagedSyncOptions options,
        ManagedGenerationLoader loader,
        EngineGenerationManager generations,
        string engineVersion,
        Action<string>? diagnostics = null,
        ManagedSyncClient? client = null,
        ManagedSyncBackoff? backoff = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(loader);
        ArgumentNullException.ThrowIfNull(generations);
        ArgumentException.ThrowIfNullOrEmpty(engineVersion);

        _options = options;
        _loader = loader;
        _generations = generations;
        _engineVersion = engineVersion;
        _diagnostics = diagnostics;
        _client = client ?? new ManagedSyncClient(options);

        // One second doubling to thirty seconds: the first retry is quick enough that a
        // one-second Platform restart is invisible, and the cap is short enough that a Platform
        // which recovers after an outage is picked up promptly without a manual restart.
        _backoff = backoff ?? new ManagedSyncBackoff(
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(30));
    }

    /// <summary>The generation currently active, or null before a first activation.</summary>
    public string? ActiveGenerationId => _activeGenerationId;

    /// <summary>The last generation activated, even if since superseded.</summary>
    public string? DeliveredGenerationId => _deliveredGenerationId;

    /// <summary>
    /// Records one committed refresh-token rotation for reconciliation.
    /// </summary>
    /// <remarks>
    /// Called from the invocation that rotated, after the local commit. Only identities are
    /// queued; the value is read back from the authoritative encrypted record when the report is
    /// sent, so a rotation that is superseded before it is acknowledged is never reported and a
    /// secret never outlives the request that carried it.
    /// </remarks>
    public void RotationCommitted(
        string mount,
        string profileId,
        string slot,
        long authorityEpoch,
        long previousRuntimeRevision,
        long runtimeRevision)
    {
        _reconciliations.Add(mount, profileId, slot, authorityEpoch, previousRuntimeRevision, runtimeRevision);

        _diagnostics?.Invoke(
            $"managed: rotation committed for profile '{profileId}' slot '{slot}' at "
            + $"epoch {authorityEpoch} revision {runtimeRevision}; awaiting reconciliation.");
    }

    /// <summary>The number of rotations still awaiting Platform acknowledgement.</summary>
    public int PendingReconciliations => _reconciliations.Count;

    /// <summary>
    /// Sends every queued rotation, regenerating each report from the authoritative record.
    /// </summary>
    /// <remarks>
    /// A report is dropped only when the Platform refused it, which means the Platform holds a
    /// different operator decision; an undeliverable report stays queued. Nothing here blocks the
    /// poll: reconciliation runs before it and a failure is reported, not retried in place.
    /// </remarks>
    public async Task ReconcilePendingAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        foreach (PendingReconciliation pending in _reconciliations.Snapshot())
        {
            ManagedSlotSnapshot? record;

            try
            {
                record = await _loader
                    .ReadSlotAsync(pending.Mount, pending.ProfileId, pending.Slot, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is InvalidOperationException or IOException)
            {
                // The record is unreadable, so no honest report can be produced. Leaving it
                // queued means the next attempt re-reads it, after an operator has had a chance
                // to restore the store.
                _diagnostics?.Invoke(
                    $"managed: reconciliation for '{pending.ProfileId}' could not read the local "
                    + $"record: {exception.Message}");
                continue;
            }

            if (record is null)
            {
                // Nothing durable backs the rotation: either the slot is not stored here or the
                // store is not configured. Reporting a value this process does not hold would be
                // inventing state, and the record cannot come back, so the entry is dropped.
                _reconciliations.Acknowledge(
                    pending.Mount,
                    pending.ProfileId,
                    pending.Slot,
                    long.MaxValue);
                continue;
            }

            ReconciliationOutcome outcome = await _client
                .ReconcileAsync(
                    new RuntimeSecretReconciliationMessage
                    {
                        Mount = record.Mount,
                        ProfileId = record.ProfileId,
                        Slot = record.Slot,
                        AuthorityEpoch = record.AuthorityEpoch,
                        PreviousRuntimeRevision = pending.PreviousRuntimeRevision,
                        RuntimeRevision = record.RuntimeRevision,
                        ScopeFingerprint = record.ScopeFingerprint,
                        Value = record.Value,
                    },
                    cancellationToken)
                .ConfigureAwait(false);

            switch (outcome)
            {
                case ReconciliationOutcome.Recorded:
                    _reconciliations.Acknowledge(
                        pending.Mount,
                        pending.ProfileId,
                        pending.Slot,
                        record.RuntimeRevision);
                    break;

                case ReconciliationOutcome.Refused:
                    // A refusal names a Platform state this report no longer matches. Retrying it
                    // would repeat the same refusal forever, and a later generation will carry the
                    // operator's decision.
                    _diagnostics?.Invoke(
                        $"managed: the Platform refused the reconciliation for '{pending.ProfileId}' "
                        + $"slot '{pending.Slot}'; it holds a different decision and the report is dropped.");
                    _reconciliations.Acknowledge(
                        pending.Mount,
                        pending.ProfileId,
                        pending.Slot,
                        long.MaxValue);
                    break;

                default:
                    _diagnostics?.Invoke(
                        $"managed: the reconciliation for '{pending.ProfileId}' slot "
                        + $"'{pending.Slot}' could not be delivered and stays queued.");
                    break;
            }
        }
    }

    /// <summary>
    /// Performs the bounded initial synchronization the listener must not open without.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Bounded means bounded: a Platform that accepts the connection and never answers must not
    /// keep the process from either serving or exiting. When the bound expires the caller gets a
    /// refusal naming synchronization, which is a configuration outcome an orchestrator can act
    /// on rather than a hang it must time out for itself.
    /// </para>
    /// <para>
    /// A Platform that answers "nothing desired" during initial synchronization is also a
    /// refusal. There is no prior generation to serve, so the only honest state is "not ready".
    /// </para>
    /// </remarks>
    /// <param name="cancellationToken">Cancels startup, such as an operator's interrupt.</param>
    /// <returns>The active generation id, or a refusal when none could be obtained.</returns>
    public async Task<ManagedInitialSync> SynchronizeInitialAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using CancellationTokenSource bound = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bound.CancelAfter(_options.InitialSyncBound);

        try
        {
            while (true)
            {
                ManagedPollResult result = await _client
                    .PollAsync(BuildRequest(), _sessionEpoch, bound.Token)
                    .ConfigureAwait(false);

                if (result.SessionEpoch is { } sessionEpoch)
                {
                    _sessionEpoch = sessionEpoch;
                }

                switch (result.Outcome)
                {
                    case ManagedPollOutcome.Delivered when result.Delivery is { } delivery:
                        if (await TryActivateAsync(delivery, bound.Token).ConfigureAwait(false))
                        {
                            return ManagedInitialSync.Ready(delivery.GenerationId);
                        }

                        // A refused first candidate is reported as a synchronization refusal: there
                        // is no previous generation to keep serving, so retrying silently would
                        // hide the defect behind the startup bound.
                        return ManagedInitialSync.Refused(
                            "managed/initial-candidate-refused",
                            $"The Platform delivered generation '{delivery.GenerationId}', and it could "
                            + "not be loaded. Engine has no prior generation to serve, so it will not "
                            + "open a listener.");

                    case ManagedPollOutcome.Unchanged:
                        return ManagedInitialSync.Refused(
                            "managed/initial-generation-absent",
                            "The Platform reports no desired generation for this deployment. Engine "
                            + "will not open a listener that would serve an empty surface; publish a "
                            + "connector and restart, or check the configured deployment identity.");

                    case ManagedPollOutcome.CandidateRefused:
                        return ManagedInitialSync.Refused(
                            result.Diagnostics.Count > 0
                                ? result.Diagnostics[0].Code
                                : "managed/initial-candidate-refused",
                            result.Diagnostics.Count > 0
                                ? result.Diagnostics[0].Message
                                : "The Platform refused the initial generation.");

                    default:
                        // Unreachable, or a retryable failure. Backoff applies within the bound so a
                        // Platform that is only briefly unavailable does not cost a restart.
                        await Task.Delay(_backoff.Next(), bound.Token).ConfigureAwait(false);
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ManagedInitialSync.Refused(
                "managed/initial-sync-timeout",
                $"The Platform at {_client.DescribeEndpoint()} did not deliver an initial generation "
                + $"within {_options.InitialSyncBound.TotalSeconds:F0} second(s). Engine will not open a "
                + "listener without one.");
        }
    }

    /// <summary>
    /// Starts the background long-poll that activates replacements.
    /// </summary>
    /// <remarks>
    /// Called only after the listener has started, so a synchronization failure can no longer
    /// stop the process; it can only leave the active generation in place until the Platform
    /// answers again.
    /// </remarks>
    public void Start(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_running is not null)
        {
            return;
        }

        _stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _running = RunAsync(_stopping.Token);
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // Queued rotations are offered before the poll, so a rotation committed during a
                // long wait is reconciled on the next pass rather than waiting for a wake. A
                // failure here is a diagnostic, never a reason to stop synchronizing.
                if (_reconciliations.Count > 0)
                {
                    await ReconcilePendingAsync(cancellationToken).ConfigureAwait(false);
                }

                ManagedPollResult result = await _client
                    .PollAsync(BuildRequest(), _sessionEpoch, cancellationToken)
                    .ConfigureAwait(false);

                if (result.SessionEpoch is { } sessionEpoch)
                {
                    _sessionEpoch = sessionEpoch;
                }

                switch (result.Outcome)
                {
                    case ManagedPollOutcome.Delivered when result.Delivery is { } delivery:
                        // A duplicate delivery of the generation already active is acknowledged,
                        // not rebuilt. Activating a second generation over an identical one would
                        // retire a generation whose leases are still executing, for no change.
                        if (string.Equals(delivery.GenerationId, _activeGenerationId, StringComparison.Ordinal))
                        {
                            _deliveredGenerationId = delivery.GenerationId;
                            _backoff.Reset();
                            break;
                        }

                        if (await TryActivateAsync(delivery, cancellationToken).ConfigureAwait(false))
                        {
                            _backoff.Reset();
                            break;
                        }

                        // A candidate the loader refused is retried, but never in a hot loop. The
                        // Platform keeps offering the same desired generation until its state
                        // changes, and every poll costs a full desired-state compilation there, so
                        // an immediate retry would turn one bad candidate into a request storm
                        // against the control plane. The bounded backoff applies instead, and the
                        // refusal stays recorded for the next report.
                        await Task.Delay(_backoff.Next(), cancellationToken).ConfigureAwait(false);
                        break;

                    case ManagedPollOutcome.CandidateRefused:
                        _lastCandidateOutcome = ManagedProtocol.CandidateFailed;
                        _lastCandidateCode = result.Diagnostics.Count > 0
                            ? result.Diagnostics[0].Code
                            : "managed/refused";
                        _lastCandidateMessage = result.Diagnostics.Count > 0
                            ? result.Diagnostics[0].Message
                            : "The Platform refused the generation.";
                        await Task.Delay(_backoff.Next(), cancellationToken).ConfigureAwait(false);
                        break;

                    case ManagedPollOutcome.Unchanged:
                        _backoff.Reset();
                        break;

                    default:
                        await Task.Delay(_backoff.Next(), cancellationToken).ConfigureAwait(false);
                        break;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Shutdown. The active generation is retired by the manager's disposal.
                return;
            }
            catch (ObjectDisposedException)
            {
                // The client was disposed while a poll was in flight; shutdown.
                return;
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // One failed pass must not end synchronization for the lifetime of the process.
                // The active generation is already serving; the fault is reported and the bounded
                // backoff applies before the next attempt.
                _diagnostics?.Invoke($"managed: synchronization pass failed: {exception.Message}");
                await Task.Delay(_backoff.Next(), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Loads and activates one delivered generation, reporting a refused candidate.
    /// </summary>
    /// <remarks>
    /// The refusal is reported and the active generation is left alone. That is the whole point
    /// of validating a candidate completely before the swap: a half-applied generation would
    /// serve a mount set nobody desired, and which one a client saw would depend on timing.
    /// </remarks>
    private async Task<bool> TryActivateAsync(ManagedGenerationDelivery delivery, CancellationToken cancellationToken)
    {
        // Receipt is recorded the moment the payload is accepted, before any attempt to load it.
        // The Platform distinguishes "received and refused" from "never arrived", and a refusal
        // that left this unset would make the deployment read as pending when Engine had rejected
        // the candidate outright.
        _deliveredGenerationId = delivery.GenerationId;

        ManagedGenerationLoad loaded;

        try
        {
            // The loader contract reports rotations in primitives because the library side may not
            // name this host's queue; the closure binds them onto it.
            loaded = _loader.Load(
                delivery,
                (mount, profile, slot, epoch, previous, revision, _) =>
                {
                    RotationCommitted(mount, profile, slot, epoch, previous, revision);
                    return ValueTask.CompletedTask;
                });
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or ArgumentException)
        {
            CandidateRefused(
                delivery.GenerationId,
                "managed/candidate-load-failed",
                $"The delivered generation could not be loaded: {exception.Message}");
            return false;
        }

        if (!loaded.Succeeded || loaded.Generation is not { } generation)
        {
            CandidateRefused(
                delivery.GenerationId,
                loaded.Refusals.Count > 0 ? loaded.Refusals[0].Code : "managed/candidate-refused",
                loaded.Refusals.Count > 0
                    ? loaded.Refusals[0].Message
                    : "The delivered generation was refused by the loader.");
            return false;
        }

        long number;

        try
        {
            number = _generations.NextNumber;
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentOutOfRangeException)
        {
            generation.Dispose();
            CandidateRefused(delivery.GenerationId, "managed/activation-failed", exception.Message);
            return false;
        }

        EngineGeneration candidate = new(
            number,
            MountSet.From(generation.Mounts),
            generation.TakeExecution());

        Task retirement = _generations.Activate(candidate);

        _activeGenerationId = delivery.GenerationId;
        _lastCandidateOutcome = ManagedProtocol.Active;
        _lastCandidateCode = null;
        _lastCandidateMessage = null;

        _diagnostics?.Invoke(
            $"managed: activated generation {delivery.GenerationId} at address number {number}.");

        // Retirement is observed in the background: a superseded generation finishes its leased
        // requests on its own schedule, and blocking activation on that would stop new admissions
        // for as long as the oldest in-flight call took.
        Observe(retirement);

        return true;
    }

    /// <summary>
    /// Reports a retirement that ended in failure, without blocking activation on it.
    /// </summary>
    /// <remarks>
    /// A continuation rather than an await: the retirement task is started by the manager, so
    /// awaiting it here would tie this admission path to work it does not own. Only a fault is
    /// interesting; success needs no report because activation already reported.
    /// </remarks>
    private void Observe(Task retirement)
    {
        _ = retirement.ContinueWith(
            task => _diagnostics?.Invoke(
                $"managed: retiring a superseded generation reported {task.Exception?.GetBaseException().Message}"),
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private void CandidateRefused(string generationId, string code, string message)
    {
        // The receipt was recorded before the load attempt, so this only records the outcome. The
        // Platform distinguishes "received and refused" from "never arrived" using that receipt.
        _lastCandidateOutcome = ManagedProtocol.CandidateFailed;
        _lastCandidateCode = code;
        _lastCandidateMessage = message;

        _diagnostics?.Invoke($"managed: candidate {generationId} refused [{code}] {message}");
    }

    private ManagedPollRequestMessage BuildRequest() => new()
    {
        ProtocolVersion = ManagedProtocol.Version,
        EngineVersion = _engineVersion,
        SupportedManifestRange = EngineRuntime.SupportedManifestFormatRange,
        ActiveGenerationId = _activeGenerationId,
        DeliveredGenerationId = _deliveredGenerationId,
        LastCandidateOutcome = _lastCandidateOutcome,
        LastCandidateDiagnostics = _lastCandidateCode is null || _lastCandidateMessage is null
            ? []
            : [new ManagedDiagnosticMessage { Code = _lastCandidateCode, Message = _lastCandidateMessage }],

        // Rotations still awaiting acknowledgement. The Platform records the count for the status
        // surface, which is how an administrator sees a credential that has not converged.
        PendingReconciliationCount = _reconciliations.Count,
        EngineInstanceId = _instanceId,
        EngineReportSequence = ++_reportSequence,
        Compatibility = CompatibilityDescriptor.EngineSupport(),
    };

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_stopping is not null)
        {
            _stopping.Cancel();
            _stopping.Dispose();
        }

        _client.Dispose();
    }
}

/// <summary>The outcome of the bounded initial synchronization.</summary>
/// <param name="Started">True when a generation was activated.</param>
/// <param name="GenerationId">The activated generation id, when one was activated.</param>
/// <param name="Refusal">The startup refusal when none was activated.</param>
internal sealed record ManagedInitialSync(bool Started, string? GenerationId, StartupRefusal? Refusal)
{
    /// <summary>The initial synchronization produced a generation.</summary>
    public static ManagedInitialSync Ready(string generationId) => new(true, generationId, null);

    /// <summary>The initial synchronization produced a refusal.</summary>
    public static ManagedInitialSync Refused(string code, string message) =>
        new(false, null, new StartupRefusal(string.Empty, code, message));
}
