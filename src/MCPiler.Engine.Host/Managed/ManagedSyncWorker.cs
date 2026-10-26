using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;
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
    private readonly HostBinding _binding;
    private readonly ManagedSyncBackoff _backoff;
    private readonly Action<string>? _diagnostics;
    private readonly string _engineVersion;
    private readonly PendingReconciliationQueue _reconciliations;

    /// <summary>
    /// Minted once per process. The Platform stores it with every report so it can order the
    /// reports of one process monotonically, which is what lets a delayed poll be refused instead
    /// of recorded over a newer observation.
    /// </summary>
    private readonly string _instanceId = Guid.NewGuid().ToString("N");

    private bool _journalDegradedReported;
    private DateTime _lastJournalDegradedReportUtc = DateTime.MinValue;

    /// <summary>
    /// How often a persistent confirmation-journal degraded state is re-emitted, so a long-lived stalled
    /// Engine stays observable without flooding the diagnostic stream (R16.5).
    /// </summary>
    private static readonly TimeSpan JournalDegradedReemitInterval = TimeSpan.FromMinutes(5);

    private long _reportSequence;
    private long? _sessionEpoch;

    private string? _activeGenerationId;
    private string? _deliveredGenerationId;

    /// <summary>
    /// The active generation's mounts, retained so a recovery replay can re-derive an evicted pending
    /// rotation from its durable record on the regular reconciliation cadence rather than only at a
    /// generation activation (R8.5). The mounts are immutable manifest data; the generation wrapper is
    /// never disposed after a successful activation.
    /// </summary>
    private IReadOnlyList<MountedManifest>? _activeMounts;

    /// <summary>
    /// Resume index of the bounded recovery replay, so a replay over more unreconciled identities than
    /// the queue capacity covers all of them across passes rather than re-overflowing on the same head
    /// (R9.2).
    /// </summary>
    private int _recoveryReplayCursor;

    /// <summary>
    /// Whether the current recovery replay cycle hit a slot whose durable record could not be read.
    /// A read failure is remembered for the whole cycle, not just one batch, so a clean final batch
    /// cannot acknowledge a recovery that skipped an earlier record (R11.1).
    /// </summary>
    private bool _recoveryReplayReadFailure;
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
    /// <param name="binding">The process-lifetime HTTP/auth capabilities every candidate must remain servable by.</param>
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
        HostBinding binding,
        string engineVersion,
        Action<string>? diagnostics = null,
        ManagedSyncClient? client = null,
        ManagedSyncBackoff? backoff = null,
        int reconciliationQueueCapacity = PendingReconciliationQueue.DefaultMaximumEntries)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(loader);
        ArgumentNullException.ThrowIfNull(generations);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentException.ThrowIfNullOrEmpty(engineVersion);

        _options = options;
        _loader = loader;
        _generations = generations;
        _binding = binding;
        _engineVersion = engineVersion;
        _diagnostics = diagnostics;
        _reconciliations = new PendingReconciliationQueue(reconciliationQueueCapacity, diagnostics);
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

    /// <summary>Test seam: whether a recovery replay is still owed.</summary>
    internal bool RecoveryRequested => _reconciliations.RecoveryRequested;

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
                // inventing state, and the record cannot come back, so the entry is dropped. The
                // acknowledgement names the snapshot's full version, so a newer rotation admitted
                // during the read is never removed (R7.1).
                _reconciliations.Acknowledge(
                    pending.Mount,
                    pending.ProfileId,
                    pending.Slot,
                    pending.AuthorityEpoch,
                    pending.RuntimeRevision);
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
                    _sessionEpoch,
                    cancellationToken)
                .ConfigureAwait(false);

            switch (outcome)
            {
                case ReconciliationOutcome.Recorded:
                    // Durably remember what the Platform now holds for this slot, so a recovery report
                    // after a restart bases on it rather than on the served generation's declared
                    // revision (R10.6). The confirmation is not best-effort: if the journal cannot be
                    // written the report stays queued and is retried, because a reconciliation the
                    // Platform accepted but Engine cannot durably remember would still be stranded by a
                    // later revision mismatch (R11.2).
                    if (!_loader.RecordConfirmedRevision(
                            pending.Mount,
                            pending.ProfileId,
                            pending.Slot,
                            record.AuthorityEpoch,
                            record.RuntimeRevision))
                    {
                        _diagnostics?.Invoke(
                            $"managed: the Platform recorded the reconciliation for '{pending.ProfileId}' "
                            + $"slot '{pending.Slot}' but the local confirmation could not be written; it "
                            + "stays queued and will be retried.");
                        break;
                    }

                    _reconciliations.Acknowledge(
                        pending.Mount,
                        pending.ProfileId,
                        pending.Slot,
                        record.AuthorityEpoch,
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
                        pending.AuthorityEpoch,
                        pending.RuntimeRevision);
                    break;

                default:
                    _diagnostics?.Invoke(
                        $"managed: the reconciliation for '{pending.ProfileId}' slot "
                        + $"'{pending.Slot}' could not be delivered and stays queued.");
                    break;
            }
        }

        // A reconciliation is a path that can observe the journal: a Record refused because the journal is
        // integrity-failed must surface the degraded state without waiting for a new activation (R16.5).
        EvaluateJournalDegraded();
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
                            _lastCandidateCode ?? "managed/initial-candidate-refused",
                            _lastCandidateMessage
                                ?? $"The Platform delivered generation '{delivery.GenerationId}', and it could "
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

                // An overflow eviction drops a committed, unreconciled rotation from the in-memory
                // queue. Re-derive it from the durable record on this pass rather than waiting for a
                // generation activation that may never arrive; the acknowledged-version memory keeps an
                // already-decided rotation from being resent (R8.5).
                if (_activeMounts is { } activeMounts && _reconciliations.RecoveryRequested)
                {
                    var recoveryVersion = _reconciliations.RecoveryVersion;
                    try
                    {
                        DurableReplayBatch batch = await _loader.ReplayDurableRotationsBatchAsync(
                            activeMounts,
                            (mount, profile, slot, epoch, previous, revision, _) =>
                            {
                                RotationCommitted(mount, profile, slot, epoch, previous, revision);
                                return ValueTask.CompletedTask;
                            },
                            _recoveryReplayCursor,
                            _reconciliations.Capacity,
                            cancellationToken).ConfigureAwait(false);

                        // Advance the resume position. It restarts only once the whole candidate list has
                        // been traversed (NextCursor is null).
                        _recoveryReplayCursor = batch.NextCursor ?? 0;

                        // A read failure is a property of the whole replay cycle, not one batch: a slot
                        // that could not be read in an early batch sits behind the advanced cursor and
                        // would never be revisited by a later clean batch (R11.1).
                        if (batch.Incomplete)
                        {
                            _recoveryReplayReadFailure = true;
                        }

                        // Only a fully traversed cycle in which every durable record was readable completes
                        // recovery. While a resume cursor remains, the bounded batch left unreconciled
                        // candidates unvisited. At the end of a cycle that skipped any record, start a fresh
                        // full pass and stay requested, so the skipped slots are actually re-read before
                        // recovery is acknowledged (R10.1, R10.2, R11.1).
                        if (batch.NextCursor is null)
                        {
                            if (_recoveryReplayReadFailure)
                            {
                                _recoveryReplayReadFailure = false;
                                _diagnostics?.Invoke(
                                    "managed: recovery replay could not read one or more durable records; "
                                    + "recovery remains pending and the candidate list will be replayed again.");
                            }
                            else
                            {
                                _reconciliations.AcknowledgeRecovery(recoveryVersion);
                            }
                        }
                    }
                    catch (Exception exception) when (exception is not OperationCanceledException)
                    {
                        // Leave the request in place so a later pass retries the recovery.
                        _diagnostics?.Invoke($"managed: recovery replay failed: {exception.Message}");
                    }
                }

                // The journal's integrity is observable on any path: re-evaluate it every pass so a failure
                // first seen by the cyclic recovery replay or a reconciliation is reported without waiting
                // for a new activation, and a long-lived stalled Engine keeps a bounded re-emit (R16.5).
                EvaluateJournalDegraded();

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
    /// Evaluates and reports the confirmation journal's integrity on any path that can observe it: a
    /// generation activation, the cyclic recovery replay and a reconciliation write. The state is surfaced
    /// precisely on the <c>managed:</c> diagnostic stream (this message) and by <c>/health/managed</c>
    /// returning 503; <c>/health/ready</c> and <c>/health/live</c> are deliberately unaffected (R16.7). An
    /// integrity-failed journal is operator-visible and stalls managed recovery until an explicit reset; it
    /// is re-emitted at a bounded interval so a long-lived stalled Engine stays observable, and a return to
    /// health emits one recovery message. A transient read failure is never reported as degraded, and a
    /// failure after a clear is reported again (R15.12/R16.5). The journal path and slot values are never
    /// printed.
    /// </summary>
    private void EvaluateJournalDegraded()
    {
        if (!_loader.IsConfirmedJournalDegraded())
        {
            if (_journalDegradedReported)
            {
                _journalDegradedReported = false;
                _diagnostics?.Invoke(
                    "managed: the durable confirmation journal reads as valid again; managed reconciliation "
                    + "can resume.");
            }

            return;
        }

        var now = DateTime.UtcNow;
        if (_journalDegradedReported && now - _lastJournalDegradedReportUtc < JournalDegradedReemitInterval)
        {
            return;
        }

        _journalDegradedReported = true;
        _lastJournalDegradedReportUtc = now;
        _diagnostics?.Invoke(
            "managed: the durable confirmation journal failed its integrity check, so no reconciliation can be "
            + "confirmed from it and managed recovery is stalled. Run the operator action "
            + "'confirmed-revisions reset' to move the corrupt journal aside (its bytes are never deleted); "
            + "nothing recovers it automatically.");
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

        Dictionary<string, string> externalResources = generation.ExternalResources.ToDictionary(
            binding => binding.MountPrefix + "/" + binding.SurfaceSlug,
            binding => binding.ExternalResourceUri,
            StringComparer.Ordinal);

        MountSet mounts = MountSet.From(generation.Mounts);
        IReadOnlyList<StartupRefusal> topologyRefusals = HostRouteTopologyValidation.Find(mounts);

        if (topologyRefusals.Count > 0)
        {
            generation.Dispose();
            StartupRefusal first = topologyRefusals[0];
            CandidateRefused(delivery.GenerationId, first.Code, first.Message);
            return false;
        }

        // A managed replacement must be servable by the listener that already exists. The
        // listener's authentication middleware and public-authority policy are process-lifetime
        // capabilities; activating a protected Manifest that those capabilities cannot enforce
        // would either replace a good generation with an unusable one or bypass authorization.
        if (AuthorizationRefusal.Find(mounts.Mounts, _binding.Authorization) is { } authorizationRefusal)
        {
            generation.Dispose();
            CandidateRefused(
                delivery.GenerationId,
                authorizationRefusal.Code,
                authorizationRefusal.Message);
            return false;
        }

if (_binding.Listener.Transport is HostTransport.Http
            && ProtectedResourceAuthorityValidation.Find(
                mounts,
                externalResources,
                _binding.AllowedHosts,
                _binding.Authorization is not null) is { } authorityRefusal)
        {
            generation.Dispose();
            CandidateRefused(
                delivery.GenerationId,
                authorityRefusal.Code,
                authorityRefusal.Message);
            return false;
        }

        EngineGeneration candidate = new(
            number,
            mounts,
            generation.TakeExecution(),
            externalResources: externalResources);

        Task retirement = _generations.Activate(candidate);

        _activeGenerationId = delivery.GenerationId;
        _activeMounts = generation.Mounts;

        // Only now that the candidate is the active generation may the durable confirmation journal be
        // bounded to its mounts. A candidate that host validation refused above returned before this
        // point, so it never mutated the running generation's durable state (R12.2).
        _loader.PruneConfirmedRevisions(generation.Mounts);

        _lastCandidateOutcome = ManagedProtocol.Active;
        _lastCandidateCode = null;
        _lastCandidateMessage = null;

        _diagnostics?.Invoke(
            $"managed: activated generation {delivery.GenerationId} at address number {number}.");

        EvaluateJournalDegraded();

        // Retirement is observed in the background: a superseded generation finishes its leased
        // requests on its own schedule, and blocking activation on that would stop new admissions
        // for as long as the oldest in-flight call took.
        Observe(retirement);

        // The in-memory reconciliation queue does not survive a restart, so any rotation this
        // process committed locally and still owes the Platform is re-derived from the durable
        // encrypted records the active generation declares (MTH-ENG-9). Failure to replay never
        // fails activation: the records remain durable and a later pass retries.
        try
        {
            DurableReplayBatch replay = await _loader.ReplayDurableRotationsAsync(
                generation,
                (mount, profile, slot, epoch, previous, revision, _) =>
                {
                    RotationCommitted(mount, profile, slot, epoch, previous, revision);
                    return ValueTask.CompletedTask;
                },
                cancellationToken).ConfigureAwait(false);

            // A pass that could not read a durable record or confirmation has not recovered everything this
            // process still owes. Keep recovery requested so the cyclic replay retries the unread slot;
            // activation itself still succeeds, because the records are durable and a later pass reconciles
            // them (R13.2).
            if (replay.Incomplete)
            {
                _reconciliations.RequestRecovery();
                _diagnostics?.Invoke(
                    "managed: initial durable rotation replay could not read one or more records; "
                    + "recovery remains pending.");
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _diagnostics?.Invoke($"managed: durable rotation replay failed: {exception.Message}");
        }

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
