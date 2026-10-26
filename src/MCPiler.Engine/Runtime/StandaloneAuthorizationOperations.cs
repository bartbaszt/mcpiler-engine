using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Runtime;

/// <summary>
/// The state one file-mode authentication profile's runtime authorization is in, as an operator
/// can be told it without disclosing a credential.
/// </summary>
public enum StandaloneAuthorizationState
{
    /// <summary>No declared refresh credential and no local authorization decision exist.</summary>
    Unconfigured,

    /// <summary>A declared refresh credential exists; no local authorization decision has been made.</summary>
    Configured,

    /// <summary>An authorization attempt is in flight in this process.</summary>
    Authorizing,

    /// <summary>A usable local authorization decision is established.</summary>
    Authorized,

    /// <summary>Runtime or declared authority exists, but the current binding cannot use it.</summary>
    ReauthorizationRequired,

    /// <summary>An explicit local clear floor is in force and masks every earlier source.</summary>
    Cleared,

    /// <summary>The durable authority record cannot be authenticated or read.</summary>
    Faulted,

    /// <summary>A coherent read cannot be guaranteed, so no state is claimed.</summary>
    Unavailable,

    /// <summary>
    /// The deployment is managed by the Platform: no local authorization state is read and every
    /// local mutation is refused. Deliberately a distinct state rather than
    /// <see cref="Unavailable"/>, which means a read that could not be trusted in a file-mode
    /// deployment.
    /// </summary>
    Managed,
}

/// <summary>
/// The stable spelling of one authorization state.
/// </summary>
/// <remarks>
/// The library owns the vocabulary and every surface reads it, so an operator script that matches
/// <c>reauthorization-required</c> on the command line matches the same state on the authenticated
/// channel. Each surface deciding its own spelling would make two names for one state, and the one a
/// script matched would be whichever surface it happened to ask.
/// </remarks>
public static class StandaloneAuthorizationStateNames
{
    /// <summary>Writes the lower-case spelling of <paramref name="state"/>.</summary>
    /// <param name="state">The state one profile is in.</param>
    public static string Write(StandaloneAuthorizationState state) => state switch
    {
        StandaloneAuthorizationState.Unconfigured => "unconfigured",
        StandaloneAuthorizationState.Configured => "configured",
        StandaloneAuthorizationState.Authorizing => "authorizing",
        StandaloneAuthorizationState.Authorized => "authorized",
        StandaloneAuthorizationState.ReauthorizationRequired => "reauthorization-required",
        StandaloneAuthorizationState.Cleared => "cleared",
        StandaloneAuthorizationState.Faulted => "faulted",
        StandaloneAuthorizationState.Managed => "managed",
        _ => "unavailable",
    };
}

/// <summary>
/// One declared credential reference as it appears to an operator: reference shape and
/// availability, never a value.
/// </summary>
/// <param name="Id">The manifest credential id the profile references.</param>
/// <param name="Slot">The slot the credential fills, for example <c>refreshToken</c>.</param>
/// <param name="Scheme">The credential scheme, for example <c>oauth2-authorization-code</c>.</param>
/// <param name="Reference">
/// The reference shape, such as <c>fromEnv:NAME</c>, <c>fromFile:/path</c> or <c>inline:(redacted)</c>.
/// Never a secret value.
/// </param>
/// <param name="Availability">Whether the reference currently resolves: <c>present</c> or <c>unresolvable</c>.</param>
/// <param name="Detail">A bounded, non-secret reason when the reference does not resolve.</param>
public sealed record StandaloneAuthorizationSource(
    string Id,
    string Slot,
    string Scheme,
    string Reference,
    string Availability,
    string Detail);

/// <summary>
/// The non-secret status of one mount/profile's runtime authorization.
/// </summary>
/// <param name="MountPrefix">The mounted Manifest prefix.</param>
/// <param name="ProfileId">The manifest-local profile id.</param>
/// <param name="ProfileKind">The declared authentication kind.</param>
/// <param name="State">The deterministic state.</param>
/// <param name="Code">A stable, scriptable state code.</param>
/// <param name="Message">A bounded, actionable, non-secret description.</param>
/// <param name="NextAction">The supported operator action for this state.</param>
/// <param name="Sources">
/// Every credential the profile references, with source metadata only. Empty when the profile
/// references none.
/// </param>
/// <param name="AuthorityEpoch">The effective authority epoch, or 0 when none is established.</param>
/// <param name="RuntimeRevision">The effective runtime revision, or 0 when none is established.</param>
public sealed record StandaloneAuthorizationStatus(
    string MountPrefix,
    string ProfileId,
    string ProfileKind,
    StandaloneAuthorizationState State,
    string Code,
    string Message,
    string NextAction,
    IReadOnlyList<StandaloneAuthorizationSource> Sources,
    long AuthorityEpoch,
    long RuntimeRevision);

/// <summary>
/// The outcome of clearing one runtime-owned OAuth refresh slot, with the local and provider
/// results stated separately.
/// </summary>
/// <param name="Cleared">Whether a cleared floor is now durably authoritative for the slot.</param>
/// <param name="Code">A stable, scriptable outcome category.</param>
/// <param name="Message">A bounded, actionable, non-secret description.</param>
/// <param name="MountPrefix">The mount the clear concerned.</param>
/// <param name="ProfileId">The profile the clear concerned.</param>
/// <param name="AuthorityEpoch">The committed cleared epoch, when a clear was committed.</param>
/// <param name="RuntimeRevision">The committed revision, when a clear was committed.</param>
/// <param name="LocalOutcome">
/// <c>cleared</c>, <c>already-cleared</c> or <c>nothing-to-clear</c>. The local guarantee is stated
/// in these terms only.
/// </param>
/// <param name="ProviderOutcome"><c>revoked</c>, <c>not-attempted</c> or <c>failed</c>.</param>
/// <param name="ProviderDetail">A bounded, non-secret reason for the provider outcome.</param>
public sealed record StandaloneClearOutcome(
    bool Cleared,
    string Code,
    string Message,
    string MountPrefix,
    string ProfileId,
    long AuthorityEpoch,
    long RuntimeRevision,
    string LocalOutcome,
    string ProviderOutcome,
    string ProviderDetail);

/// <summary>
/// The outcome of an acknowledged destructive authority reset.
/// </summary>
/// <param name="Reset">Whether every affected slot now holds a fresh fail-closed baseline.</param>
/// <param name="Code">A stable, scriptable outcome category.</param>
/// <param name="Message">A bounded, actionable, non-secret description.</param>
/// <param name="MountPrefix">The mount the reset concerned.</param>
/// <param name="ProfileId">The profile the reset concerned.</param>
/// <param name="AffectedSlots">Every slot whose authority could not be authenticated.</param>
/// <param name="Results">Per-slot outcomes, in declaration order.</param>
public sealed record StandaloneResetOutcome(
    bool Reset,
    string Code,
    string Message,
    string MountPrefix,
    string ProfileId,
    IReadOnlyList<string> AffectedSlots,
    IReadOnlyList<string> Results);

/// <summary>
/// Status, clear and acknowledged reset for one file-mode mount/profile. The CLI is the first
/// caller; the authenticated in-host operator channel is the second.
/// </summary>
/// <remarks>
/// <para>
/// Every operation here is a read or a single atomic authority commit. Nothing is deleted: a clear
/// writes a cleared tombstone, and an acknowledged reset overwrites an unauthenticated record with
/// a fresh fail-closed baseline in one commit, so the slot is never observably absent.
/// </para>
/// <para>
/// Refusals are returned as values, never thrown, so a caller renders them through the same path
/// as any other operator outcome.
/// </para>
/// </remarks>
public static class StandaloneAuthorizationOperations
{
    /// <summary>The slot the runtime rotates, and the only one these operations touch.</summary>
    private const string RefreshTokenSlot = OAuthTokenService.RefreshTokenSlot;

    /// <summary>The client-secret slot a secret-based token endpoint needs.</summary>
    private const string ClientSecretSlot = "clientSecret";

    /// <summary>
    /// Reports the state of one mount/profile, or of every profile when no profile is named.
    /// </summary>
    /// <param name="start">A started runtime whose mounts are loaded and validated.</param>
    /// <param name="mountPrefix">The mount to report, or null for every mounted Manifest.</param>
    /// <param name="profileId">The profile to report, or null for every profile of the mount.</param>
    /// <param name="ownerElsewhere">
    /// Whether another process holds this runtime-state root. A status read that could race a live
    /// mutation reports <see cref="StandaloneAuthorizationState.Unavailable"/> instead of claiming
    /// a state it cannot guarantee.
    /// </param>
    /// <param name="cancellationToken">Cancels reading declared credential availability.</param>
    public static async ValueTask<IReadOnlyList<StandaloneAuthorizationStatus>> DescribeAsync(
        RuntimeStartResult start,
        string? mountPrefix = null,
        string? profileId = null,
        bool ownerElsewhere = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(start);

        if (!start.Started || start.RuntimeState is null)
        {
            return
            [
                Unavailable(
                    mountPrefix ?? string.Empty,
                    profileId ?? string.Empty,
                    string.Empty,
                    "standalone/runtime-refused",
                    "This process has no started runtime with a durable runtime-state store, so no local authorization state exists to report."),
            ];
        }

        List<StandaloneAuthorizationStatus> report = [];

        foreach (MountedManifest mount in start.Mounts)
        {
            if (mountPrefix is { Length: > 0 }
                && !string.Equals(mount.Prefix, mountPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (AuthenticationProfile profile in mount.Document.EffectiveAuthentication.Profiles)
            {
                if (profileId is { Length: > 0 }
                    && !string.Equals(profile.Id, profileId, StringComparison.Ordinal))
                {
                    continue;
                }

                report.Add(await DescribeOneAsync(start, mount, profile, ownerElsewhere, cancellationToken)
                    .ConfigureAwait(false));
            }
        }

        if (report.Count > 0)
        {
            return report;
        }

        return
        [
            Unavailable(
                mountPrefix ?? string.Empty,
                profileId ?? string.Empty,
                string.Empty,
                mountPrefix is { Length: > 0 } ? "standalone/unknown-profile" : "standalone/unknown-mount",
                mountPrefix is { Length: > 0 }
                    ? $"Mount '{mountPrefix}' declares no authentication profile '{(profileId ?? string.Empty)}'."
                    : $"No Manifest is mounted at '{(mountPrefix ?? string.Empty)}'."),
        ];
    }

    /// <summary>
    /// Clears the runtime-owned refresh authorization of one mount/profile by committing an
    /// advancing cleared tombstone, then attempts bounded best-effort provider revocation.
    /// </summary>
    /// <param name="start">A started runtime with a durable runtime-state store.</param>
    /// <param name="mountPrefix">The mounted Manifest prefix that declares the profile.</param>
    /// <param name="profileId">The manifest-local profile id to clear.</param>
    /// <param name="timeProvider">The clock used for the revocation deadline.</param>
    /// <param name="connections">Which addresses the declared revocation endpoint may be reached at.</param>
    /// <param name="allowLoopbackAuthorization">
    /// True only when the operator explicitly allowed this transport to reach a loopback
    /// revocation endpoint. Ignored when <paramref name="connections"/> is supplied, and it
    /// changes nothing for tool execution, which does not read it.
    /// </param>
    /// <param name="cancellationToken">Cancels the clear and its revocation attempt.</param>
    public static async ValueTask<StandaloneClearOutcome> ClearAsync(
        RuntimeStartResult start,
        string mountPrefix,
        string profileId,
        TimeProvider? timeProvider = null,
        OutboundConnectionPolicy? connections = null,
        bool allowLoopbackAuthorization = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentException.ThrowIfNullOrEmpty(mountPrefix);
        ArgumentException.ThrowIfNullOrEmpty(profileId);

        TargetResolution target = ResolveTarget(start, mountPrefix, profileId, authorizationCodeRequired: true);

        if (!target.Resolved)
        {
            return new StandaloneClearOutcome(
                false, target.Code!, target.Message!, mountPrefix, profileId, 0, 0,
                "not-cleared", "not-attempted", "the local clear was refused before any change");
        }

        MountedManifest mount = target.Mount!;
        AuthenticationProfile profile = target.Profile!;
        AuthenticationSlot slot = target.Slot!;
        OAuthStrategyConfiguration configuration = target.Configuration!;
        IMutableSlotStore store = start.RuntimeState!.CreateForMount(mount.Prefix);

        List<DeclaredCredential> declared = await ResolveDeclaredAsync(
            mount, profile, start.AllowInlineSecrets, cancellationToken).ConfigureAwait(false);

        MutableSlotDecision? prior;

        try
        {
            prior = await store.LoadDecisionAsync(profile.Id, slot.Slot, cancellationToken).ConfigureAwait(false);
        }
        catch (RuntimeStateStoreException)
        {
            return new StandaloneClearOutcome(
                false,
                "oauth/authority-unreadable",
                "The local authority record exists but cannot be authenticated with the configured key, so it is not equivalent to an absent slot and cannot be cleared. This needs the acknowledged destructive recovery: 'auth authority-reset <mount> <profile> --acknowledge-irrecoverable'.",
                mount.Prefix,
                profile.Id,
                0,
                0,
                "not-cleared",
                "not-attempted",
                "nothing was read or written because the local authority could not be authenticated");
        }

        bool declaredRefresh = declared.Any(static credential =>
            credential.Declaration.Scheme == CredentialScheme.OAuth2AuthorizationCode
            && string.Equals(credential.Declaration.Slot, RefreshTokenSlot, StringComparison.Ordinal));

        if (prior is { Kind: MutableSlotDecisionKind.Cleared })
        {
            // Already cleared. Advancing another epoch would change nothing an operator can
            // observe, and the existing floor already masks every earlier source, so this is the
            // documented no-op: no write, no unmasking.
            return new StandaloneClearOutcome(
                false,
                "oauth/already-cleared",
                "This slot is already cleared. The existing clear floor still masks the runtime record and every earlier Manifest-declared value, so nothing was changed.",
                mount.Prefix,
                profile.Id,
                prior.AuthorityEpoch,
                prior.RuntimeRevision,
                "already-cleared",
                "not-attempted",
                "no local authorization remained to revoke");
        }

        if (prior is null && !declaredRefresh)
        {
            return new StandaloneClearOutcome(
                false,
                "oauth/nothing-to-clear",
                "Neither a local authorization decision nor a Manifest-declared refresh credential exists for this slot, so there is nothing to clear and nothing was changed.",
                mount.Prefix,
                profile.Id,
                slot.AuthorityEpoch,
                0,
                "nothing-to-clear",
                "not-attempted",
                "no runtime or Manifest-declared refresh credential exists for this slot");
        }

        // The cleared epoch must exceed both the Manifest-declared authority and any committed
        // local decision. A clear is an explicit operator act, so it starts a new epoch at revision
        // zero rather than revising the previous one.
        long baseEpoch = Math.Max(slot.AuthorityEpoch, prior?.AuthorityEpoch ?? slot.AuthorityEpoch);

        if (baseEpoch == long.MaxValue)
        {
            return new StandaloneClearOutcome(
                false,
                "oauth/persistence-failed",
                "The local authority epoch cannot be advanced further, so the slot was not cleared.",
                mount.Prefix, profile.Id, 0, 0,
                "not-cleared", "not-attempted", "the local clear was refused before any change");
        }

        var tombstone = new MutableSlotDecision(
            profile.Id,
            slot.Slot,
            profile.ScopeFingerprint,
            AuthorityBinding.Declaration(profile),
            AuthorityBinding.Configuration(configuration),
            baseEpoch + 1,
            0,
            MutableSlotDecisionKind.Cleared,
            RefreshToken: null);

        MutableSlotDecision committed;

        try
        {
            committed = await store
                .CompareAndCommitAsync(tombstone, prior?.Version, slot.AuthorityEpoch, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (RuntimeStateStoreException)
        {
            return new StandaloneClearOutcome(
                false,
                "oauth/persistence-failed",
                "The cleared floor could not be durably committed, so the slot was not cleared and the previous authority is unchanged. Make the runtime-state store writable and try again.",
                mount.Prefix, profile.Id, 0, 0,
                "not-cleared", "not-attempted", "the local clear was refused before any remote attempt");
        }

        // The commit point has passed. Nothing below may report the local clear as failed: a
        // provider revocation attempt, a diagnostic failure or a caller cancellation cannot undo a
        // committed tombstone.
        var revocationClient = new OAuthTokenEndpointClient(
            new UpstreamSender(new UpstreamClientFactory(
                StandaloneAuthorizationTransport.Policy(connections, allowLoopbackAuthorization))),
            timeProvider ?? TimeProvider.System);

        (string? revokeToken, string? revokeSecret) = RevocationMaterial(prior?.RefreshToken, declared);

        (string providerOutcome, string providerDetail) = await TryRevokeAsync(
            revocationClient, profile, configuration, revokeToken, revokeSecret, cancellationToken)
            .ConfigureAwait(false);

        return new StandaloneClearOutcome(
            true,
            "oauth/cleared",
            "The runtime-owned refresh authorization was durably cleared, so the next acquisition and a fresh restarted Engine cannot use the previous record or an earlier Manifest-declared value.",
            mount.Prefix,
            profile.Id,
            committed.AuthorityEpoch,
            committed.RuntimeRevision,
            "cleared",
            providerOutcome,
            providerDetail);
    }

    /// <summary>
    /// Clears one mount/profile's local authority through the runtime the serving process is
    /// actually using, then attempts bounded best-effort provider revocation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the in-host counterpart of <see cref="ClearAsync"/>. The difference is not the
    /// decision — the same tombstone is committed over the same store — but the <em>gate it commits
    /// under</em>. Routing it through the mount's own runtime means the clear shares the slot gate
    /// and the access-token cache a served request uses, so an acquisition already in flight when
    /// the clear commits refuses to publish what it holds. A CLI clear has no in-flight acquisition
    /// to fence, which is why it takes the store directly.
    /// </para>
    /// <para>
    /// The mount's own transport performs the revocation attempt, so the address judgement that
    /// governs the served deployment is the one that governs its revocation traffic. Nothing here
    /// widens what a deployment may reach.
    /// </para>
    /// </remarks>
    /// <param name="start">A started runtime with a durable runtime-state store.</param>
    /// <param name="execution">The execution graph the serving process invokes through.</param>
    /// <param name="mountPrefix">The mounted Manifest prefix that declares the profile.</param>
    /// <param name="profileId">The manifest-local profile id to clear.</param>
    /// <param name="timeProvider">The clock used for the revocation deadline.</param>
    /// <param name="cancellationToken">Cancels the clear and its revocation attempt.</param>
    public static async ValueTask<StandaloneClearOutcome> ClearServingAsync(
        RuntimeStartResult start,
        EngineExecution execution,
        string mountPrefix,
        string profileId,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentException.ThrowIfNullOrEmpty(mountPrefix);
        ArgumentException.ThrowIfNullOrEmpty(profileId);

        TargetResolution target = ResolveTarget(start, mountPrefix, profileId, authorizationCodeRequired: true);

        if (!target.Resolved)
        {
            return new StandaloneClearOutcome(
                false, target.Code!, target.Message!, mountPrefix, profileId, 0, 0,
                "not-cleared", "not-attempted", "the local clear was refused before any change");
        }

        MountedManifest mount = target.Mount!;
        AuthenticationProfile profile = target.Profile!;
        OAuthStrategyConfiguration configuration = target.Configuration!;

        if (execution.MountAuthentication(mount.Prefix) is not { } runtime)
        {
            // The generation serves no such prefix. Refusing here keeps a clear from being reported
            // against a mount this process does not serve.
            return new StandaloneClearOutcome(
                false,
                "standalone/unknown-mount",
                $"The serving execution serves no mount at '{mountPrefix}', so there is no in-flight authority to fence and nothing to clear.",
                mountPrefix, profileId, 0, 0,
                "not-cleared", "not-attempted", "nothing was read or written");
        }

        List<DeclaredCredential> declared = await ResolveDeclaredAsync(
            mount, profile, start.AllowInlineSecrets, cancellationToken).ConfigureAwait(false);

        bool declaredRefresh = declared.Any(static credential =>
            credential.Declaration.Scheme == CredentialScheme.OAuth2AuthorizationCode
            && string.Equals(credential.Declaration.Slot, RefreshTokenSlot, StringComparison.Ordinal));

        OAuthAuthorityClear clear = await runtime.OAuth
            .ClearAuthorityAsync(profile, declaredRefresh, cancellationToken)
            .ConfigureAwait(false);

        if (!clear.Cleared)
        {
            string local = clear.Code switch
            {
                "oauth/already-cleared" => "already-cleared",
                "oauth/nothing-to-clear" => "nothing-to-clear",
                _ => "not-cleared",
            };

            return new StandaloneClearOutcome(
                false,
                clear.Code,
                clear.Message,
                mount.Prefix,
                profile.Id,
                clear.AuthorityEpoch,
                clear.RuntimeRevision,
                local,
                "not-attempted",
                "the local clear was refused before any remote attempt");
        }

        // The commit point has passed, so nothing below can report the local clear as failed.
        (string? revokeToken, string? revokeSecret) = RevocationMaterial(clear.PriorRefreshToken, declared);

        (string providerOutcome, string providerDetail) = await TryRevokeAsync(
            new OAuthTokenEndpointClient(runtime.Transport, timeProvider ?? TimeProvider.System),
            profile,
            configuration,
            revokeToken,
            revokeSecret,
            cancellationToken).ConfigureAwait(false);

        return new StandaloneClearOutcome(
            true,
            "oauth/cleared",
            "The runtime-owned refresh authorization was durably cleared, so the next acquisition and a fresh restarted Engine cannot use the previous record or an earlier Manifest-declared value.",
            mount.Prefix,
            profile.Id,
            clear.AuthorityEpoch,
            clear.RuntimeRevision,
            "cleared",
            providerOutcome,
            providerDetail);
    }

    /// <summary>
    /// Opens one host-owned authorization attempt and records it as a single-use relay session.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The attempt is built by the serving process and stays there; the caller receives a handle, the
    /// authorization URL to present, the callback the attempt is registered for, and the deadline.
    /// The session is bound to <paramref name="credentialFingerprint"/>, so only the credential that
    /// opened it may complete or abandon it.
    /// </para>
    /// <para>
    /// Nothing is contacted here: opening a session builds a URL and a verifier. The provider is
    /// reached only when the callback is completed.
    /// </para>
    /// </remarks>
    /// <param name="start">A started runtime with a durable runtime-state store.</param>
    /// <param name="execution">The execution graph the serving process invokes through.</param>
    /// <param name="sessions">The process-wide set of unfinished sessions.</param>
    /// <param name="target">The mount, profile and loopback callback URI to authorize.</param>
    /// <param name="credentialFingerprint">A non-secret identity for the credential opening it.</param>
    /// <param name="timeProvider">The clock used for the attempt lifetime and exchange.</param>
    /// <param name="cancellationToken">Cancels reading a declared file-backed client secret.</param>
    public static async ValueTask<StandaloneAuthorizationRelayStart> OpenRelayAsync(
        RuntimeStartResult start,
        EngineExecution execution,
        StandaloneAuthorizationRelaySessions sessions,
        StandaloneAuthorizationTarget target,
        string credentialFingerprint,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sessions);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentException.ThrowIfNullOrEmpty(credentialFingerprint);

        StandaloneServingAuthorizationStart begun = await StandaloneAuthorization
            .BeginServingAsync(start, execution, target, timeProvider, cancellationToken)
            .ConfigureAwait(false);

        if (!begun.Started || begun.Attempt is not { } attempt)
        {
            StartupRefusal refusal = begun.Refusals.Count > 0
                ? begun.Refusals[0]
                : new StartupRefusal(target.MountPrefix, "standalone/runtime-refused", "The authorization attempt could not be built.");

            return StandaloneAuthorizationRelayStart.Refused(target.MountPrefix, refusal.Code, refusal.Message);
        }

        StandaloneAuthorizationRelay? relay;

        // The operator has already demonstrated a bound listener: asking this process for an attempt
        // is what the operator does after binding the callback. So the attempt moves to pending here,
        // where it becomes presentable, rather than staying in its pre-presentation state and
        // refusing the callback it was opened for.
        attempt.Begin();

        relay = sessions.Open(target.MountPrefix, target.ProfileId, attempt, credentialFingerprint);

        if (relay is null)
        {
            // The attempt is live but unrecorded, so it is cancelled rather than left holding a
            // verifier no session can ever complete.
            attempt.Cancel();

            return StandaloneAuthorizationRelayStart.Refused(
                target.MountPrefix,
                "standalone/relay-capacity",
                $"This process is already holding {StandaloneAuthorizationRelaySessions.MaximumSessions} unfinished authorizations. Complete or abandon one, then retry.");
        }

        return StandaloneAuthorizationRelayStart.Ready(relay);
    }

    /// <summary>
    /// Takes the session a handle names and commits what the completed provider exchange produced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The handle is single-use: taking it removes it, so a replayed callback is refused before the
    /// attempt is touched. The attempt is single-use too, and the forwarded
    /// <paramref name="state"/> is still compared with the attempt's own value before any exchange.
    /// A handle opened with a different credential is refused without being consumed.
    /// </para>
    /// <para>
    /// A refusal before the take returns a <c>standalone/relay-*</c> category, which says whether the
    /// handle was unknown, expired or presented under the wrong credential. Everything after that is
    /// the same outcome any other completion reports.
    /// </para>
    /// </remarks>
    /// <param name="start">A started runtime with a durable runtime-state store.</param>
    /// <param name="execution">The execution graph the serving process invokes through.</param>
    /// <param name="sessions">The process-wide set of unfinished sessions.</param>
    /// <param name="handle">The single-use handle the operator presented.</param>
    /// <param name="credentialFingerprint">A non-secret identity for the presenting credential.</param>
    /// <param name="state">The callback's decoded <c>state</c>.</param>
    /// <param name="code">The callback's decoded <c>code</c>, when it carried one.</param>
    /// <param name="error">The callback's decoded <c>error</c>, when the provider refused.</param>
    /// <param name="cancellationToken">The completion deadline.</param>
    public static async ValueTask<StandaloneAuthorizationOutcome> CompleteRelayAsync(
        RuntimeStartResult start,
        EngineExecution execution,
        StandaloneAuthorizationRelaySessions sessions,
        string handle,
        string credentialFingerprint,
        string? state,
        string? code,
        string? error,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sessions);
        ArgumentException.ThrowIfNullOrEmpty(handle);
        ArgumentException.ThrowIfNullOrEmpty(credentialFingerprint);

        if (!sessions.TryTake(handle, credentialFingerprint, out OAuthAuthorizationAttempt attempt, out StandaloneAuthorizationRelayRefusal refusal))
        {
            (string refusalCode, string refusalMessage) = RelayRefusal(refusal);

            return new StandaloneAuthorizationOutcome(false, refusalCode, refusalMessage, string.Empty, string.Empty, 0, 0);
        }

        return await AuthorizeServingAsync(start, execution, attempt, state, code, error, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Abandons the session a handle names, for an operator who will not finish it.
    /// </summary>
    /// <remarks>
    /// Abandoning is idempotent: a handle that is already gone is answered as done, because the
    /// operator's intent — this authorization will not be completed — already holds. A handle opened
    /// with a different credential is refused instead of being consumed.
    /// </remarks>
    /// <param name="sessions">The process-wide set of unfinished sessions.</param>
    /// <param name="handle">The single-use handle the operator presented.</param>
    /// <param name="credentialFingerprint">A non-secret identity for the presenting credential.</param>
    /// <returns>Whether a session was removed, and whether the credential matched.</returns>
    public static (bool Removed, bool Matched) AbandonRelay(
        StandaloneAuthorizationRelaySessions sessions,
        string handle,
        string credentialFingerprint)
    {
        ArgumentNullException.ThrowIfNull(sessions);
        ArgumentException.ThrowIfNullOrEmpty(handle);
        ArgumentException.ThrowIfNullOrEmpty(credentialFingerprint);

        return sessions.Abandon(handle, credentialFingerprint);
    }

    private static (string Code, string Message) RelayRefusal(StandaloneAuthorizationRelayRefusal refusal)
        => refusal switch
        {
            StandaloneAuthorizationRelayRefusal.CredentialMismatch => (
                "standalone/relay-credential-mismatch",
                "That authorization session was opened with a different operator credential, so it was left untouched."),
            StandaloneAuthorizationRelayRefusal.Expired => (
                "standalone/relay-expired",
                "That authorization session expired before the callback arrived, so nothing was exchanged."),
            _ => (
                "standalone/relay-unknown",
                "No authorization session answers to that handle. It may already have been completed or abandoned."),
        };

    /// <summary>
    /// Commits the credential a completed host-owned authorization attempt obtained.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The host half of a relayed authorization: the attempt was built by
    /// <see cref="StandaloneAuthorization.BeginServingAsync"/> and has been held by whatever session
    /// the operator channel tracks, and this drives it to a result and commits that result through
    /// the runtime the mount serves with. Committing through that runtime is what makes a concurrent
    /// acquisition observe the change: the same gate serializes both, and the same generation fence
    /// invalidates what an in-flight acquisition would otherwise publish.
    /// </para>
    /// <para>
    /// The target is taken from the attempt's own binding rather than from the caller, so a caller
    /// holding one operator credential cannot complete attempt A and have it committed against
    /// profile B. The profile is still re-resolved from the live Manifest, because a Manifest that
    /// changed while the attempt was open must refuse rather than commit against a stale identity.
    /// </para>
    /// <para>
    /// The commit point is inside the service. A refusal here means nothing was published; a
    /// committed authorization means the very next ordinary call observes it.
    /// </para>
    /// </remarks>
    /// <param name="start">A started runtime with a durable runtime-state store.</param>
    /// <param name="execution">The execution graph the serving process invokes through.</param>
    /// <param name="attempt">The bounded attempt the operator channel opened for this authorization.</param>
    /// <param name="state">The callback's decoded <c>state</c>.</param>
    /// <param name="code">The callback's decoded <c>code</c>, when it carried one.</param>
    /// <param name="error">The callback's decoded <c>error</c>, when the provider refused.</param>
    /// <param name="cancellationToken">The completion deadline.</param>
    public static async ValueTask<StandaloneAuthorizationOutcome> AuthorizeServingAsync(
        RuntimeStartResult start,
        EngineExecution execution,
        OAuthAuthorizationAttempt attempt,
        string? state,
        string? code,
        string? error,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(attempt);

        string mountPrefix = attempt.Binding.Mount;
        string profileId = attempt.Binding.ProfileId;

        TargetResolution target = ResolveTarget(start, mountPrefix, profileId, authorizationCodeRequired: true);

        if (!target.Resolved)
        {
            return new StandaloneAuthorizationOutcome(false, target.Code!, target.Message!, mountPrefix, profileId, 0, 0);
        }

        if (execution.MountAuthentication(target.Mount!.Prefix) is not { } runtime)
        {
            return new StandaloneAuthorizationOutcome(
                false,
                "standalone/unknown-mount",
                $"The serving execution serves no mount at '{mountPrefix}', so it cannot commit an authorization there.",
                mountPrefix,
                profileId,
                0,
                0);
        }

        OAuthAuthorizationResult result;

        try
        {
            result = await attempt.CompleteAsync(state, code, error, cancellationToken).ConfigureAwait(false);
        }
        catch (OAuthAuthorizationAttemptException refusal)
        {
            return new StandaloneAuthorizationOutcome(
                false,
                StandaloneAuthorizationAttempt.CodeFor(refusal.Error),
                refusal.Message,
                mountPrefix,
                profileId,
                0,
                0);
        }

        OAuthAuthorityAuthorization committed = await runtime.OAuth
            .CompleteAuthorizationAsync(target.Profile!, result, cancellationToken)
            .ConfigureAwait(false);

        return new StandaloneAuthorizationOutcome(
            committed.Authorized,
            committed.Code,
            committed.Message,
            mountPrefix,
            profileId,
            committed.AuthorityEpoch,
            committed.RuntimeRevision);
    }

    /// <summary>
    /// Reports the authentication profiles of a managed generation, read-only.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A managed deployment's local authorizations are Platform-owned, so this reports identity,
    /// declaration metadata and the direction to take, and resolves nothing: no credential value is
    /// read, no runtime-state record is opened, and no state is claimed. That is what makes the
    /// managed boundary read-only rather than a second, weaker copy of the file-mode view.
    /// </para>
    /// <para>
    /// The declared sources are reported by reference and by declared kind, with availability stated
    /// as Platform-resolved rather than probed, because a managed credential may arrive with a
    /// generation rather than from this host's own environment or files.
    /// </para>
    /// </remarks>
    /// <param name="mounts">The mounted Manifests of the leased generation.</param>
    /// <param name="mountPrefix">The mount to report, or null for every mounted Manifest.</param>
    /// <param name="profileId">The profile to report, or null for every profile of the mount.</param>
    public static IReadOnlyList<StandaloneAuthorizationStatus> DescribeManaged(
        IReadOnlyList<MountedManifest> mounts,
        string? mountPrefix = null,
        string? profileId = null)
    {
        ArgumentNullException.ThrowIfNull(mounts);

        List<StandaloneAuthorizationStatus> report = [];

        foreach (MountedManifest mount in mounts)
        {
            if (mountPrefix is { Length: > 0 }
                && !string.Equals(mount.Prefix, mountPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (AuthenticationProfile profile in mount.Document.EffectiveAuthentication.Profiles)
            {
                if (profileId is { Length: > 0 }
                    && !string.Equals(profile.Id, profileId, StringComparison.Ordinal))
                {
                    continue;
                }

                report.Add(ManagedStatus(mount, profile));
            }
        }

        if (report.Count > 0)
        {
            return report;
        }

        return
        [
            Unavailable(
                mountPrefix ?? string.Empty,
                profileId ?? string.Empty,
                string.Empty,
                mountPrefix is { Length: > 0 } ? "standalone/unknown-profile" : "standalone/unknown-mount",
                mountPrefix is { Length: > 0 }
                    ? $"Mount '{mountPrefix}' declares no authentication profile '{(profileId ?? string.Empty)}'."
                    : $"No Manifest is mounted at '{(mountPrefix ?? string.Empty)}'."),
        ];
    }

    private static StandaloneAuthorizationStatus ManagedStatus(
        MountedManifest mount,
        AuthenticationProfile profile)
    {
        var wanted = new HashSet<string>(profile.CredentialRef, StringComparer.Ordinal);
        List<StandaloneAuthorizationSource> sources = [];

        foreach (ManifestCredential credential in mount.Document.EffectiveCredentials.Credentials)
        {
            if (!wanted.Contains(credential.Id))
            {
                continue;
            }

            sources.Add(new StandaloneAuthorizationSource(
                credential.Id,
                credential.Slot,
                Vocabulary.Write(credential.Scheme),
                credential.Value.ToString(),
                "managed",
                "The Platform deployment resolves this credential for the generation it delivers."));
        }

        return new StandaloneAuthorizationStatus(
            mount.Prefix,
            profile.Id,
            Vocabulary.Write(profile.Kind),
            StandaloneAuthorizationState.Managed,
            "oauth/managed",
            "This deployment is managed by the Platform, so its authorizations are Platform-owned and no local authorization state is read here.",
            "Change the deployment from the Platform. Local authorization commands are refused in managed mode.",
            sources,
            0,
            0);
    }

    /// <summary>
    /// Establishes a fresh authenticated fail-closed baseline for every slot whose durable
    /// authority cannot be read, after an explicit acknowledgement.
    /// </summary>
    /// <param name="start">A started runtime whose runtime-state key can read and write the store.</param>
    /// <param name="mountPrefix">The mounted Manifest prefix that declares the profile.</param>
    /// <param name="profileId">The manifest-local profile id to reprovision.</param>
    /// <param name="acknowledge">
    /// Whether the operator explicitly acknowledged the irrecoverable effect. False reports the
    /// affected slots and refuses before any write.
    /// </param>
    /// <param name="cancellationToken">Cancels the reset.</param>
    public static async ValueTask<StandaloneResetOutcome> ResetAsync(
        RuntimeStartResult start,
        string mountPrefix,
        string profileId,
        bool acknowledge,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentException.ThrowIfNullOrEmpty(mountPrefix);
        ArgumentException.ThrowIfNullOrEmpty(profileId);

        TargetResolution target = ResolveTarget(start, mountPrefix, profileId, authorizationCodeRequired: true);

        if (!target.Resolved)
        {
            return new StandaloneResetOutcome(
                false, target.Code!, target.Message!, mountPrefix, profileId, [], []);
        }

        MountedManifest mount = target.Mount!;
        AuthenticationProfile profile = target.Profile!;
        OAuthStrategyConfiguration configuration = target.Configuration!;
        IMutableSlotStore store = start.RuntimeState!.CreateForMount(mount.Prefix);

        List<string> affected = [];
        List<AuthenticationSlot> affectedSlots = [];

        foreach (AuthenticationSlot candidate in profile.Slots)
        {
            try
            {
                // A readable decision — absent, authorized or cleared — is not this operation's
                // business: ordinary authorize/clear handles those. Only authority this deployment
                // cannot authenticate needs the destructive path.
                _ = await store.LoadDecisionAsync(profile.Id, candidate.Slot, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (RuntimeStateStoreException)
            {
                affected.Add(candidate.Slot);
                affectedSlots.Add(candidate);
            }
        }

        if (affected.Count == 0)
        {
            return new StandaloneResetOutcome(
                false,
                "oauth/reset-not-required",
                "Every runtime-owned slot of this profile can still be read and authenticated, so no destructive reset is needed. Use 'auth clear' or 'auth authorize' instead.",
                mount.Prefix, profile.Id, [], []);
        }

        if (!acknowledge)
        {
            return new StandaloneResetOutcome(
                false,
                "oauth/reset-acknowledgement-required",
                "This destructive reset is refused without an explicit acknowledgement. It will retire the unreadable authority of "
                + string.Join(", ", affected)
                + " and replace it with a fresh fail-closed baseline. The previous credential and the previous authority epoch cannot be recovered; "
                + "the profile stays unauthorized until 'auth authorize' succeeds. Re-run with --acknowledge-irrecoverable to proceed.",
                mount.Prefix, profile.Id, affected, []);
        }

        List<string> results = [];
        bool allEstablished = true;

        foreach (AuthenticationSlot candidate in affectedSlots)
        {
            if (candidate.AuthorityEpoch == long.MaxValue)
            {
                allEstablished = false;
                results.Add(candidate.Slot + ": refused (the declared authority epoch cannot be advanced)");
                continue;
            }

            var baseline = new MutableSlotDecision(
                profile.Id,
                candidate.Slot,
                profile.ScopeFingerprint,
                AuthorityBinding.Declaration(profile),
                AuthorityBinding.Configuration(configuration),
                candidate.AuthorityEpoch + 1,
                0,
                MutableSlotDecisionKind.Cleared,
                RefreshToken: null);

            try
            {
                // One atomic replacement retires the unreadable envelope and establishes the
                // baseline. The slot is never observably absent, so an interrupted reset cannot
                // re-expose a Manifest-declared credential.
                MutableSlotDecision established = await store
                    .EstablishBaselineAsync(baseline, candidate.AuthorityEpoch, cancellationToken)
                    .ConfigureAwait(false);

                results.Add(candidate.Slot + ": baseline-established epoch " + established.AuthorityEpoch.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            catch (RuntimeStateStoreException)
            {
                allEstablished = false;
                results.Add(candidate.Slot + ": failed (the store could not be written; authority remains fail-closed)");
            }
        }

        return new StandaloneResetOutcome(
            allEstablished,
            allEstablished ? "oauth/reset-complete" : "oauth/reset-incomplete",
            allEstablished
                ? "A fresh authenticated fail-closed baseline now covers " + string.Join(", ", affected)
                    + ". The profile is unauthorized until 'auth authorize' succeeds."
                : "The reset is incomplete. The affected slots remain fail-closed and no previous credential is usable; fix the store and retry.",
            mount.Prefix,
            profile.Id,
            affected,
            results);
    }

    /// <summary>Reports one profile's state from the durable decision and the declared sources.</summary>
    private static async ValueTask<StandaloneAuthorizationStatus> DescribeOneAsync(
        RuntimeStartResult start,
        MountedManifest mount,
        AuthenticationProfile profile,
        bool ownerElsewhere,
        CancellationToken cancellationToken)
    {
        List<DeclaredCredential> declared = await ResolveDeclaredAsync(
            mount, profile, start.AllowInlineSecrets, cancellationToken).ConfigureAwait(false);

        List<StandaloneAuthorizationSource> sources = [.. declared.Select(static credential => new StandaloneAuthorizationSource(
            credential.Declaration.Id,
            credential.Declaration.Slot,
            Vocabulary.Write(credential.Declaration.Scheme),
            credential.Declaration.Value.ToString(),
            credential.Failure is null ? "present" : "unresolvable",
            credential.Failure ?? string.Empty))];

        if (ownerElsewhere)
        {
            return Unavailable(
                mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind), sources,
                "oauth/status-conflict",
                "Another process owns this runtime-state root and may be mutating the local authority, so a coherent read cannot be guaranteed. Stop it or retry when it has stopped.");
        }

        AuthenticationSlot? slot = profile.Slots.FirstOrDefault(candidate =>
            string.Equals(candidate.Slot, RefreshTokenSlot, StringComparison.Ordinal));

        if (StandaloneAuthorizationAttempts.IsAuthorizing(mount.Prefix, profile.Id))
        {
            return new StandaloneAuthorizationStatus(
                mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind),
                StandaloneAuthorizationState.Authorizing,
                "oauth/authorizing",
                "An authorization attempt for this profile is in flight in this process. Its outcome is not durable until the provider redirects the browser back.",
                "Complete the provider redirect in the browser that opened the printed authorization URL.",
                sources, slot?.AuthorityEpoch ?? 0, 0);
        }

        if (slot is null)
        {
            bool resolvable = sources.Any(static source => source.Availability == "present");
            return new StandaloneAuthorizationStatus(
                mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind),
                resolvable ? StandaloneAuthorizationState.Configured : StandaloneAuthorizationState.Unconfigured,
                "oauth/no-runtime-slot",
                "This profile declares no runtime-owned 'refreshToken' slot, so it has no local authorization state to manage.",
                "No local bootstrap is available for this profile kind; check the Manifest's authentication declaration.",
                sources, 0, 0);
        }

        OAuthStrategyConfiguration? configuration;

        try
        {
            configuration = OAuthStrategyConfiguration.FromConfiguration(profile.Configuration, authorizationCodeRequired: false);
        }
        catch (AuthenticationPlanException)
        {
            configuration = null;
        }

        IMutableSlotStore store = start.RuntimeState!.CreateForMount(mount.Prefix);
        MutableSlotDecision? prior;

        try
        {
            prior = await store.LoadDecisionAsync(profile.Id, slot.Slot, cancellationToken).ConfigureAwait(false);
        }
        catch (RuntimeStateStoreException)
        {
            return new StandaloneAuthorizationStatus(
                mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind),
                StandaloneAuthorizationState.Faulted,
                "oauth/authority-unreadable",
                "A durable authority record exists for this slot but cannot be authenticated with the configured key. It is deliberately not treated as an absent slot, and no credential value is disclosed.",
                "Run 'auth authority-reset " + mount.Prefix + " " + profile.Id + " --acknowledge-irrecoverable' to establish a fresh fail-closed baseline, then 'auth authorize'.",
                sources, 0, 0);
        }

        if (prior is null)
        {
            DeclaredCredential? declaredRefresh = declared.FirstOrDefault(static credential =>
                credential.Declaration.Scheme == CredentialScheme.OAuth2AuthorizationCode
                && string.Equals(credential.Declaration.Slot, RefreshTokenSlot, StringComparison.Ordinal));

            string nextAction =
                "Run 'auth authorize " + mount.Prefix + " " + profile.Id + " --oauth-redirect-uri <loopback-uri>' to establish local runtime authority.";

            if (declaredRefresh is null)
            {
                return new StandaloneAuthorizationStatus(
                    mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind),
                    StandaloneAuthorizationState.Unconfigured,
                    "oauth/unconfigured",
                    "The profile declares no refresh credential and no local authorization decision exists, so no authority is available for this slot yet.",
                    nextAction,
                    sources, slot.AuthorityEpoch, 0);
            }

            if (declaredRefresh.Failure is not null)
            {
                // The reference exists but does not resolve. Reporting this as configured would tell
                // the operator a credential is ready when it is not, so it is reported as a missing
                // source with the reference that needs supplying.
                return new StandaloneAuthorizationStatus(
                    mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind),
                    StandaloneAuthorizationState.Unconfigured,
                    "oauth/missing-source",
                    "The declared refresh credential " + declaredRefresh.Declaration.Value
                        + " does not currently resolve. No credential value is shown.",
                    "Supply what " + declaredRefresh.Declaration.Value
                        + " names, or run 'auth authorize " + mount.Prefix + " " + profile.Id + " --oauth-redirect-uri <loopback-uri>' to authorize without it.",
                    sources, slot.AuthorityEpoch, 0);
            }

            return new StandaloneAuthorizationStatus(
                mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind),
                StandaloneAuthorizationState.Configured,
                "oauth/configured",
                "A declared refresh credential resolves and no local authorization decision has been made, so the declared credential is the current authority.",
                nextAction,
                sources, slot.AuthorityEpoch, 0);
        }

        if (prior.Kind == MutableSlotDecisionKind.Cleared)
        {
            return new StandaloneAuthorizationStatus(
                mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind),
                StandaloneAuthorizationState.Cleared,
                "oauth/cleared",
                "An explicit local clear floor is in force. It masks the previous runtime record and every earlier Manifest-declared value, including a newer Manifest epoch.",
                "Run 'auth authorize " + mount.Prefix + " " + profile.Id + " --oauth-redirect-uri <loopback-uri>' to authorize again.",
                sources, prior.AuthorityEpoch, prior.RuntimeRevision);
        }

        if (prior.IsLegacy)
        {
            bool eligible = !string.IsNullOrEmpty(prior.RefreshToken)
                && prior.AuthorityEpoch == slot.AuthorityEpoch
                && prior.ScopeFingerprint == profile.ScopeFingerprint
                && prior.RuntimeRevision >= slot.RuntimeRevision;

            return new StandaloneAuthorizationStatus(
                mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind),
                eligible ? StandaloneAuthorizationState.Authorized : StandaloneAuthorizationState.ReauthorizationRequired,
                eligible ? "oauth/authorized" : "oauth/reauthorization-required",
                eligible
                    ? "A runtime-rotated refresh credential from the current authority epoch is usable."
                    : "A runtime-rotated refresh credential exists but no longer matches the declared authority epoch or scope, so it cannot be used.",
                eligible
                    ? "Nothing to do. Run 'auth authorize' to reauthorize if the provider has retired this credential."
                    : "Run 'auth authorize " + mount.Prefix + " " + profile.Id + " --oauth-redirect-uri <loopback-uri>' to reauthorize.",
                sources, prior.AuthorityEpoch, prior.RuntimeRevision);
        }

        bool bound = configuration is not null
            && prior.ScopeFingerprint == profile.ScopeFingerprint
            && string.Equals(prior.DeclarationFingerprint, AuthorityBinding.Declaration(profile), StringComparison.Ordinal)
            && string.Equals(prior.ConfigurationFingerprint, AuthorityBinding.Configuration(configuration), StringComparison.Ordinal);

        return new StandaloneAuthorizationStatus(
            mount.Prefix, profile.Id, Vocabulary.Write(profile.Kind),
            bound ? StandaloneAuthorizationState.Authorized : StandaloneAuthorizationState.ReauthorizationRequired,
            bound ? "oauth/authorized" : "oauth/reauthorization-required",
            bound
                ? "A local authorization decision is in force and matches the current declaration and configuration."
                : "A local authorization decision exists but its declaration, scope or configuration binding no longer matches the deployed profile, so the profile fails closed.",
            bound
                ? "Nothing to do. Run 'auth authorize' to reauthorize if the provider has retired this credential."
                : "Run 'auth authorize " + mount.Prefix + " " + profile.Id + " --oauth-redirect-uri <loopback-uri>' to reauthorize under the current binding.",
            sources, prior.AuthorityEpoch, prior.RuntimeRevision);
    }

    /// <summary>
    /// Selects the mount, profile, runtime-owned refresh slot and validated configuration, or
    /// reports the first reason it cannot.
    /// </summary>
    private static TargetResolution ResolveTarget(
        RuntimeStartResult start,
        string mountPrefix,
        string profileId,
        bool authorizationCodeRequired)
    {
        if (!start.Started || start.RuntimeState is null)
        {
            return TargetResolution.Refused(
                "standalone/runtime-refused",
                "This operation needs a started runtime with a durable runtime-state store, because local authority must survive a restart.");
        }

        MountedManifest? mount = start.Mounts.FirstOrDefault(candidate =>
            string.Equals(candidate.Prefix, mountPrefix, StringComparison.Ordinal));

        if (mount is null)
        {
            return TargetResolution.Refused("standalone/unknown-mount", $"No Manifest is mounted at '{mountPrefix}'.");
        }

        AuthenticationProfile? profile = mount.Document.EffectiveAuthentication.Profile(profileId);

        if (profile is null)
        {
            return TargetResolution.Refused(
                "standalone/unknown-profile",
                $"Mount '{mountPrefix}' declares no authentication profile '{profileId}'.");
        }

        if (profile.Kind != AuthenticationKind.OAuth2AuthorizationCodePkceRefresh)
        {
            return TargetResolution.Refused(
                "standalone/unsupported-profile",
                $"Authentication profile '{profileId}' is '{Vocabulary.Write(profile.Kind)}', not an authorization-code profile, so it has no local refresh authorization to manage.");
        }

        AuthenticationSlot? slot = profile.Slots.FirstOrDefault(candidate =>
            string.Equals(candidate.Slot, RefreshTokenSlot, StringComparison.Ordinal));

        if (slot is null)
        {
            return TargetResolution.Refused(
                "standalone/no-refresh-slot",
                $"Authentication profile '{profileId}' declares no runtime-owned '{RefreshTokenSlot}' slot.");
        }

        OAuthStrategyConfiguration configuration;

        try
        {
            configuration = OAuthStrategyConfiguration.FromConfiguration(
                profile.Configuration, authorizationCodeRequired);
        }
        catch (AuthenticationPlanException refusal)
        {
            return TargetResolution.Refused("standalone/unsupported-profile", refusal.Message);
        }

        return TargetResolution.Ready(mount, profile, slot, configuration);
    }

    /// <summary>
    /// Resolves every credential the profile references, one at a time, recording a non-secret
    /// reason instead of failing the whole operation when one does not resolve.
    /// </summary>
    private static async ValueTask<List<DeclaredCredential>> ResolveDeclaredAsync(
        MountedManifest mount,
        AuthenticationProfile profile,
        bool allowInlineCredentials,
        CancellationToken cancellationToken)
    {
        List<DeclaredCredential> declared = [];

        if (profile.CredentialRef.Count == 0)
        {
            return declared;
        }

        var wanted = new HashSet<string>(profile.CredentialRef, StringComparer.Ordinal);
        var resolver = new ManifestSecretResolver(new SecretResolutionOptions(allowInlineCredentials));

        foreach (ManifestCredential credential in mount.Document.EffectiveCredentials.Credentials)
        {
            if (!wanted.Contains(credential.Id))
            {
                continue;
            }

            string? value = null;
            string? failure = null;

            try
            {
                IReadOnlyList<ResolvedCredential> resolved = await resolver
                    .ResolveAsync(mount.Document.EffectiveCredentials, [credential.Id], cancellationToken)
                    .ConfigureAwait(false);

                value = resolved.Count > 0 ? resolved[0].Value : null;
            }
            catch (CredentialUnavailableException refusal)
            {
                failure = refusal.Message;
            }

            declared.Add(new DeclaredCredential(credential, value, failure));
        }

        return declared;
    }

    /// <summary>
    /// Attempts a bounded best-effort revocation of the pre-clear refresh credential at the
    /// profile's own declared endpoint. Never discovers or guesses an endpoint, and never lets a
    /// failure here redefine the local clear.
    /// </summary>
    private static async ValueTask<(string Outcome, string Detail)> TryRevokeAsync(
        OAuthTokenEndpointClient client,
        AuthenticationProfile profile,
        OAuthStrategyConfiguration configuration,
        string? token,
        string? clientSecret,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(token))
        {
            return ("not-attempted", "no usable refresh credential was available in memory before the local clear");
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));

        try
        {
            await client
                .RevokeRefreshTokenAsync(configuration, profile.AuthenticationOrigins, token, clientSecret, deadline.Token)
                .ConfigureAwait(false);

            return ("revoked", "the provider accepted a revocation request at the declared endpoint");
        }
        catch (AuthenticationPlanException)
        {
            return ("not-attempted", "the profile declares no revocation endpoint, or the declared endpoint is outside the reviewed authentication origins");
        }
        catch (OperationCanceledException)
        {
            return ("failed", "the bounded revocation attempt did not complete");
        }
        catch (Exception failure) when (failure is CredentialUnavailableException
            or AddressPolicyViolationException
            or OriginPolicyViolationException
            or HostResolutionException
            or UpstreamTransportException
            or RedirectLimitException)
        {
            // Every transport and containment failure is the same answer here: the provider
            // revocation was not obtained. None of them can undo the committed local clear, and
            // none of them may escape a best-effort attempt after the commit point.
            return ("failed", "the provider refused the revocation request or the reviewed network policy stopped it");
        }
    }

    /// <summary>
    /// The refresh value and client secret a bounded revocation may use, read from the in-memory
    /// superseded decision first and the declared credentials second.
    /// </summary>
    /// <remarks>
    /// The superseded decision is preferred because it is the value the provider actually issued;
    /// the declared value is the fallback for a slot that had no local authority to displace. Both
    /// stay in memory: neither is returned to a caller, rendered or persisted.
    /// </remarks>
    private static (string? Token, string? ClientSecret) RevocationMaterial(
        string? priorRefreshToken,
        List<DeclaredCredential> declared)
    {
        string? token = priorRefreshToken;

        if (string.IsNullOrEmpty(token))
        {
            token = declared.FirstOrDefault(static credential =>
                credential.Declaration.Scheme == CredentialScheme.OAuth2AuthorizationCode
                && string.Equals(credential.Declaration.Slot, RefreshTokenSlot, StringComparison.Ordinal))?.Value;
        }

        string? clientSecret = declared.FirstOrDefault(static credential =>
            credential.Declaration.Scheme == CredentialScheme.OAuth2AuthorizationCode
            && string.Equals(credential.Declaration.Slot, ClientSecretSlot, StringComparison.Ordinal))?.Value;

        return (token, clientSecret);
    }

    private static StandaloneAuthorizationStatus Unavailable(
        string mountPrefix,
        string profileId,
        string profileKind,
        string code,
        string message)
        => new(
            mountPrefix, profileId, profileKind,
            StandaloneAuthorizationState.Unavailable,
            code, message,
            "Check the mount prefix, profile id and runtime-state configuration, then retry.",
            [], 0, 0);

    private static StandaloneAuthorizationStatus Unavailable(
        string mountPrefix,
        string profileId,
        string profileKind,
        IReadOnlyList<StandaloneAuthorizationSource> sources,
        string code,
        string message)
        => new(
            mountPrefix, profileId, profileKind,
            StandaloneAuthorizationState.Unavailable,
            code, message,
            "Check the mount prefix, profile id and runtime-state configuration, then retry.",
            sources, 0, 0);

    /// <summary>One declared credential, with its value (when it resolved) or its failure reason.</summary>
    private sealed record DeclaredCredential(ManifestCredential Declaration, string? Value, string? Failure);

    /// <summary>The outcome of selecting one clear/reset/describe target.</summary>
    private sealed record TargetResolution(
        MountedManifest? Mount,
        AuthenticationProfile? Profile,
        AuthenticationSlot? Slot,
        OAuthStrategyConfiguration? Configuration,
        string? Code,
        string? Message)
    {
        internal bool Resolved => Mount is not null;

        internal static TargetResolution Ready(
            MountedManifest mount,
            AuthenticationProfile profile,
            AuthenticationSlot slot,
            OAuthStrategyConfiguration configuration)
            => new(mount, profile, slot, configuration, null, null);

        internal static TargetResolution Refused(string code, string message)
            => new(null, null, null, null, code, message);
    }
}
