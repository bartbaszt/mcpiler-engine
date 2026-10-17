using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Runtime;

/// <summary>The one file-mode mount/profile a standalone authorization targets.</summary>
/// <param name="MountPrefix">The mounted Manifest prefix that declares the profile.</param>
/// <param name="ProfileId">The manifest-local profile id to authorize.</param>
/// <param name="RedirectUri">
/// The explicitly configured loopback callback URI the operator registered with the provider.
/// </param>
public sealed record StandaloneAuthorizationTarget(
    string MountPrefix,
    string ProfileId,
    Uri RedirectUri);

/// <summary>
/// What beginning a standalone authorization produced: either a bounded attempt the host drives,
/// or the reasons it could not start.
/// </summary>
/// <remarks>
/// A refusal here happens before any listener, provider request or durable write. The host owns
/// the loopback callback listener and the operator interaction; this type owns the protocol.
/// </remarks>
public sealed class StandaloneAuthorizationStart
{
    private StandaloneAuthorizationStart(
        StandaloneAuthorizationAttempt? attempt,
        IReadOnlyList<StartupRefusal> refusals)
    {
        Attempt = attempt;
        Refusals = refusals;
    }

    /// <summary>Whether an attempt was built and may be presented.</summary>
    public bool Started => Attempt is not null;

    /// <summary>The bounded attempt, when one was built.</summary>
    public StandaloneAuthorizationAttempt? Attempt { get; }

    /// <summary>Every reason the attempt could not start. Empty on success.</summary>
    public IReadOnlyList<StartupRefusal> Refusals { get; }

    internal static StandaloneAuthorizationStart Ready(StandaloneAuthorizationAttempt attempt)
        => new(attempt, []);

    internal static StandaloneAuthorizationStart Refused(string mount, string code, string message)
        => new(null, [new StartupRefusal(mount, code, message)]);
}

/// <summary>
/// What beginning a host-owned authorization attempt produced for a process that is already serving.
/// </summary>
/// <remarks>
/// The attempt is the protocol engine itself rather than the CLI's store-committing wrapper, because
/// the serving process commits through its own per-mount runtime. The caller owns the session that
/// carries this attempt: it decides who may present the URL and who may hand back the values the
/// listener received.
/// </remarks>
internal sealed class StandaloneServingAuthorizationStart
{
    private StandaloneServingAuthorizationStart(
        OAuthAuthorizationAttempt? attempt,
        IReadOnlyList<StartupRefusal> refusals)
    {
        Attempt = attempt;
        Refusals = refusals;
    }

    /// <summary>Whether an attempt was built and may be presented.</summary>
    public bool Started => Attempt is not null;

    /// <summary>The bounded attempt, when one was built.</summary>
    public OAuthAuthorizationAttempt? Attempt { get; }

    /// <summary>Every reason the attempt could not start. Empty on success.</summary>
    public IReadOnlyList<StartupRefusal> Refusals { get; }

    internal static StandaloneServingAuthorizationStart Ready(OAuthAuthorizationAttempt attempt)
        => new(attempt, []);

    internal static StandaloneServingAuthorizationStart Refused(string mount, string code, string message)
        => new(null, [new StartupRefusal(mount, code, message)]);
}

/// <summary>
/// The non-secret outcome of completing one standalone authorization. It carries a stable code,
/// a bounded message and the identity it concerns, never a token, code, verifier or provider body.
/// </summary>
/// <param name="Authorized">Whether the profile is now durably authorized.</param>
/// <param name="Code">A stable, scriptable outcome category.</param>
/// <param name="Message">A bounded, actionable, non-secret description.</param>
/// <param name="MountPrefix">The mount the attempt concerned.</param>
/// <param name="ProfileId">The profile the attempt concerned.</param>
/// <param name="AuthorityEpoch">The committed effective epoch, when authorized.</param>
/// <param name="RuntimeRevision">The committed runtime revision, when authorized.</param>
public sealed record StandaloneAuthorizationOutcome(
    bool Authorized,
    string Code,
    string Message,
    string MountPrefix,
    string ProfileId,
    long AuthorityEpoch,
    long RuntimeRevision);

/// <summary>
/// One bounded, presented authorization attempt the host completes with the raw callback query.
/// </summary>
/// <remarks>
/// <para>
/// The host binds its loopback listener to the attempt's own redirect endpoint, calls
/// <see cref="Begin"/>, presents <see cref="AuthorizationUrl"/>, and hands the callback's raw
/// query to <see cref="CompleteAsync"/>. The attempt owns the PKCE verifier and the single-use
/// state; neither is ever exposed or persisted.
/// </para>
/// <para>
/// Completion exchanges the code and commits an advancing local authority decision to the
/// deployment's durable store. The provider-issued refresh credential becomes authoritative only
/// when that atomic compare-and-commit succeeds; a failed commit leaves the predecessor or a
/// fail-closed state and reports failure, never a success.
/// </para>
/// </remarks>
public sealed class StandaloneAuthorizationAttempt
{
    private readonly OAuthAuthorizationAttempt _attempt;
    private readonly IMutableSlotStore _store;
    private readonly AuthenticationProfile _profile;
    private readonly AuthenticationSlot _slot;
    private readonly OAuthStrategyConfiguration _configuration;

    internal StandaloneAuthorizationAttempt(
        OAuthAuthorizationAttempt attempt,
        IMutableSlotStore store,
        AuthenticationProfile profile,
        AuthenticationSlot slot,
        OAuthStrategyConfiguration configuration)
    {
        _attempt = attempt;
        _store = store;
        _profile = profile;
        _slot = slot;
        _configuration = configuration;
    }

    /// <summary>The mount the attempt authorizes.</summary>
    public string MountPrefix => _attempt.Binding.Mount;

    /// <summary>The profile id the attempt authorizes.</summary>
    public string ProfileId => _profile.Id;

    /// <summary>The exact loopback callback URI the attempt is registered for.</summary>
    public Uri RedirectUri => _attempt.RedirectUri;

    /// <summary>The authorization URL to present to the operator.</summary>
    public Uri AuthorizationUrl => _attempt.AuthorizationUrl;

    /// <summary>When the bounded attempt lifetime elapses.</summary>
    public DateTimeOffset ExpiresAtUtc => _attempt.ExpiresAtUtc;

    /// <summary>Whether the attempt has reached a state it cannot leave.</summary>
    public bool IsTerminal => _attempt.IsTerminal;

    /// <summary>Moves the attempt to the pending state once a listener is bound.</summary>
    public void Begin() => _attempt.Begin();

    /// <summary>Marks a non-terminal attempt cancelled.</summary>
    public void Cancel() => _attempt.Cancel();

    /// <summary>
    /// Admits the single callback, exchanges its code at the declared token endpoint, and commits
    /// the resulting refresh credential as an advancing local authority decision.
    /// </summary>
    /// <param name="rawCallbackQuery">
    /// The callback's raw query string, with or without a leading <c>?</c>, exactly as received.
    /// </param>
    /// <param name="cancellationToken">The completion deadline.</param>
    public async ValueTask<StandaloneAuthorizationOutcome> CompleteAsync(
        string rawCallbackQuery,
        CancellationToken cancellationToken)
    {
        OAuthAuthorizationResult result;

        try
        {
            result = await _attempt.CompleteAsync(rawCallbackQuery, cancellationToken).ConfigureAwait(false);
        }
        catch (OAuthAuthorizationAttemptException refusal)
        {
            return new StandaloneAuthorizationOutcome(
                false, CodeFor(refusal.Error), refusal.Message, MountPrefix, _profile.Id, 0, 0);
        }

        try
        {
            MutableSlotDecision? prior = await _store
                .LoadDecisionAsync(_profile.Id, _slot.Slot, cancellationToken)
                .ConfigureAwait(false);

            // The successor's epoch must exceed both the declared authority and any committed local
            // decision, and its revision starts at zero: an explicit authorization is a new epoch,
            // never a revision of the previous one.
            long baseEpoch = Math.Max(_slot.AuthorityEpoch, prior?.AuthorityEpoch ?? _slot.AuthorityEpoch);

            if (baseEpoch == long.MaxValue)
            {
                return new StandaloneAuthorizationOutcome(
                    false,
                    "oauth/persistence-failed",
                    "The local authority epoch cannot be advanced further, so the profile is not authorized.",
                    MountPrefix,
                    _profile.Id,
                    0,
                    0);
            }

            var successor = new MutableSlotDecision(
                _profile.Id,
                _slot.Slot,
                _profile.ScopeFingerprint,
                AuthorityBinding.Declaration(_profile),
                AuthorityBinding.Configuration(_configuration),
                baseEpoch + 1,
                0,
                MutableSlotDecisionKind.Authorized,
                result.RefreshToken);

            MutableSlotDecision committed = await _store
                .CompareAndCommitAsync(successor, prior?.Version, _slot.AuthorityEpoch, cancellationToken)
                .ConfigureAwait(false);

            return new StandaloneAuthorizationOutcome(
                true,
                "oauth/authorized",
                "The profile is now authorized; the provider-issued refresh credential was committed to the durable runtime store.",
                MountPrefix,
                _profile.Id,
                committed.AuthorityEpoch,
                committed.RuntimeRevision);
        }
        catch (RuntimeStateStoreException)
        {
            // The provider may already have retired the predecessor when it issued this credential.
            // No ordering can restore that; the operator must authorize again once the store is
            // writable. The failure is reported, and nothing is published as authorized.
            return new StandaloneAuthorizationOutcome(
                false,
                "oauth/persistence-failed",
                "The provider issued a refresh credential but it could not be durably committed, so the profile is not authorized. Make the runtime-state store writable and authorize again.",
                MountPrefix,
                _profile.Id,
                0,
                0);
        }
    }

    internal static string CodeFor(OAuthAuthorizationAttemptError error) => error switch
    {
        OAuthAuthorizationAttemptError.UnsupportedProfile => "oauth/unsupported-profile",
        OAuthAuthorizationAttemptError.MissingClientSecret => "oauth/missing-client-secret",
        OAuthAuthorizationAttemptError.RedirectUriInvalid => "oauth/redirect-invalid",
        OAuthAuthorizationAttemptError.AuthorizationParameterRefused => "oauth/authorization-parameter-refused",
        OAuthAuthorizationAttemptError.LifetimeInvalid => "oauth/lifetime-invalid",
        OAuthAuthorizationAttemptError.AttemptNotPending => "oauth/attempt-not-pending",
        OAuthAuthorizationAttemptError.AttemptExpired => "oauth/attempt-expired",
        OAuthAuthorizationAttemptError.MalformedCallback => "oauth/malformed-callback",
        OAuthAuthorizationAttemptError.DuplicateCallbackParameter => "oauth/duplicate-callback-parameter",
        OAuthAuthorizationAttemptError.MissingState => "oauth/missing-state",
        OAuthAuthorizationAttemptError.StateMismatch => "oauth/state-mismatch",
        OAuthAuthorizationAttemptError.MissingCode => "oauth/missing-code",
        OAuthAuthorizationAttemptError.AmbiguousCallback => "oauth/ambiguous-callback",
        OAuthAuthorizationAttemptError.ProviderDenied => "oauth/provider-denied",
        OAuthAuthorizationAttemptError.ProviderExchangeFailed => "oauth/provider-exchange-failed",
        OAuthAuthorizationAttemptError.RefreshTokenRequired => "oauth/refresh-token-required",
        _ => "oauth/failed",
    };
}

/// <summary>
/// Builds the bounded standalone authorization attempt for one file-mode mount/profile.
/// </summary>
/// <remarks>
/// <para>
/// This is the seam the CLI reaches for: the deployable holds no Manifest model and no OAuth
/// protocol, so it asks the library to select and validate the target and to build the attempt.
/// Every refusal is produced here, before the host opens a socket or contacts a provider.
/// </para>
/// <para>
/// The attempt requires a started runtime with a durable runtime-state store. A deployment that
/// keeps mutable state in memory cannot make a provider-issued refresh credential survive a
/// restart, and a bootstrap that could not be durable is refused rather than reported as done.
/// </para>
/// </remarks>
public static class StandaloneAuthorization
{
    /// <summary>
    /// Selects and validates the target, resolves the declared client secret, and builds the
    /// attempt, or reports why it cannot.
    /// </summary>
    /// <param name="start">A started runtime whose mounts are loaded and validated.</param>
    /// <param name="target">The mount, profile and loopback callback URI to authorize.</param>
    /// <param name="timeProvider">The clock used for the attempt lifetime and exchange.</param>
    /// <param name="connections">
    /// Which addresses the token endpoint may be reached at. Production uses the shipped policy;
    /// a test supplies a permissive one because every in-process provider lives on loopback.
    /// </param>
    /// <param name="allowLoopbackAuthorization">
    /// True only when the operator explicitly allowed this transport to reach a loopback
    /// endpoint, which is what an authorization server on the operator's own machine needs.
    /// Ignored when <paramref name="connections"/> is supplied, because that argument is already a
    /// complete judgement. It never widens the judgement for tool execution: the serving path
    /// does not read it and does not receive it.
    /// </param>
    /// <param name="cancellationToken">Cancels reading a declared file-backed client secret.</param>
    public static async ValueTask<StandaloneAuthorizationStart> BeginAsync(
        RuntimeStartResult start,
        StandaloneAuthorizationTarget target,
        TimeProvider? timeProvider = null,
        OutboundConnectionPolicy? connections = null,
        bool allowLoopbackAuthorization = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(target);

        if (start.RuntimeState is null)
        {
            return StandaloneAuthorizationStart.Refused(
                target.MountPrefix,
                "standalone/runtime-refused",
                "Standalone authorization needs a started runtime with a durable runtime-state store, because an authorized refresh credential must survive a restart.");
        }

        (ResolvedTarget? resolved, StartupRefusal? refusal) = await ResolveAsync(start, target, cancellationToken)
            .ConfigureAwait(false);

        if (resolved is null)
        {
            return StandaloneAuthorizationStart.Refused(
                target.MountPrefix, refusal!.Code, refusal.Message);
        }

        TimeProvider clock = timeProvider ?? TimeProvider.System;
        var tokenClient = new OAuthTokenEndpointClient(
            new UpstreamSender(new UpstreamClientFactory(
                StandaloneAuthorizationTransport.Policy(connections, allowLoopbackAuthorization))),
            clock);

        OAuthAuthorizationAttempt attempt;

        try
        {
            attempt = OAuthAuthorizationAttempt.Create(
                new OAuthAuthorizationAttemptRequest(
                    resolved.Mount.Prefix,
                    resolved.Profile,
                    resolved.Slot,
                    resolved.Configuration,
                    target.RedirectUri,
                    resolved.ClientSecret),
                tokenClient,
                clock);
        }
        catch (OAuthAuthorizationAttemptException failure)
        {
            return StandaloneAuthorizationStart.Refused(
                target.MountPrefix, StandaloneAuthorizationAttempt.CodeFor(failure.Error), failure.Message);
        }

        var ready = new StandaloneAuthorizationAttempt(
            attempt,
            start.RuntimeState.CreateForMount(resolved.Mount.Prefix),
            resolved.Profile,
            resolved.Slot,
            resolved.Configuration);

        StandaloneAuthorizationAttempts.Track(ready);

        return StandaloneAuthorizationStart.Ready(ready);
    }

    /// <summary>
    /// Builds the same bounded attempt for a process that is already serving the mount.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A serving process already holds the store-root lease and already owns the mount's outbound
    /// connections, so this variant differs in exactly two ways: the exchange runs over the
    /// connections the mount's own authentication runtime uses, and the result is committed through
    /// that same runtime rather than through a store this call would have to open. A second store or
    /// a second transport over the same mount would fence nothing that the serving path observes.
    /// </para>
    /// <para>
    /// The attempt is deliberately not registered for the <c>authorizing</c> status read: the caller
    /// is an in-host operator channel that tracks its own sessions, and a relay that outlived its
    /// session would otherwise keep a profile reporting progress it no longer has.
    /// </para>
    /// </remarks>
    /// <param name="start">The started runtime this process is serving.</param>
    /// <param name="execution">The execution whose per-mount authentication runtime owns the transport.</param>
    /// <param name="target">The mount, profile and loopback callback URI to authorize.</param>
    /// <param name="timeProvider">The clock used for the attempt lifetime and exchange.</param>
    /// <param name="cancellationToken">Cancels reading a declared file-backed client secret.</param>
    internal static async ValueTask<StandaloneServingAuthorizationStart> BeginServingAsync(
        RuntimeStartResult start,
        EngineExecution execution,
        StandaloneAuthorizationTarget target,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(target);

        if (!start.Started || start.RuntimeState is null)
        {
            return StandaloneServingAuthorizationStart.Refused(
                target.MountPrefix,
                "standalone/runtime-refused",
                "Serving authorization needs a started runtime with a durable runtime-state store, because an authorized refresh credential must survive a restart.");
        }

        if (execution.MountAuthentication(target.MountPrefix) is not { } runtime)
        {
            return StandaloneServingAuthorizationStart.Refused(
                target.MountPrefix,
                "standalone/unknown-mount",
                $"This process serves no mount at '{target.MountPrefix}', so it cannot authorize a profile there.");
        }

        (ResolvedTarget? resolved, StartupRefusal? refusal) = await ResolveAsync(start, target, cancellationToken)
            .ConfigureAwait(false);

        if (resolved is null)
        {
            return StandaloneServingAuthorizationStart.Refused(
                target.MountPrefix, refusal!.Code, refusal.Message);
        }

        TimeProvider clock = timeProvider ?? TimeProvider.System;
        var tokenClient = new OAuthTokenEndpointClient(runtime.Transport, clock);

        OAuthAuthorizationAttempt attempt;

        try
        {
            attempt = OAuthAuthorizationAttempt.Create(
                new OAuthAuthorizationAttemptRequest(
                    resolved.Mount.Prefix,
                    resolved.Profile,
                    resolved.Slot,
                    resolved.Configuration,
                    target.RedirectUri,
                    resolved.ClientSecret),
                tokenClient,
                clock);
        }
        catch (OAuthAuthorizationAttemptException failure)
        {
            return StandaloneServingAuthorizationStart.Refused(
                target.MountPrefix, StandaloneAuthorizationAttempt.CodeFor(failure.Error), failure.Message);
        }

        return StandaloneServingAuthorizationStart.Ready(attempt);
    }

    /// <summary>The one mount/profile/configuration a target resolves to, with its client secret.</summary>
    private sealed record ResolvedTarget(
        MountedManifest Mount,
        AuthenticationProfile Profile,
        AuthenticationSlot Slot,
        OAuthStrategyConfiguration Configuration,
        string? ClientSecret);

    /// <summary>
    /// Selects and validates the target and resolves the declared client secret, or says why not.
    /// </summary>
    /// <remarks>
    /// Every refusal is produced here, before any listener, provider request or durable write, and
    /// the order is the order an operator reads: an unknown target before an unusable one, and a
    /// missing secret before the attempt that would need it.
    /// </remarks>
    private static async ValueTask<(ResolvedTarget? Resolved, StartupRefusal? Refusal)> ResolveAsync(
        RuntimeStartResult start,
        StandaloneAuthorizationTarget target,
        CancellationToken cancellationToken)
    {
        MountedManifest? mount = start.Mounts.FirstOrDefault(candidate =>
            string.Equals(candidate.Prefix, target.MountPrefix, StringComparison.Ordinal));

        if (mount is null)
        {
            return (null, new StartupRefusal(
                target.MountPrefix, "standalone/unknown-mount", $"No Manifest is mounted at '{target.MountPrefix}'."));
        }

        AuthenticationProfile? profile = mount.Document.EffectiveAuthentication.Profile(target.ProfileId);

        if (profile is null)
        {
            return (null, new StartupRefusal(
                target.MountPrefix,
                "standalone/unknown-profile",
                $"Mount '{target.MountPrefix}' declares no authentication profile '{target.ProfileId}'."));
        }

        if (profile.Kind != AuthenticationKind.OAuth2AuthorizationCodePkceRefresh)
        {
            return (null, new StartupRefusal(
                target.MountPrefix,
                "standalone/unsupported-profile",
                $"Authentication profile '{target.ProfileId}' is '{profile.Kind}', not an authorization-code profile, so it cannot be authorized interactively."));
        }

        AuthenticationSlot? slot = profile.Slots.FirstOrDefault(candidate =>
            string.Equals(candidate.Slot, OAuthTokenService.RefreshTokenSlot, StringComparison.Ordinal));

        if (slot is null)
        {
            return (null, new StartupRefusal(
                target.MountPrefix,
                "standalone/no-refresh-slot",
                $"Authentication profile '{target.ProfileId}' declares no runtime-owned '{OAuthTokenService.RefreshTokenSlot}' slot, so there is nowhere to commit a refresh credential."));
        }

        OAuthStrategyConfiguration configuration;

        try
        {
            configuration = OAuthStrategyConfiguration.FromConfiguration(
                profile.Configuration,
                authorizationCodeRequired: true);
        }
        catch (AuthenticationPlanException refusal)
        {
            return (null, new StartupRefusal(
                target.MountPrefix, "standalone/unsupported-profile", refusal.Message));
        }

        string? clientSecret = null;

        if (configuration.TokenAuthMethod is "client_secret_post" or "client_secret_basic")
        {
            try
            {
                IReadOnlyList<ResolvedCredential> declared = await new ManifestSecretResolver(
                        new SecretResolutionOptions(start.AllowInlineSecrets))
                    .ResolveAsync(mount.Document.EffectiveCredentials, profile.CredentialRef, cancellationToken)
                    .ConfigureAwait(false);

                clientSecret = declared
                    .FirstOrDefault(credential =>
                        credential.Declaration.Scheme == CredentialScheme.OAuth2AuthorizationCode
                        && string.Equals(credential.Declaration.Slot, "clientSecret", StringComparison.Ordinal))
                    ?.Value;
            }
            catch (CredentialUnavailableException refusal)
            {
                return (null, new StartupRefusal(
                    target.MountPrefix, "standalone/missing-client-secret", refusal.Message));
            }

            if (string.IsNullOrEmpty(clientSecret))
            {
                return (null, new StartupRefusal(
                    target.MountPrefix,
                    "standalone/missing-client-secret",
                    $"Authentication profile '{target.ProfileId}' authenticates with '{configuration.TokenAuthMethod}' but declares no usable client secret."));
            }
        }

        return (new ResolvedTarget(mount, profile, slot, configuration, clientSecret), null);
    }
}

/// <summary>
/// The bounded set of authorization attempts this process has presented, so a status read in the
/// same process can report <c>authorizing</c> instead of guessing.
/// </summary>
/// <remarks>
/// Deliberately process-local and in-memory: a transient attempt is not durable state, and a
/// separate CLI invocation cannot observe another process's attempt. A status read from a second
/// process therefore reports the durable authority, which is exactly what the next real call will
/// use. Entries are dropped once an attempt is terminal or its lifetime has passed, so the set
/// cannot grow without bound.
/// </remarks>
internal static class StandaloneAuthorizationAttempts
{
    private const int MaximumTracked = 64;

    private static readonly object Gate = new();
    private static readonly Dictionary<(string Mount, string Profile), StandaloneAuthorizationAttempt> Tracked = [];

    /// <summary>Records an in-flight attempt for the status read.</summary>
    internal static void Track(StandaloneAuthorizationAttempt attempt)
    {
        lock (Gate)
        {
            Prune();

            if (Tracked.Count < MaximumTracked)
            {
                Tracked[(attempt.MountPrefix, attempt.ProfileId)] = attempt;
            }
        }
    }

    /// <summary>Whether a non-terminal attempt for this target exists in this process.</summary>
    internal static bool IsAuthorizing(string mount, string profile)
    {
        lock (Gate)
        {
            Prune();

            return Tracked.TryGetValue((mount, profile), out StandaloneAuthorizationAttempt? attempt)
                && !attempt.IsTerminal;
        }
    }

    private static void Prune()
    {
        if (Tracked.Count == 0)
        {
            return;
        }

        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        List<(string Mount, string Profile)>? expired = null;

        foreach (((string mount, string profile), StandaloneAuthorizationAttempt attempt) in Tracked)
        {
            if (attempt.IsTerminal || attempt.ExpiresAtUtc <= now)
            {
                (expired ??= []).Add((mount, profile));
            }
        }

        if (expired is null)
        {
            return;
        }

        foreach ((string mount, string profile) in expired)
        {
            Tracked.Remove((mount, profile));
        }
    }
}

/// <summary>
/// The address judgement the standalone authorization transport connects through.
/// </summary>
/// <remarks>
/// <para>
/// One place decides which addresses an operator's own bootstrap may reach, so the shipped table
/// has exactly one alternative and the whole difference fits on one screen. The serving path
/// never calls this: it takes <see cref="OutboundConnectionPolicy"/>'s default judgement directly,
/// so no setting an operator makes here can widen what a served request reaches.
/// </para>
/// <para>
/// The bounded allowance widens loopback alone. Private, carrier-NAT, link-local, documentation,
/// benchmarking and every other reserved range stay refused, because the reason the shipped table
/// refuses them — an address that leads into infrastructure the operator did not choose, most
/// sharply the instance-metadata address — is unchanged by an operator bootstrapping a credential
/// from a machine of their own.
/// </para>
/// </remarks>
internal static class StandaloneAuthorizationTransport
{
    /// <summary>
    /// The judgement to connect through: an explicit one when a caller supplied it, otherwise
    /// the shipped table, widened to loopback only when the operator allowed it.
    /// </summary>
    internal static OutboundConnectionPolicy Policy(
        OutboundConnectionPolicy? connections,
        bool allowLoopbackAuthorization)
    {
        if (connections is not null)
        {
            return connections;
        }

        return allowLoopbackAuthorization
            ? new OutboundConnectionPolicy(OutboundConnectionPolicy.LoopbackAllowedGuard)
            : new OutboundConnectionPolicy();
    }
}
