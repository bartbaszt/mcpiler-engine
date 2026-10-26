using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

using MCPiler.Engine.Host.Authorization;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace MCPiler.Engine.Host.Hosting;

/// <summary>
/// The authenticated, non-MCP operator channel for standalone authentication state.
/// </summary>
/// <remarks>
/// <para>
/// This is stage 2 of the staged operator channel. Stage 1 is the CLI, which works on a process that
/// is not serving because it takes the store-root lease first. This channel works on a process that
/// <em>is</em> serving, and it can only work there because the serving process already holds that
/// lease: an operator does not have to stop the Engine to see its authorization state or to clear
/// one profile's local authority.
/// </para>
/// <para>
/// The channel is opt-in and entirely absent unless the operator names a dedicated secret file.
/// Absent configuration means no route is mapped, so the safe default needs no request-time branch.
/// A managed deployment maps only the read-only routes: local authorization is Platform-owned there,
/// and a local clear would be a second authority for the same fact.
/// </para>
/// <para>
/// It is deliberately not an MCP tool. Clearing a local authorization is an operator action on one
/// process; advertising it as a tool would make a caller's own MCP surface able to drop another
/// principal's credential, and would put a deployment mutation behind a listing a caller reads
/// rather than behind the deployment's own credential.
/// </para>
/// <para>
/// The relay routes are the one place this channel starts work rather than only reading or clearing
/// it. A serving process owns the store-root lease, so it is the only process that can both authorize
/// a profile and commit the result without a second authority: the operator's own listener receives
/// the callback and hands back only the values the exchange needs, while the verifier, the protocol
/// state and the commit stay here.
/// </para>
/// </remarks>
internal static class OAuthOperatorEndpoints
{
    /// <summary>The base path of the operator channel.</summary>
    /// <remarks>
    /// A two-segment shape no Manifest prefix is expected to claim, and one that is never an MCP
    /// address. It is deliberately distinct from the response-cache channel's path so an operator
    /// can grant the two credentials separately.
    /// </remarks>
    internal const string BasePath = "/.engine/oauth";

    /// <summary>The negotiation route: the contract, the mode and the admitted capabilities.</summary>
    internal const string CapabilityPath = BasePath + "/capability";

    /// <summary>The read-only route reporting standalone authorization state.</summary>
    internal const string StatusPath = BasePath + "/status";

    /// <summary>The read-only route reporting recent sanitized authorization outcomes.</summary>
    internal const string EventsPath = BasePath + "/events";

    /// <summary>The destructive route clearing one profile's local authority, file mode only.</summary>
    internal const string ClearPath = BasePath + "/clear";

    /// <summary>The route that opens one host-owned authorization attempt, file mode only.</summary>
    internal const string AuthorizePath = BasePath + "/authorize";

    /// <summary>The route that completes the attempt a handle names, file mode only.</summary>
    internal const string AuthorizeCompletePath = AuthorizePath + "/complete";

    /// <summary>The route that abandons an attempt the caller no longer intends to finish.</summary>
    internal const string AuthorizeAbortPath = AuthorizePath + "/abort";

    /// <summary>Largest query string this channel reads, in characters.</summary>
    /// <remarks>
    /// No read-only route here reads a request body, so the query string is the only caller-supplied
    /// input there and it is bounded rather than parsed at whatever length arrives.
    /// </remarks>
    internal const int MaximumQueryCharacters = 2048;

    /// <summary>
    /// Largest request body this channel reads, in characters.
    /// </summary>
    /// <remarks>
    /// Only the three relay routes read a body, and they read it as one small JSON object. A
    /// completion body carries a callback code, so it is deliberately not a URL: a code in a query
    /// string is a code in every access log between the two processes.
    /// </remarks>
    internal const int MaximumBodyCharacters = 4096;

    private const string MountQuery = "mount";
    private const string ProfileQuery = "profile";
    private const string LimitQuery = "limit";

    /// <summary>The number of recent outcomes returned when the caller names no limit.</summary>
    internal const int DefaultEventLimit = 16;

    /// <summary>The capabilities a file-mode deployment admits.</summary>
    private static readonly string[] FileCapabilities =
        ["capability", "status", "events", "clear", "authorize", "complete", "abort"];

    /// <summary>The capabilities a managed deployment admits.</summary>
    private static readonly string[] ManagedCapabilities = ["capability", "status", "events"];

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Maps the operator channel when a secret was configured, and nothing otherwise.</summary>
    /// <param name="app">The application being built.</param>
    /// <param name="binding">The bound configuration, which carries the operator secret.</param>
    /// <param name="managed">Whether this process serves a Platform-owned mount set.</param>
    internal static void Map(WebApplication app, HostBinding binding, bool managed)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(binding);

        if (binding.OAuthOperatorSecret is not { Length: > 0 } secret)
        {
            return;
        }

        // One authenticator and one admission budget for the process. The secret is already resident
        // because startup read and kept it, and the budget is process-wide because there is one
        // operator credential: a caller cannot earn more budget by naming more mounts.
        OperatorChannelCredential credential = new(secret);
        OAuthOperatorAdmission admission = new();

        // The configured validation mode is a startup fact. The observation buffer cannot name it
        // before anything was observed, so the status route reports it from the bound configuration.
        string? availabilityMode = binding.Authorization?.Validation switch
        {
            HostTokenValidation.Jwks => IssuerAvailabilityNames.Write(IssuerAvailabilityMode.Jwks),
            HostTokenValidation.Introspection => IssuerAvailabilityNames.Write(IssuerAvailabilityMode.Introspection),
            _ => null,
        };

        app.MapGet(CapabilityPath, (HttpContext context) =>
            HandleCapabilityAsync(context, credential, admission, managed));

        app.MapGet(StatusPath, (HttpContext context) =>
            HandleStatusAsync(context, credential, admission, managed, availabilityMode));

        app.MapGet(EventsPath, (HttpContext context) =>
            HandleEventsAsync(context, credential, admission));

        if (!managed)
        {
            // A managed deployment maps no clear route at all: there is no local authority for this
            // process to clear, so a route that could only refuse would be advertising an operator
            // action that does not exist here. The capability route states the boundary instead.
            StandaloneAuthorizationRelaySessions sessions = new();

            app.MapPost(ClearPath, (HttpContext context) =>
                HandleClearAsync(context, credential, admission));

            app.MapPost(AuthorizePath, (HttpContext context) =>
                HandleAuthorizeAsync(context, credential, admission, sessions));

            app.MapPost(AuthorizeCompletePath, (HttpContext context) =>
                HandleAuthorizeCompleteAsync(context, credential, admission, sessions));

            app.MapPost(AuthorizeAbortPath, (HttpContext context) =>
                HandleAuthorizeAbortAsync(context, credential, admission, sessions));        }
    }

    private static async Task HandleCapabilityAsync(
        HttpContext context,
        OperatorChannelCredential credential,
        OAuthOperatorAdmission admission,
        bool managed)
    {
        using IDisposable? lease = await AdmitAsync(context, credential, admission).ConfigureAwait(false);

        if (lease is null)
        {
            return;
        }

        if (!TryQuery(context.Request.Query, MountQuery, required: false, out _, out string? failure)
            || !TryQuery(context.Request.Query, ProfileQuery, required: false, out _, out failure)
            || !TryQuery(context.Request.Query, LimitQuery, required: false, out _, out failure))
        {
            await WriteJsonAsync(context, StatusCodes.Status400BadRequest, new { error = failure })
                .ConfigureAwait(false);
            return;
        }

        await WriteJsonAsync(context, StatusCodes.Status200OK, managed
            ? new
            {
                contract = CompatibilitySchema.OAuthOperator,
                generation = CompatibilitySchema.OAuthOperatorGeneration,
                mode = "managed",
                state = "read-only",
                capabilities = ManagedCapabilities,
                message = "This deployment is managed by the Platform, so its authorizations are Platform-owned and no local clear route is mapped.",
                nextAction = "Change the deployment from the Platform.",
            }
            : new
            {
                contract = CompatibilitySchema.OAuthOperator,
                generation = CompatibilitySchema.OAuthOperatorGeneration,
                mode = "file",
                state = "enabled",
                capabilities = FileCapabilities,
                bounds = new
                {
                    concurrent = OAuthOperatorAdmission.MaximumConcurrent,
                    pending = OAuthOperatorAdmission.MaximumPending,
                    ratePerWindow = OAuthOperatorAdmission.MaximumRequestsPerWindow,
                    windowSeconds = (int)OAuthOperatorAdmission.Window.TotalSeconds,
                    maxWaitSeconds = (int)OAuthOperatorAdmission.MaximumWait.TotalSeconds,
                    maxEventLimit = AuthorizationOutcomeLog.DefaultMaximumEntries,
                    maxQueryCharacters = MaximumQueryCharacters,
                    maxBodyCharacters = MaximumBodyCharacters,
                    maxRelaySessions = StandaloneAuthorizationRelaySessions.MaximumSessions,
                },
                message = "Standalone authorization state for this process, read-only except for clearing one profile's local authority and for driving one relayed authorization attempt.",
            }).ConfigureAwait(false);
    }

    private static async Task HandleStatusAsync(
        HttpContext context,
        OperatorChannelCredential credential,
        OAuthOperatorAdmission admission,
        bool managed,
        string? availabilityMode)
    {
        using IDisposable? lease = await AdmitAsync(context, credential, admission).ConfigureAwait(false);

        if (lease is null)
        {
            return;
        }

        if (!TryQuery(context.Request.Query, MountQuery, required: false, out string? mount, out string? failure)
            || !TryQuery(context.Request.Query, ProfileQuery, required: false, out string? profile, out failure))
        {
            await WriteJsonAsync(context, StatusCodes.Status400BadRequest, new { error = failure })
                .ConfigureAwait(false);
            return;
        }

        IReadOnlyList<StandaloneAuthorizationStatus> report;

        if (managed)
        {
            if (!TryLease(context, out EngineGenerationLease? generation, out Task? refused))
            {
                await refused!.ConfigureAwait(false);
                return;
            }

            using (generation)
            {
                report = StandaloneAuthorizationOperations.DescribeManaged(
                    generation!.Generation.Mounts.Mounts,
                    mount,
                    profile);
            }
        }
        else
        {
            if (context.RequestServices.GetService<RuntimeStartResult>() is not { } start)
            {
                await WriteJsonAsync(
                        context,
                        StatusCodes.Status409Conflict,
                        new { error = "This process has no started file-mode runtime, so it holds no local authorization state to report." })
                    .ConfigureAwait(false);
                return;
            }

            // This process is the serving owner of its own runtime-state root, so the read does not
            // race another process holding the lease: there is none to hold it.
            report = await StandaloneAuthorizationOperations
                .DescribeAsync(start, mount, profile, ownerElsewhere: false, context.RequestAborted)
                .ConfigureAwait(false);
        }

        IssuerAvailabilityObservations? availability =
            context.RequestServices.GetService<IssuerAvailabilityObservations>();

        await WriteJsonAsync(context, StatusCodes.Status200OK, new
        {
            profiles = report.Select(StatusPayload).ToArray(),
            issuerAvailability = availability is null
                ? null
                : AvailabilityPayload(availability, availabilityMode),
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// The bounded issuer trust observations an operator reads beside authorization state.
    /// </summary>
    /// <remarks>
    /// Each entry is a mode, a timestamp, a stable category and the fixed fail-closed consequence of
    /// that category. Nothing observed at runtime is echoed, so no endpoint spelling, response
    /// member, token or credential has a field to travel in. The buffer is in-memory and discarded
    /// with the process; an empty history means no observation was recorded, never that validation
    /// behaved differently.
    /// </remarks>
    private static object AvailabilityPayload(
        IssuerAvailabilityObservations observations,
        string? mode)
    {
        IReadOnlyList<IssuerAvailabilityObservation> events =
            observations.Recent(TimeProvider.System.GetUtcNow());

        return new
        {
            mode,
            storage = "in-memory",
            durable = false,
            maximumEntries = observations.MaximumEntries,
            retained = events.Count,
            events = events.Select(observation => new
            {
                observedAtUtc = observation.ObservedAtUtc,
                mode = IssuerAvailabilityNames.Write(observation.Mode),
                category = IssuerAvailabilityNames.Write(observation.Category),
                effect = IssuerAvailabilityEffects.Describe(observation.Mode, observation.Category),
            }).ToArray(),
        };
    }

    /// <summary>
    /// One status entry as an operator reads it.
    /// </summary>
    /// <remarks>
    /// The state is projected to its wire spelling rather than left as an enum member, so the
    /// authenticated channel and the command line name one state one way. Everything else is the
    /// library's own non-secret value, passed through unshaped.
    /// </remarks>
    private static object StatusPayload(StandaloneAuthorizationStatus status) => new
    {
        status.MountPrefix,
        status.ProfileId,
        status.ProfileKind,
        state = StandaloneAuthorizationStateNames.Write(status.State),
        status.Code,
        status.Message,
        status.NextAction,
        status.Sources,
        status.AuthorityEpoch,
        status.RuntimeRevision,
    };

    private static async Task HandleEventsAsync(
        HttpContext context,
        OperatorChannelCredential credential,
        OAuthOperatorAdmission admission)
    {
        using IDisposable? lease = await AdmitAsync(context, credential, admission).ConfigureAwait(false);

        if (lease is null)
        {
            return;
        }

        if (!TryQuery(context.Request.Query, LimitQuery, required: false, out string? limit, out string? failure))
        {
            await WriteJsonAsync(context, StatusCodes.Status400BadRequest, new { error = failure })
                .ConfigureAwait(false);
            return;
        }

        int maximum = DefaultEventLimit;

        if (limit is not null
            && (!int.TryParse(limit, NumberStyles.None, CultureInfo.InvariantCulture, out maximum)
                || maximum < 1
                || maximum > AuthorizationOutcomeLog.DefaultMaximumEntries))
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    new
                    {
                        error = $"The '{LimitQuery}' query parameter must be a whole number between 1 and {AuthorizationOutcomeLog.DefaultMaximumEntries}.",
                    })
                .ConfigureAwait(false);
            return;
        }

        AuthorizationOutcomeLog log = AuthorizationOutcomeLog.Shared;
        IReadOnlyList<AuthorizationOutcome> recent = log.Recent(TimeProvider.System.GetUtcNow(), maximum);

        await WriteJsonAsync(context, StatusCodes.Status200OK, new
        {
            storage = "in-memory",
            durable = false,
            retained = log.Count,
            maximumEntries = log.MaximumEntries,
            events = recent,
        }).ConfigureAwait(false);
    }

    private static async Task HandleClearAsync(
        HttpContext context,
        OperatorChannelCredential credential,
        OAuthOperatorAdmission admission)
    {
        using IDisposable? lease = await AdmitAsync(context, credential, admission).ConfigureAwait(false);

        if (lease is null)
        {
            return;
        }

        if (!TryQuery(context.Request.Query, MountQuery, required: true, out string? mount, out string? failure)
            || !TryQuery(context.Request.Query, ProfileQuery, required: true, out string? profile, out failure))
        {
            await WriteJsonAsync(context, StatusCodes.Status400BadRequest, new { error = failure })
                .ConfigureAwait(false);
            return;
        }

        if (context.RequestServices.GetService<RuntimeStartResult>() is not { } start)
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status409Conflict,
                    new { error = "This process has no started file-mode runtime, so there is no local authorization to clear." })
                .ConfigureAwait(false);
            return;
        }

        if (!TryLease(context, out EngineGenerationLease? generation, out Task? refused))
        {
            await refused!.ConfigureAwait(false);
            return;
        }

        StandaloneClearOutcome outcome;

        // The generation lease is held for the whole clear, so an activation cannot retire the
        // execution this clear fences while the commit is still in progress.
        using (generation)
        {
            outcome = await StandaloneAuthorizationOperations
                .ClearServingAsync(
                    start,
                    generation!.Generation.Execution,
                    mount!,
                    profile!,
                    timeProvider: TimeProvider.System,
                    context.RequestAborted)
                .ConfigureAwait(false);
        }

        RecordOutcomes(outcome);

        await WriteJsonAsync(context, ClearStatusCode(outcome), outcome).ConfigureAwait(false);
    }

    private static int ClearStatusCode(StandaloneClearOutcome outcome)
    {
        if (outcome.Cleared)
        {
            return StatusCodes.Status200OK;
        }

        return outcome.Code switch
        {
            "oauth/already-cleared" => StatusCodes.Status200OK,
            "oauth/nothing-to-clear" => StatusCodes.Status200OK,
            "oauth/authority-unreadable" => StatusCodes.Status409Conflict,
            "oauth/persistence-failed" => StatusCodes.Status409Conflict,

            // An unknown mount or profile is the caller naming something this process does not serve.
            // It answers 404 so it cannot be confused with a refusal about state.
            "standalone/unknown-mount" => StatusCodes.Status404NotFound,
            "standalone/unknown-profile" => StatusCodes.Status404NotFound,
            _ => StatusCodes.Status400BadRequest,
        };
    }

    private static void RecordOutcomes(StandaloneClearOutcome outcome)
    {
        AuthorizationOutcomeLog log = AuthorizationOutcomeLog.Shared;
        DateTimeOffset at = TimeProvider.System.GetUtcNow();

        log.Record(new AuthorizationOutcome(
            at, "clear", outcome.MountPrefix, outcome.ProfileId, "local", outcome.Code, outcome.Message));

        if (outcome.ProviderOutcome is { Length: > 0 })
        {
            log.Record(new AuthorizationOutcome(
                at,
                "clear",
                outcome.MountPrefix,
                outcome.ProfileId,
                "provider",
                "oauth/revocation-" + outcome.ProviderOutcome,
                outcome.ProviderDetail ?? string.Empty));
        }
    }

    /// <summary>
    /// Opens one host-owned authorization attempt for an authenticated operator.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The attempt is built here, in the process that holds the store-root lease, and it stays here:
    /// the response carries the authorization URL to open and a handle standing for the session,
    /// never the PKCE verifier or the protocol state. What the caller must demonstrate is an exact
    /// loopback callback it can bind, which is the redirect URI in the request; nothing else about
    /// the caller's machine is assumed and no callback endpoint is exposed by this process.
    /// </para>
    /// <para>
    /// The generation lease is held while the attempt is built so an activation cannot retire the
    /// execution whose runtime will later commit it.
    /// </para>
    /// </remarks>
    /// <summary>
    /// Opens one host-owned authorization attempt for an authenticated operator.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The attempt is built here, in the process that holds the store-root lease, and it stays here:
    /// the response carries the authorization URL to open and a handle standing for the session,
    /// never the PKCE verifier or the protocol state. What the caller must demonstrate is an exact
    /// loopback callback it can bind, which is the redirect URI in the request; nothing else about
    /// the caller's machine is assumed and this process exposes no callback endpoint of its own.
    /// </para>
    /// <para>
    /// The generation lease is held while the attempt is built and recorded, so an activation cannot
    /// retire the execution whose runtime will later commit the result.
    /// </para>
    /// </remarks>
    private static async Task HandleAuthorizeAsync(
        HttpContext context,
        OperatorChannelCredential credential,
        OAuthOperatorAdmission admission,
        StandaloneAuthorizationRelaySessions sessions)
    {
        using IDisposable? lease = await AdmitAsync(context, credential, admission, allowsBody: true).ConfigureAwait(false);

        if (lease is null)
        {
            return;
        }

        if (await ReadBodyAsync<AuthorizeRequest>(context).ConfigureAwait(false) is not { } request)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(request.Mount) || string.IsNullOrWhiteSpace(request.Profile))
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    new { error = "The 'mount' and 'profile' body members are required." })
                .ConfigureAwait(false);
            return;
        }

        if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out Uri? redirect))
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    new { error = "The 'redirectUri' body member must be the absolute loopback callback URI your own listener is bound to." })
                .ConfigureAwait(false);
            return;
        }

        if (context.RequestServices.GetService<RuntimeStartResult>() is not { } start)
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status409Conflict,
                    new { error = "This process has no started file-mode runtime, so it has nowhere to commit an authorization." })
                .ConfigureAwait(false);
            return;
        }

        if (!TryLease(context, out EngineGenerationLease? generation, out Task? refused))
        {
            await refused!.ConfigureAwait(false);
            return;
        }

        StandaloneAuthorizationRelayStart opened;

        // The generation lease is held while the attempt is built and recorded, so an activation
        // cannot retire the execution whose runtime will later commit the result.
        using (generation)
        {
            opened = await StandaloneAuthorizationOperations
                .OpenRelayAsync(
                    start,
                    generation!.Generation.Execution,
                    sessions,
                    new StandaloneAuthorizationTarget(request.Mount, request.Profile, redirect),
                    credential.Fingerprint,
                    cancellationToken: context.RequestAborted)
                .ConfigureAwait(false);
        }

        if (!opened.Opened || opened.Relay is not { } relay)
        {
            await WriteJsonAsync(
                    context,
                    PrepareStatusCode(opened.Refusals),
                    new { refusals = opened.Refusals })
                .ConfigureAwait(false);
            return;
        }

        await WriteJsonAsync(context, StatusCodes.Status200OK, new
        {
            relay = relay.Handle,
            authorizationUrl = relay.AuthorizationUrl.AbsoluteUri,
            redirectUri = relay.RedirectUri.AbsoluteUri,
            expiresAtUtc = relay.ExpiresAtUtc,
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// Completes the attempt a handle names and commits what the provider issued.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The handle is single-use: taking it removes it, so a replayed callback is refused before the
    /// attempt is touched, and the attempt itself is single-use as well. The forwarded values are the
    /// callback's decoded <c>state</c>, <c>code</c> and <c>error</c> — the state is still compared
    /// with this attempt's own value before any exchange, so a callback minted for another attempt
    /// cannot complete this one.
    /// </para>
    /// <para>
    /// Nothing here logs, stores or echoes what it was handed: the outcome carries a stable code, a
    /// bounded message and the epoch a commit established.
    /// </para>
    /// </remarks>
    private static async Task HandleAuthorizeCompleteAsync(
        HttpContext context,
        OperatorChannelCredential credential,
        OAuthOperatorAdmission admission,
        StandaloneAuthorizationRelaySessions sessions)
    {
        using IDisposable? lease = await AdmitAsync(context, credential, admission, allowsBody: true).ConfigureAwait(false);

        if (lease is null)
        {
            return;
        }

        if (await ReadBodyAsync<CompleteRequest>(context).ConfigureAwait(false) is not { } request)
        {
            return;
        }

        if (string.IsNullOrEmpty(request.Relay))
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    new { error = "The 'relay' body member is required." })
                .ConfigureAwait(false);
            return;
        }

        if (context.RequestServices.GetService<RuntimeStartResult>() is not { } start)
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status409Conflict,
                    new { error = "This process has no started file-mode runtime, so the authorization cannot be committed." })
                .ConfigureAwait(false);
            return;
        }

        if (!TryLease(context, out EngineGenerationLease? generation, out Task? refused))
        {
            await refused!.ConfigureAwait(false);
            return;
        }

        StandaloneAuthorizationOutcome outcome;

        // The generation lease is held for the whole completion, so an activation cannot retire the
        // execution whose runtime performs this compare-and-commit.
        using (generation)
        {
            outcome = await StandaloneAuthorizationOperations
                .CompleteRelayAsync(
                    start,
                    generation!.Generation.Execution,
                    sessions,
                    request.Relay,
                    credential.Fingerprint,
                    request.State,
                    request.Code,
                    request.Error,
                    context.RequestAborted)
                .ConfigureAwait(false);
        }

        RecordAuthorization(outcome);

        await WriteJsonAsync(context, AuthorizeStatusCode(outcome), new
        {
            authorized = outcome.Authorized,
            outcome.Code,
            outcome.Message,
            outcome.MountPrefix,
            outcome.ProfileId,
            outcome.AuthorityEpoch,
            outcome.RuntimeRevision,
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// Abandons the attempt a handle names, for an operator who will not finish it.
    /// </summary>
    /// <remarks>
    /// Abandoning is idempotent: a handle that is already gone is answered as not-abandoned rather
    /// than as an error, because the operator's intent — this authorization will not be completed —
    /// already holds. A handle opened with a different credential is refused instead of consumed.
    /// </remarks>
    private static async Task HandleAuthorizeAbortAsync(
        HttpContext context,
        OperatorChannelCredential credential,
        OAuthOperatorAdmission admission,
        StandaloneAuthorizationRelaySessions sessions)
    {
        using IDisposable? lease = await AdmitAsync(context, credential, admission, allowsBody: true).ConfigureAwait(false);

        if (lease is null)
        {
            return;
        }

        if (await ReadBodyAsync<AbortRequest>(context).ConfigureAwait(false) is not { } request)
        {
            return;
        }

        if (string.IsNullOrEmpty(request.Relay))
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    new { error = "The 'relay' body member is required." })
                .ConfigureAwait(false);
            return;
        }

        (bool removed, bool matched) = StandaloneAuthorizationOperations
            .AbandonRelay(sessions, request.Relay, credential.Fingerprint);

        if (!matched)
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status403Forbidden,
                    new { error = "That authorization session was opened with a different operator credential." })
                .ConfigureAwait(false);
            return;
        }

        await WriteJsonAsync(context, StatusCodes.Status200OK, new { abandoned = removed }).ConfigureAwait(false);
    }

    private static void RecordAuthorization(StandaloneAuthorizationOutcome outcome)
    {
        AuthorizationOutcomeLog.Shared.Record(new AuthorizationOutcome(
            TimeProvider.System.GetUtcNow(),
            "authorize",
            outcome.MountPrefix,
            outcome.ProfileId,
            "local",
            outcome.Code,
            outcome.Message));
    }

    private static int PrepareStatusCode(IReadOnlyList<StartupRefusal> refusals)
    {
        string code = refusals.Count > 0 ? refusals[0].Code : "standalone/runtime-refused";

        if (code.StartsWith("standalone/unknown", StringComparison.Ordinal))
        {
            return StatusCodes.Status404NotFound;
        }

        return code switch
        {
            "standalone/relay-capacity" => StatusCodes.Status503ServiceUnavailable,
            var other when other.StartsWith("standalone/", StringComparison.Ordinal) => StatusCodes.Status409Conflict,
            _ => StatusCodes.Status400BadRequest,
        };
    }

    private static int AuthorizeStatusCode(StandaloneAuthorizationOutcome outcome)
    {
        if (outcome.Authorized)
        {
            return StatusCodes.Status200OK;
        }

        if (outcome.Code.StartsWith("standalone/unknown", StringComparison.Ordinal))
        {
            return StatusCodes.Status404NotFound;
        }

        return outcome.Code switch
        {
            "standalone/relay-credential-mismatch" => StatusCodes.Status403Forbidden,
            "standalone/relay-expired" => StatusCodes.Status410Gone,
            "standalone/relay-unknown" => StatusCodes.Status404NotFound,
            "oauth/persistence-failed" => StatusCodes.Status409Conflict,
            "oauth/authority-unreadable" => StatusCodes.Status409Conflict,
            "oauth/declaration-changed" => StatusCodes.Status409Conflict,
            "oauth/attempt-expired" => StatusCodes.Status409Conflict,
            "oauth/attempt-not-pending" => StatusCodes.Status409Conflict,
            _ => StatusCodes.Status400BadRequest,
        };
    }

    /// <summary>Reads the one bounded JSON object a relay route accepts.</summary>
    /// <remarks>
    /// The length is checked before the body is read, so an oversized body is refused rather than
    /// buffered, and the read is bounded even when the declared length was accurate. A route that
    /// reads no body at all is refused a body by <see cref="AdmitAsync"/>, so this is never reached
    /// with an unexpected payload.
    /// </remarks>
    private static async ValueTask<T?> ReadBodyAsync<T>(HttpContext context)
        where T : class
    {
        byte[] buffer = new byte[MaximumBodyCharacters];
        int read = 0;

        while (read < buffer.Length)
        {
            int chunk = await context.Request.Body
                .ReadAsync(buffer.AsMemory(read), context.RequestAborted)
                .ConfigureAwait(false);

            if (chunk == 0)
            {
                break;
            }

            read += chunk;
        }

        try
        {
            if (JsonSerializer.Deserialize<T>(buffer.AsSpan(0, read), Json) is { } value)
            {
                return value;
            }

            await WriteJsonAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    new { error = "The request body is empty." })
                .ConfigureAwait(false);
            return null;
        }
        catch (JsonException)
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    new { error = "The request body is not a JSON object this route understands." })
                .ConfigureAwait(false);
            return null;
        }
    }

    private sealed record AuthorizeRequest(string? Mount, string? Profile, string? RedirectUri = null);

    private sealed record CompleteRequest(string? Relay, string? State = null, string? Code = null, string? Error = null);

    private sealed record AbortRequest(string? Relay);

    /// <summary>
    /// The whole request-level precondition set, in order: credential, transport, contract, bounds.
    /// </summary>
    /// <remarks>
    /// Authenticating before anything else is what makes the rest of this file safe to read in any
    /// order: a caller that has not proved the operator credential cannot learn whether a mount
    /// prefix exists, cannot make this process read durable state, and cannot cause an outbound
    /// request. The transport and contract checks follow because they are properties of the request
    /// itself, and admission is last so that only an otherwise-valid request costs operator budget.
    /// </remarks>
    /// <param name="context">The request being admitted.</param>
    /// <param name="credential">The configured operator credential.</param>
    /// <param name="admission">The process-wide admission budget.</param>
    /// <param name="allowsBody">
    /// Whether this route reads one bounded JSON body. The read-only routes read none, and refusing a
    /// body they would ignore keeps a caller from smuggling an unbounded payload through a route
    /// that never looks at it.
    /// </param>
    /// <returns>An admission lease to dispose when the operation completes, or null when refused.</returns>
    private static async ValueTask<IDisposable?> AdmitAsync(
        HttpContext context,
        OperatorChannelCredential credential,
        OAuthOperatorAdmission admission,
        bool allowsBody = false)
    {
        if (!credential.IsAuthorized(context.Request))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = "Bearer realm=\"engine-operator\"";
            return null;
        }

        if (!OperatorChannel.IsTransportAcceptable(context.Request.IsHttps, context.Connection.RemoteIpAddress))
        {
            // Reached over plain http from somewhere other than loopback. Refuse before any state is
            // read or changed: the secret travels on this request, and a remote plaintext channel
            // would disclose both the credential and the observation.
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status403Forbidden,
                    new { error = "The operator channel requires https unless the request originates on loopback." })
                .ConfigureAwait(false);
            return null;
        }

        if (!HasContract(context.Request))
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status409Conflict,
                    new { error = "The operator contract generation is missing or unsupported." })
                .ConfigureAwait(false);
            return null;
        }

        // No read-only route here reads a request body, and only the relay routes read one at all.
        // Either way the size is decided before the body is touched.
        if (!allowsBody)
        {
            if (context.Request.ContentLength is > 0)
            {
                await WriteJsonAsync(
                        context,
                        StatusCodes.Status400BadRequest,
                        new { error = "This route reads no request body." })
                    .ConfigureAwait(false);
                return null;
            }
        }
        else if (context.Request.ContentLength is null or 0 or > MaximumBodyCharacters)
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    new { error = $"This route reads one JSON body of at most {MaximumBodyCharacters} characters." })
                .ConfigureAwait(false);
            return null;
        }

        if (context.Request.QueryString.Value is { Length: > MaximumQueryCharacters })
        {
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    new { error = $"The query string exceeds {MaximumQueryCharacters} characters." })
                .ConfigureAwait(false);
            return null;
        }

        IDisposable? lease = await admission.TryEnterAsync(context.RequestAborted).ConfigureAwait(false);

        if (lease is not null)
        {
            return lease;
        }

        if (admission.RateLimited)
        {
            context.Response.Headers.RetryAfter = ((int)OAuthOperatorAdmission.Window.TotalSeconds)
                .ToString(CultureInfo.InvariantCulture);
            await WriteJsonAsync(
                    context,
                    StatusCodes.Status429TooManyRequests,
                    new
                    {
                        error = $"Too many operator requests. At most {OAuthOperatorAdmission.MaximumRequestsPerWindow} are admitted per second.",
                    })
                .ConfigureAwait(false);
            return null;
        }

        await WriteJsonAsync(
                context,
                StatusCodes.Status503ServiceUnavailable,
                new
                {
                    error = $"The operator channel is at its admitted bound ({OAuthOperatorAdmission.MaximumConcurrent} active, {OAuthOperatorAdmission.MaximumPending} pending). Retry shortly.",
                })
            .ConfigureAwait(false);
        return null;
    }

    private static bool HasContract(HttpRequest request)
    {
        if (!request.Headers.TryGetValue(CompatibilitySchema.ContractGenerationHeader, out var values)
            || values.Count != 1)
        {
            return false;
        }

        return string.Equals(
            values[0],
            CompatibilitySchema.OAuthOperatorGeneration,
            StringComparison.Ordinal);
    }

    private static bool TryLease(HttpContext context, out EngineGenerationLease? lease, out Task? refused)
    {
        refused = null;

        if (context.RequestServices.GetRequiredService<EngineGenerationManager>().TryLease(out lease)
            && lease is not null)
        {
            return true;
        }

        refused = WriteJsonAsync(
            context,
            StatusCodes.Status503ServiceUnavailable,
            new { error = "No generation is currently serving." });
        lease = null;
        return false;
    }

    private static bool TryQuery(
        IQueryCollection query,
        string name,
        bool required,
        out string? value,
        out string? failure)
    {
        value = null;
        failure = null;

        if (!query.TryGetValue(name, out Microsoft.Extensions.Primitives.StringValues values)
            || values.Count == 0)
        {
            if (required)
            {
                failure = $"The '{name}' query parameter is required.";
                return false;
            }

            return true;
        }

        // Repeated members are refused rather than resolved. Choosing one would let two callers
        // disagree about which target they named while the response describes only one.
        if (values.Count != 1)
        {
            failure = $"The '{name}' query parameter must be given exactly once.";
            return false;
        }

        value = values[0];

        if (string.IsNullOrEmpty(value))
        {
            failure = $"The '{name}' query parameter must not be empty.";
            return false;
        }

        return true;
    }

    private static Task WriteJsonAsync(HttpContext context, int status, object payload)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        return context.Response.WriteAsync(JsonSerializer.Serialize(payload, Json), context.RequestAborted);
    }
}

/// <summary>
/// Bounded admission for the authorization operator channel.
/// </summary>
/// <remarks>
/// <para>
/// Explicit rather than left to the thread pool. The channel can clear a live credential, so a burst
/// of operator requests must cost a bounded amount of work: at most
/// <see cref="MaximumConcurrent"/> operations run, at most <see cref="MaximumPending"/> wait behind
/// them, and a caller beyond either bound is refused rather than queued without limit.
/// </para>
/// <para>
/// The rate window is separate from the concurrency bound because the two refuse different things:
/// the window stops a fast loop of cheap refusals from consuming the channel at all, and the
/// concurrency bound stops a small number of expensive mutations from piling up. A refusal caused by
/// the concurrency bound does not consume the rate budget, so an operator who retries after a busy
/// answer is not then refused for asking too often.
/// </para>
/// <para>
/// Admission is process-wide because there is one operator credential, and therefore one operator
/// budget. A caller cannot earn more of it by naming more mounts.
/// </para>
/// </remarks>
internal sealed class OAuthOperatorAdmission
{
    /// <summary>Operations admitted at once.</summary>
    internal const int MaximumConcurrent = 4;

    /// <summary>Operations admitted to wait beyond those running.</summary>
    internal const int MaximumPending = 8;

    /// <summary>Requests admitted per <see cref="Window"/>.</summary>
    internal const int MaximumRequestsPerWindow = 20;

    /// <summary>The sliding window the request rate is measured over.</summary>
    internal static readonly TimeSpan Window = TimeSpan.FromSeconds(1);

    /// <summary>How long a wait behind the running set may last before the caller is refused.</summary>
    internal static readonly TimeSpan MaximumWait = TimeSpan.FromSeconds(2);

    private readonly object _gate = new();
    private readonly LinkedList<TaskCompletionSource<bool>> _waiters = new();
    private readonly Queue<DateTimeOffset> _arrivals = new();
    private int _active;

    /// <summary>Whether the last refusal was the rate window rather than the concurrency bound.</summary>
    internal bool RateLimited { get; private set; }

    /// <summary>Operations currently admitted.</summary>
    internal int Active
    {
        get
        {
            lock (_gate)
            {
                return _active;
            }
        }
    }

    /// <summary>Operations waiting to be admitted.</summary>
    internal int Waiting
    {
        get
        {
            lock (_gate)
            {
                return _waiters.Count;
            }
        }
    }

    /// <summary>
    /// Admits one operation, waiting behind the running set when the bound allows it, or refusing.
    /// </summary>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>A lease to dispose when the operation completes; null when refused.</returns>
    internal async ValueTask<IDisposable?> TryEnterAsync(CancellationToken cancellationToken)
    {
        RateLimited = false;
        LinkedListNode<TaskCompletionSource<bool>>? waiter = null;

        lock (_gate)
        {
            Prune(TimeProvider.System.GetUtcNow());

            if (_arrivals.Count >= MaximumRequestsPerWindow)
            {
                RateLimited = true;
                return null;
            }

            if (_active < MaximumConcurrent)
            {
                _arrivals.Enqueue(TimeProvider.System.GetUtcNow());
                _active++;
                return new Lease(this);
            }

            if (_waiters.Count >= MaximumPending)
            {
                return null;
            }

            _arrivals.Enqueue(TimeProvider.System.GetUtcNow());
            waiter = _waiters.AddLast(
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously));
        }

        bool admitted = false;

        try
        {
            admitted = await waiter.Value.Task.WaitAsync(MaximumWait, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (TimeoutException)
        {
        }

        if (admitted)
        {
            return new Lease(this);
        }

        lock (_gate)
        {
            if (waiter.Value.TrySetResult(false))
            {
                // No releaser transferred a slot to this waiter, so it withdraws its own request and
                // is refused. Both sides decide inside this lock, so a release and a timeout cannot
                // interleave into a slot that is neither handed over nor kept.
                _waiters.Remove(waiter);
                return null;
            }

            // A releaser handed this waiter the slot between the timeout and this lock. The slot is
            // now this caller's, so it proceeds rather than leaving an admission unaccounted for.
        }

        return new Lease(this);
    }

    private void Prune(DateTimeOffset now)
    {
        DateTimeOffset horizon = now - Window;

        while (_arrivals.Count > 0 && _arrivals.Peek() <= horizon)
        {
            _arrivals.Dequeue();
        }
    }

    private void Release()
    {
        lock (_gate)
        {
            // A waiting caller takes over the running slot rather than the count dropping and rising,
            // so the number of operations in flight never exceeds the bound at any instant.
            if (_waiters.First is { } next)
            {
                _waiters.RemoveFirst();
                next.Value.SetResult(true);
                return;
            }

            _active--;
        }
    }

    private sealed class Lease(OAuthOperatorAdmission admission) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                admission.Release();
            }
        }
    }
}
