using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Challenge;
using MCPiler.Engine.Authentication.Exchange;
using MCPiler.Engine.Authentication.OAuth1;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Authentication.Signing;
using MCPiler.Engine.Compound;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Projection;
using MCPiler.Engine.Files;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Runtime.Projection;
using MCPiler.Engine.Transform;

namespace MCPiler.Engine.Execution;

/// <summary>One execution as a caller describes it.</summary>
/// <param name="Manifest">The compiled manifest that governs the execution.</param>
/// <param name="Slug">The agent operation to execute.</param>
/// <param name="Arguments">The arguments as the caller supplied them.</param>
public sealed record ExecutionRequest(ManifestDocument Manifest, string Slug, JsonObject Arguments)
{
    /// <summary>
    /// File payloads by agent-facing slot name. The execution owns these sources and disposes
    /// them before it returns, whatever the outcome.
    /// </summary>
    public IReadOnlyDictionary<string, ExecutionFile>? Files { get; init; }

    /// <summary>
    /// The scope an issued file handle belongs to, defaulting to the manifest's server name.
    /// </summary>
    /// <remarks>
    /// Recorded now although nothing authorizes against it yet. A handle issued without a scope
    /// could not be retrofitted with one later without invalidating every handle already
    /// outstanding.
    /// </remarks>
    public string? Scope { get; init; }

    /// <summary>
    /// A response ceiling for this one execution, which may only narrow the policy's.
    /// </summary>
    /// <remarks>
    /// A workflow's aggregate budget is spent by its steps, and a step told only the policy's
    /// per-response ceiling would let the sum overrun by a whole response before anyone noticed.
    /// Stating what is left makes the aggregate a bound on what arrives rather than a total
    /// checked after it already did. It never widens: the effective limit is the smaller of the
    /// two, so a caller cannot raise a ceiling the policy compiled.
    /// </remarks>
    public long? ResponseSizeLimitBytes { get; init; }

    /// <summary>
    /// The serving layer's continuation resolution, when the caller can supply one.
    /// </summary>
    /// <remarks>
    /// Projection itself is protocol-neutral, but deciding whether a continuation names a target
    /// the addressed surface can actually call is not: it needs the mounted surface and its
    /// exposure table. The resolver is supplied rather than derived so this service keeps
    /// reaching nothing, and so a workflow step, which has no one addressed surface, can omit it
    /// and receive an <c>unavailable</c> continuation instead of a guessed one.
    /// </remarks>
    public IContinuationResolver? Continuations { get; init; }
    /// The authorization scope the current request was admitted under, when the host proved one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A protected HTTP request supplies the digest of the presented token, the canonical resource
    /// it was admitted for and the scopes it carried; an unauthenticated mount supplies
    /// <see cref="CallerPartition.Public"/>; a stdio caller or a library caller that proves nothing
    /// supplies nothing at all.
    /// </para>
    /// <para>
    /// Absence is meaningful. It means no component established who this caller is, and a
    /// response-cache decision must then bypass rather than choose a partition, because any
    /// partition it chose would conflate callers the runtime cannot tell apart.
    /// </para>
    /// </remarks>
    public CallerPartition? CallerPartition { get; init; }
}

/// <summary>
/// Runs one operation: which destination, which credentials, which limits, and what the answer
/// means.
/// </summary>
/// <remarks>
/// <para>
/// Everything that decides something lives here, and everything that touches the host is behind
/// a port. The consequence worth stating is that the whole order of operations — perimeter
/// before credentials, credentials before compilation, compilation before any socket — is
/// exercisable against a transport that opens nothing, so "no request was sent" is an assertion
/// rather than an inference.
/// </para>
/// <para>
/// The exchange has exactly one deadline, and it spans the chain rather than a request. A
/// redirect chain whose hops are each individually fast can take arbitrarily long, and a
/// per-request timeout bounds none of it. The budget also covers reading the body, because an
/// upstream that answers immediately and then trickles bytes has not been bounded by anything
/// that stops at the response headers.
/// </para>
/// </remarks>
public sealed class ExecutionService
{
    /// <summary>
    /// Prefixes an authentication failure reason.
    /// </summary>
    /// <remarks>
    /// A challenge refusal and an ordinary transport fault can both surface as a non-success
    /// response. The prefix is what lets a caller tell "the upstream refused this credential"
    /// from "the request failed", which is the difference between reauthorizing and retrying.
    /// </remarks>
    public const string AuthFailurePrefix = "auth-failure: ";

    private readonly IUpstreamTransport _transport;
    private readonly IManifestSecretResolver _secrets;
    private readonly FileHandleStore? _files;
    private readonly AuthenticationRuntime? _authentication;
    private readonly ResponseCache? _responseCache;

    /// <summary>
    /// The per-process key every cache-scoping identity is derived under.
    /// </summary>
    /// <remarks>
    /// Random and never persisted, so an opaque identity that escapes into a diagnostic or a
    /// telemetry event cannot be recomputed, correlated or replayed outside this process. One key
    /// per service is also why two processes serving byte-identical manifests never produce
    /// interchangeable identities.
    /// </remarks>
    private readonly byte[] _identityKey;

    private readonly IProjectionWorker? _projections;

    /// <summary>Creates a service over the supplied ports.</summary>
    /// <param name="transport">How an exchange reaches an upstream.</param>
    /// <param name="secrets">How credential references become values.</param>
    /// <param name="files">
    /// Where a binary response is stored. With none configured, a binary body is returned as
    /// bytes rather than as a handle.
    /// </param>
    /// <param name="authentication">
    /// The dynamic-auth runtime. With none configured, a manifest whose bindings reference an
    /// authentication profile is refused rather than executed unauthenticated.
    /// </param>
    public ExecutionService(
        IUpstreamTransport transport,
        IManifestSecretResolver secrets,
        FileHandleStore? files = null,
        AuthenticationRuntime? authentication = null,
        IProjectionWorker? projections = null)
        : this(transport, secrets, files, authentication, responseCache: null, identityKey: null, projections)
    {
    }

    /// <summary>Creates a mount-scoped service sharing its graph identity key with its cache.</summary>
    internal ExecutionService(
        IUpstreamTransport transport,
        IManifestSecretResolver secrets,
        FileHandleStore? files,
        AuthenticationRuntime? authentication,
        ResponseCache? responseCache,
        byte[]? identityKey,
        IProjectionWorker? projections = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(secrets);

        _transport = transport;
        _secrets = secrets;
        _files = files;
        _authentication = authentication;
        _responseCache = responseCache;
        _identityKey = identityKey ?? CacheIdentity.NewKey();
        _projections = projections;
    }

    /// <summary>The optional mount cache; null means this library execution is uncached.</summary>
    internal ResponseCache? ResponseCache => _responseCache;

    /// <summary>
    /// Mutable accumulator for one invocation's sanitized cache decision.
    /// </summary>
    /// <remarks>
    /// The defaults describe the two cases a cache decision must keep apart: no policy at all
    /// (a bypass because nothing opted in) and a policy whose lookup could not be attempted. The
    /// invocation overwrites the reason as it learns more, and the accumulated value is turned
    /// into one immutable decision at the end so the buffer never observes a partial record.
    /// </remarks>
    private sealed class CacheObservation
    {
        private CacheObservation(string operationSlug)
        {
            OperationSlug = operationSlug;
        }

        internal string OperationSlug { get; }

        internal ResponseCacheDecisionKind Kind { get; set; } = ResponseCacheDecisionKind.Bypass;

        internal ResponseCacheExecution Execution { get; set; } = ResponseCacheExecution.Upstream;

        internal string Reason { get; set; } = ResponseCacheDecisionReason.Unavailable;

        internal string? Fingerprint { get; set; }

        internal int? TtlSeconds { get; set; }

        internal int? AgeSeconds { get; set; }

        internal int? RemainingSeconds { get; set; }

        internal ResponseCacheFlightRole Role { get; set; } = ResponseCacheFlightRole.None;

        internal long? EntryBytes { get; set; }

        internal bool Stored { get; set; }

        internal static CacheObservation Start(string operationSlug, ResponseCachePolicySettings? policy)
            => new(operationSlug)
            {
                Reason = policy is null
                    ? ResponseCacheDecisionReason.PolicyAbsent
                    : ResponseCacheDecisionReason.Unavailable,
            };

        internal ResponseCacheDecision Finish(DateTimeOffset observedAtUtc)
            => new(
                observedAtUtc,
                OperationSlug,
                Kind,
                Execution,
                Reason,
                Fingerprint,
                TtlSeconds,
                AgeSeconds,
                RemainingSeconds,
                Role,
                EntryBytes,
                Stored);
    }

    private static ResponseCacheDecisionKind MapKind(ResponseCacheLookupKind kind)
        => kind switch
        {
            ResponseCacheLookupKind.Hit => ResponseCacheDecisionKind.Hit,
            ResponseCacheLookupKind.Miss => ResponseCacheDecisionKind.Miss,
            _ => ResponseCacheDecisionKind.Bypass,
        };

    private static string MapBypass(ResponseCacheBypassReason reason)
        => reason switch
        {
            ResponseCacheBypassReason.Disabled => ResponseCacheDecisionReason.Disabled,
            ResponseCacheBypassReason.FlightCapacity => ResponseCacheDecisionReason.FlightCapacity,
            ResponseCacheBypassReason.Disposed => ResponseCacheDecisionReason.Disposed,
            ResponseCacheBypassReason.UnknownDimension => ResponseCacheDecisionReason.UnknownDimension,
            _ => ResponseCacheDecisionReason.Unavailable,
        };

    private static string MapRequestBypass(ResponseCacheRequestBypassReason reason)
        => reason switch
        {
            ResponseCacheRequestBypassReason.UnsupportedMethod => ResponseCacheDecisionReason.UnsupportedMethod,
            ResponseCacheRequestBypassReason.RangeOrConditional => ResponseCacheDecisionReason.RangeOrConditional,
            ResponseCacheRequestBypassReason.RequestDirective => ResponseCacheDecisionReason.RequestDirective,
            ResponseCacheRequestBypassReason.MalformedHeader => ResponseCacheDecisionReason.MalformedRequestHeader,
            _ => ResponseCacheDecisionReason.Unavailable,
        };

    private static string MapAdmission(ResponseCacheAdmissionReason reason)
        => reason switch
        {
            ResponseCacheAdmissionReason.InvalidPolicy => ResponseCacheDecisionReason.InvalidPolicy,
            ResponseCacheAdmissionReason.UnsupportedMethod => ResponseCacheDecisionReason.UnsupportedMethod,
            ResponseCacheAdmissionReason.UnsuccessfulStatus => ResponseCacheDecisionReason.UnsuccessfulStatus,
            ResponseCacheAdmissionReason.PartialResponse => ResponseCacheDecisionReason.PartialResponse,
            ResponseCacheAdmissionReason.Redirected => ResponseCacheDecisionReason.Redirected,
            ResponseCacheAdmissionReason.FileResponse => ResponseCacheDecisionReason.FileResponse,
            ResponseCacheAdmissionReason.UnsupportedMediaType => ResponseCacheDecisionReason.UnsupportedMediaType,
            ResponseCacheAdmissionReason.ConditionalRequest => ResponseCacheDecisionReason.ConditionalRequest,
            ResponseCacheAdmissionReason.RequestDirective => ResponseCacheDecisionReason.RequestDirective,
            ResponseCacheAdmissionReason.MalformedRequestHeader => ResponseCacheDecisionReason.MalformedRequestHeader,
            ResponseCacheAdmissionReason.AuthenticationMetadata => ResponseCacheDecisionReason.AuthenticationMetadata,
            ResponseCacheAdmissionReason.ResponseDirective => ResponseCacheDecisionReason.ResponseDirective,
            ResponseCacheAdmissionReason.UnsupportedVary => ResponseCacheDecisionReason.UnsupportedVary,
            ResponseCacheAdmissionReason.PublicPrivateResponse => ResponseCacheDecisionReason.PublicPrivateResponse,
            ResponseCacheAdmissionReason.MalformedFreshness => ResponseCacheDecisionReason.MalformedFreshness,
            ResponseCacheAdmissionReason.FreshnessExpired => ResponseCacheDecisionReason.FreshnessExpired,
            ResponseCacheAdmissionReason.AuthorityExpired => ResponseCacheDecisionReason.AuthorityExpired,
            _ => ResponseCacheDecisionReason.AdmissionRefused,
        };

    private static int SecondsBetween(long from, long to, ResponseCache cache)
    {
        if (to <= from || cache.TimestampFrequency <= 0)
        {
            return 0;
        }

        return checked((int)((to - from) / cache.TimestampFrequency));
    }

    private static string ReasonForRejectedShared(
        ResponseCacheEnvelope shared,
        ExecutionRequest request,
        ExecutionLimits limits,
        IUpstreamTransport transport)
        => !ResponseIsWithinInvocationLimit(shared, request, limits)
            ? ResponseCacheDecisionReason.ResponseSizeExceeded
            : transport is IResponseCacheTransportState { HasUnrepresentedRequestState: false }
                ? ResponseCacheDecisionReason.Unavailable
                : ResponseCacheDecisionReason.TransportState;


    /// <summary>Executes <paramref name="request"/> and returns what happened.</summary>
    public async Task<EngineExecutionResult> ExecuteAsync(
        ExecutionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // The execution owns every supplied file source from the moment it accepts the request.
        // Keep the lease ahead of every refusal so an unknown operation, a compilation failure,
        // cancellation, or a transport failure cannot strand an opened/replayable source.
        await using var ownedFiles = new ExecutionFileLease(request.Files);

        var manifest = request.Manifest;
        var entry = manifest.AgentSurface.Operation(request.Slug);

        if (entry is null)
        {
            return Failed(ExecutionFailureKind.Compilation, $"No operation is exposed as '{request.Slug}'.");
        }

        // Before anything single-exchange is resolved. A workflow has no one destination, no
        // one credential scope and no one response, so every question below is the wrong
        // question to ask about it — and it is asked of the dispatcher, not of the binding's
        // type, so this stays the only place that knows a workflow is a possibility.
        if (ManifestBindingDispatcher.TryResolveCompound(entry.Binding) is { } workflow)
        {
            return await CompoundExecutor
                .ExecuteAsync(this, _files, request, workflow, cancellationToken)
                .ConfigureAwait(false);
        }

        var operationKey = ManifestBindingDispatcher.TryResolveOperationKey(entry.Binding);
        var operation = operationKey is null ? null : manifest.Operations.Operation(operationKey);

        if (operation is null)
        {
            return Failed(
                ExecutionFailureKind.Compilation,
                $"Operation '{request.Slug}' has no HTTP binding this runtime can execute.");
        }

        var policy = manifest.Policy;
        var limits = policy.EffectiveLimits;

        OriginAllowList origins;
        try
        {
            origins = new OriginAllowList(policy.AllowedOrigins);
        }
        catch (ArgumentException ex)
        {
            return Failed(ExecutionFailureKind.OriginPolicy, ex.Message);
        }

        var serverUrl = ManifestBindingDispatcher.TryResolveServerUrl(entry.Binding);
        if (!TryResolveBaseUri(serverUrl, policy.BaseUrl, out var baseUri, out var baseFailure))
        {
            return Failed(ExecutionFailureKind.Compilation, baseFailure!);
        }

        // Before anything is resolved, compiled or opened. A binding override outside the
        // governing perimeter is a configuration mistake, and discovering it after a credential
        // has been read would mean a secret was fetched to serve a request that could never be
        // sent.
        if (!origins.IsAllowed(baseUri))
        {
            return Failed(
                ExecutionFailureKind.OriginPolicy,
                $"The destination '{baseUri}' is not inside the governing allowed-origin set.");
        }

        // Before a credential is read and before anything is compiled. A presented handle is
        // authorized here against the invocation itself — the same reason a secret is not read
        // for a request that could never be sent: a refused handle must cost nothing either.
        if (_files is not null)
        {
            (request, string? redemptionFailure) = await RedeemAsync(request, entry, cancellationToken)
                .ConfigureAwait(false);

            if (redemptionFailure is not null)
            {
                return Failed(ExecutionFailureKind.Compilation, redemptionFailure);
            }

            ownedFiles.Track(request.Files);
        }

        if (!TransformStage.TryInput(
                manifest,
                entry,
                operation,
                request.Arguments,
                out JsonObject arguments,
                out string? transformFailure))
        {
            return Failed(ExecutionFailureKind.Transformation, transformFailure);
        }

        // The profile, when the binding names one, owns the credential references: a profiled
        // binding declares no scope of its own, because the strategy decides which slots it
        // reveals. Resolving from the binding's empty list instead would hand every dynamic
        // strategy no secret at all.
        AuthenticationProfile? profile = null;
        if (ManifestBindingDispatcher.AuthenticationRefOf(entry.Binding) is { } profileId)
        {
            profile = manifest.EffectiveAuthentication.Profile(profileId);

            if (profile is null)
            {
                return Failed(
                    ExecutionFailureKind.Authentication,
                    $"The binding references authentication profile '{profileId}', which the manifest does not declare.");
            }
        }

        IReadOnlyList<string> credentialRefs = profile is not null
            ? profile.CredentialRef
            : ManifestBindingDispatcher.CredentialRefsOf(entry.Binding);

        // OAuth1 request-shape refusals must happen before resolving any credential references.
        // Compilation is independent of signer material, so retain this ordinary request and
        // reuse it below after the method/transport and parameter locations are validated.
        CompiledRequest? precompiledOAuth1 = null;
        UpstreamRequest? prevalidatedOAuth1 = null;
        if (profile is { Kind: AuthenticationKind.OAuth1Authorization })
        {
            try
            {
                ResolvedOAuth1Signing.ValidateConfiguration(profile);
                ResolvedOAuth1Signing.ValidateDestinationScope(profile, baseUri);
                precompiledOAuth1 = RequestCompiler.Compile(
                    operation,
                    baseUri,
                    arguments,
                    request.Files);
                prevalidatedOAuth1 = CredentialApplier.Apply(precompiledOAuth1, []);
                await ResolvedOAuth1Signing.ValidateRequestShapeAsync(
                    profile,
                    prevalidatedOAuth1,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (CredentialUnavailableException ex)
            {
                return Failed(ExecutionFailureKind.Authentication, ex.Message);
            }
            catch (UnsupportedAuthenticationStrategyException ex)
            {
                return Failed(ExecutionFailureKind.Authentication, ex.Message);
            }
            catch (AuthenticationPlanException ex)
            {
                return Failed(ExecutionFailureKind.Authentication, ex.Message);
            }
            catch (FileRuntimeException ex)
            {
                return Failed(ExecutionFailureKind.FileRuntime, ex.Message);
            }
            catch (Exception ex) when (ex is ArgumentValidationException
                or InvalidBaseUrlException
                or UnsupportedSerializationException
                or UnsupportedBodyMediaTypeException)
            {
                return Failed(ExecutionFailureKind.Compilation, ex.Message);
            }
        }

        IReadOnlyList<ResolvedCredential> credentials;
        try
        {
            credentials = await _secrets.ResolveAsync(
                manifest.EffectiveCredentials,
                credentialRefs,
                cancellationToken).ConfigureAwait(false);
        }
        catch (CredentialUnavailableException ex)
        {
            return Failed(ExecutionFailureKind.Authentication, ex.Message);
        }

        // Other dynamic profiles resolve before compilation so a token endpoint failure is
        // reported without building the downstream request. OAuth1 is the deliberate exception:
        // its compiled unsigned request was shape-checked above before its credentials resolve.
        ResolvedAuthentication? authentication = null;
        if (profile is not null)
        {
            if (_authentication is null)
            {
                return Failed(
                    ExecutionFailureKind.Authentication,
                    $"Authentication profile '{profile.Id}' needs the dynamic-auth runtime, which this execution was not given.");
            }

            try
            {
                authentication = await _authentication
                    .ResolveAsync(profile, credentials, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is CredentialUnavailableException
                or UnsupportedAuthenticationStrategyException
                or AuthenticationPlanException
                or RuntimeStateStoreException)
            {
                return Failed(ExecutionFailureKind.Authentication, ex.Message);
            }
        }

        CompiledRequest compiled;
        UpstreamRequest upstream;
        try
        {
            compiled = precompiledOAuth1 ?? RequestCompiler.Compile(
                operation,
                baseUri,
                arguments,
                request.Files);

            if (authentication?.DestinationAuthority is { } destination)
            {
                compiled = Rebind(compiled, destination);
            }

            // The initial binding was checked before authentication resolution, but a dynamic
            // strategy may select a different authority. A cache hit skips UpstreamSender's
            // final perimeter check, so the resolved destination must be refused before either
            // credential application or cache lookup when it is outside the governing policy.
            if (!origins.IsAllowed(compiled.Uri))
            {
                return Failed(
                    ExecutionFailureKind.OriginPolicy,
                    $"The resolved destination '{compiled.Uri}' is not inside the governing allowed-origin set.");
            }

            upstream = prevalidatedOAuth1 ?? CredentialApplier.Apply(
                compiled,
                authentication?.Credentials ?? credentials);
        }
        catch (CredentialUnavailableException ex)
        {
            return Failed(ExecutionFailureKind.Authentication, ex.Message);
        }
        catch (Exception ex) when (ex is ArgumentValidationException
            or InvalidBaseUrlException
            or UnsupportedSerializationException
            or UnsupportedBodyMediaTypeException)
        {
            return Failed(ExecutionFailureKind.Compilation, ex.Message);
        }

        ResponseCache? responseCache = _responseCache;
        ResponseCachePolicySettings? cachePolicy = entry.ResponseCache;
        ResponseCacheIdentity? lookupIdentity = null;
        ResponseCacheKey? cacheKey = null;
        ResponseCacheEnvelope? cachedEnvelope = null;
        ResponseFlightLease? producerFlight = null;
        ExecutionAuthorityIdentity? requestedAuthority = null;

        // Sanitized observation state, accumulated as the invocation decides and emitted once per
        // invocation. Nothing here is a preimage, a body or a header value: the fingerprint is a
        // derivative of the fixed key digest.
        CacheObservation observation = CacheObservation.Start(entry.Slug, cachePolicy);

        ResponseCache? cache = responseCache;
        ResponseCachePolicySettings? settings = cachePolicy;
        bool caching = cache is not null
            && settings is { TtlSeconds: >= ResponseCacheOptions.MinimumTtlSeconds };

        if (caching && _transport is not IResponseCacheTransportState { HasUnrepresentedRequestState: false })
        {
            observation.Reason = ResponseCacheDecisionReason.TransportState;
            caching = false;
        }

        if (caching)
        {
            ResponseCache activeCache = cache!;
            ResponseCachePolicySettings activePolicy = settings!;

            requestedAuthority = DeriveAuthority(profile, authentication, credentials, compiled);

            if (requestedAuthority is not null)
            {
                ResponseCacheRequestHeaderSnapshot requestHeaders = ResponseCacheRequestHeaders.Create(upstream);
                ResponseCacheRequestDecision requestDecision = ResponseCacheAdmissionParser.CheckRequest(
                    upstream.Method,
                    requestHeaders.Headers);

                if (requestDecision.CanLookup)
                {
                    lookupIdentity = CreateResponseCacheIdentity(
                        entry,
                        operation,
                        upstream,
                        requestHeaders,
                        requestedAuthority,
                        request.CallerPartition,
                        activePolicy);

                    ResponseCacheLookup lookup = activeCache.Acquire(lookupIdentity, activePolicy.TtlSeconds);
                    cacheKey = lookup.Key;
                    observation.Kind = MapKind(lookup.Kind);
                    observation.Fingerprint = lookup.Key?.Fingerprint;

                    if (lookup.Kind == ResponseCacheLookupKind.Hit
                        && lookup.Envelope is { } hit
                        && ResponseIsWithinInvocationLimit(hit, request, limits)
                        && _transport is IResponseCacheTransportState { HasUnrepresentedRequestState: false })
                    {
                        cachedEnvelope = hit;
                        observation.Execution = ResponseCacheExecution.Cached;
                        observation.Reason = ResponseCacheDecisionReason.Hit;
                        observation.TtlSeconds = hit.EffectiveTtlSeconds;
                        observation.AgeSeconds = SecondsBetween(
                            hit.StoredAtTimestamp,
                            activeCache.GetTimestamp(),
                            activeCache);
                        observation.RemainingSeconds = SecondsBetween(
                            activeCache.GetTimestamp(),
                            hit.ExpiresAtTimestamp,
                            activeCache);
                    }
                    else if (lookup.Kind == ResponseCacheLookupKind.Bypass)
                    {
                        observation.Reason = MapBypass(lookup.BypassReason);
                    }
                    else if (lookup.Flight is { IsProducer: true } producer)
                    {
                        producerFlight = producer;
                        observation.Reason = ResponseCacheDecisionReason.LiveSend;
                        observation.Role = ResponseCacheFlightRole.Producer;
                    }
                    else if (lookup.Flight is { IsProducer: false } waiter)
                    {
                        observation.Role = ResponseCacheFlightRole.Joined;

                        using (waiter)
                        {
                            ResponseCacheEnvelope? shared = await waiter.WaitAsync(cancellationToken)
                                .ConfigureAwait(false);

                            if (shared is not null
                                && ResponseIsWithinInvocationLimit(shared, request, limits)
                                && _transport is IResponseCacheTransportState { HasUnrepresentedRequestState: false })
                            {
                                cachedEnvelope = shared;
                                observation.Execution = ResponseCacheExecution.Cached;
                                observation.Reason = ResponseCacheDecisionReason.Joined;
                                observation.TtlSeconds = shared.EffectiveTtlSeconds;
                                observation.AgeSeconds = SecondsBetween(
                                    shared.StoredAtTimestamp,
                                    activeCache.GetTimestamp(),
                                    activeCache);
                                observation.RemainingSeconds = SecondsBetween(
                                    activeCache.GetTimestamp(),
                                    shared.ExpiresAtTimestamp,
                                    activeCache);
                            }
                            else
                            {
                                observation.Reason = shared is null
                                    ? ResponseCacheDecisionReason.LiveSend
                                    : ReasonForRejectedShared(shared, request, limits, _transport);
                            }
                        }
                    }
                    else if (lookup.Kind == ResponseCacheLookupKind.Hit)
                    {
                        // A hit whose envelope was unusable. The invocation falls through to a
                        // live send, so the reason names the ceiling that rejected it.
                        observation.Reason = lookup.Envelope is { } rejected
                                && !ResponseIsWithinInvocationLimit(rejected, request, limits)
                            ? ResponseCacheDecisionReason.ResponseSizeExceeded
                            : ResponseCacheDecisionReason.TransportState;
                    }
                }
                else
                {
                    observation.Reason = MapRequestBypass(requestDecision.Reason);
                }
            }
            else
            {
                observation.Reason = ResponseCacheDecisionReason.UnknownDimension;
            }
        }

        try
        {
            // Lookup authority is known before cache lookup. Re-derive after the exchange as
            // response-driven negotiation can replace it; a challenge replay never admits a
            // candidate under the pre-challenge key.
            var used = new UsedAuthentication
            {
                Value = authentication,
                Compiled = compiled,
                Request = upstream,
            };

            EngineExecutionResult outcome = cachedEnvelope is not null
                ? FromCache(cachedEnvelope, compiled, requestedAuthority!, request.CallerPartition)
                : await SendAsync(
                        request,
                        entry,
                        operation,
                        compiled,
                        upstream,
                        origins,
                        limits,
                        profile,
                        authentication,
                        used,
                        cancellationToken)
                    .ConfigureAwait(false);

            ExecutionAuthorityIdentity? authority = cachedEnvelope is not null
                ? requestedAuthority
                : DeriveAuthority(profile, used.Value, credentials, used.Compiled ?? outcome.Request ?? compiled);

            // The identity travels with every outcome the exchange reached, including a failed
            // one. These fingerprints are opaque display aids, never cache preimages.
            outcome = WithIdentityMetadata(outcome, request.CallerPartition, authority);

            // The same post-response processing runs on hits and live responses. Candidate
            // retention occurs only after this succeeds, and the raw result remains unchanged
            // until the transformed copy is assigned below.
            if (!outcome.Succeeded)
            {
                observation.Reason = ResponseCacheDecisionReason.Failed;
                return outcome;
            }

            byte[]? projectionRawBody = outcome.ResponseBody;
            OutputProjectionResult outputProjection = await OutputProjectionStage
                .ApplyAsync(
                    manifest,
                    entry,
                    operation,
                    outcome,
                    _projections,
                    cancellationToken)
                .ConfigureAwait(false);

            if (!outputProjection.Succeeded)
            {
                observation.Reason = ResponseCacheDecisionReason.Failed;
                return outcome with
                {
                    Failure = outputProjection.FailureKind,
                    FailureReason = outputProjection.FailureReason,
                    FailureDetail = outputProjection.FailureDetail,
                };
            }

            EngineExecutionResult transformed = ReferenceEquals(outputProjection.Body, outcome.ResponseBody)
                ? outcome
                : outcome with { ResponseBody = outputProjection.Body };

            ResponseCacheEnvelope? admitted = null;
            if (cachedEnvelope is null
                && cache is not null
                && cachePolicy is { TtlSeconds: >= ResponseCacheOptions.MinimumTtlSeconds } admissionPolicy
                && cacheKey is { } expectedKey
                && lookupIdentity is not null
                && requestedAuthority is not null
                && authority is not null
                && string.Equals(requestedAuthority.OpaqueValue, authority.OpaqueValue, StringComparison.Ordinal)
                && !used.WasReplayed
                && !outcome.ResponseWasRedirected
                && outcome.StatusCode is { } statusCode
                && outcome.ResponseHeaders is { } responseHeaders
                && outcome.ResponseBody is { } rawBody
                && _transport is IResponseCacheTransportState { HasUnrepresentedRequestState: false })
            {
                ResponseCacheRequestHeaderSnapshot actualRequestHeaders = ResponseCacheRequestHeaders.Create(
                    used.Request ?? upstream);
                ResponseCacheIdentity actualIdentity = CreateResponseCacheIdentity(
                    entry,
                    operation,
                    used.Request ?? upstream,
                    actualRequestHeaders,
                    authority,
                    request.CallerPartition,
                    admissionPolicy);

                if (cache.HasSameKey(expectedKey, actualIdentity, admissionPolicy.TtlSeconds))
                {
                    ResponseCacheAdmissionDecision admission = ResponseCacheAdmissionParser.Evaluate(
                        new ResponseCacheAdmissionInput(
                            Method: (used.Request ?? upstream).Method,
                            StatusCode: statusCode,
                            MediaType: outcome.ResponseMediaType,
                            BodyLength: rawBody.LongLength,
                            RequestHeaders: actualRequestHeaders.Headers,
                            ResponseHeaders: responseHeaders,
                            WasRedirected: outcome.ResponseWasRedirected,
                            HasFile: outcome.ResponseFile is not null || outcome.ResponseFileHandle is not null,
                            CallerIsSpecific: request.CallerPartition?.IsCallerSpecific == true,
                            AuthorityExpiresAtUtc: authority.ExpiresAtUtc,
                            AuthoredTtlSeconds: admissionPolicy.TtlSeconds,
                            HostMaxTtlSeconds: cache.Options.MaxTtlSeconds,
                            NowUtc: cache.GetUtcNow()));

                    if (admission.CanStore
                        && rawBody.LongLength <= cache.Options.MaxBodyBytes
                        && ResponseCacheEnvelope.TryCapture(
                            statusCode,
                            outcome.ResponseMediaType,
                            responseHeaders,
                            rawBody,
                            ResponseCacheOptions.HardMaxRetainedHeaderBytesPerEntry,
                            out ResponseCacheEnvelope? candidate))
                    {
                        admitted = cache.TryStore(expectedKey, candidate, admission.EffectiveTtlSeconds);
                    }

                    if (admitted is { } stored)
                    {
                        observation.Stored = true;
                        observation.TtlSeconds = stored.EffectiveTtlSeconds;
                        observation.EntryBytes = stored.AccountedBytes;
                        observation.Reason = ResponseCacheDecisionReason.Stored;
                    }
                    else
                    {
                        observation.Reason = MapAdmission(admission.Reason);
                    }
                }
                else
                {
                    observation.Reason = ResponseCacheDecisionReason.NotStored;
                }
            }

            producerFlight?.Publish(admitted);
            // A stored binary response is never projected: its bytes were deliberately not
            // materialized, and an envelope around a file handle would advertise structured content
            // the caller cannot receive. Apply projection after cache admission so cache entries
            // remain raw upstream responses and both hits and live responses share one result path.
            return entry.OutputProjection is { } projection && transformed.ResponseFile is null
                ? Project(projection, transformed, arguments, projectionRawBody, credentials, profile, authentication, request)
                : transformed;
        }
        finally
        {
            if (responseCache is not null)
            {
                responseCache.RecordObservation(observation.Finish(responseCache.GetUtcNow()));
            }

            // Publish wakes joined callers with null after an error/ineligible response if the
            // live path exited before its successful admission point.
            producerFlight?.Dispose();
        }
    }


    /// <summary>
    /// Builds the agent-facing projection envelope over one completed response.
    /// </summary>
    /// <remarks>
    /// The body is the final value after any accepted output transformation; a declared
    /// <c>jsonPointer</c> extraction reads the bounded raw upstream body instead. A refusal
    /// inside the projection becomes an <c>unavailable</c> state or an omitted mapping plus a
    /// diagnostic, never a failed call: the upstream answered, and the answer is the result.
    /// </remarks>
    private static EngineExecutionResult Project(
        AgentOutputProjection projection,
        EngineExecutionResult shaped,
        JsonObject currentArguments,
        byte[]? rawBody,
        IReadOnlyList<ResolvedCredential> credentials,
        AuthenticationProfile? profile,
        ResolvedAuthentication? authentication,
        ExecutionRequest request)
    {
        ResponseProjectionOutcome outcome = ResponseProjectionEvaluator.Evaluate(
            projection,
            shaped.StatusCode ?? 0,
            shaped.ResponseHeaders ?? new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            shaped.ResponseEffectiveUri ?? shaped.Request?.Uri,
            Parse(shaped.ResponseBody),
            Parse(rawBody),
            currentArguments,
            SensitiveHeaderNames.For(profile, credentials, authentication),
            request.Continuations,
            shaped.ResponseBody is { Length: > 0 },
            SensitiveHeaderNames.QueryFor(profile, credentials, authentication));

        IReadOnlyDictionary<string, string[]>? responseHeaders = shaped.ResponseHeaders;
        if (outcome.Diagnostics.Any(static diagnostic => diagnostic.Code == ResponseProjectionCodes.ValueSensitive)
            && projection.Pagination?.Source is LinkHeaderPaginationSource link)
        {
            responseHeaders = shaped.ResponseHeaders?
                .Where(entry => !string.Equals(entry.Key, link.Header, StringComparison.OrdinalIgnoreCase))
                .ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.OrdinalIgnoreCase);
        }
        else if (outcome.Diagnostics.Any(static diagnostic => diagnostic.Code == ResponseProjectionCodes.ValueSensitive)
            && projection.Pagination?.Source is ResponseHeaderPaginationSource header)
        {
            responseHeaders = shaped.ResponseHeaders?
                .Where(entry => !string.Equals(entry.Key, header.Name, StringComparison.OrdinalIgnoreCase))
                .ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.OrdinalIgnoreCase);
        }

        return shaped with
        {
            ResponseBody = outcome.Value is null ? shaped.ResponseBody : Encoding.UTF8.GetBytes(outcome.Value.ToJsonString()),
            ResponseHeaders = responseHeaders,
            Diagnostics = [.. shaped.Diagnostics, .. outcome.Diagnostics],
        };
    }

    /// <summary>
    /// Parses a materialized body as JSON, or preserves non-empty non-JSON bytes as text.
    /// </summary>
    /// <remarks>
    /// A non-JSON body leaves the envelope's body target as a JSON string rather than failing the
    /// projection: an operation may legitimately return text, and the metadata half of the
    /// projection is still meaningful. Empty bytes remain absent.
    /// </remarks>
    private static JsonNode? Parse(byte[]? body)
    {
        if (body is null || body.Length == 0)
        {
            return null;
        }

        try
        {
            return JsonNode.Parse(body);
        }
        catch (JsonException)
        {
            return JsonValue.Create(Encoding.UTF8.GetString(body));
        }
    }

    private async Task<EngineExecutionResult> SendAsync(
        ExecutionRequest request,
        AgentOperationEntry entry,
        ManifestOperation operation,
        CompiledRequest compiled,
        UpstreamRequest upstream,
        OriginAllowList origins,
        ExecutionLimits limits,
        AuthenticationProfile? profile,
        ResolvedAuthentication? authentication,
        UsedAuthentication used,
        CancellationToken cancellationToken)
    {
        using var exchange = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        if (limits.UpstreamRequestTimeout > TimeSpan.Zero)
        {
            exchange.CancelAfter(limits.UpstreamRequestTimeout);
        }

        // One attempt per exchange, preserved across redirect hops. A provider signature carries
        // its own timestamp and nonce, and re-deriving them per hop would make two hops of one
        // chain look like two independent attempts to a nonce-rejecting upstream.
        // OAuth 1.0a is the deliberate exception: every hop is a new authenticated request, so
        // its closure mints fresh hop values instead of reusing an exchange-wide attempt.
        var signingAttempt = authentication?.Signing?.CreateAttempt();

        IReadOnlyCollection<string> sensitiveQueryParameters = authentication?.OAuth1Signing is { } oauth1
            ? ResolvedOAuth1Signing.SensitiveQueryParameters
            : authentication?.Signing?.SensitiveQueryParameters ?? upstream.SensitiveQueryParameters;
        upstream = upstream with { SensitiveQueryParameters = sensitiveQueryParameters };

        var policy = SendPolicy(origins, limits, authentication, signingAttempt);
        var effective = compiled;

        UpstreamResponse response;
        try
        {
            response = await _transport.SendAsync(upstream, policy, exchange.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (BudgetExpired(exchange, cancellationToken))
        {
            return TimedOut(effective, limits.UpstreamRequestTimeout);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Failed(Classify(ex), ex.Message) with { Request = effective };
        }

        // Response-driven negotiation. The first challenge may seed only the profile-scoped
        // ephemeral session; a replay happens at most once and only for an operation the profile
        // declares replay-safe. A refused acquisition is a classified authentication failure
        // rather than an escaping exception.
        if (profile is { Kind: AuthenticationKind.ChallengeSession } && _authentication is not null)
        {
            ChallengeSessionResult challenge;
            try
            {
                challenge = _authentication.Challenge.ProcessResponse(
                    profile,
                    operation.Key,
                    response.StatusCode,
                    response.Headers,
                    replayAttempt: 0,
                    automaticReplayAllowed: true);
            }
            catch (Exception ex) when (ex is CredentialUnavailableException
                or UnsupportedAuthenticationStrategyException
                or AuthenticationPlanException)
            {
                await response.DisposeAsync().ConfigureAwait(false);
                return Failed(ExecutionFailureKind.Authentication, ex.Message) with { Request = effective };
            }

            if (challenge.Disposition == ChallengeSessionDisposition.Replay)
            {
                await response.DisposeAsync().ConfigureAwait(false);

                try
                {
                    ResolvedAuthentication replayed = await _authentication
                        .ResolveAsync(profile, [], exchange.Token)
                        .ConfigureAwait(false);

                    if (replayed.DestinationAuthority is { } destination)
                    {
                        effective = Rebind(compiled, destination);
                    }

                    upstream = CredentialApplier.Apply(effective, replayed.Credentials);
                    used.Value = replayed;
                    used.Compiled = effective;
                    used.Request = upstream;
                    used.WasReplayed = true;

                    // A replay is a new exchange. The provider sees a fresh nonce and timestamp
                    // because the previous attempt was already presented with the challenged
                    // request the upstream refused.
                    signingAttempt = replayed.Signing?.CreateAttempt();
                    policy = SendPolicy(origins, limits, replayed, signingAttempt);

                    response = await _transport.SendAsync(upstream, policy, exchange.Token).ConfigureAwait(false);

                    challenge = _authentication.Challenge.ProcessResponse(
                        profile,
                        operation.Key,
                        response.StatusCode,
                        response.Headers,
                        replayAttempt: 1,
                        automaticReplayAllowed: true);
                }
                catch (OperationCanceledException) when (BudgetExpired(exchange, cancellationToken))
                {
                    return TimedOut(effective, limits.UpstreamRequestTimeout);
                }
                catch (Exception ex) when (ex is CredentialUnavailableException
                    or UnsupportedAuthenticationStrategyException
                    or AuthenticationPlanException
                    or RuntimeStateStoreException)
                {
                    return Failed(ExecutionFailureKind.Authentication, ex.Message) with { Request = effective };
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    return Failed(Classify(ex), ex.Message) with { Request = effective };
                }
            }

            if (challenge.Disposition != ChallengeSessionDisposition.None)
            {
                var message = challenge.PublicMessage
                    ?? "Upstream authentication challenge could not be completed safely.";
                var status = response.StatusCode;

                await response.DisposeAsync().ConfigureAwait(false);

                return new EngineExecutionResult
                {
                    Request = effective,
                    StatusCode = status,
                    Failure = ExecutionFailureKind.Authentication,
                    FailureReason = AuthFailurePrefix + message,
                };
            }
        }

        await using (response.ConfigureAwait(false))
        {
            // Captured while the response is open. Reading status or headers from a released
            // transport object happens to work today and is not a contract.
            var partial = new EngineExecutionResult
            {
                Request = effective,
                StatusCode = response.StatusCode,
                ResponseHeaders = response.Headers,
                ResponseMediaType = response.MediaType,
                ResponseEffectiveUri = response.EffectiveUri,
                ResponseWasRedirected = response.WasRedirected,
            };

            try
            {
                return await ReadBodyAsync(request, operation, response, limits, partial, exchange.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (BudgetExpired(exchange, cancellationToken))
            {
                // The status and headers observed before the body ran out of time are still
                // true, and a diagnosis that lost them would be missing the only evidence about
                // what the upstream was doing.
                return partial with
                {
                    Failure = ExecutionFailureKind.Timeout,
                    FailureReason = TimeoutReason(limits.UpstreamRequestTimeout),
                };
            }
            catch (ResponseSizeLimitException ex)
            {
                return partial with
                {
                    Failure = ExecutionFailureKind.ResponseSize,
                    FailureReason = ex.Message,
                };
            }
            catch (FileRuntimeException ex)
            {
                // A store refusal is a classified result carrying the response that was
                // observed, not an exception escaping the execution path.
                return partial with
                {
                    Failure = ExecutionFailureKind.FileRuntime,
                    FailureReason = ex.Message,
                };
            }
        }
    }

    private static ResponseCacheIdentity CreateResponseCacheIdentity(
        AgentOperationEntry entry,
        ManifestOperation operation,
        UpstreamRequest upstream,
        ResponseCacheRequestHeaderSnapshot requestHeaders,
        ExecutionAuthorityIdentity authority,
        CallerPartition? callerPartition,
        ResponseCachePolicySettings policy)
        => new()
        {
            // The cache itself is owned by one immutable mounted generation and its activation
            // token is part of every key. Managed generation ids are included by ResponseCache.
            ManifestGeneration = null,
            OperationSlug = entry.Slug,
            ResolvedBindingSemantics = entry.Binding.BindingId ?? entry.Slug,
            EffectiveHttpOperationKey = operation.Key,
            Method = upstream.Method,
            EffectiveUri = (upstream.CacheIdentityUri ?? upstream.Uri).AbsoluteUri,
            Headers = requestHeaders.Headers,
            SensitiveHeaders = requestHeaders.SensitiveHeaders,
            AuthorityRepresentedSensitiveHeaders = requestHeaders.AuthorityRepresentedSensitiveHeaders,
            Body = upstream.Body,
            HasStreamingBody = upstream.BodySource is not null,
            UpstreamAuthority = authority.OpaqueValue,
            CallerPartition = callerPartition?.OpaqueValue,
            PolicyFingerprint = string.Create(
                CultureInfo.InvariantCulture,
                $"response-cache-policy-1;ttl={policy.TtlSeconds}"),
        };

    private static bool ResponseIsWithinInvocationLimit(
        ResponseCacheEnvelope envelope,
        ExecutionRequest request,
        ExecutionLimits limits)
    {
        long maximumBytes = request.ResponseSizeLimitBytes is { } requested
            ? Math.Min(limits.UpstreamResponseSizeLimitBytes, requested)
            : limits.UpstreamResponseSizeLimitBytes;

        return envelope.Body.Length <= maximumBytes;
    }

    private static EngineExecutionResult FromCache(
        ResponseCacheEnvelope envelope,
        CompiledRequest compiled,
        ExecutionAuthorityIdentity authority,
        CallerPartition? callerPartition)
    {
        Dictionary<string, string[]> headers = new(StringComparer.OrdinalIgnoreCase);
        foreach ((string name, System.Collections.Immutable.ImmutableArray<string> values) in envelope.Headers)
        {
            headers[name] = values.ToArray();
        }

        return new EngineExecutionResult
        {
            Request = compiled,
            StatusCode = envelope.StatusCode,
            ResponseHeaders = headers,
            ResponseMediaType = envelope.MediaType,
            ResponseBody = envelope.Body.ToArray(),
            CallerPartitionFingerprint = callerPartition is { } partition
                ? CacheIdentity.Fingerprint(partition.OpaqueValue)
                : null,
            AuthorityFingerprint = CacheIdentity.Fingerprint(authority.OpaqueValue),
            AuthorityExpiresAtUtc = authority.ExpiresAtUtc,
        };
    }

    private static EngineExecutionResult WithIdentityMetadata(
        EngineExecutionResult outcome,
        CallerPartition? callerPartition,
        ExecutionAuthorityIdentity? authority)
        => outcome with
        {
            CallerPartitionFingerprint = callerPartition is { } partition
                ? CacheIdentity.Fingerprint(partition.OpaqueValue)
                : null,
            AuthorityFingerprint = authority is null
                ? null
                : CacheIdentity.Fingerprint(authority.OpaqueValue),
            AuthorityExpiresAtUtc = authority?.ExpiresAtUtc,
        };

    /// <summary>
    /// The send policy, carrying the per-hop signing closure when the profile signs.
    /// </summary>
    /// <remarks>
    /// The closure captures one attempt for the whole chain. The transport re-applies it per hop
    /// because a redirect target is a different request that no signature has covered yet, while
    /// a single timestamp and nonce keep the chain legible as one attempt. OAuth 1.0a signs
    /// through its own closure instead: each hop mints its own nonce and timestamp over the
    /// request that hop actually sends. The two closures are mutually exclusive by profile kind.
    /// </remarks>
    private static UpstreamSendPolicy SendPolicy(
        OriginAllowList origins,
        ExecutionLimits limits,
        ResolvedAuthentication? authentication,
        RequestSigningAttempt? attempt)
    {
        var policy = new UpstreamSendPolicy(origins, OutboundLimits.From(limits));

        if (authentication?.Signing is { } signing && attempt is not null)
        {
            return policy with
            {
                SignRequest = (request, _, token) => signing.SignAsync(request, attempt, token),
            };
        }

        if (authentication?.OAuth1Signing is { } oauth1)
        {
            return policy with
            {
                SignRequest = oauth1.SignAsync,
            };
        }

        return policy;
    }

    /// <summary>Rebinds a compiled request onto a strategy-selected destination authority.</summary>
    private static CompiledRequest Rebind(CompiledRequest compiled, Uri destination)
    {
        var uri = TokenSessionExchangeService.RebindUri(compiled.Uri, destination);

        return compiled with
        {
            Uri = uri,
            ExactUrl = uri.ToString(),
        };
    }

    /// <summary>
    /// The authentication an exchange actually used, which negotiation can replace mid-flight.
    /// </summary>
    /// <remarks>
    /// A challenge replay re-resolves the profile and can rebind the destination, so the
    /// authentication handed to the first send is no longer what the returned response belongs
    /// to. The reference is carried through the exchange and read once it completes, which keeps
    /// the authority identity describing the request that produced the response rather than the
    /// one that was refused.
    /// </remarks>
    private sealed class UsedAuthentication
    {
        internal ResolvedAuthentication? Value { get; set; }

        internal CompiledRequest? Compiled { get; set; }

        internal UpstreamRequest? Request { get; set; }

        internal bool WasReplayed { get; set; }
    }

    /// <summary>
    /// The upstream authority this execution runs under, or null when it cannot be proven.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Derived after every component that decides authority has resolved: the profile's declared
    /// material, the dynamic strategy's acquired session or destination, and the final compiled
    /// destination. The acquired token itself is deliberately not digested. An OAuth access token
    /// is derived from the declared material under the profile's authority epoch, and digesting
    /// the token would make a refresh produce a new identity for the same authority — a rotation a
    /// caller cannot observe, turning every token renewal into a cache miss.
    /// </para>
    /// <para>
    /// A signing profile returns null. Its per-attempt nonce and timestamp are part of the wire
    /// request and are not representable in any stable identity, so the honest answer is that the
    /// authority is unprovable and caching must bypass.
    /// </para>
    /// <para>
    /// A request with no profile is still an authority, and a distinct one: it runs under exactly
    /// the declared credentials the binding resolved, and two requests with different such
    /// material must not share a response even though neither names a profile.
    /// </para>
    /// </remarks>
    private ExecutionAuthorityIdentity? DeriveAuthority(
        AuthenticationProfile? profile,
        ResolvedAuthentication? authentication,
        IReadOnlyList<ResolvedCredential> declared,
        CompiledRequest compiled)
    {
        // Signing material never reaches a stable value: the signature covers a fresh nonce and
        // timestamp per attempt, so an identity derived now would not describe the request that
        // is actually sent.
        if (authentication?.Signing is not null || profile?.Kind == AuthenticationKind.RequestSigning)
        {
            return null;
        }

        List<string?> parts =
        [
            // A version tag, so a future change to what contributes to authority cannot produce
            // the same digest for a different meaning.
            "authority-1",
            profile?.Id,
            profile is null ? null : profile.Kind.ToString(),
            profile?.ScopeFingerprint,
            profile?.Kind is AuthenticationKind.OAuth2ClientCredentials
                or AuthenticationKind.OAuth2AuthorizationCodePkceRefresh
                or AuthenticationKind.ChallengeSession
                    ? AuthenticationRuntime.AuthorityEpoch(profile).ToString(CultureInfo.InvariantCulture)
                    : null,
            profile?.Kind is AuthenticationKind.OAuth2ClientCredentials
                or AuthenticationKind.OAuth2AuthorizationCodePkceRefresh
                or AuthenticationKind.ChallengeSession
                    ? AuthenticationRuntime.RuntimeRevision(profile).ToString(CultureInfo.InvariantCulture)
                    : null,

            // The destination the request actually goes to, after a strategy rebind. Two
            // profiles that acquire the same session for different destinations must not share.
            compiled.Uri.GetLeftPart(UriPartial.Authority),

            // Credential material by declaration identity and value digest. The identity of each
            // declaration keeps a scheme, placement or slot change visible even when the value
            // is unchanged, which is exactly the case a rotation-less configuration change
            // produces.
            .. DeclaredMaterial(declared),

            // Resolved session material, only for the kinds whose session is the authority and
            // is not already represented by the declared material. An OAuth access token is
            // deliberately excluded: it is derived from the declared material under the profile's
            // epoch, so digesting it would turn every routine token refresh into an unobservable
            // cache miss. A static credential is excluded because it is the declared material.
            .. (profile?.Kind is AuthenticationKind.TokenSessionExchange
                    or AuthenticationKind.ChallengeSession
                ? ResolvedMaterial(authentication?.Credentials)
                : []),
        ];

        return new ExecutionAuthorityIdentity(
            CacheIdentity.Derive(_identityKey, [.. parts]),
            authentication?.ExpiresAtUtc);
    }

    /// <summary>
    /// Declared credential material as digestable parts: the declaration identity followed by
    /// the digest of the value.
    /// </summary>
    /// <remarks>
    /// The value is digested rather than used directly, so no raw secret can enter an identity.
    /// The declaration's scheme, placement and slot are included by their own members because
    /// moving a credential to another header is an authority change even when the value did not
    /// change.
    /// </remarks>
    private IEnumerable<string?> DeclaredMaterial(IReadOnlyList<ResolvedCredential> credentials)
    {
        foreach (ResolvedCredential credential in credentials)
        {
            yield return credential.Declaration.Scheme.ToString();
            yield return credential.Declaration.Slot;
            yield return credential.Declaration.EffectiveLocation.ToString();
            yield return CacheIdentity.DeriveValue(_identityKey, credential.Value);
        }
    }

    /// <summary>
    /// Resolved dynamic material as digestable parts, so a session change the declared material
    /// does not show still separates entries.
    /// </summary>
    private IEnumerable<string?> ResolvedMaterial(IReadOnlyList<ResolvedCredential>? credentials)
    {
        if (credentials is null)
        {
            yield break;
        }

        foreach (ResolvedCredential credential in credentials)
        {
            yield return "resolved";
            yield return credential.Declaration.Scheme.ToString();
            yield return credential.Declaration.Slot;
            yield return CacheIdentity.DeriveValue(_identityKey, credential.Value);
        }
    }

    private async Task<EngineExecutionResult> ReadBodyAsync(
        ExecutionRequest request,
        ManifestOperation operation,
        UpstreamResponse response,
        ExecutionLimits limits,
        EngineExecutionResult partial,
        CancellationToken cancellationToken)
    {
        // The smaller of the two. A caller may narrow this for its own accounting — a workflow
        // spending an aggregate budget does — and may never raise what the policy compiled.
        var limit = request.ResponseSizeLimitBytes is { } requested
            ? Math.Min(limits.UpstreamResponseSizeLimitBytes, requested)
            : limits.UpstreamResponseSizeLimitBytes;

        var binary = ResponseClassification.IsBinaryResponse(operation, response.StatusCode, response.MediaType);

        if (binary && _files is not null)
        {
            // Bounded before the store sees it. The store enforces its own ceiling on what it
            // will keep, which is a different question from how much this response was allowed
            // to be, and only the outer one classifies as a response-size failure.
            await using var bounded = new BoundedStream(response.Body, limit);

            var reference = await _files.IssueAsync(
                bounded,
                FileNameFor(operation, response.MediaType),
                response.MediaType,
                request.Scope ?? request.Manifest.Server.Name,
                cancellationToken).ConfigureAwait(false);

            string wireHandle = _files.WireFormFor(reference.Id);

            if (!HandleCodec.IsWireForm(wireHandle))
            {
                throw new FileRuntimeException("The stored response has no transferable file capability.");
            }

            return partial with { ResponseFile = reference, ResponseFileHandle = wireHandle };
        }

        var body = await BoundedResponseReader
            .ReadAllWithLimitAsync(response.Body, limit, cancellationToken)
            .ConfigureAwait(false);

        return partial with { ResponseBody = body };
    }

    /// <summary>
    /// Maps a send failure onto the closed classification.
    /// </summary>
    /// <remarks>
    /// Every arm names an Engine type. The transport wraps whatever a framework raised, so the
    /// set is closed and the fallback is a floor rather than the usual answer — which is what
    /// makes it possible to assert that each classification is reachable from a producing site.
    /// </remarks>
    internal static ExecutionFailureKind Classify(Exception exception) => exception switch
    {
        CredentialUnavailableException or RuntimeStateStoreException => ExecutionFailureKind.Authentication,
        OriginPolicyViolationException => ExecutionFailureKind.OriginPolicy,
        AddressPolicyViolationException or HostResolutionException => ExecutionFailureKind.AddressPolicy,
        RedirectLimitException => ExecutionFailureKind.RedirectLimit,
        ResponseSizeLimitException => ExecutionFailureKind.ResponseSize,
        FileRuntimeException => ExecutionFailureKind.FileRuntime,

        // A redirect status with no destination is a malformed answer, not a refused one.
        // Reporting it as a policy failure would send an operator to inspect an allow-list that
        // was never consulted.
        MalformedRedirectException => ExecutionFailureKind.Transport,
        UpstreamTransportException => ExecutionFailureKind.Transport,
        _ => ExecutionFailureKind.Transport,
    };

    /// <summary>
    /// A filename for a stored response body.
    /// </summary>
    /// <remarks>
    /// Derived from the operation and the observed media type rather than from anything the
    /// upstream supplied. A name is a label for a human; taking it from a remote header would
    /// let an upstream choose what a downstream consumer saves the payload as.
    /// </remarks>
    private static string FileNameFor(ManifestOperation operation, string? mediaType)
    {
        var extension = ContentSignature.Essence(mediaType) switch
        {
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/gif" => "gif",
            "application/pdf" => "pdf",
            "application/zip" => "zip",
            "application/gzip" => "gz",
            "application/x-tar" => "tar",
            _ => "bin",
        };

        var stem = FileHandleStore.SanitizeFileName(operation.UpstreamId ?? operation.Key);

        return $"{stem}.{extension}";
    }

    /// <summary>
    /// Redeems every file-slot argument that presents a handle, authorizing each against the
    /// invocation itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A file slot is part of the wire contract, so what a caller may hand it is a wire fact,
    /// decided before any transformation reads the document. A presented handle is decoded,
    /// authorized against the invocation's scope and attached to the request; the argument keeps
    /// its value for the transformation stage to see, where a handle moves by reference.
    /// </para>
    /// <para>
    /// A handle whose scope disagrees is answered exactly as one that never existed, so the
    /// refusal never confirms which handles exist. The presented form is never echoed anywhere.
    /// </para>
    /// </remarks>
    /// <returns>The request with redemptions attached, and a refusal message, or null.</returns>
    private async Task<(ExecutionRequest Request, string? Failure)> RedeemAsync(
        ExecutionRequest request,
        AgentOperationEntry entry,
        CancellationToken cancellationToken)
    {
        var slots = ExclusionValidation.FileArguments(entry.InputSchema?.Object);

        if (slots.Count == 0)
        {
            return (request, null);
        }

        var files = request.Files is null
            ? new Dictionary<string, ExecutionFile>(StringComparer.Ordinal)
            : new Dictionary<string, ExecutionFile>(request.Files, StringComparer.Ordinal);
        var created = new List<ExecutionFile>();

        foreach (string slot in slots)
        {
            if (request.Arguments[slot] is not JsonValue text
                || text.GetValueKind() != JsonValueKind.String
                || text.GetValue<string>() is not { } wire
                || !HandleCodec.IsWireForm(wire))
            {
                // A file slot that carries no presented handle is an ordinary argument value,
                // and the compiler decides what a string in a file slot is worth.
                continue;
            }

            var redemption = await RedemptionAuthorization
                .RedeemAsync(_files!, wire, request.Scope ?? request.Manifest.Server.Name, cancellationToken)
                .ConfigureAwait(false);

            if (redemption.Succeeded)
            {
                files[slot] = redemption.File!;
                created.Add(redemption.File!);

                continue;
            }

            foreach (ExecutionFile file in created)
            {
                await file.Content.DisposeAsync().ConfigureAwait(false);
            }

            return (request, redemption.Refusal == FileRedemptionRefusalKind.Expired
                ? "The presented file reference has expired; obtain a valid reference before invoking."
                : RedemptionAuthorization.UnknownMessage);
        }

        return (request with
        {
            Files = files,
        }, null);
    }

    private sealed class ExecutionFileLease : IAsyncDisposable
    {
        private readonly HashSet<ReplayableBodySource> _sources = new(ReferenceEqualityComparer.Instance);

        public ExecutionFileLease(IReadOnlyDictionary<string, ExecutionFile>? files)
            => Track(files);

        public void Track(IReadOnlyDictionary<string, ExecutionFile>? files)
        {
            if (files is null)
            {
                return;
            }

            foreach (ExecutionFile file in files.Values)
            {
                _sources.Add(file.Content);
            }
        }

        public async ValueTask DisposeAsync()
        {
            foreach (ReplayableBodySource source in _sources)
            {
                await source.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static bool TryResolveBaseUri(
        string? serverUrl,
        Uri policyBaseUrl,
        out Uri baseUri,
        out string? failure)
    {
        if (serverUrl is null)
        {
            baseUri = policyBaseUrl;
            failure = null;
            return true;
        }

        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out var parsed))
        {
            baseUri = policyBaseUrl;
            failure = $"The binding server URL '{serverUrl}' is not an absolute URI.";
            return false;
        }

        baseUri = parsed;
        failure = null;
        return true;
    }

    /// <summary>
    /// True when the exchange's own deadline fired rather than the caller abandoning the call.
    /// </summary>
    /// <remarks>
    /// Both surface as the same exception type. Without this distinction a caller cancelling a
    /// request would be told the upstream was slow, and a genuinely slow upstream would look
    /// like a caller changing its mind.
    /// </remarks>
    private static bool BudgetExpired(CancellationTokenSource exchange, CancellationToken caller)
        => exchange.IsCancellationRequested && !caller.IsCancellationRequested;

    private static EngineExecutionResult TimedOut(CompiledRequest compiled, TimeSpan budget)
        => new()
        {
            Request = compiled,
            Failure = ExecutionFailureKind.Timeout,
            FailureReason = TimeoutReason(budget),
        };

    private static string TimeoutReason(TimeSpan budget)
        => $"The exchange exceeded its total time budget of {budget}.";

    private static EngineExecutionResult Failed(ExecutionFailureKind kind, string reason)
        => new() { Failure = kind, FailureReason = reason };

    /// <summary>
    /// A read-only view over a stream that refuses to yield more than a stated number of bytes.
    /// </summary>
    /// <remarks>
    /// Exists so that a consumer which does its own reading — the file store — is still bounded
    /// by the response ceiling. Handing the raw stream over and trusting the consumer's own
    /// limit would make the response ceiling depend on which consumer happened to be
    /// configured.
    /// </remarks>
    private sealed class BoundedStream(Stream inner, long limit) : Stream
    {
        private long _read;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => _read;
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Count(read);
            return read;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = inner.Read(buffer, offset, count);
            Count(read);
            return read;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private void Count(int read)
        {
            _read += read;

            if (_read > limit)
            {
                throw new ResponseSizeLimitException(_read, limit);
            }
        }
    }
}
