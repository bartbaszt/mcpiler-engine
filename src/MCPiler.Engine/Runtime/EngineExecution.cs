using System.Text.Json.Nodes;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Files;
using MCPiler.Engine.Mcp;
using MCPiler.Engine.Runtime.Managed;

namespace MCPiler.Engine.Runtime;

/// <summary>
/// The process-wide machinery a mounted Manifest is invoked through.
/// </summary>
/// <remarks>
/// <para>
/// The second half of the seam. <see cref="EngineRuntime"/> answers what a process serves;
/// this answers what happens when a client calls one of it. A deployable holds both and names
/// nothing else, which is why an outbound client, a credential resolver and a handle store are
/// assembled here rather than wired up by whatever is hosting.
/// </para>
/// <para>
/// The caller owns the lifetime, deliberately. An outbound client pool is the one thing in the
/// process whose disposal has to happen at a point somebody chose: a pool disposed by a
/// container's teardown ordering would close connections at a moment no drain accounted for.
/// </para>
/// <para>
/// Created from a started runtime, so the store this executes against is the store startup
/// proved usable, and the credential rules are the ones loading was told about. Passing those
/// separately would let a process resolve secrets under a switch the Manifests were not read
/// under.
/// </para>
/// </remarks>
public sealed class EngineExecution : IDisposable
{
    private readonly IReadOnlyDictionary<MountedManifest, MountExecution> _mounts;
    private readonly FileHandleStore _files;
    private readonly Action<RuntimeDiagnostic>? _diagnostics;

    private EngineExecution(
        IReadOnlyDictionary<MountedManifest, MountExecution> mounts,
        FileHandleStore files,
        Action<RuntimeDiagnostic>? diagnostics)
    {
        _mounts = mounts;
        _files = files;
        _diagnostics = diagnostics;
    }

    /// <summary>Assembles the execution machinery for a started runtime.</summary>
    /// <param name="started">A runtime whose every mount is ready.</param>
    /// <param name="diagnostics">
    /// Receives operational diagnostics the engine emits instead of failing a call, such as a
    /// structured-content payload that did not conform to its advertised schema. A sink must
    /// not throw; a sink that throws is ignored after the outcome was already decided. Sinks
    /// may be called concurrently and must be thread-safe.
    /// </param>
    public static EngineExecution Create(
        RuntimeStartResult started,
        Action<RuntimeDiagnostic>? diagnostics = null)
        => Create(started, new OutboundConnectionPolicy(), diagnostics);

    /// <summary>
    /// Assembles the execution machinery over a stated outbound connection policy.
    /// </summary>
    /// <remarks>
    /// The policy is a parameter for the same reason it is a seam one layer down: the shipped
    /// one refuses loopback, and every in-process server a test can reach lives there. A test
    /// supplies a permissive judgement instead of the real policy being weakened to
    /// accommodate it.
    /// </remarks>
    /// <param name="started">A runtime whose every mount is ready.</param>
    /// <param name="connections">Which addresses a connection may be opened to.</param>
    /// <param name="diagnostics">
    /// Receives operational diagnostics the engine emits instead of failing a call. A sink
    /// must not throw; a sink that throws is ignored after the outcome was already decided.
    /// Sinks may be called concurrently and must be thread-safe.
    /// </param>
    public static EngineExecution Create(
        RuntimeStartResult started,
        OutboundConnectionPolicy connections,
        Action<RuntimeDiagnostic>? diagnostics = null,
        string? generationLabel = null,
        TimeProvider? timeProvider = null)
        => Create(
            started,
            providers: null,
            connections: connections,
            diagnostics: diagnostics,
            rotations: null,
            generationLabel: generationLabel,
            timeProvider: timeProvider);

    /// <summary>
    /// Assembles the execution machinery for a managed runtime that delivered provider values.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A managed generation delivers the values its <c>fromProvider</c> references name in
    /// memory, and this is where they enter execution. The map is keyed by mount prefix because
    /// a value belongs to the generation that delivered it: two mounts can declare the same
    /// provider key and must not resolve each other's value, so the lookup is per mount rather
    /// than process-wide.
    /// </para>
    /// <para>
    /// Every source is owned by the execution that received it. Disposing the execution clears
    /// every held provider value, which is what makes a retired generation's secrets
    /// unreachable instead of merely unreferenced.
    /// </para>
    /// </remarks>
    /// <param name="started">A runtime whose every mount is ready.</param>
    /// <param name="providers">
    /// Provider values by mount prefix, or null when the process serves no managed generation.
    /// A mount absent from the map is served without a provider source, so a manifest naming
    /// one fails as unresolved rather than resolving from another mount's set.
    /// </param>
    /// <param name="connections">Which addresses a connection may be opened to.</param>
    /// <param name="diagnostics">
    /// Receives operational diagnostics the engine emits instead of failing a call. A sink
    /// must not throw; a sink that throws is ignored after the outcome was already decided.
    /// Sinks may be called concurrently and must be thread-safe.
    /// </param>
    /// <param name="rotations">
    /// Receives one committed refresh-token rotation per mount, so a managed host can reconcile
    /// it with the deployment that issued the profile. The mount prefix is supplied so a host
    /// never has to guess which mount a manifest-local profile id belongs to.
    /// </param>
    public static EngineExecution Create(
        RuntimeStartResult started,
        IReadOnlyDictionary<string, GenerationSecretSource>? providers,
        OutboundConnectionPolicy connections,
        Action<RuntimeDiagnostic>? diagnostics = null,
        RotationNotification? rotations = null,
        string? generationLabel = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(started);
        ArgumentNullException.ThrowIfNull(connections);

        if (!started.Started || started.Files is null)
        {
            throw new InvalidOperationException(
                "A refused runtime executes nothing. Nothing partially mounts, so a caller that "
                + "reached here has already ignored a refusal.");
        }

        Dictionary<MountedManifest, MountExecution> mounts = [];

        try
        {
            foreach (MountedManifest mount in started.Mounts)
            {
                // A connector owns its connection pool and concurrency budget. Two mounts with
                // byte-identical limits must still receive distinct factories; otherwise one
                // mount could occupy the other's MaxConnectionsPerServer slots.
                UpstreamClientFactory clients = new(connections);
                UpstreamSender sender = new(clients);

                // Durable runtime state is scoped to the mount, not the process: records are bound
                // to the mount that wrote them, so a profile id that appears in two mounts cannot
                // resolve the other mount's rotated credential. Without a configured runtime-state
                // directory the runtime keeps its in-memory store, which is the supported
                // non-durable configuration.
                AuthenticationRuntime authentication = started.RuntimeState is { } state
                    ? new AuthenticationRuntime(
                        sender,
                        slots: state.CreateForMount(mount.Prefix),
                        rotationSink: RotationSink(mount.Prefix, rotations))
                    : new AuthenticationRuntime(sender);

                GenerationSecretSource? generation = null;
                providers?.TryGetValue(mount.Prefix, out generation);

                byte[] identityKey = CacheIdentity.NewKey();
                ResponseCache? responseCache = started.ResponseCache.Enabled
                    ? new ResponseCache(
                        mount.Prefix,
                        generationLabel,
                        started.ResponseCache,
                        identityKey,
                        timeProvider,
                        mount.Document.AgentSurface.Operations
                            .Select(static op => op.Slug)
                            .ToHashSet(StringComparer.Ordinal))
                    : null;

                ExecutionService executions = new(
                    sender,
                    new ManifestSecretResolver(
                        new SecretResolutionOptions(started.AllowInlineSecrets),
                        new HostSecretSource(),
                        generation),
                    started.Files,
                    authentication,
                    responseCache,
                    identityKey,
                    started.ProjectionWorker);

                try
                {
                    mounts.Add(mount, new MountExecution(clients, executions, authentication, generation, responseCache));
                }
                catch
                {
                    responseCache?.Dispose();
                    throw;
                }
            }

            return new EngineExecution(mounts, started.Files, diagnostics);
        }
        catch
        {
            foreach (MountExecution mount in mounts.Values)
            {
                mount.Dispose();
            }

            throw;
        }
    }

    /// <summary>
    /// Binds the mount prefix onto the host's rotation callback, or supplies none when the host
    /// does not reconcile. A rotation without a configured runtime-state directory is not
    /// reconcilable: the value would change and disappear with the process.
    /// </summary>
    private static Func<RotatedRefreshToken, CancellationToken, ValueTask>? RotationSink(
        string mountPrefix,
        RotationNotification? rotations)
        => rotations is null
            ? null
            : (rotated, token) => rotations(
                mountPrefix,
                rotated.ProfileId,
                rotated.Slot,
                rotated.AuthorityEpoch,
                rotated.PreviousRuntimeRevision,
                rotated.RuntimeRevision,
                token);

    /// <summary>
    /// Streams one HTTP-transfer payload into the runtime's file store and issues its opaque
    /// process-local capability in the exact protected-resource scope supplied by the host.
    /// </summary>
    public async Task<RuntimeFileUploadResult> UploadFileAsync(
        Stream content,
        string? fileName,
        string? mediaType,
        string resourceIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentException.ThrowIfNullOrEmpty(resourceIdentity);

        try
        {
            FileHandleReference reference = await _files
                .IssueAsync(content, fileName, mediaType, resourceIdentity, cancellationToken)
                .ConfigureAwait(false);

            string capability = _files.WireFormFor(reference.Id);

            if (capability.Length == 0)
            {
                return RuntimeFileUploadResult.Refused(
                    "The file was stored but no transfer capability could be issued.");
            }

            return RuntimeFileUploadResult.Issued(
                capability,
                reference.FileName,
                reference.MediaType,
                reference.Length);
        }
        catch (FileRuntimeException refusal)
        {
            return RuntimeFileUploadResult.Refused(refusal.Message);
        }
    }

    /// <summary>
    /// Authorizes and opens one wire capability for a transfer download. Unknown and
    /// cross-resource values share one result; expiry remains distinct for the owning resource.
    /// </summary>
    public async Task<RuntimeFileDownload> OpenFileAsync(
        string capability,
        string resourceIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentException.ThrowIfNullOrEmpty(resourceIdentity);

        FileRedemption redemption = await RedemptionAuthorization
            .RedeemAsync(_files, capability, resourceIdentity, cancellationToken)
            .ConfigureAwait(false);

        if (!redemption.Succeeded || redemption.Reference is not { } reference)
        {
            return redemption.Refusal == FileRedemptionRefusalKind.Expired
                ? RuntimeFileDownload.Expired()
                : RuntimeFileDownload.Unknown();
        }

        if (redemption.File is { } descriptor)
        {
            await descriptor.Content.DisposeAsync().ConfigureAwait(false);
        }

        FileHandleLookup opened = await _files
            .OpenAsync(reference.Id, cancellationToken)
            .ConfigureAwait(false);

        if (opened.Status == FileHandleStatus.Expired)
        {
            return RuntimeFileDownload.Expired();
        }

        if (opened.Status != FileHandleStatus.Available || opened.Content is not { } content)
        {
            return RuntimeFileDownload.Unknown();
        }

        return RuntimeFileDownload.Available(
            reference.FileName,
            reference.MediaType,
            reference.Length,
            content);
    }

    /// <summary>Runs one tool call against one surface of one mount.</summary>
    /// <remarks>
    /// The mount and the surface are passed as the values a caller already resolved by
    /// routing, rather than as names to be resolved again. A second resolution would be a
    /// second answer to which Manifest a request addressed, and the one that disagreed would
    /// be the one that accepted an address the first had already rejected.
    /// </remarks>
    /// <param name="mount">The Manifest the request addressed.</param>
    /// <param name="surface">The surface the request addressed.</param>
    /// <param name="tool">The tool name the caller sent, exactly as sent.</param>
    /// <param name="arguments">The arguments the caller sent.</param>
    /// <param name="callerPartition">
    /// The authorization scope the host admitted this caller under, when it proved one. Absent
    /// means no component established who the caller is, which a cache decision must treat as a
    /// bypass rather than as a shared identity.
    /// </param>
    /// <param name="cancellationToken">The caller's deadline.</param>
    public async Task<ToolOutcome> InvokeAsync(
        MountedManifest mount,
        MountedSurface surface,
        string invocationScope,
        string tool,
        JsonObject arguments,
        string? negotiatedProtocolRevision,
        CancellationToken cancellationToken,
        CallerPartition? callerPartition = null)
    {
        ArgumentNullException.ThrowIfNull(mount);
        ArgumentNullException.ThrowIfNull(surface);
        ArgumentException.ThrowIfNullOrEmpty(invocationScope);
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(arguments);

        if (!_mounts.TryGetValue(mount, out MountExecution? mounted))
        {
            throw new InvalidOperationException(
                "The invocation names a Manifest that is not mounted in this execution runtime.");
        }

        ToolOutcome outcome = await ToolInvocation
            .InvokeAsync(
                mounted.Executions,
                mount,
                surface,
                invocationScope,
                tool,
                arguments,
                negotiatedProtocolRevision,
                cancellationToken,
                callerPartition)
            .ConfigureAwait(false);

        if (outcome.Diagnostic is { } diagnostic)
        {
            // The tool outcome is already decided; a sink that throws must not convert
            // a finished call into an unexplained failure. Sinks are non-throwing by
            // contract and may be called concurrently, so they must be thread-safe.
            try
            {
                _diagnostics?.Invoke(diagnostic);
            }
            catch
            {
            }
        }

        return outcome;
    }

    /// <summary>Returns the cache owned by a mounted execution, for Engine operator wiring.</summary>
    internal ResponseCache? ResponseCacheFor(MountedManifest mount)
        => _mounts.TryGetValue(mount, out MountExecution? execution) ? execution.Cache : null;

    /// <summary>
    /// Reads the bounded, sanitized recent cache decisions for one mounted prefix.
    /// </summary>
    /// <remarks>
    /// The prefix is supplied rather than a mount object because the operator reaches Engine by
    /// the address it configured, not by the object graph. A prefix that names no mount, or a
    /// mount whose caching is disabled, has nothing to observe and returns null; the caller
    /// distinguishes the two by the refusal it already produced for an unknown prefix.
    /// </remarks>
    /// <param name="mountPrefix">The mounted Manifest prefix to inspect.</param>
    public ResponseCacheObservation? ObserveResponseCache(string mountPrefix)
    {
        if (string.IsNullOrEmpty(mountPrefix))
        {
            return null;
        }

        return CacheForPrefix(mountPrefix)?.Observe();
    }

    /// <summary>
    /// Clears one mounted prefix's completed cache entries, optionally for one operation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only Engine runtime cache state changes. Nothing here republishes a Manifest, touches
    /// managed desired state, rotates a credential or cancels an in-flight producer; a producer
    /// that began before the clear can only admit if the clear epoch it derived its key under is
    /// still current, which the cache itself enforces.
    /// </para>
    /// <para>
    /// A prefix that names no mount, or a mount whose caching is disabled, returns null and
    /// changes nothing.
    /// </para>
    /// </remarks>
    /// <param name="mountPrefix">The mounted Manifest prefix to clear.</param>
    /// <param name="operationSlug">An optional AgentOperation slug to narrow the clear.</param>
    public ResponseCacheClearOutcome? ClearResponseCache(string mountPrefix, string? operationSlug = null)
    {
        if (string.IsNullOrEmpty(mountPrefix))
        {
            return null;
        }

        ResponseCache? cache = CacheForPrefix(mountPrefix);
        if (cache is null)
        {
            return null;
        }

        if (operationSlug is { Length: > 0 })
        {
            // Only a declared slug advances an operation epoch; an unknown slug is refused without
            // growing the epoch map, so a caller-supplied value cannot allocate state.
            cache.TryClearOperation(operationSlug, out ResponseCacheClearOutcome outcome);
            return outcome;
        }

        return cache.ClearScope(null);
    }

    /// <summary>
    /// Clears one mount's cache, optionally one declared operation, distinguishing a mount that is
    /// not served, a mount whose caching is disabled, and an operation slug the mount does not declare.
    /// </summary>
    public ResponseCacheScopedClear ClearResponseCacheScoped(string mountPrefix, string? operationSlug)
    {
        if (string.IsNullOrEmpty(mountPrefix))
        {
            return new ResponseCacheScopedClear(ResponseCacheClearScope.MountUnknown, null);
        }

        ResponseCache? cache = CacheForPrefix(mountPrefix);
        if (cache is null)
        {
            // Distinguish a prefix that names no mount (unknown) from a served mount that carries no
            // cache (caching disabled). An unknown mount is a refusal, not a successful no-op.
            return MountPrefixes.Contains(mountPrefix, StringComparer.Ordinal)
                ? new ResponseCacheScopedClear(ResponseCacheClearScope.CachingDisabled, null)
                : new ResponseCacheScopedClear(ResponseCacheClearScope.MountUnknown, null);
        }

        if (operationSlug is { Length: > 0 })
        {
            if (!cache.TryClearOperation(operationSlug, out ResponseCacheClearOutcome scoped))
            {
                return new ResponseCacheScopedClear(ResponseCacheClearScope.OperationUnknown, scoped);
            }

            return new ResponseCacheScopedClear(ResponseCacheClearScope.Cleared, scoped);
        }

        return new ResponseCacheScopedClear(ResponseCacheClearScope.Cleared, cache.ClearScope(null));
    }

    /// <summary>The mounted prefixes this execution owns, in mount order.</summary>
    public IReadOnlyList<string> MountPrefixes
        => [.. _mounts.Keys.Select(static mount => mount.Prefix)];

    private ResponseCache? CacheForPrefix(string mountPrefix)
    {
        foreach ((MountedManifest mount, MountExecution execution) in _mounts)
        {
            if (string.Equals(mount.Prefix, mountPrefix, StringComparison.Ordinal))
            {
                return execution.Cache;
            }
        }

        return null;
    }

    /// <summary>
    /// The authentication runtime one mounted prefix serves through, or null when this execution
    /// serves no such prefix.
    /// </summary>
    /// <remarks>
    /// An in-host operator mutation reaches the mount through the runtime the serving path acquires
    /// through, so the clear shares that mount's slot gate, its access-token cache and its durable
    /// store instance. A second runtime over the same mount would fence nothing: it would hold a
    /// different gate and would not be the cache a served request reads.
    /// </remarks>
    internal AuthenticationRuntime? MountAuthentication(string mountPrefix)
    {
        foreach ((MountedManifest mount, MountExecution execution) in _mounts)
        {
            if (string.Equals(mount.Prefix, mountPrefix, StringComparison.Ordinal))
            {
                return execution.Authentication;
            }
        }

        return null;
    }

    public ResponseCacheObservation? ObserveScopedResponseCache(string mountPrefix, string? operationSlug)
    {
        if (string.IsNullOrEmpty(mountPrefix))
        {
            return null;
        }

        return CacheForPrefix(mountPrefix)?.Observe(operationSlug);
    }

    /// <summary>
    /// Whether the served mount with this prefix declares an operation with this slug.
    /// </summary>
    /// <remarks>
    /// Used by an operator channel to reject an unknown slug before any cache state is touched.
    /// </remarks>
    public bool MountDeclaresOperation(string mountPrefix, string operationSlug)
    {
        foreach ((MountedManifest mount, _) in _mounts)
        {
            if (string.Equals(mount.Prefix, mountPrefix, StringComparison.Ordinal))
            {
                return mount.Document.AgentSurface.Operation(operationSlug) is not null;
            }
        }

        return false;
    }


    /// <inheritdoc />
    public void Dispose()
    {
        foreach (MountExecution mount in _mounts.Values)
        {
            mount.Dispose();
        }
    }

    /// <summary>The outbound execution state one independent mount owns.</summary>
    private sealed class MountExecution(
        UpstreamClientFactory clients,
        ExecutionService executions,
        AuthenticationRuntime authentication,
        GenerationSecretSource? providers,
        ResponseCache? cache) : IDisposable
    {
        public ExecutionService Executions { get; } = executions;

        public AuthenticationRuntime Authentication { get; } = authentication;

        public ResponseCache? Cache { get; } = cache;

        public void Dispose()
        {
            // Providers first: a retired generation's secrets must stop resolving before the
            // execution that could still read them finishes disposing.
            providers?.Dispose();
            Authentication.Dispose();
            clients.Dispose();
            Cache?.Dispose();
        }
    }
}

/// <summary>The disposition of a scoped cache clear request.</summary>
public enum ResponseCacheClearScope
{
    /// <summary>The operation (or whole mount) was cleared.</summary>
    Cleared,

    /// <summary>No mount with that prefix is served by this generation.</summary>
    MountUnknown,

    /// <summary>The mount is served but carries no cache (caching disabled).</summary>
    CachingDisabled,

    /// <summary>The mount declares no operation with the requested slug; nothing was cleared.</summary>
    OperationUnknown,
}

/// <summary>A scoped clear result, or null when nothing could be cleared.</summary>
public sealed record ResponseCacheScopedClear(
    ResponseCacheClearScope Scope,
    ResponseCacheClearOutcome? Outcome);
