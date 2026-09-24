using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Sealing;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Runtime.Managed;

/// <summary>One mount of a delivered generation: where it is addressed and what it contains.</summary>
/// <param name="Prefix">The route prefix this mount is served under.</param>
/// <param name="Bundle">The packed Manifest bundle, exactly as delivered.</param>
public sealed record ManagedMountDelivery(string Prefix, ReadOnlyMemory<byte> Bundle);

/// <summary>
/// One committed refresh-token rotation, reported in primitives so a host can act on it without
/// naming the authentication namespace. The value is deliberately absent: a host regenerates it
/// from the authoritative encrypted record at send time, so nothing queues a secret in memory
/// longer than the request that carries it.
/// </summary>
/// <param name="Mount">The mount the rotation happened under.</param>
/// <param name="ProfileId">The manifest-local profile identity.</param>
/// <param name="Slot">The rotated slot.</param>
/// <param name="AuthorityEpoch">The authority epoch the rotation happened under.</param>
/// <param name="PreviousRuntimeRevision">The revision before the rotation.</param>
/// <param name="RuntimeRevision">The revision the rotation established.</param>
/// <param name="CancellationToken">Cancellation of the invocation that rotated.</param>
public delegate ValueTask RotationNotification(
    string Mount,
    string ProfileId,
    string Slot,
    long AuthorityEpoch,
    long PreviousRuntimeRevision,
    long RuntimeRevision,
    CancellationToken CancellationToken);

/// <summary>
/// One authoritative mutable-slot record, read back from the local encrypted store so a host can
/// report exactly what it committed rather than what a callback remembered.
/// </summary>
/// <param name="Mount">The mount the record belongs to.</param>
/// <param name="ProfileId">The manifest-local profile identity.</param>
/// <param name="Slot">The slot identity.</param>
/// <param name="AuthorityEpoch">The committed authority epoch.</param>
/// <param name="RuntimeRevision">The committed runtime revision.</param>
/// <param name="ScopeFingerprint">The committed scope fingerprint, when one was recorded.</param>
/// <param name="Value">The committed value.</param>
public sealed record ManagedSlotSnapshot(
    string Mount,
    string ProfileId,
    string Slot,
    long AuthorityEpoch,
    long RuntimeRevision,
    string? ScopeFingerprint,
    string Value);

/// <summary>
/// One complete desired generation, decoded from the managed protocol but not yet loaded.
/// </summary>
/// <param name="GenerationId">The producer's deterministic generation identity.</param>
/// <param name="EngineVersion">The producer's reported Engine version, for diagnostics only.</param>
/// <param name="Mounts">Every mount, in delivery order.</param>
/// <param name="Secrets">
/// Provider key to value, exactly as delivered. Values never leave this process, are never
/// written anywhere, and are not part of any identity the producer sees.
/// </param>
public sealed record ManagedGenerationDelivery(
    string GenerationId,
    string? EngineVersion,
    IReadOnlyList<ManagedMountDelivery> Mounts,
    IReadOnlyDictionary<string, string> Secrets);

/// <summary>A loaded generation, ready to be leased and executed.</summary>
public sealed class ManagedGeneration : IDisposable
{
    private readonly RuntimeStartResult _started;
    private readonly EngineExecution _execution;
    private bool _disposed;
    private bool _taken;

    internal ManagedGeneration(
        string generationId,
        string? engineVersion,
        RuntimeStartResult started,
        EngineExecution execution)
    {
        GenerationId = generationId;
        EngineVersion = engineVersion;
        _started = started;
        _execution = execution;
    }

    /// <summary>The producer's deterministic generation identity.</summary>
    public string GenerationId { get; }

    /// <summary>The producer's reported Engine version, as delivered.</summary>
    public string? EngineVersion { get; }

    /// <summary>The loaded mounts, in delivery order.</summary>
    public IReadOnlyList<MountedManifest> Mounts => _started.Mounts;

    /// <summary>Warnings the load produced; nothing here blocks serving.</summary>
    public IReadOnlyList<StartupRefusal> Warnings => _started.Warnings;

    /// <summary>The execution graph a lease resolves through.</summary>
    public EngineExecution Execution => _execution;

    /// <summary>
    /// Transfers the execution graph out of this wrapper to the caller.
    /// </summary>
    /// <remarks>
    /// A managed process re-homes a loaded generation into its own generation object, which owns
    /// the lease bookkeeping. The execution graph is deliberately not shared: after this call the
    /// wrapper's <see cref="Dispose"/> is a no-op, so the graph lives exactly as long as the
    /// generation that now owns it and is disposed once, after that generation's leases drain.
    /// </remarks>
    public EngineExecution TakeExecution()
    {
        _taken = true;
        return _execution;
    }

    /// <summary>
    /// Disposes the execution graph, and with it every provider value this generation owned.
    /// </summary>
    /// <remarks>
    /// A superseded generation that was never disposed would keep its provider values reachable
    /// for as long as the process lived, which is exactly the leak the narrow provider surface
    /// exists to prevent.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed || _taken)
        {
            return;
        }

        _disposed = true;
        _execution.Dispose();
    }
}

/// <summary>The outcome of loading a delivered generation: the generation, or why it was refused.</summary>
/// <param name="Generation">The loaded generation; null when any refusal was produced.</param>
/// <param name="Refusals">Every refusal, in the order produced.</param>
/// <param name="Warnings">Every warning the load produced.</param>
public sealed record ManagedGenerationLoad(
    ManagedGeneration? Generation,
    IReadOnlyList<StartupRefusal> Refusals,
    IReadOnlyList<StartupRefusal> Warnings)
{
    /// <summary>True when a generation was produced.</summary>
    public bool Succeeded => Generation is not null && Refusals.Count == 0;
}

/// <summary>
/// Loads a delivered managed generation into the same runtime objects a file mount produces.
/// </summary>
/// <remarks>
/// <para>
/// This lives on the library side of the seam because decoding a bundle, loading a Manifest and
/// assembling an execution graph are product decisions. The deployable supplies bytes, strings
/// and options, and receives a generation it can lease; it never names the loader, the archive
/// format, the Manifest model or the execution graph.
/// </para>
/// <para>
/// The file store is opened once per loader and shared by every generation, because it carries
/// the wire index that makes a handle issued before an activation redeemable after it. A
/// generation that owned its own store would strand every outstanding file handle at the moment
/// a new generation became current.
/// </para>
/// </remarks>
public sealed class ManagedGenerationLoader : IDisposable
{
    private readonly RuntimeOptions _options;
    private readonly OutboundConnectionPolicy _connections;
    private readonly FileHandleStore _files;
    private readonly RuntimeStateLocation? _runtimeState;
    private bool _disposed;

    private ManagedGenerationLoader(
        RuntimeOptions options,
        OutboundConnectionPolicy connections,
        FileHandleStore files,
        RuntimeStateLocation? runtimeState)
    {
        _options = options;
        _connections = connections;
        _files = files;
        _runtimeState = runtimeState;
    }

    /// <summary>Whether rotated authentication state survives a restart.</summary>
    /// <remarks>
    /// The answer is a property of the process, not of a generation: the store is opened once and
    /// every generation writes through the same key. Stating it here keeps the startup report from
    /// having to name the runtime-state type on the host side of the seam.
    /// </remarks>
    public bool DurableRuntimeState => _runtimeState is not null;

    /// <summary>
    /// Opens the process-scoped state a managed deployment serves from, using the product's
    /// outbound address policy.
    /// </summary>
    /// <remarks>
    /// The overload exists so a caller on the deployable side of the seam can open a loader
    /// without naming the execution namespace, which that side is not allowed to name. Choosing
    /// the outbound policy is a product decision and is made here.
    /// </remarks>
    /// <param name="options">The deployment options; mounts are ignored because generations supply them.</param>
    /// <param name="loader">The loader, or null when the process-scoped state could not be opened.</param>
    /// <param name="refusals">Why the process-scoped state could not be opened.</param>
    public static bool TryOpen(
        RuntimeOptions options,
        out ManagedGenerationLoader? loader,
        out IReadOnlyList<StartupRefusal> refusals)
        => TryOpen(options, new OutboundConnectionPolicy(), out loader, out refusals);

    /// <summary>
    /// Opens the process-scoped state a managed deployment serves from: the file store and the
    /// durable runtime state.
    /// </summary>
    /// <param name="options">The deployment options; mounts are ignored because generations supply them.</param>
    /// <param name="connections">The outbound address policy every generation's transport obeys.</param>
    /// <param name="loader">The loader, or null when the process-scoped state could not be opened.</param>
    /// <param name="refusals">Why the process-scoped state could not be opened.</param>
    public static bool TryOpen(
        RuntimeOptions options,
        OutboundConnectionPolicy connections,
        out ManagedGenerationLoader? loader,
        out IReadOnlyList<StartupRefusal> refusals)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(connections);

        List<StartupRefusal> collected = [];

        FileHandleStore? files = EngineRuntime.OpenFileStore(options, [], collected);
        RuntimeStateLocation? runtimeState = EngineRuntime.OpenRuntimeState(options, collected);

        if (collected.Count > 0 || files is null)
        {
            loader = null;
            refusals = collected;
            return false;
        }

        loader = new ManagedGenerationLoader(options, connections, files, runtimeState);
        refusals = [];
        return true;
    }

    /// <summary>
    /// Loads one delivered generation, or reports every reason it cannot be served.
    /// </summary>
    /// <remarks>
    /// Every mount is loaded before any is served, and one refusal refuses the whole generation.
    /// A partially loaded candidate would advertise a mount set that differs from the desired one,
    /// which is indistinguishable to a client from a connector that was intentionally removed.
    /// </remarks>
    /// <param name="delivery">The delivered generation.</param>
    /// <param name="rotations">
    /// Receives one committed refresh-token rotation per mount, when the caller reconciles with
    /// the deployment that issued the profile. Absent means rotations stay local.
    /// </param>
    public ManagedGenerationLoad Load(
        ManagedGenerationDelivery delivery,
        RotationNotification? rotations = null)
    {
        ArgumentNullException.ThrowIfNull(delivery);
        ObjectDisposedException.ThrowIf(_disposed, this);

        List<StartupRefusal> refusals = [];
        List<StartupRefusal> warnings = [];

        if (string.IsNullOrWhiteSpace(delivery.GenerationId))
        {
            refusals.Add(new StartupRefusal(
                string.Empty,
                "managed/generation-identity-missing",
                "The delivered generation declares no identity, so Engine could not report which generation it activated."));
            return new ManagedGenerationLoad(null, refusals, warnings);
        }

        if (delivery.Mounts.Count == 0)
        {
            refusals.Add(new StartupRefusal(
                string.Empty,
                "managed/generation-empty",
                "The delivered generation contains no mount. Serving it would advertise an empty surface and report it as a successful activation."));
            return new ManagedGenerationLoad(null, refusals, warnings);
        }

        IReadOnlyDictionary<string, long>? floors = EngineRuntime.ParseFloors(
            _options,
            refusals);

        if (floors is null)
        {
            return new ManagedGenerationLoad(null, refusals, warnings);
        }

        List<MountedManifest> mounts = [];
        Dictionary<string, GenerationSecretSource> providers = new(StringComparer.Ordinal);

        foreach (ManagedMountDelivery mount in delivery.Mounts)
        {
            InMemoryManifestSource? source;

            try
            {
                source = Unpack(mount, refusals);
            }
            catch (Exception exception) when (exception is InvalidOperationException or IOException)
            {
                refusals.Add(new StartupRefusal(
                    mount.Prefix,
                    "managed/bundle-unreadable",
                    $"The mount's bundle could not be read: {exception.Message}"));
                continue;
            }

            if (source is null)
            {
                continue;
            }

            MountedManifest? loaded = EngineRuntime.Mount(
                source,
                new MountRequest(mount.Prefix, "(managed generation)"),
                _options,
                floors,
                allowProviderReferences: true,
                refusals,
                warnings);

            if (loaded is not null)
            {
                mounts.Add(loaded);
            }
        }

        if (refusals.Count > 0)
        {
            return new ManagedGenerationLoad(null, refusals, warnings);
        }

        // Provider values are bound per mount after every Manifest is known, because one mount's
        // value must never satisfy another mount's reference.
        foreach (MountedManifest mount in mounts)
        {
            IReadOnlyList<string> required = RequiredProviderKeys(mount);

            Dictionary<string, string> values = new(StringComparer.Ordinal);

            foreach (string key in required)
            {
                if (!delivery.Secrets.TryGetValue(key, out string? value) || string.IsNullOrEmpty(value))
                {
                    refusals.Add(new StartupRefusal(
                        mount.Prefix,
                        "managed/provider-value-missing",
                        $"The generation references provider key '{key}', which it did not deliver. Engine cannot execute a credential it was not given."));
                    continue;
                }

                values[key] = value;
            }

            if (refusals.Count == 0)
            {
                providers[mount.Prefix] = new GenerationSecretSource(values);
            }
        }

        if (refusals.Count > 0)
        {
            foreach (GenerationSecretSource source in providers.Values)
            {
                source.Dispose();
            }

            return new ManagedGenerationLoad(null, refusals, warnings);
        }

        RuntimeStartResult started = RuntimeStartResult.Ready(
            mounts,
            warnings,
            _files,
            _options.AllowInlineSecrets,
            _runtimeState,
            _options.ResponseCache.ClampToHardMaxima());

        EngineExecution execution;

        try
        {
            execution = EngineExecution.Create(
                started,
                providers,
                _connections,
                diagnostics: null,
                rotations: rotations,
                generationLabel: delivery.GenerationId);
        }
        catch
        {
            foreach (GenerationSecretSource source in providers.Values)
            {
                source.Dispose();
            }

            throw;
        }

        return new ManagedGenerationLoad(
            new ManagedGeneration(delivery.GenerationId, delivery.EngineVersion, started, execution),
            refusals,
            warnings);
    }

    /// <summary>
    /// Reads one committed mutable slot back from the local encrypted store, so a host reconciles
    /// exactly what it committed rather than what a callback remembered.
    /// </summary>
    /// <remarks>
    /// No managed payload and no secret is queued anywhere: a pending report re-reads the
    /// authoritative record each attempt, and the record stops existing when the slot is not
    /// declared or the store is not configured, which are the two cases where no report should be
    /// generated at all.
    /// </remarks>
    /// <param name="mount">The mount the slot belongs to.</param>
    /// <param name="profileId">The manifest-local profile identity.</param>
    /// <param name="slot">The slot identity.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The committed record, or null when the slot is not durably stored.</returns>
    public async ValueTask<ManagedSlotSnapshot?> ReadSlotAsync(
        string mount,
        string profileId,
        string slot,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_runtimeState is null || string.IsNullOrEmpty(mount))
        {
            return null;
        }

        MutableSlotRecord? record = await _runtimeState
            .CreateForMount(mount)
            .LoadAsync(profileId, slot, cancellationToken)
            .ConfigureAwait(false);

        return record is null
            ? null
            : new ManagedSlotSnapshot(
                mount,
                record.ProfileId,
                record.Slot,
                record.AuthorityEpoch,
                record.RuntimeRevision,
                record.ScopeFingerprint,
                record.Value);
    }

    /// <summary>
    /// Every provider key the mount's Manifests declare, in a deterministic order.
    /// </summary>
    private static IReadOnlyList<string> RequiredProviderKeys(MountedManifest mount)
    {
        SortedSet<string> keys = new(StringComparer.Ordinal);

        if (mount.Document.EffectiveCredentials is { } credentials)
        {
            foreach (var credential in credentials.Credentials)
            {
                if (credential.Value.FromProvider is { } key)
                {
                    keys.Add(key);
                }
            }
        }

        return [.. keys];
    }

    /// <summary>
    /// Extracts a mount bundle into an in-memory source, or reports why it could not be read.
    /// </summary>
    private static InMemoryManifestSource? Unpack(ManagedMountDelivery mount, List<StartupRefusal> refusals)
    {
        using MemoryStream stream = new(mount.Bundle.ToArray(), writable: false);

        ManifestArchiveExtraction extraction = ManifestArchive.Extract(stream);

        if (!extraction.Succeeded || extraction.Errors.Count > 0)
        {
            foreach (ManifestDiagnostic diagnostic in extraction.Errors)
            {
                refusals.Add(new StartupRefusal(mount.Prefix, diagnostic.Code, diagnostic.Message));
            }

            return null;
        }

        if (!extraction.Entries.TryGetValue(DirectoryManifestSource.RootFileName, out ReadOnlyMemory<byte> root))
        {
            refusals.Add(new StartupRefusal(
                mount.Prefix,
                "managed/bundle-root-missing",
                $"The mount's bundle carries no '{DirectoryManifestSource.RootFileName}', so there is no Manifest to serve."));
            return null;
        }

        Dictionary<string, ReadOnlyMemory<byte>> sections = new(StringComparer.Ordinal);

        foreach ((string name, ReadOnlyMemory<byte> payload) in extraction.Entries)
        {
            if (string.Equals(name, DirectoryManifestSource.RootFileName, StringComparison.Ordinal))
            {
                continue;
            }

            sections[name] = payload;
        }

        return new InMemoryManifestSource(root, sections);
    }

    /// <summary>
    /// Stops this loader admitting new generations. Loaded generations are disposed by their owner.
    /// </summary>
    /// <remarks>
    /// The file store holds no process-scoped resource to release: its state is the records on
    /// disk, which outlive any one loader so a handle issued before a restart stays redeemable
    /// after it. Marking the loader closed is therefore the whole of the work.
    /// </remarks>
    public void Dispose() => _disposed = true;
}
