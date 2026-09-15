using System.Globalization;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Mcp;
using MCPiler.Engine.Mcp.Navigator;

namespace MCPiler.Engine.Runtime;

/// <summary>
/// Brings a set of Manifests up to the point just before a listener would open.
/// </summary>
/// <remarks>
/// <para>
/// This is the seam a deployable talks to. Everything that decides what the product does —
/// what loads, what is valid, what a bound becomes, what a surface contains — happens here,
/// on this side of the line, so that a host holds wiring and nothing else.
/// </para>
/// <para>
/// The order is normative and the reason is the same each time: every failure that can be
/// discovered before a listener opens is a failure an operator sees at deploy time instead of
/// a client seeing it as an error on the first call.
/// </para>
/// </remarks>
public static class EngineRuntime
{
    /// <summary>The Manifest format range this build serves.</summary>
    /// <remarks>
    /// Exposed here so a host can state its own identity without naming a manifest type. It
    /// is the same value the loader enforces, read from the same place, so the version a
    /// process prints cannot drift from the version it accepts.
    /// </remarks>
    public static string SupportedManifestFormatRange => ManifestFormatSupport.SupportedRange;

    /// <summary>
    /// Loads, validates, narrows and prepares every mount, or refuses the whole process.
    /// </summary>
    /// <param name="options">Everything the operator configured.</param>
    public static RuntimeStartResult Start(RuntimeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<StartupRefusal> refusals = [];
        List<StartupRefusal> warnings = [];

        if (options.Mounts.Count == 0)
        {
            // Serving nothing is never what an operator meant. A process that starts with an
            // empty surface looks healthy to an orchestrator and answers every client with an
            // empty tool list, which reads as a broken Manifest rather than absent configuration.
            refusals.Add(new StartupRefusal(string.Empty, "host/no-mount", "No Manifest is mounted. The host serves what it is given and there is nothing to serve."));
            return RuntimeStartResult.Refused(refusals, warnings);
        }

        RefusePrefixCollisions(options.Mounts, refusals);

        IReadOnlyDictionary<string, long>? floors = ParseFloors(options, refusals);

        List<MountedManifest> mounts = [];

        foreach (MountRequest request in options.Mounts)
        {
            // A mount names a directory holding the Manifest, and whether that directory holds one
            // is decided by the component whose declared purpose is reading a bundle from a
            // directory. Probing here would put a second existence decision in a component that
            // is supposed to reach nothing, and the guard says so.
            MountedManifest? mounted = Mount(
                new DirectoryManifestSource(request.Path),
                request,
                options,
                floors,
                allowProviderReferences: false,
                refusals,
                warnings);

            if (mounted is not null)
            {
                mounts.Add(mounted);
            }
        }

        // The file-store root is verified after the Manifests because a Manifest's file policy
        // is what the store is configured from. Verifying it first would mean verifying a root
        // under defaults that the Manifests then change.
        FileHandleStore? files = OpenFileStore(options, mounts, refusals);

        // Runtime-owned mutable authentication state, opened for the same reason: a key that
        // cannot be read is a deploy-time fault, not something an operator should discover on the
        // first refresh-token rotation.
        RuntimeStateLocation? runtimeState = OpenRuntimeState(options, refusals);

        // A Manifest that declares a rotatable slot cannot be served without the store. Served
        // memory-only it would look healthy and lose the rotated credential on the first
        // restart, after the provider had already invalidated the predecessor — a failure the
        // deployment would discover as an authentication outage it cannot recover by retrying.
        RequireRuntimeStateForMutableMounts(mounts, runtimeState, refusals);

        return refusals.Count > 0 || files is null
            ? RuntimeStartResult.Refused(refusals, warnings)
            : RuntimeStartResult.Ready(mounts, warnings, files, options.AllowInlineSecrets, runtimeState);
    }

    /// <summary>
    /// Refuses a process that would have to rotate a durable credential but has no store to
    /// commit the replacement into.
    /// </summary>
    /// <remarks>
    /// The refusal names the mount and the missing settings rather than the credential, so an
    /// operator learns what to configure without the diagnostic becoming a secret channel. A
    /// static-only deployment pays nothing: no profile declares a slot, so nothing here fires.
    /// </remarks>
    private static void RequireRuntimeStateForMutableMounts(
        IReadOnlyList<MountedManifest> mounts,
        RuntimeStateLocation? runtimeState,
        List<StartupRefusal> refusals)
    {
        if (runtimeState is not null)
        {
            return;
        }

        foreach (MountedManifest mount in mounts)
        {
            foreach (AuthenticationProfile profile in mount.Document.EffectiveAuthentication.Profiles)
            {
                if (profile.Slots.Count == 0)
                {
                    continue;
                }

                refusals.Add(new StartupRefusal(
                    mount.Prefix,
                    "host/runtime-state-required",
                    $"The Manifest mounted here declares runtime-owned mutable authentication state " +
                    $"('{profile.Id}'), so a rotated credential must survive a restart. Configure " +
                    $"'{nameof(RuntimeOptions.RuntimeStateRoot)}' and " +
                    $"'{nameof(RuntimeOptions.RuntimeStateKeyFile)}' to give the process a durable " +
                    "store, or the process refuses to start rather than lose the rotated value.")
                {
                    Manifest = mount.Path,
                    Setting = nameof(RuntimeOptions.RuntimeStateRoot),
                });

                return;
            }
        }
    }

    /// <summary>
    /// Opens durable runtime state, or records why it cannot be used.
    /// </summary>
    /// <remarks>
    /// Unconfigured is supported and means the process keeps mutable state in memory. A configured
    /// pair that is unusable refuses the process rather than silently degrading, because a
    /// deployment that believes a rotating credential is durable must not be given one that is not.
    /// </remarks>
    internal static RuntimeStateLocation? OpenRuntimeState(RuntimeOptions options, List<StartupRefusal> refusals)
    {
        if (refusals.Count > 0)
        {
            return null;
        }

        if (!RuntimeStateLocation.TryOpen(
            options.RuntimeStateRoot,
            options.RuntimeStateKeyFile,
            out var state,
            out var refusal))
        {
            refusals.Add(new StartupRefusal(string.Empty, "host/runtime-state-unusable", refusal!)
            {
                Setting = options.RuntimeStateKeyFile is null ? "RuntimeStateRoot" : "RuntimeStateKeyFile",
                Attempted = options.RuntimeStateKeyFile ?? options.RuntimeStateRoot,
            });

            return null;
        }

        return state;
    }

    /// <summary>
    /// Loads one mount from an arbitrary source, applying the same rules a directory mount gets.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The source is a parameter rather than a path because a managed generation arrives as
    /// bytes. Loading it here — through the same load, narrowing and derivation sequence — is
    /// what makes "the same Manifest" mean the same thing whichever way it was delivered, and
    /// keeps a second loading rule from existing.
    /// </para>
    /// <para>
    /// <paramref name="allowProviderReferences"/> is a parameter rather than a process option
    /// because it is not an operator preference: a standalone deployment must refuse a Manifest
    /// that names provider values it can never be given, while a managed generation is exactly
    /// the case those references exist for. Only the delivery mode may decide it.
    /// </para>
    /// </remarks>
    internal static MountedManifest? Mount(
        IManifestSource source,
        MountRequest request,
        RuntimeOptions options,
        IReadOnlyDictionary<string, long>? floors,
        bool allowProviderReferences,
        List<StartupRefusal> refusals,
        List<StartupRefusal> warnings)
    {
        ManifestReadResult loaded = ManifestReader.Read(
            source,
            new ManifestLoadOptions
            {
                RequireSealed = options.RequireSealed,
                AllowInlineSecrets = options.AllowInlineSecrets,
                AllowProviderReferences = allowProviderReferences,
            });

        foreach (ManifestDiagnostic diagnostic in loaded.Warnings)
        {
            warnings.Add(Translate(request, diagnostic));
        }

        if (!loaded.Succeeded || loaded.Manifest is null)
        {
            foreach (ManifestDiagnostic diagnostic in loaded.Errors)
            {
                refusals.Add(Translate(request, diagnostic));
            }

            return null;
        }

        ManifestDocument document = loaded.Manifest;
        PolicySection policy = document.Policy;

        // A mount's own narrowing first, because asking for more than this Manifest compiled is
        // an error about this Manifest and must be reported as one.
        IReadOnlyDictionary<string, long>? requested = ParseSettings(
            request.Narrowing,
            request.Prefix,
            request.Path,
            "host/limit-unknown",
            "host/limit-malformed",
            refusals);

        if (requested is null || floors is null)
        {
            return null;
        }

        List<ManifestDiagnostic> narrowing = [];
        policy = PolicyNarrowing.ApplyNamed(policy, requested, narrowing);
        policy = PolicyNarrowing.Apply(policy, new PolicyOverrides { AllowedOrigins = request.AllowedOrigins }, narrowing);

        // Then the floor, clamped to whatever survived. Clamping is what makes a floor
        // structurally unable to widen: the value handed to the narrowing rules is never
        // larger than the compiled one, so the widening branch cannot be reached from here.
        policy = PolicyNarrowing.ApplyNamed(policy, Clamp(floors, policy), narrowing);

        if (narrowing.Any(static diagnostic => diagnostic.IsError))
        {
            foreach (ManifestDiagnostic diagnostic in narrowing.Where(static candidate => candidate.IsError))
            {
                refusals.Add(Translate(request, diagnostic) with
                {
                    Setting = SettingOf(diagnostic, requested),
                });
            }

            return null;
        }

        warnings.AddRange(narrowing.Where(static candidate => !candidate.IsError).Select(diagnostic => Translate(request, diagnostic)));

        // Derived here, before anything listens. A surface that cannot be derived is a
        // configuration fault, and discovering it on the first request would report it as a
        // runtime fault to whoever happened to connect.
        List<ManifestDiagnostic> derivation = [];
        List<MountedSurface> surfaces = [];

        // The index before the surfaces, because every surface ranks from it and a Manifest
        // whose declared index no longer describes its own operations degrades discovery
        // silently: fewer or worse results, and nothing in the answer saying so. The same
        // reconciliation rule the tool set gets, and the same consequence.
        NavigatorIndex index = NavigatorIndex.Resolve(document, derivation);

        foreach (ManifestSurface surface in document.Server.Surfaces.Where(static candidate => candidate.Enabled))
        {
            surfaces.Add(SurfaceCatalogue.Build(document, surface, derivation));
        }

        if (derivation.Any(static diagnostic => diagnostic.IsError))
        {
            refusals.AddRange(derivation.Where(static candidate => candidate.IsError).Select(diagnostic => Translate(request, diagnostic)));
            return null;
        }

        warnings.AddRange(derivation.Where(static candidate => !candidate.IsError).Select(diagnostic => Translate(request, diagnostic)));

        return new MountedManifest(request.Prefix, request.Path, document, policy, surfaces, index);
    }

    /// <summary>
    /// Reduces every floor to the value the mount already compiled when the floor is looser.
    /// </summary>
    private static IReadOnlyDictionary<string, long> Clamp(IReadOnlyDictionary<string, long> floors, PolicySection policy)
    {
        Dictionary<string, long> clamped = new(StringComparer.Ordinal);

        foreach ((string name, long value) in floors)
        {
            clamped[name] = Math.Min(value, PolicyNarrowing.Compiled(policy, name));
        }

        return clamped;
    }

    private static void RefusePrefixCollisions(IReadOnlyList<MountRequest> mounts, List<StartupRefusal> refusals)
    {
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        foreach (MountRequest mount in mounts)
        {
            if (!seen.Add(mount.Prefix))
            {
                // Two Manifests on one prefix means one of them is unreachable, and which one
                // depends on iteration order. That is a coin flip an operator cannot see.
                refusals.Add(new StartupRefusal(mount.Prefix, "host/prefix-duplicate", $"Two Manifests are mounted at '{mount.Prefix}'. A prefix addresses exactly one Manifest."));
            }
        }
    }

    /// <summary>
    /// Opens the file-handle store the process will use, or records why it cannot.
    /// </summary>
    /// <remarks>
    /// The store is returned rather than constructed and discarded. Verifying a root and then
    /// building a second store later would mean the object that was proven usable is not the
    /// object that stores anything, and only the first one was checked.
    /// </remarks>
    internal static FileHandleStore? OpenFileStore(RuntimeOptions options, IReadOnlyList<MountedManifest> mounts, List<StartupRefusal> refusals)
    {
        if (refusals.Count > 0)
        {
            // Nothing will start, and constructing a store would create directories for a
            // process that is about to exit.
            return null;
        }

        FilePolicy policy = mounts.Count == 1
            ? mounts[0].Policy.EffectiveFiles
            : FilePolicy.Default;

        try
        {
            return new FileHandleStore(FileHandleStoreOptions.For(options.FileStoreRoot, policy, options.ServedContentRoots));
        }
        catch (FileRuntimeException failure)
        {
            refusals.Add(new StartupRefusal(string.Empty, "host/file-store-unusable", failure.Message)
            {
                Setting = "FileStoreRoot",
                Attempted = options.FileStoreRoot,
            });

            return null;
        }
    }

    /// <summary>
    /// Parses the process floors, or records why they cannot be used.
    /// </summary>
    /// <remarks>
    /// Exposed to the managed loader so an activation and a file-mode start apply the same floor
    /// rules rather than maintaining a second interpretation of the same settings.
    /// </remarks>
    internal static IReadOnlyDictionary<string, long>? ParseFloors(RuntimeOptions options, List<StartupRefusal> refusals)
        => ParseSettings(
            options.Floors,
            string.Empty,
            manifest: null,
            "host/floor-unknown",
            "host/floor-malformed",
            refusals);

    private static IReadOnlyDictionary<string, long>? ParseSettings(
        IReadOnlyDictionary<string, string> settings,
        string mount,
        string? manifest,
        string unknownCode,
        string malformedCode,
        List<StartupRefusal> refusals)
    {
        Dictionary<string, long> parsed = new(StringComparer.Ordinal);
        bool ok = true;

        foreach ((string name, string text) in settings)
        {
            if (!PolicyNarrowing.ByName.TryGetValue(name, out ProtectedLimit? limit))
            {
                // Refused by name rather than ignored. A setting that silently does nothing is
                // indistinguishable from one that worked, and the operator finds out from
                // behaviour rather than from startup.
                refusals.Add(new StartupRefusal(mount, unknownCode, $"'{name}' is not a bound local configuration may narrow.")
                {
                    Manifest = manifest,
                    Setting = name,
                    Attempted = text,
                });
                ok = false;
                continue;
            }

            if (!TryParse(text, limit.Unit, out long value))
            {
                refusals.Add(new StartupRefusal(mount, malformedCode, $"'{name}' was given '{text}', which is not {Expected(limit.Unit)}.")
                {
                    Manifest = manifest,
                    Setting = name,
                    Attempted = text,
                });
                ok = false;
                continue;
            }

            parsed[name] = value;
        }

        return ok ? parsed : null;
    }

    private static bool TryParse(string text, LimitUnit unit, out long value)
    {
        switch (unit)
        {
            case LimitUnit.Duration:
                // A bare number is refused deliberately. TimeSpan reads "30" as thirty DAYS,
                // and an operator who writes it in a timeout field means thirty seconds. The
                // misreading is five orders of magnitude and silent whenever the result still
                // narrows, so the form that can be misread is not accepted at all.
                if (text.Contains(':', StringComparison.Ordinal)
                    && TimeSpan.TryParse(text, CultureInfo.InvariantCulture, out TimeSpan duration)
                    && duration >= TimeSpan.Zero)
                {
                    value = duration.Ticks;
                    return true;
                }

                break;

            case LimitUnit.Flag:
                if (bool.TryParse(text, out bool hardened))
                {
                    // A flag is compared as permissiveness, where the hardened setting is the
                    // lower number, so that "narrower" means the same thing for every bound.
                    value = hardened ? 0 : 1;
                    return true;
                }

                break;

            default:
                if (long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long number) && number >= 0)
                {
                    value = number;
                    return true;
                }

                break;
        }

        value = 0;
        return false;
    }

    private static string Expected(LimitUnit unit) => unit switch
    {
        LimitUnit.Duration => "a duration such as 00:01:40",
        LimitUnit.Flag => "true or false",
        LimitUnit.Bytes => "a byte count",
        _ => "a count",
    };

    private static string? SettingOf(ManifestDiagnostic diagnostic, IReadOnlyDictionary<string, long> requested)
        => requested.Keys.FirstOrDefault(name => diagnostic.Message.Contains($"'{name}'", StringComparison.Ordinal));

    private static StartupRefusal Translate(MountRequest request, ManifestDiagnostic diagnostic)
        => new(request.Prefix, diagnostic.Code, diagnostic.Message)
        {
            Manifest = request.Path,
            Section = diagnostic.Section,
            ProgramCode = diagnostic.ProgramCode,
        };
}
