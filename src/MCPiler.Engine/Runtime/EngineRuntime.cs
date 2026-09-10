using System.Globalization;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

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

        IReadOnlyDictionary<string, long>? floors = ParseSettings(
            options.Floors,
            string.Empty,
            manifest: null,
            "host/floor-unknown",
            "host/floor-malformed",
            refusals);

        List<MountedManifest> mounts = [];

        foreach (MountRequest request in options.Mounts)
        {
            MountedManifest? mounted = Mount(request, options, floors, refusals, warnings);

            if (mounted is not null)
            {
                mounts.Add(mounted);
            }
        }

        // The file-store root is verified after the Manifests because a Manifest's file policy
        // is what the store is configured from. Verifying it first would mean verifying a root
        // under defaults that the Manifests then change.
        VerifyFileStoreRoot(options, mounts, refusals);

        return refusals.Count > 0
            ? RuntimeStartResult.Refused(refusals, warnings)
            : RuntimeStartResult.Ready(mounts, warnings);
    }

    private static MountedManifest? Mount(
        MountRequest request,
        RuntimeOptions options,
        IReadOnlyDictionary<string, long>? floors,
        List<StartupRefusal> refusals,
        List<StartupRefusal> warnings)
    {
        // A mount names a directory holding the Manifest, and whether that directory holds one
        // is decided by the component whose declared purpose is reading a bundle from a
        // directory. Probing here would put a second existence decision in a component that
        // is supposed to reach nothing, and the guard says so.
        ManifestReadResult loaded = ManifestReader.Read(
            new DirectoryManifestSource(request.Path),
            new ManifestLoadOptions
            {
                RequireSealed = options.RequireSealed,
                AllowInlineSecrets = options.AllowInlineSecrets,
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

        return new MountedManifest(request.Prefix, request.Path, document, policy);
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

    private static void VerifyFileStoreRoot(RuntimeOptions options, IReadOnlyList<MountedManifest> mounts, List<StartupRefusal> refusals)
    {
        if (refusals.Count > 0)
        {
            // Nothing will start, and constructing a store would create directories for a
            // process that is about to exit.
            return;
        }

        FilePolicy policy = mounts.Count == 1
            ? mounts[0].Policy.EffectiveFiles
            : FilePolicy.Default;

        try
        {
            _ = new FileHandleStore(FileHandleStoreOptions.For(options.FileStoreRoot, policy, options.ServedContentRoots));
        }
        catch (FileRuntimeException failure)
        {
            refusals.Add(new StartupRefusal(string.Empty, "host/file-store-unusable", failure.Message)
            {
                Setting = "FileStoreRoot",
                Attempted = options.FileStoreRoot,
            });
        }
    }

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
        };
}
