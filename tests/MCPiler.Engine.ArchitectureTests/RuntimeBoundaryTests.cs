using System.Text.RegularExpressions;

using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Guards the properties that make a manifest safe to load from an untrusted bundle and safe
/// to act on: the host is reachable from a named handful of components, provenance is carried
/// without being read, and a reference is resolved in exactly one place that has no way to
/// fetch anything.
/// </summary>
/// <remarks>
/// <para>
/// These are architecture guards rather than unit tests because they are statements about
/// what does <em>not</em> exist. A unit test can show that today's resolver does not open a
/// socket; only a guard over the whole source tree can show that no future component quietly
/// adds one.
/// </para>
/// <para>
/// The scan covers every production source file, not one namespace. That distinction is the
/// whole point: a guard scoped to the namespace it was written for stops guarding the moment
/// somebody adds a second one, and it stops silently, because a passing guard and an absent
/// guard are indistinguishable from the test report. Request compilation is the first component
/// to arrive outside <c>Manifest/</c>, and it is deliberately granted no exemption below - a
/// compiler turns an operation and an argument object into bytes, which needs neither a socket
/// nor a file nor an environment variable.
/// </para>
/// </remarks>
public sealed class RuntimeBoundaryTests
{
    /// <summary>Everything the guards read. Widening this constant is how a new namespace gets covered.</summary>
    private const string EngineSourceRoot = "src/MCPiler.Engine";

    private const string ManifestSourceRoot = EngineSourceRoot + "/Manifest";

    private const string Resolver = ManifestSourceRoot + "/Loading/SchemaReferenceResolver.cs";

    private const string Pointer = ManifestSourceRoot + "/Loading/JsonPointer.cs";

    /// <summary>
    /// Components whose declared purpose is to touch the host: reading a bundle from a
    /// directory, and packing, unpacking or sealing one.
    /// </summary>
    /// <remarks>
    /// Everything else - the readers, the validator, the reference resolver, both derivers,
    /// the ranker, the canonical writer and the request compiler - operates on bytes it was
    /// handed. Keeping the set this small is what makes "loading a manifest cannot reach the
    /// machine" checkable rather than merely intended. Credential resolution will eventually
    /// read an environment variable or a secret file, and sending a compiled request will
    /// eventually open a socket; when they do, they must be added here deliberately and
    /// reviewed as components that touch the host, not arrive unnoticed inside an unrelated
    /// change. A failure of the guard below is a finding about the code, never a reason to add
    /// an entry here.
    /// </remarks>
    private static readonly string[] HostAccessPermitted =
    [
        ManifestSourceRoot + "/Loading/DirectoryManifestSource.cs",
        ManifestSourceRoot + "/Sealing/ManifestArchive.cs",
        ManifestSourceRoot + "/Sealing/ManifestSealer.cs",
    ];

    /// <summary>
    /// Entry points into the filesystem, the environment, the network and other processes.
    /// </summary>
    private static readonly string[] HostAccessTokens =
    [
        "File.",
        "Directory.",
        "FileStream",
        "StreamReader",
        "StreamWriter",
        "Environment.",
        "HttpClient",
        "HttpRequestMessage",
        "WebRequest",
        "System.Net",
        "Socket",
        "Process.",
        "DriveInfo",
    ];

    [Fact]
    public void Runtime_code_reaches_the_host_only_where_that_is_the_component_s_purpose()
    {
        var offenders = new List<string>();

        foreach (var file in RuntimeSources())
        {
            var relative = EngineRepository.Relative(file);

            if (HostAccessPermitted.Contains(relative, StringComparer.Ordinal))
            {
                continue;
            }

            var text = File.ReadAllText(file);

            offenders.AddRange(
                HostAccessTokens
                    .Where(token => text.Contains(token, StringComparison.Ordinal))
                    .Select(token => $"{relative} -> {token}"));
        }

        Assert.True(
            offenders.Count == 0,
            "Loading, validating and deriving from a manifest must not reach the host. "
                + "A component that needs to may be added to HostAccessPermitted with a stated reason. "
                + $"Unexpected host access: {string.Join("; ", offenders)}");
    }

    /// <summary>
    /// The scan reaches every production file, so narrowing it back to one namespace fails
    /// here instead of quietly reducing what the guards above prove.
    /// </summary>
    /// <remarks>
    /// A guard that scans nothing passes. That is the failure mode this test exists for: the
    /// host-access and provenance guards were originally scoped to <c>Manifest/</c>, and when
    /// request compilation arrived beside it they kept passing while covering none of it.
    /// Asserting the scan is complete, and that it genuinely reaches outside the namespace it
    /// was born in, is what makes the other assertions worth reading.
    /// </remarks>
    [Fact]
    public void The_scan_covers_every_production_source_file()
    {
        var scanned = RuntimeSources().Select(EngineRepository.Relative).ToList();
        var produced = EngineRepository.ProductionSources().Select(EngineRepository.Relative).ToList();

        Assert.Equal(produced, scanned);

        var outsideManifest = scanned
            .Where(path => !path.StartsWith(ManifestSourceRoot + "/", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            outsideManifest.Count > 0,
            "The boundary guards are meant to cover the whole library, not the namespace they were "
                + "written for. Nothing outside "
                + ManifestSourceRoot
                + " was scanned, so either the source tree collapsed back to one namespace or the "
                + "scan root was narrowed and these guards stopped proving what they claim.");
    }

    /// <summary>
    /// A stale exemption is worse than no exemption: it silently widens the permitted set
    /// the moment a file is renamed.
    /// </summary>
    [Fact]
    public void Every_host_access_exemption_names_a_file_that_exists()
    {
        var missing = HostAccessPermitted
            .Where(entry => !EngineRepository.Exists(entry))
            .ToList();

        Assert.True(missing.Count == 0, $"Stale host-access exemption: {string.Join(", ", missing)}");
    }

    /// <summary>
    /// Provenance is Studio-only identity travelling inside a public artifact. Engine carries
    /// it so an export round-trips, and reads nothing from it.
    /// </summary>
    /// <remarks>
    /// The moment any Engine behaviour depends on a provenance member, the manifest stops
    /// being sufficient on its own: a hand-authored manifest that omits the member behaves
    /// differently from a Studio export that includes it, and the Studio identity has become
    /// a required runtime key through the back door.
    /// </remarks>
    [Fact]
    public void Provenance_is_carried_but_never_inspected()
    {
        // Member access on the model property. A whole-object read - passing it along or
        // cloning it - is how the loader and reader are meant to treat it.
        var pattern = new Regex(
            @"\.Provenance\s*(\[|\?\.|\.|!)",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));

        var offenders = new List<string>();

        foreach (var file in RuntimeSources())
        {
            offenders.AddRange(
                pattern
                    .Matches(File.ReadAllText(file))
                    .Select(match => $"{EngineRepository.Relative(file)}: {match.Value.Trim()}"));
        }

        Assert.True(
            offenders.Count == 0,
            "Engine must not read a member of 'provenance'; it is opaque Studio state. "
                + $"Offending sites: {string.Join("; ", offenders)}");
    }

    /// <summary>
    /// One component turns a reference into a target node, so the bounds that make reference
    /// resolution safe cannot be bypassed by a second, unbounded walk.
    /// </summary>
    [Fact]
    public void Only_the_reference_resolver_resolves_a_json_pointer()
    {
        var offenders = new List<string>();

        foreach (var file in EngineRepository.ProductionSources())
        {
            var relative = EngineRepository.Relative(file);

            if (string.Equals(relative, Resolver, StringComparison.Ordinal)
                || string.Equals(relative, Pointer, StringComparison.Ordinal))
            {
                continue;
            }

            if (File.ReadAllText(file).Contains("JsonPointer.TryResolve", StringComparison.Ordinal))
            {
                offenders.Add(relative);
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Pointer resolution must go through SchemaReferenceResolver so every resolution is "
                + $"charged against the declared schema bounds. Offending files: {string.Join(", ", offenders)}");
    }

    /// <summary>
    /// Engine must never interpret a source API description. It must, deliberately, resolve a
    /// manifest-local reference. These are different rules and the first must not be allowed to
    /// swallow the second.
    /// </summary>
    /// <remarks>
    /// Reference resolution is the reason a manifest is a fraction of the size of the
    /// intermediate model it is projected from, and the reason a section is small enough to
    /// edit by hand. Banning it in the name of "no source-format parsing" would silently
    /// reintroduce the fully inlined document this format exists to avoid, so the distinction
    /// is asserted rather than left to a reviewer's memory.
    /// </remarks>
    [Fact]
    public void Manifest_local_references_are_supported_and_are_not_source_format_parsing()
    {
        Assert.True(EngineRepository.Exists(Resolver), $"The manifest reference resolver is missing from {Resolver}.");
        Assert.True(EngineRepository.Exists(Pointer), $"The JSON Pointer implementation is missing from {Pointer}.");
        Assert.True(
            EngineRepository.Exists("tests/fixtures/manifests/refs/manifest.json"),
            "The fixture that exercises manifest-local references is missing, so its support is unproven.");

        var resolverText = File.ReadAllText(EngineRepository.Absolute(Resolver));
        var pointerText = File.ReadAllText(EngineRepository.Absolute(Pointer));

        var widened = EngineBoundaryTests.ForbiddenPackages
            .Concat(EngineBoundaryTests.ForbiddenNamespaces)
            .Where(token => resolverText.Contains(token, StringComparison.Ordinal)
                || pointerText.Contains(token, StringComparison.Ordinal))
            .ToList();

        Assert.True(
            widened.Count == 0,
            "A boundary rule now names something manifest-local reference resolution depends on. "
                + "The prohibition is on interpreting source API description formats, not on resolving a "
                + $"fragment-only pointer inside one section document. Conflicting entries: {string.Join(", ", widened)}");
    }

    /// <summary>
    /// Every production source file of the Engine library.
    /// </summary>
    /// <remarks>
    /// The prefix filter is redundant while <c>src/</c> holds one project, and it is kept
    /// anyway so that adding a second project is a decision about what these guards cover
    /// rather than an accident that silently extends them.
    /// </remarks>
    private static IEnumerable<string> RuntimeSources()
        => EngineRepository
            .ProductionSources()
            .Where(path => EngineRepository
                .Relative(path)
                .StartsWith(EngineSourceRoot + "/", StringComparison.Ordinal));
}
