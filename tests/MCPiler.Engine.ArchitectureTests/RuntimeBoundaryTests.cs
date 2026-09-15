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
    /// <summary>
    /// Every production project. The scan starts here so a new project is covered by
    /// arriving, not by somebody remembering to widen a constant.
    /// </summary>
    /// <remarks>
    /// This used to be <c>src/MCPiler.Engine</c>. A second project under <c>src/</c> was
    /// therefore invisible to every guard in this file, and invisible silently: the
    /// existing assertions would all have stayed green while covering none of it. That is
    /// the failure mode <c>LESSONS.md</c> names - a guard scoped to the namespace it was
    /// written for stops guarding without saying so. The partition assertion below is what
    /// makes a third project a decision rather than an omission.
    /// </remarks>
    private const string SourceRoot = "src";

    /// <summary>The library. The host-access rules below are rules about this project.</summary>
    private const string EngineSourceRoot = SourceRoot + "/MCPiler.Engine";

    /// <summary>The deployable. Governed by <c>HostBoundaryTests</c>, on different terms.</summary>
    private const string HostSourceRoot = SourceRoot + "/MCPiler.Engine.Host";

    private const string ManifestSourceRoot = EngineSourceRoot + "/Manifest";

    private const string Resolver = ManifestSourceRoot + "/Loading/SchemaReferenceResolver.cs";

    private const string Pointer = ManifestSourceRoot + "/Loading/JsonPointer.cs";

    private const string ExecutionSourceRoot = EngineSourceRoot + "/Execution";

    /// <summary>
    /// Directories whose declared purpose is to touch the host, plus the three manifest files
    /// that predate them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per ADR-0057 the exemption names directories rather than files. A per-file list grows by
    /// one every time something legitimately needs a socket or a secret, each addition is
    /// individually reasonable, and after a few stages the rule asserts that host access is
    /// confined to wherever host access happens to be - which nobody ever decided. Naming a
    /// directory means adding a capability is a decision about structure: a new file inside an
    /// adapter is ordinary, and a new adapter directory needs its own record.
    /// </para>
    /// <para>
    /// The three manifest entries stay files. They are not an adapter surface, they are two
    /// components that existed before the boundary was drawn this way, and widening them to
    /// <c>Manifest/Loading/</c> and <c>Manifest/Sealing/</c> would exempt readers that must
    /// stay covered.
    /// </para>
    /// <para>
    /// A failure of the guard below is a finding about the code, never a reason to add an entry
    /// here.
    /// </para>
    /// </remarks>
    private static readonly string[] HostAccessPermitted =
    [
        ManifestSourceRoot + "/Loading/DirectoryManifestSource.cs",
        ManifestSourceRoot + "/Sealing/ManifestArchive.cs",
        ManifestSourceRoot + "/Sealing/ManifestSealer.cs",
        ExecutionSourceRoot + "/Outbound/",
        ExecutionSourceRoot + "/Secrets/",
        ExecutionSourceRoot + "/Files/",
    ];

    /// <summary>The exempted directories, which carry the additional containment rule.</summary>
    private static readonly string[] HostAdapterDirectories =
        [.. HostAccessPermitted.Where(entry => entry.EndsWith('/'))];

    /// <summary>
    /// Entry points into the filesystem, the environment and the network.
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
        "System.Net",
        "Socket",
    ];

    /// <summary>
    /// Capabilities Engine does not need, forbidden everywhere including the adapters.
    /// </summary>
    /// <remarks>
    /// Engine starts no process and inspects no volume, and it sends over the modern client, so
    /// a second HTTP stack would be a second set of policy defaults - a redirect rule and a
    /// connect callback configured in one place and silently absent in the other. An exemption
    /// exists to let a named component do the thing it is named for, not to make every host API
    /// available inside it.
    /// </remarks>
    private static readonly string[] AlwaysForbiddenTokens =
    [
        "WebRequest",
        "Process.",
        "DriveInfo",
    ];

    /// <summary>
    /// Namespaces that carry product meaning: what a manifest says, whether it is valid, what
    /// is derived from it and how it is searched.
    /// </summary>
    private static readonly string[] ProductNamespaces =
    [
        "MCPiler.Engine.Manifest.Model",
        "MCPiler.Engine.Manifest.Validation",
        "MCPiler.Engine.Manifest.Derivation",
        "MCPiler.Engine.Manifest.Search",
        "MCPiler.Engine.Manifest.Loading",
        "MCPiler.Engine.Manifest.Canonical",
        "MCPiler.Engine.Manifest.Sealing",
        "MCPiler.Engine.Search.Hybrid",
        "MCPiler.Engine.Mcp",
        "MCPiler.Engine.Transform",
        "MCPiler.Engine.Compound",

        // Authentication decides how a request proves who it is: which credential is
        // revealed, to which origin, and how a signature is constructed. An adapter
        // directory holds one host capability and no such decision, so referencing this
        // namespace from inside Outbound/, Secrets/ or Files/ inverts the dependency the
        // sign-request delegate exists to keep one-directional.
        "MCPiler.Engine.Authentication",
    ];

    [Fact]
    public void Runtime_code_reaches_the_host_only_where_that_is_the_component_s_purpose()
    {
        var offenders = new List<string>();

        foreach (var file in LibrarySources())
        {
            var relative = EngineRepository.Relative(file);
            var text = File.ReadAllText(file);

            offenders.AddRange(
                AlwaysForbiddenTokens
                    .Where(token => text.Contains(token, StringComparison.Ordinal))
                    .Select(token => $"{relative} -> {token} (forbidden everywhere)"));

            if (IsExempt(relative))
            {
                continue;
            }

            offenders.AddRange(
                HostAccessTokens
                    .Where(token => text.Contains(token, StringComparison.Ordinal))
                    .Select(token => $"{relative} -> {token}"));
        }

        Assert.True(
            offenders.Count == 0,
            "Loading a manifest, validating it, deriving from it and deciding what to send must not "
                + "reach the host. A component that needs to belongs inside an adapter directory named "
                + "in ADR-0057, and a capability listed as always forbidden belongs nowhere. "
                + $"Unexpected host access: {string.Join("; ", offenders)}");
    }

    /// <summary>
    /// An adapter directory holds the capability it is named for and no product decision.
    /// </summary>
    /// <remarks>
    /// Without this, an exemption granted to reach a socket doubles as the one place where
    /// product logic escapes the rule that would otherwise cover it - and it would escape
    /// invisibly, because the host-access guard is satisfied by the exemption and no other
    /// guard looks inside. The adapters take numbers, names and bytes; what a manifest declared
    /// is decided in <c>Execution/</c>, which the guard above still covers in full.
    /// </remarks>
    [Fact]
    public void An_adapter_directory_contains_no_manifest_knowledge()
    {
        var offenders = new List<string>();

        foreach (var file in RuntimeSources())
        {
            var relative = EngineRepository.Relative(file);

            if (!HostAdapterDirectories.Any(directory => relative.StartsWith(directory, StringComparison.Ordinal)))
            {
                continue;
            }

            var text = File.ReadAllText(file);

            offenders.AddRange(
                ProductNamespaces
                    .Where(space => text.Contains(space, StringComparison.Ordinal))
                    .Select(space => $"{relative} -> {space}"));
        }

        Assert.True(
            offenders.Count == 0,
            "An adapter directory is exempted from the host-access rule because it holds one "
                + "capability, not because it is unsupervised. Manifest model, validation, derivation "
                + "and search belong in Execution/ and the rest of the library, where the host-access "
                + $"guard still applies. Offending references: {string.Join("; ", offenders)}");
    }

    /// <summary>
    /// The containment assertion is not vacuous: the namespaces it forbids are ones the
    /// adapters would plausibly reach for, and a synthetic file inside an adapter directory is
    /// caught.
    /// </summary>
    /// <remarks>
    /// A guard over a set that nothing would ever contain passes forever and proves nothing.
    /// The drivers below are the shapes the adapters were actually written with before this
    /// rule existed - a client factory keyed on the manifest's execution limits, a store
    /// configured from the manifest's file policy, a resolver reading the credentials section -
    /// so the assertion is checked against the mistake it is meant to catch.
    /// </remarks>
    [Theory]
    [InlineData("using MCPiler.Engine.Manifest.Model;")]
    [InlineData("public HttpClient Client(MCPiler.Engine.Manifest.Model.ExecutionLimits limits)")]
    [InlineData("// see MCPiler.Engine.Manifest.Validation.ManifestValidator")]
    [InlineData("private readonly MCPiler.Engine.Manifest.Search.LexicalRanker _ranker;")]
    [InlineData("using MCPiler.Engine.Manifest.Derivation;")]
    [InlineData("var findings = MCPiler.Engine.Transform.TransformValidation.Validate(program, ceiling, files);")]
    [InlineData("using MCPiler.Engine.Compound;")]
    [InlineData("var schema = MCPiler.Engine.Mcp.OutputSchemaEnvelope.Shape(authored);")]
    [InlineData("var signing = MCPiler.Engine.Authentication.Signing.ResolvedRequestSigning.Create(profile);")]
    public void The_containment_assertion_catches_manifest_knowledge_inside_an_adapter(string driver)
    {
        var caught = ProductNamespaces.Any(space => driver.Contains(space, StringComparison.Ordinal));

        Assert.True(
            caught,
            "A file with this line inside an adapter directory would carry manifest knowledge and "
                + $"the containment assertion would not notice: {driver}");
    }

    /// <summary>
    /// The new authentication namespace is scanned by the host-access rule like every other
    /// library namespace, so its host-freedom is a guard rather than a claim.
    /// </summary>
    /// <remarks>
    /// A guard scoped to the subtree it was written for goes green forever when the next
    /// namespace arrives, which is the failure mode <c>LESSONS.md</c> names twice. The
    /// authentication runtime is where a naive port would reach for <c>HttpClient</c> and
    /// <c>Environment</c>, because the Platform implementation it replaces does exactly that.
    /// These assertions make the port's host-freedom explicit at the place a future change
    /// would break it.
    /// </remarks>
    [Fact]
    public void The_authentication_runtime_is_scanned_and_stays_host_free()
    {
        const string AuthenticationSourceRoot = EngineSourceRoot + "/Authentication";

        var scanned = RuntimeSources()
            .Select(EngineRepository.Relative)
            .Where(path => path.StartsWith(AuthenticationSourceRoot + "/", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            scanned.Count > 0,
            $"No production source was found under {AuthenticationSourceRoot}, so the "
                + "host-access rule is asserting nothing about the authentication runtime.");

        var exempt = scanned.Where(IsExempt).ToList();

        Assert.True(
            exempt.Count == 0,
            "The authentication runtime reaches secrets and the network through the transport "
                + "port and resolved credentials, never through an adapter exemption. These files "
                + $"were exempted instead of kept host-free: {string.Join(", ", exempt)}");
    }

    /// <summary>
    /// A file that sits beside an adapter directory rather than inside it is still covered.
    /// </summary>
    /// <remarks>
    /// The exemption is a prefix match, and a prefix that ends at a directory name rather than
    /// at a separator would exempt a sibling whose name merely starts the same way -
    /// <c>Execution/FilesExtra.cs</c> against an exemption for <c>Execution/Files</c>. The
    /// separator is why every directory entry ends in one; this asserts it stays that way.
    /// </remarks>
    [Fact]
    public void An_exemption_covers_a_directory_and_not_a_name_that_merely_starts_the_same_way()
    {
        foreach (var directory in HostAdapterDirectories)
        {
            var sibling = directory.TrimEnd('/') + "Extra.cs";

            Assert.False(
                IsExempt(sibling),
                $"The exemption '{directory}' also covers '{sibling}', which is a different component.");
        }
    }

    /// <summary>Protocol-era literals belong in the MCP adapter, never in the Manifest contract.</summary>
    [Fact]
    public void Manifest_code_contains_no_protocol_revision_literal()
    {
        var revision = new Regex(
            @"\b20\d{2}-\d{2}-\d{2}\b",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));
        var offenders = LibrarySources()
            .Where(path => EngineRepository
                .Relative(path)
                .StartsWith(ManifestSourceRoot + "/", StringComparison.Ordinal))
            .SelectMany(path => revision
                .Matches(File.ReadAllText(path))
                .Select(match => $"{EngineRepository.Relative(path)} -> {match.Value}"))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A protocol revision in Manifest model, loading, validation or derivation would make "
                + "the persisted contract decide a request-era behavior. Keep revisions in Mcp/. "
                + $"Offending literals: {string.Join("; ", offenders)}");
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

        var outsideLibrary = scanned
            .Where(path => !path.StartsWith(EngineSourceRoot + "/", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            outsideLibrary.Count > 0,
            "The scan root is "
                + SourceRoot
                + ", not one project. Nothing outside "
                + EngineSourceRoot
                + " was scanned, which is exactly what the previous scan root did silently when the "
                + "host project arrived beside the library.");
    }

    /// <summary>
    /// Every production project is claimed by a boundary guard, and a third one fails here
    /// rather than shipping ungoverned.
    /// </summary>
    /// <remarks>
    /// The two projects are governed on different terms. The library reaches the host only
    /// through named adapter directories; the deployable reaches the host freely and holds no
    /// product decision instead. Both are real rules, and neither is the default, so a new
    /// project belongs to neither until somebody says which. Without this assertion the
    /// default is "governed by nothing" and it is reached by adding a directory.
    /// </remarks>
    [Fact]
    public void Every_production_project_is_claimed_by_a_boundary_guard()
    {
        string[] governed = [EngineSourceRoot + "/", HostSourceRoot + "/"];

        var unclaimed = RuntimeSources()
            .Select(EngineRepository.Relative)
            .Where(path => !governed.Any(root => path.StartsWith(root, StringComparison.Ordinal)))
            .ToList();

        Assert.True(
            unclaimed.Count == 0,
            "A production source file belongs to no project this guard knows about. Decide which "
                + "boundary rules apply to it and say so here, in RuntimeBoundaryTests for a library "
                + $"and in HostBoundaryTests for a deployable. Unclaimed: {string.Join(", ", unclaimed)}");

        foreach (var root in governed)
        {
            Assert.True(
                RuntimeSources().Any(path => EngineRepository
                    .Relative(path)
                    .StartsWith(root, StringComparison.Ordinal)),
                $"No scanned file lives under '{root}', so the rules written for it are asserted "
                    + "against nothing.");
        }
    }

    /// <summary>
    /// A stale exemption is worse than no exemption: it silently widens the permitted set
    /// the moment a file is renamed or a directory is emptied.
    /// </summary>
    [Fact]
    public void Every_host_access_exemption_names_something_that_exists()
    {
        var missing = HostAccessPermitted
            .Where(entry => entry.EndsWith('/')
                ? !Directory.Exists(EngineRepository.Absolute(entry.TrimEnd('/')))
                : !EngineRepository.Exists(entry))
            .ToList();

        Assert.True(missing.Count == 0, $"Stale host-access exemption: {string.Join(", ", missing)}");
    }

    /// <summary>
    /// The exemption is a named handful, not the tree.
    /// </summary>
    /// <remarks>
    /// Two failures this catches. An exemption that covers no scanned file is stale and its
    /// removal is silent; an exemption set that covers everything scanned turns the host-access
    /// guard into a formality that still reports green. Both are how a boundary stops meaning
    /// anything without anyone deciding it should.
    /// </remarks>
    [Fact]
    public void The_exemption_set_stays_a_named_minority_of_what_is_scanned()
    {
        var scanned = LibrarySources().Select(EngineRepository.Relative).ToList();

        var uncovered = HostAccessPermitted
            .Where(entry => !scanned.Any(path => entry.EndsWith('/')
                ? path.StartsWith(entry, StringComparison.Ordinal)
                : string.Equals(path, entry, StringComparison.Ordinal)))
            .ToList();

        Assert.True(
            uncovered.Count == 0,
            $"An exemption covers no scanned production file: {string.Join(", ", uncovered)}");

        var covered = scanned.Where(IsExempt).ToList();

        Assert.True(
            covered.Count < scanned.Count,
            "Every scanned file is exempt, so the host-access guard asserts nothing.");

        Assert.True(
            covered.Count > 0,
            "No scanned file is exempt, so either the adapters moved or the exemption prefixes no "
                + "longer match the tree and the guard is passing for the wrong reason.");
    }

    /// <summary>Whether <paramref name="relative"/> is inside the exempted set.</summary>
    private static bool IsExempt(string relative)
        => HostAccessPermitted.Any(entry => entry.EndsWith('/')
            ? relative.StartsWith(entry, StringComparison.Ordinal)
            : string.Equals(relative, entry, StringComparison.Ordinal));

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
    /// Only the declared mutable-slot kinds may reach the durable store, and only through the
    /// port's one implementation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The store exists for exactly one kind of material: a value an upstream rotates at runtime
    /// for a slot the Manifest declares mutable. Static credentials, managed provider values,
    /// access tokens, exchange sessions and challenge sessions are all excluded by the accepted
    /// decision, and the exclusion has to be structural rather than a discipline a future
    /// strategy is trusted to keep: a second writer is how a cache becomes a credential database,
    /// and a general credential database is precisely what the accepted decision refuses.
    /// </para>
    /// <para>
    /// The port is also the whole of what authentication logic may know about persistence. A
    /// direct <c>File</c>/<c>Directory</c> write from the OAuth service would bypass the commit
    /// ordering the port encodes - commit before publish - which is correctness for a provider
    /// that retires the presented refresh token.
    /// </para>
    /// </remarks>
    [Fact]
    public void Only_the_mutable_slot_port_writes_durable_runtime_state()
    {
        string[] permitted =
        [
            ExecutionSourceRoot + "/RuntimeState/IMutableSlotStore.cs",
            EngineSourceRoot + "/Authentication/OAuth/OAuthTokenService.cs",
            ExecutionSourceRoot + "/Secrets/RuntimeState/FileMutableSlotStore.cs",
        ];

        string[] writers = ["new MutableSlotRecord", "ReplaceAsync("];

        var offenders = LibrarySources()
            .Select(EngineRepository.Relative)
            .Where(relative => !permitted.Contains(relative, StringComparer.Ordinal))
            .Where(relative =>
            {
                var text = File.ReadAllText(EngineRepository.Absolute(relative));

                return writers.Any(token => text.Contains(token, StringComparison.Ordinal));
            })
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Durable runtime state is written by the mutable-slot port alone, and only the "
                + "declared mutable slot kinds may call it. These files write it outside the "
                + $"declared set: {string.Join(", ", offenders)}");

        // The permitted set is a claim about the code, not a placeholder: each entry must exist
        // and must still be the site that writes.
        Assert.All(permitted, path => Assert.True(
            EngineRepository.Exists(path),
            $"The mutable-slot writer '{path}' does not exist, so the exemption list is stale."));
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
                .StartsWith(SourceRoot + "/", StringComparison.Ordinal));

    /// <summary>
    /// The library only. The host-access rules are rules about the library, and applying
    /// them to the deployable would forbid it from opening the listener it exists to open.
    /// </summary>
    private static IEnumerable<string> LibrarySources()
        => RuntimeSources()
            .Where(path => EngineRepository
                .Relative(path)
                .StartsWith(EngineSourceRoot + "/", StringComparison.Ordinal));
}
