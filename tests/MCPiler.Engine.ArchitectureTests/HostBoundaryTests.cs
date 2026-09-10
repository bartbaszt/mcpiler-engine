using System.Text.RegularExpressions;

using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Guards the deployable on the terms ADR-0058 §5 sets for it: it may reach the host
/// freely, and it may hold no decision the product depends on.
/// </summary>
/// <remarks>
/// <para>
/// The library's rule is the opposite shape - host access confined to three named adapter
/// directories - and extending that rule to a whole project would have turned "host access
/// is confined to a named handful" into "…and also everywhere inside the executable",
/// which is a description rather than a rule. So the deployable gets a different rule, and
/// the two together still say something checkable: every capability is somewhere named,
/// and every decision is somewhere guarded.
/// </para>
/// <para>
/// What makes this enforceable is the shape of the seam. The library computes what to
/// serve into protocol-neutral values; this project converts those values into whatever
/// the transport wants and carries them to a client. A conversion holds no decision. The
/// moment it does - a branch on a manifest value, a default supplied here because the
/// library did not supply one - the split has been crossed, and it has been crossed in the
/// one project no library guard looks at.
/// </para>
/// </remarks>
public sealed class HostBoundaryTests
{
    private const string HostSourceRoot = "src/MCPiler.Engine.Host";

    /// <summary>
    /// Namespaces that carry product meaning: what a Manifest says, whether it is valid,
    /// what is derived from it, how it is searched, and how its programs are run.
    /// </summary>
    /// <remarks>
    /// The root <c>MCPiler.Engine.Manifest</c> namespace is deliberately absent. It holds
    /// the supported format range, which the deployable must be able to state about itself
    /// before it has read anything at all. Reporting a constant the library declares is the
    /// permitted direction; reaching into the model, the readers, the validators, the
    /// derivers or the ranker is not.
    /// </remarks>
    private static readonly string[] ProductNamespaces =
    [
        "MCPiler.Engine.Manifest.Model",
        "MCPiler.Engine.Manifest.Validation",
        "MCPiler.Engine.Manifest.Derivation",
        "MCPiler.Engine.Manifest.Loading",
        "MCPiler.Engine.Manifest.Canonical",
        "MCPiler.Engine.Manifest.Sealing",
        "MCPiler.Engine.Manifest.Search",
        "MCPiler.Engine.Execution",
        "MCPiler.Engine.Transform",
        "MCPiler.Engine.Compound",
        "MCPiler.Engine.Search",
    ];

    /// <summary>
    /// Capabilities Engine does not need, forbidden in the deployable as well as the library.
    /// </summary>
    /// <remarks>
    /// The deployable's exemption is from the rule about <em>where</em> host access may
    /// happen, not a grant of every host API. Engine starts no process and inspects no
    /// volume, and a second HTTP stack would be a second set of policy defaults - a connect
    /// callback and a redirect rule configured in one place and silently absent in the
    /// other.
    /// </remarks>
    private static readonly string[] AlwaysForbiddenTokens =
    [
        "WebRequest",
        "Process.",
        "DriveInfo",
    ];

    [Fact]
    public void The_deployable_contains_no_product_decision()
    {
        var offenders = new List<string>();

        foreach (var file in HostSources())
        {
            var relative = EngineRepository.Relative(file);
            var text = File.ReadAllText(file);

            offenders.AddRange(
                ProductNamespaces
                    .Where(space => text.Contains(space, StringComparison.Ordinal))
                    .Select(space => $"{relative} -> {space}"));
        }

        Assert.True(
            offenders.Count == 0,
            "The deployable carries a Manifest to the library and the library's answer to a client. "
                + "What a Manifest declares, whether it is valid, what is derived from it and how a "
                + "program is evaluated are decisions, and decisions live in the library where the "
                + $"boundary guards can see them. Offending references: {string.Join("; ", offenders)}");
    }

    /// <summary>
    /// The deployable may reach the host, and still not reach a capability Engine has no
    /// use for.
    /// </summary>
    [Fact]
    public void The_deployable_reaches_no_capability_the_engine_does_not_need()
    {
        var offenders = new List<string>();

        foreach (var file in HostSources())
        {
            var relative = EngineRepository.Relative(file);
            var text = File.ReadAllText(file);

            offenders.AddRange(
                AlwaysForbiddenTokens
                    .Where(token => text.Contains(token, StringComparison.Ordinal))
                    .Select(token => $"{relative} -> {token}"));
        }

        Assert.True(
            offenders.Count == 0,
            "Being the deployable is permission to open a socket and read a file, not permission to "
                + "start a process, inspect a volume, or stand up a second HTTP stack. "
                + $"Offending references: {string.Join("; ", offenders)}");
    }

    /// <summary>
    /// The deployable does not read a member of <c>provenance</c> either.
    /// </summary>
    /// <remarks>
    /// The library is already forbidden from doing so, and the rule would be worth nothing
    /// if the executable that hands the library its Manifest could read the same member on
    /// the way past. Provenance is Studio identity travelling inside a portable artifact; a
    /// hand-authored Manifest that omits it must behave identically.
    /// </remarks>
    [Fact]
    public void Provenance_is_not_inspected_by_the_deployable_either()
    {
        var pattern = new Regex(
            @"\.Provenance\s*(\[|\?\.|\.|!)",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(5));

        var offenders = new List<string>();

        foreach (var file in HostSources())
        {
            offenders.AddRange(
                pattern
                    .Matches(File.ReadAllText(file))
                    .Select(match => $"{EngineRepository.Relative(file)}: {match.Value.Trim()}"));
        }

        Assert.True(
            offenders.Count == 0,
            "Provenance is opaque Studio state on both sides of the library boundary. "
                + $"Offending sites: {string.Join("; ", offenders)}");
    }

    /// <summary>
    /// The scan reaches the deployable and is not passing because it found nothing.
    /// </summary>
    [Fact]
    public void The_scan_reaches_the_deployable()
    {
        var scanned = HostSources().Select(EngineRepository.Relative).ToList();

        Assert.True(
            scanned.Count > 0,
            $"No production source was found under {HostSourceRoot}, so every assertion in this "
                + "class passed by looking at nothing. Either the project moved or the root above "
                + "is stale.");

        Assert.True(
            EngineRepository.Exists(HostSourceRoot + "/MCPiler.Engine.Host.csproj"),
            "The deployable's project file is missing, so the guard is describing a project that "
                + "does not exist.");
    }

    /// <summary>
    /// The containment assertion is checked against the mistakes it exists to catch.
    /// </summary>
    /// <remarks>
    /// A guard over a set that nothing would ever contain passes forever and proves nothing.
    /// Every driver below is a line somebody would plausibly write in a host: resolving a
    /// tool from the model, validating on the way in, ranking before answering, evaluating a
    /// program where the response is already in hand.
    /// </remarks>
    [Theory]
    [InlineData("using MCPiler.Engine.Manifest.Model;")]
    [InlineData("var operation = document.Operations.Operation(key);")]
    [InlineData("using MCPiler.Engine.Manifest.Validation;")]
    [InlineData("using MCPiler.Engine.Manifest.Derivation;")]
    [InlineData("private readonly MCPiler.Engine.Execution.ExecutionService _execution;")]
    [InlineData("using MCPiler.Engine.Transform;")]
    [InlineData("using MCPiler.Engine.Search;")]
    public void The_containment_assertion_catches_a_product_decision_in_the_deployable(string driver)
    {
        var caught = ProductNamespaces.Any(space => driver.Contains(space, StringComparison.Ordinal))
            || driver.Contains("document.Operations", StringComparison.Ordinal);

        Assert.True(
            caught,
            "A file with this line in the deployable would hold a product decision and the "
                + $"containment assertion would not notice: {driver}");
    }

    /// <summary>
    /// Naming the library's own namespace is how the deployable does its job, so the rule
    /// must not forbid it.
    /// </summary>
    /// <remarks>
    /// A containment rule that also refused the seam would be satisfied only by a host that
    /// cannot call the library, which is not a boundary, it is a disconnection. These are
    /// the lines the deployable is supposed to contain.
    /// </remarks>
    [Theory]
    [InlineData("using MCPiler.Engine.Manifest;")]
    [InlineData("Console.Out.WriteLine(ManifestFormatSupport.SupportedRange);")]
    [InlineData("var listener = WebApplication.CreateBuilder(args);")]
    [InlineData("await File.ReadAllBytesAsync(path, cancellationToken);")]
    public void The_containment_assertion_permits_the_seam_and_the_host(string driver)
    {
        var caught = ProductNamespaces.Any(space => driver.Contains(space, StringComparison.Ordinal))
            || AlwaysForbiddenTokens.Any(token => driver.Contains(token, StringComparison.Ordinal));

        Assert.False(
            caught,
            "The deployable is refused a line it needs in order to be a deployable at all: "
                + driver);
    }

    private static IEnumerable<string> HostSources()
        => EngineRepository
            .ProductionSources()
            .Where(path => EngineRepository
                .Relative(path)
                .StartsWith(HostSourceRoot + "/", StringComparison.Ordinal));
}
