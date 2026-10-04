using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Guards the rule that exactly one component decides whether a deployment bounds its protected
/// request-derived resource identities.
/// </summary>
/// <remarks>
/// <para>
/// The same decision was made three times. The file-mode startup path, the managed candidate path
/// and the web host each carried their own copy of the boolean test and their own copy of the
/// message, and the copies had already drifted: the web host's message omitted the settings the
/// other two named. Three copies of one refusal is three places an operator can be told to change
/// something that is not what is wrong.
/// </para>
/// <para>
/// It is also the rule the two shipped deployment profiles silently violate. Neither compose file
/// supplies an allowed host, so a protected mount refuses to start with a message that named only a
/// missing setting and never the surface that still wanted it. Collapsing the copies is what makes
/// that surface nameable at all.
/// </para>
/// <para>
/// The signal is deliberately narrow and positive: a file that carries the refusal code, the
/// protected-mount test and the allowed-host test together is deciding this rule. A file that
/// inspects <c>AllowedHosts</c> for an unrelated reason - the configuration reader normalizes and
/// rejects wildcard entries, and that is correct where it stands - must not be reported.
/// </para>
/// </remarks>
public sealed class ProtectedResourceAuthoritySeamTests
{
    /// <summary>The one file permitted to decide whether the deployment bounds request-derived identities.</summary>
    private const string Validator =
        "src/MCPiler.Engine.Host/Hosting/ProtectedResourceAuthorityValidation.cs";

    /// <summary>
    /// Production sites that decide startup or activation and therefore must consult the validator.
    /// </summary>
    /// <remarks>
    /// Every listed file must resolve to the shared decision. A site that stopped consulting it
    /// would be a fourth copy, and a new startup path is added here so the set stays reviewable
    /// rather than discovered after a deployment refuses for no stated reason.
    /// </remarks>
    private static readonly string[] Consumers =
    [
        "src/MCPiler.Engine.Host/Cli/HostCommands.cs",
        "src/MCPiler.Engine.Host/Managed/ManagedSyncWorker.cs",
        "src/MCPiler.Engine.Host/Hosting/EngineWebHost.cs",
    ];

    /// <summary>
    /// Every part of the decision that must appear together before a file counts as owning it.
    /// </summary>
    /// <remarks>
    /// The refusal code is included deliberately. It is the one string an operator or a monitor
    /// matches on, so a site that raises it has taken responsibility for the whole decision; a file
    /// that reasons about allowed hosts for another reason raises no such code.
    /// </remarks>
    private static readonly (string Token, string Of)[] DecisionParts =
    [
        ("RequiresAuthorization", "the protected-mount test"),
        ("AllowedHosts", "the allowed-host boundary"),
        ("auth/allowed-host-missing", "the refusal code"),
    ];

    [Fact]
    public void Only_the_shared_validator_decides_the_listener_authority_requirement()
    {
        var offenders = new List<string>();

        foreach (string file in ProductionSources())
        {
            string relative = Relative(file);

            if (string.Equals(relative, Validator, StringComparison.Ordinal))
            {
                continue;
            }

            string source = File.ReadAllText(file);

            if (DecisionParts.All(part => source.Contains(part.Token, StringComparison.Ordinal)))
            {
                offenders.Add(relative);
            }
        }

        Assert.True(
            offenders.Count == 0,
            "The requirement that a deployment bound its protected request-derived resource "
                + "identities must be decided by ProtectedResourceAuthorityValidation, so the three "
                + "startup paths cannot drift into three different diagnostics. Offending sites: "
                + string.Join("; ", offenders));
    }

    [Fact]
    public void The_shared_validator_exists_where_the_guard_expects_it()
    {
        Assert.True(
            EngineRepository.Exists(Validator),
            $"The listener-authority validator is missing from {Validator}, so this guard would "
                + "silently pass.");
    }

    [Fact]
    public void The_shared_validator_states_every_part_the_guard_names()
    {
        string source = File.ReadAllText(EngineRepository.Absolute(Validator));

        foreach ((string token, string of) in DecisionParts)
        {
            Assert.True(
                source.Contains(token, StringComparison.Ordinal),
                $"The validator states no {of}.");
        }
    }

    /// <summary>
    /// The permitted file has to actually own the decision. Otherwise the guard permits one file to
    /// hold it and a different file to hold a second copy, because the copy would then be the only
    /// file holding all the parts.
    /// </summary>
    [Fact]
    public void The_shared_validator_names_the_surfaces_it_refuses()
    {
        string source = File.ReadAllText(EngineRepository.Absolute(Validator));

        Assert.True(
            source.Contains("MountedSurface", StringComparison.Ordinal)
                && source.Contains("Prefix", StringComparison.Ordinal)
                && source.Contains("Slug", StringComparison.Ordinal),
            "The validator does not enumerate the unbound surfaces, so the refusal it produces cannot "
                + "name the surface an operator must bind - which is the whole reason the copies were "
                + "collapsed.");
    }

    [Fact]
    public void Every_consumer_resolves_to_the_shared_validator()
    {
        var detached = Consumers
            .Where(relative => !File.ReadAllText(EngineRepository.Absolute(relative))
                .Contains("ProtectedResourceAuthorityValidation.", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            detached.Count == 0,
            "These sites decide startup or activation without the shared validator, so they are copies "
                + $"by another name: {string.Join(", ", detached)}");
    }

    [Fact]
    public void Every_consumer_exists()
    {
        var missing = Consumers
            .Where(relative => !EngineRepository.Exists(relative))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"Stale listener-authority consumer: {string.Join(", ", missing)}. A renamed or deleted "
                + "startup path would otherwise leave this guard reporting agreement with a file that "
                + "is gone.");
    }

    /// <summary>
    /// The scan has to reach the whole product tree. A guard scoped to the namespace it was written
    /// for stops guarding the moment a new namespace arrives, then reports green while the gap it
    /// was meant to close is open.
    /// </summary>
    [Fact]
    public void The_scan_covers_every_production_source_file()
    {
        int scanned = ProductionSources().Count();

        Assert.True(
            scanned > 100,
            $"The listener-authority guard scanned {scanned} production files. A scan that reaches "
                + "almost nothing passes every assertion above while proving nothing.");
    }

    /// <summary>
    /// Proves the guard is not vacuous: this shape is a copy of the decision and must be caught.
    /// </summary>
    [Fact]
    public void The_guard_catches_a_copy_of_the_decision()
    {
        const string Copy =
            "if (binding.Authorization is not null\n"
            + "    && mounts.Mounts.Any(m => m.RequiresAuthorization() && m.Surfaces.Any(s => !resources.ContainsKey(s)))\n"
            + "    && binding.AllowedHosts.Count == 0)\n"
            + "{\n"
            + "    throw new InvalidOperationException(\"auth/allowed-host-missing\");\n"
            + "}";

        Assert.True(
            DecisionParts.All(part => Copy.Contains(part.Token, StringComparison.Ordinal)),
            "The guard does not recognise this shape of decision copy.");
    }

    /// <summary>
    /// Proves the guard stays quiet about the validator it is most likely to catch by accident. The
    /// configuration reader inspects allowed hosts for its own reason - it normalizes them and
    /// refuses wildcard entries - and raises no refusal code, so it is not a copy of this decision.
    /// </summary>
    [Fact]
    public void The_guard_does_not_flag_allowed_host_normalization()
    {
        const string Normalization =
            "foreach (string entry in allowedHosts)\n"
            + "{\n"
            + "    if (entry is \"*\" or \"+\" || IPAddress.TryParse(entry, out var any) && any.Equals(IPAddress.Any))\n"
            + "    {\n"
            + "        refused = \"A wildcard authority is not a concrete allowed host.\";\n"
            + "    }\n"
            + "}";

        Assert.False(
            DecisionParts.All(part => Normalization.Contains(part.Token, StringComparison.Ordinal)),
            "The guard would flag allowed-host normalization, which is a different concern.");
    }

    private static IEnumerable<string> ProductionSources() => EngineRepository.ProductionSources();

    private static string Relative(string path) => EngineRepository.Relative(path);
}