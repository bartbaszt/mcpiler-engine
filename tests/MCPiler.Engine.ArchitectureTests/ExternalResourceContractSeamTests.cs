using System.Text.RegularExpressions;

using Xunit;

namespace MCPiler.Engine.ArchitectureTests;

/// <summary>
/// Guards the rule that exactly one component decides what an external MCP resource identity may be.
/// </summary>
/// <remarks>
/// <para>
/// The contract that governs an external resource lived in more than one place. It was duplicated as
/// a private predicate in the host configuration reader and again in the managed generation loader,
/// and a third site in the CLI validated the surrounding mapping under a name that read like a
/// fourth. The copies happened to agree, so every suite was green, and nothing in either build
/// would have reported a change to one that did not reach the others. A defect they all share is
/// invisible in all of them at once, which is the only kind of defect a per-side assertion chain
/// cannot find.
/// </para>
/// <para>
/// The guard is textual because the failure mode is textual, and it is deliberately built on a
/// positive signal rather than a suggestive one. An earlier draft matched any method whose name
/// mentioned an external resource and any expression that inspected scheme, query, and fragment
/// together. Both were wrong: the CLI site only resolves routes against enabled surfaces and never
/// looks at a URI, and token/session exchange validates the destination origin of a credential
/// exchange, which is a different subject with deliberately stricter rules and must not be forced
/// through this contract. A guard that catches those is a guard that gets deleted, so the signal is
/// now "one file evaluates the whole contract", which is exactly what a copy of the contract is.
/// </para>
/// <para>
/// Platform carries its own copy of the same contract. Agreement between the two is not this
/// guard's business and cannot be: it is proven by replaying one authored corpus that both
/// repositories hold.
/// </para>
/// </remarks>
public sealed class ExternalResourceContractSeamTests
{
    /// <summary>The one file permitted to decide external-resource validity.</summary>
    private const string Contract = "src/MCPiler.Engine/Runtime/Managed/ExternalResourceContract.cs";

    /// <summary>
    /// Production sites that consume the contract.
    /// </summary>
    /// <remarks>
    /// Every listed file must resolve to the shared predicate. A consumer that stopped calling it
    /// would be a copy by another name, and a new consumer is added here so the set stays
    /// reviewable rather than discovered later.
    /// </remarks>
    private static readonly string[] Consumers =
    [
        "src/MCPiler.Engine/Runtime/Managed/ManagedGenerationLoader.cs",
        "src/MCPiler.Engine.Host/Configuration/HostConfiguration.cs",
    ];

    /// <summary>
    /// Every part of the contract that must appear together before a file counts as evaluating it.
    /// </summary>
    /// <remarks>
    /// All four are required. Scheme, query, and fragment alone are shared with other validators;
    /// the length rule is what makes a match this contract rather than a related one.
    /// </remarks>
    private static readonly (string Token, string Of)[] ContractParts =
    [
        ("UriSchemeHttps", "the https scheme comparison"),
        ("Query", "the query rule"),
        ("Fragment", "the fragment rule"),
        ("UserInfo", "the userinfo rule"),
    ];

    [Fact]
    public void Only_the_shared_contract_decides_external_resource_validity()
    {
        var offenders = new List<string>();

        foreach (string file in ProductionSources())
        {
            string relative = Relative(file);

            if (string.Equals(relative, Contract, StringComparison.Ordinal))
            {
                continue;
            }

            string source = File.ReadAllText(file);
            var absent = ContractParts
                .Where(part => !source.Contains(part.Token, StringComparison.Ordinal))
                .Select(part => part.Of)
                .ToList();

            if (absent.Count == 0 && EvaluatesLengthRule(source))
            {
                offenders.Add(relative);
            }
        }

        Assert.True(
            offenders.Count == 0,
            "External-resource validity must be decided by ExternalResourceContract so a producing "
                + "side and a consuming side cannot disagree about one value. Offending sites: "
                + string.Join("; ", offenders));
    }

    [Fact]
    public void The_shared_contract_exists_where_the_guard_expects_it()
    {
        Assert.True(
            EngineRepository.Exists(Contract),
            $"The external-resource contract is missing from {Contract}, so this guard would silently pass.");
    }

    [Fact]
    public void The_shared_contract_evaluates_every_rule_the_guard_names()
    {
        // The permitted file has to actually be the contract. Otherwise this guard permits one file
        // to hold the whole contract and a different file to hold a second copy of it, because the
        // second copy would then be the only one holding all the parts.
        string source = File.ReadAllText(EngineRepository.Absolute(Contract));

        foreach ((string token, string of) in ContractParts)
        {
            Assert.True(source.Contains(token, StringComparison.Ordinal), $"The contract states no {of}.");
        }

        Assert.True(EvaluatesLengthRule(source), "The contract states no length rule.");
    }

    [Fact]
    public void Every_consumer_resolves_to_the_shared_contract()
    {
        var detached = Consumers
            .Where(relative => !File.ReadAllText(EngineRepository.Absolute(relative))
                .Contains("ExternalResourceContract.", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            detached.Count == 0,
            "These sites decide or consume an external resource without the shared contract, so they "
                + $"are copies by another name: {string.Join(", ", detached)}");
    }

    [Fact]
    public void Every_consumer_exists()
    {
        var missing = Consumers
            .Where(relative => !EngineRepository.Exists(relative))
            .ToList();

        Assert.True(
            missing.Count == 0,
            $"Stale external-resource consumer: {string.Join(", ", missing)}. A renamed or deleted "
                + "site would otherwise leave this guard reporting agreement with a file that is gone.");
    }

    /// <summary>
    /// The scan has to reach the whole product tree. A guard scoped to the namespace it was written
    /// for stops guarding the moment a new namespace arrives, and then reports green while the gap
    /// it was meant to close is open.
    /// </summary>
    [Fact]
    public void The_scan_covers_every_production_source_file()
    {
        int scanned = ProductionSources().Count();

        Assert.True(
            scanned > 100,
            $"The external-resource contract guard scanned {scanned} production files. A scan that "
                + "reaches almost nothing passes every assertion above while proving nothing.");
    }

    /// <summary>
    /// Proves the guard is not vacuous: each snippet is a copy of the contract that must be caught.
    /// </summary>
    [Theory]
    [InlineData(
        "bool ok = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)\n"
            + "    && string.IsNullOrEmpty(uri.Query)\n"
            + "    && string.IsNullOrEmpty(uri.Fragment)\n"
            + "    && string.IsNullOrEmpty(uri.UserInfo)\n"
            + "    && resource.Length <= 2048;")]
    [InlineData(
        "// A copy written against a different authority and the same bound.\n"
            + "bool valid = resource.Length <= ExternalResourceContract.MaxLength\n"
            + "    && uri.Scheme == Uri.UriSchemeHttps\n"
            + "    && uri.Query.Length == 0 && uri.Fragment.Length == 0\n"
            + "    && uri.UserInfo.Length == 0;")]
    public void The_guard_catches_a_copy_of_the_contract(string snippet)
        => Assert.True(
            EvaluatesLengthRule(snippet)
                && ContractParts.All(part => snippet.Contains(part.Token, StringComparison.Ordinal)),
            "The guard does not recognise this shape of contract copy.");

    /// <summary>
    /// Proves the guard stays quiet about other validators. Both shapes really occur in the tree,
    /// and both are correct where they stand.
    /// </summary>
    [Fact]
    public void The_guard_does_not_flag_related_but_separate_validators()
    {
        // Token/session exchange validates the destination origin of a credential exchange: https,
        // no userinfo, no query, no fragment, an empty root path, and a host that is not an IP
        // literal. It is a different subject with deliberately stricter rules. Folding it into this
        // contract would be wrong, so it must not be reported as a copy.
        const string ExchangeDestination =
            "if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)\n"
            + "    || uri.Scheme != Uri.UriSchemeHttps\n"
            + "    || string.IsNullOrEmpty(uri.Host)\n"
            + "    || !string.IsNullOrEmpty(uri.UserInfo)\n"
            + "    || !string.IsNullOrEmpty(uri.Query)\n"
            + "    || !string.IsNullOrEmpty(uri.Fragment)\n"
            + "    || uri.AbsolutePath is not (\"\" or \"/\")) refuse();";

        // The CLI checks that each mapped route names an enabled surface. It never inspects a URI,
        // so a rule that matched on the name alone would flag a site that is doing no such thing.
        const string RouteResolution =
            "private static bool TryValidateExternalResources(\n"
            + "    RuntimeStartResult started,\n"
            + "    IReadOnlyDictionary<string, string> externalResources)";

        foreach (string snippet in new[] { ExchangeDestination, RouteResolution })
        {
            bool looksLikeACopy = EvaluatesLengthRule(snippet)
                && ContractParts.All(part => snippet.Contains(part.Token, StringComparison.Ordinal));

            Assert.False(looksLikeACopy, $"The guard would flag a separate validator: {snippet}");
        }
    }

    /// <summary>
    /// Recognises the length rule, written either as the shared constant or as the literal the
    /// constant replaced.
    /// </summary>
    private static bool EvaluatesLengthRule(string source)
        => source.Contains("MaxLength", StringComparison.Ordinal)
            || LengthLiteral().IsMatch(source);

    private static Regex LengthLiteral() => new(
        @"\b2048\b",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(5));

    private static IEnumerable<string> ProductionSources() => EngineRepository.ProductionSources();

    private static string Relative(string path) => EngineRepository.Relative(path);
}