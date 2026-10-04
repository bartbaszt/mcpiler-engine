using System.Text.Json.Nodes;

using MCPiler.Engine.Runtime.Managed;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>
/// Replays the authored external-resource contract corpus shared with the MCPiler Platform suite.
/// </summary>
/// <remarks>
/// <para>
/// Two implementations decide what an external MCP resource identity may be: this one and the one
/// in MCPiler Platform, which produces the value this one consumes. Neither references the other,
/// so nothing in either build stops them from drifting, and a defect both share would be invisible
/// in both suites at once. The corpus is the mechanism that is not blind to that: its expected
/// outcomes are authored from the specification, not recorded from either implementation.
/// </para>
/// <para>
/// Platform asserts the two copies of the file are byte-identical and runs the same rows. A
/// standalone Engine checkout has no Platform tree beside it, so this suite replays its own copy and
/// does not pretend to compare them.
/// </para>
/// <para>
/// A row is asserted against the reported rule name, not only against accept-or-refuse. Prose may
/// differ between the two implementations without either being wrong, but the machine-readable
/// diagnosis an operator reads from both refusals is a fact they must agree on.
/// </para>
/// </remarks>
public sealed class ExternalResourceContractCorpusTests
{
    private static readonly string[] Outcomes = ["accepted", "refused"];

    private static readonly string CorpusPath = TestRepository.Fixture("mcp", "external-resource-contract.json");

    public static TheoryData<string> ResourceCases()
    {
        var data = new TheoryData<string>();

        foreach (JsonObject entry in ResourceCaseArray())
        {
            data.Add(Text(entry, "name"));
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(ResourceCases))]
    public void A_resource_case_is_decided_exactly_as_the_corpus_states(string name)
    {
        JsonObject entry = ResourceCase(name);
        string resource = Text(entry, "resource");
        string expected = Text(entry, "expected");
        JsonNode? expectedRule = entry["rule"];

        ExternalResourceViolation observed = ExternalResourceContract.Evaluate(resource);

        if (expected == "accepted")
        {
            Assert.True(
                observed is ExternalResourceViolation.None,
                $"Case '{name}' is authored as accepted but rule '{ExternalResourceContract.RuleName(observed)}' refused it.");
            return;
        }

        Assert.Equal("refused", expected);
        Assert.NotEqual(ExternalResourceViolation.None, observed);
        Assert.Equal(
            expectedRule!.GetValue<string>(),
            ExternalResourceContract.RuleName(observed));
    }

    [Fact]
    public void Every_row_states_a_name_a_reason_and_a_wrapped_expectation()
    {
        foreach (JsonObject entry in Rows())
        {
            string name = Text(entry, "name");

            Assert.False(string.IsNullOrWhiteSpace(name), "A corpus row states no name.");
            Assert.False(string.IsNullOrWhiteSpace(entry["why"]!.GetValue<string>()), $"Row '{name}' states no reason.");
            Assert.Contains(
                Text(entry, "expected"),
                Outcomes);
            Assert.True(entry.ContainsKey("rule"), $"Row '{name}' states no rule, accepted or not.");
        }
    }

    [Fact]
    public void Every_row_is_reachable_by_exactly_one_name()
    {
        var names = Rows().Select(entry => Text(entry, "name")).ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void The_corpus_states_both_outcomes()
    {
        var expected = ResourceCaseArray()
            .Select(entry => Text(entry, "expected"))
            .ToHashSet(StringComparer.Ordinal);

        Assert.Contains("accepted", expected);
        Assert.Contains("refused", expected);
    }

    [Fact]
    public void The_corpus_exercises_every_rule_the_contract_declares()
    {
        // A corpus that exercises six of seven rules proves six of seven agree.
        var exercised = ResourceCaseArray()
            .Where(entry => Text(entry, "expected") == "refused")
            .Select(entry => Text(entry, "rule"))
            .ToHashSet(StringComparer.Ordinal);

        foreach (string rule in DeclaredRules())
        {
            Assert.True(exercised.Contains(rule), $"No corpus case is refused for rule '{rule}'.");
        }
    }

    [Fact]
    public void The_corpus_evaluation_order_is_the_declared_rule_order()
    {
        // The order is part of the contract, not a detail of one implementation: a value can break
        // more than one rule, and both sides must name the same one.
        Assert.Equal(DeclaredRules(), DeclaredEvaluationOrder());
    }

    [Fact]
    public void The_corpus_declares_the_length_bound_this_build_enforces()
    {
        int declared = Corpus()["contract"]!["maxLength"]!.GetValue<int>();

        Assert.Equal(ExternalResourceContract.MaxLength, declared);
    }

    [Fact]
    public void The_boundary_rows_sit_exactly_on_the_declared_bound()
    {
        // The bound is a boundary, so rows generated from a stale constant would drift silently:
        // both would be accepted, the corpus would stay green, and the two implementations would
        // agree on a bound nobody intended. Assert the rows are where the file says they are.
        JsonObject accepted = ResourceCase("at-max-length");
        JsonObject refused = ResourceCase("over-max-length");
        int declared = ExternalResourceContract.MaxLength;

        Assert.Equal(declared, accepted["resource"]!.GetValue<string>().Length);
        Assert.Equal(declared + 1, refused["resource"]!.GetValue<string>().Length);
    }

    [Fact]
    public void The_userinfo_rule_covers_the_forms_a_parsed_property_would_miss()
    {
        // System.Uri reports an empty UserInfo for 'https://@host/', so a predicate written as an
        // emptiness check on that property accepts a value the storage layer refuses. This is the
        // disagreement the corpus exists to catch, so it is asserted directly rather than left to a
        // row someone might delete as redundant.
        foreach (string name in new[]
        {
            "userinfo-empty-user",
            "userinfo-colon-only",
            "userinfo-empty-password",
            "userinfo-user-only",
            "userinfo-with-password",
        })
        {
            Assert.Equal(
                ExternalResourceViolation.HasUserInfo,
                ExternalResourceContract.Evaluate(Text(ResourceCase(name), "resource")));
        }
    }

    [Fact]
    public void The_corpus_covers_every_tunnel_id_rule_it_declares()
    {
        // The id rows travel with the resource rows so the id contract and the resource contract it
        // builds are versioned together. That only works if the file proves coverage: an unexercised
        // id rule would sit in a corpus both repositories replay and prove nothing.
        var declared = Corpus()["tunnelIdRules"]!.AsArray()
            .Select(static node => node!.GetValue<string>())
            .ToArray();
        var exercised = Corpus()["tunnelIdCases"]!.AsArray()
            .Where(static node => node!["expected"]!.GetValue<string>() == "refused")
            .Select(static node => node!["rule"]!.GetValue<string>())
            .ToHashSet(StringComparer.Ordinal);

        Assert.NotEmpty(declared);

        foreach (string rule in declared)
        {
            Assert.True(exercised.Contains(rule), $"No corpus tunnel id row is refused for rule '{rule}'.");
        }
    }

    [Fact]
    public void The_tunnel_id_rule_order_is_declared_and_the_declaration_is_self_consistent()
    {
        // A corpus that publishes the rules but not their order cannot state which diagnosis an
        // operator should expect for a value that breaks two of them, and a row asserting a rule the
        // implied order cannot produce is a corpus defect that no single implementation can see. This
        // shape test fails rather than silently reinterpreting either declaration.
        Assert.Equal(DeclaredTunnelIdRules(), DeclaredTunnelIdEvaluationOrder());
    }

    [Fact]
    public void The_tunnel_id_rows_are_out_of_this_suites_scope_and_say_so()
    {
        // Engine receives no tunnel id and never parses the resource. The rows are here so the id
        // contract travels with the contract it builds, and the exclusion is stated in the file
        // rather than left as an inference from the absence of a test.
        Assert.NotEmpty(Corpus()["tunnelIdCases"]!.AsArray());

        string scope = Corpus()["scopeNote"]!.GetValue<string>();

        Assert.Contains("Platform-only", scope, StringComparison.Ordinal);
        Assert.Contains("tunnelIdCases", scope, StringComparison.Ordinal);
    }

    [Fact]
    public void A_refusal_names_a_rule_and_a_requirement_without_echoing_the_value()
    {
        // The corpus states the same constraint for the userinfo row; a message that quoted the
        // offending value would put the credential it exists to keep out of deployment state into a
        // refusal message instead.
        const string Secret = "corpus-userinfo-canary";

        ExternalResourceViolation violation = ExternalResourceContract.Evaluate(
            $"https://user:{Secret}@tunnel.example/v1/mcp/tunnel_0123456789abcdef0123456789abcdef");

        Assert.Equal(ExternalResourceViolation.HasUserInfo, violation);
        Assert.False(string.IsNullOrWhiteSpace(ExternalResourceContract.RuleName(violation)));
        Assert.False(string.IsNullOrWhiteSpace(ExternalResourceContract.RuleRequirement(violation)));
        Assert.DoesNotContain(Secret, ExternalResourceContract.RuleName(violation)!, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, ExternalResourceContract.RuleRequirement(violation), StringComparison.Ordinal);
    }

    private static JsonObject ResourceCase(string name)
        => ResourceCaseArray().Single(entry => string.Equals(Text(entry, "name"), name, StringComparison.Ordinal));

    private static IEnumerable<JsonObject> ResourceCaseArray()
        => Corpus()["resourceCases"]!.AsArray().Select(static node => node!.AsObject());

    private static IEnumerable<JsonObject> Rows()
        => ResourceCaseArray().Concat(
            Corpus()["tunnelIdCases"]!.AsArray().Select(static node => node!.AsObject()));

    private static string[] DeclaredRules()
        => Corpus()["contract"]!["rules"]!.AsArray().Select(static node => node!.GetValue<string>()).ToArray();

    private static string[] DeclaredTunnelIdRules()
        => Corpus()["tunnelIdRules"]!.AsArray().Select(static node => node!.GetValue<string>()).ToArray();

    private static string[] DeclaredTunnelIdEvaluationOrder()
        => Corpus()["tunnelIdEvaluationOrder"]!.AsArray().Select(static node => node!.GetValue<string>()).ToArray();

    private static string[] DeclaredEvaluationOrder()
        => Corpus()["contract"]!["evaluationOrder"]!.AsArray().Select(static node => node!.GetValue<string>()).ToArray();

    private static string Text(JsonObject entry, string key) => entry[key]!.GetValue<string>()!;

    private static JsonObject Corpus() => JsonNode.Parse(File.ReadAllText(CorpusPath))!.AsObject();
}