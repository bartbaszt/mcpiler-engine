using System.Text.Json.Nodes;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Guards the shared corpus itself: that every committed case is claimed by exactly one of the two
/// dispositions, that a case cannot leave the corpus unnoticed, and that a declared divergence says
/// something.
/// </summary>
/// <remarks>
/// <para>
/// A parity suite is only as honest as its coverage. Deleting a test makes the corresponding case
/// stop being checked while every remaining test still passes, and a data-driven suite whose own
/// dispatch helper lacks an arm under-covers silently — this repository has already been bitten by
/// exactly that shape. So the expected set is written out here rather than discovered, and the
/// cross-reference is computed from the suite's source instead of trusted.
/// </para>
/// <para>
/// The divergence register exists because the two implementations are not meant to agree forever.
/// One of them will eventually be improved on purpose, and at that moment the parity assertion for
/// the affected case becomes wrong rather than the implementation. Without somewhere to record that,
/// the pressure falls on the gate: the quickest way to a green suite would be to regenerate the
/// expectation and lose the record of what changed. A declared divergence has to name a real case and
/// give a reason, so the exemption costs more than the fix.
/// </para>
/// </remarks>
public sealed class GoldenCorpusTests
{
    private static readonly string[] ExpectedCases =
    [
        "basepath-encoded-query.txt",
        "basepath-simple-primitive.txt",
        "body-binary.txt",
        "body-form.txt",
        "body-json.txt",
        "body-multipart-mixed.txt",
        "body-text.txt",
        "body-vnd-json.txt",
        "compound-step-create.txt",
        "compound-step-fetch.txt",
        "params-deepobject.txt",
        "params-form-array-explode.txt",
        "params-form-array-nonexplode.txt",
        "params-header-cookie.txt",
        "params-label-array.txt",
        "params-matrix.txt",
        "params-object-cookie-inherited.txt",
        "params-object-cookie.txt",
        "params-object-form.txt",
        "params-pipe.txt",
        "params-reserved.txt",
        "params-simple-primitive.txt",
        "params-space.txt",
    ];

    private static readonly string[] ExpectedSections =
    [
        "bodies-multipart-binary.json",
        "bodies-scalar.json",
        "compound-commerce.json",
        "params-matrix-label.json",
        "params-object.json",
        "params-simple-form.json",
        "params-space-pipe.json",
    ];

    private const string SuitePath = "tests/MCPiler.Engine.UnitTests/Execution/RequestCompilationGoldenTests.cs";

    private static readonly string[] Placeholders = ["", "tbd", "todo", "-", "--", "n/a", "na", "none", "?"];

    [Fact]
    public void The_committed_cases_are_exactly_the_declared_ones()
    {
        Assert.Equal(ExpectedCases, GoldenCorpus.CaseNames());
    }

    [Fact]
    public void The_committed_sections_are_exactly_the_declared_ones()
    {
        var actual = Directory
            .EnumerateFiles(Path.Combine(GoldenCorpus.Directory, "operations"), "*.json")
            .Select(Path.GetFileName)
            .Select(static name => name!)
            .OrderBy(static name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(ExpectedSections, actual);
    }

    [Fact]
    public void Every_case_is_either_a_parity_case_or_a_declared_divergence()
    {
        var referenced = ReferencedCases();
        var diverged = Divergences().Select(static entry => entry.Case).ToHashSet(StringComparer.Ordinal);

        var unclaimed = ExpectedCases
            .Where(name => !referenced.Contains(name) && !diverged.Contains(name))
            .ToArray();

        Assert.True(
            unclaimed.Length == 0,
            "These cases are committed but neither compiled by the parity suite nor declared as a "
            + "divergence, so nothing checks them: " + string.Join(", ", unclaimed));
    }

    [Fact]
    public void No_case_is_both_a_parity_case_and_a_divergence()
    {
        var referenced = ReferencedCases();

        var both = Divergences()
            .Select(static entry => entry.Case)
            .Where(referenced.Contains)
            .ToArray();

        Assert.True(
            both.Length == 0,
            "A case is either checked byte-for-byte or exempt from that check, never both: "
            + string.Join(", ", both));
    }

    [Fact]
    public void Every_declared_divergence_names_a_real_case_and_gives_a_reason()
    {
        foreach (var entry in Divergences())
        {
            Assert.Contains(entry.Case, ExpectedCases);
            Assert.DoesNotContain(entry.Behavior.Trim().ToLowerInvariant(), Placeholders);
            Assert.DoesNotContain(entry.Reason.Trim().ToLowerInvariant(), Placeholders);
        }
    }

    // Without this the cross-reference could pass by finding nothing: a reader that returned an empty
    // set would make every case look unclaimed, but a reader that matched everything would make every
    // case look claimed, and that is the direction that hides a deleted test.
    [Fact]
    public void The_cross_reference_reads_the_suite_it_claims_to_read()
    {
        var referenced = ReferencedCases();

        Assert.True(File.Exists(TestRepository.Absolute(SuitePath)));
        Assert.Contains("params-simple-primitive.txt", referenced);
        Assert.Contains("body-multipart-mixed.txt", referenced);
        Assert.Contains("compound-step-fetch.txt", referenced);
        Assert.DoesNotContain("no-such-case.txt", referenced);
    }

    private static HashSet<string> ReferencedCases()
    {
        var source = File.ReadAllText(TestRepository.Absolute(SuitePath));
        var names = new HashSet<string>(StringComparer.Ordinal);
        const string marker = "GoldenCorpus.Case(\"";

        var index = source.IndexOf(marker, StringComparison.Ordinal);
        while (index >= 0)
        {
            var start = index + marker.Length;
            var end = source.IndexOf('"', start);
            if (end < 0)
            {
                break;
            }

            names.Add(source[start..end]);
            index = source.IndexOf(marker, end, StringComparison.Ordinal);
        }

        return names;
    }

    private static IReadOnlyList<Divergence> Divergences()
    {
        var path = Path.Combine(GoldenCorpus.Directory, "divergences.json");
        var root = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        var cases = root["cases"]!.AsArray();

        return
        [
            .. cases.Select(static node =>
            {
                var entry = node!.AsObject();
                return new Divergence(
                    entry["case"]?.GetValue<string>() ?? string.Empty,
                    entry["behavior"]?.GetValue<string>() ?? string.Empty,
                    entry["reason"]?.GetValue<string>() ?? string.Empty);
            }),
        ];
    }

    private sealed record Divergence(string Case, string Behavior, string Reason);
}
