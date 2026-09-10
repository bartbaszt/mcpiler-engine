using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using MCPiler.Engine.Execution;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution;

/// <summary>
/// Replays the shared origin corpus against this repository's allowed-origin list.
/// </summary>
/// <remarks>
/// The corpus states what the perimeter is supposed to decide. It is authored rather than
/// generated from either implementation, because a corpus generated from one of them would
/// record that implementation's beliefs and a defect present in both would then be
/// invisible in both suites at once.
///
/// A failing case is a claim about the perimeter that this implementation does not honour.
/// Editing the corpus to match the code is only correct when the case itself is wrong, and
/// the other repository replays the same bytes, so a one-sided edit shows up there.
/// </remarks>
public class OriginCorpusTests
{
    private static string CorpusPath => Path.Combine(TestRepository.Fixture("http"), "origins.json");

    [Fact]
    public void EveryAuthoredMatchCaseIsDecidedAsTheCorpusStates()
    {
        var failures = new List<string>();

        foreach (var node in Cases("matchCases"))
        {
            var name = node["name"]!.GetValue<string>();
            var entries = node["entries"]!.AsArray().Select(e => e!.GetValue<string>()).ToArray();
            var target = node["target"]!.GetValue<string>();
            var expected = node["allowed"]!.GetValue<bool>();

            if (!Uri.TryCreate(target, UriKind.Absolute, out var uri))
            {
                // A target that will not parse would pass vacuously as "not allowed" while
                // proving nothing about the decision the case is meant to exercise.
                failures.Add($"{name}: target '{target}' is not an absolute URI.");
                continue;
            }

            bool actual;
            try
            {
                actual = new OriginAllowList(entries).IsAllowed(uri);
            }
            catch (ArgumentException ex)
            {
                failures.Add($"{name}: entries were refused ({ex.Message}), so no decision was reached.");
                continue;
            }

            if (actual != expected)
            {
                failures.Add($"{name}: expected allowed={expected}, got {actual}. {node["why"]!.GetValue<string>()}");
            }
        }

        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public void EveryAuthoredRejectedEntryIsRefusedAtConstruction()
    {
        var failures = new List<string>();

        foreach (var node in Cases("rejectedEntries"))
        {
            var name = node["name"]!.GetValue<string>();
            var entry = node["entry"]!.GetValue<string>();

            // Only the refusal is asserted, not its wording: two implementations may phrase
            // one refusal differently without disagreeing about it.
            var thrown = Record.Exception(() => new OriginAllowList([entry]));
            if (thrown is not ArgumentException)
            {
                failures.Add($"{name}: entry '{entry}' was accepted. {node["reason"]!.GetValue<string>()}");
            }
        }

        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public void TheCorpusStatesBothOutcomes()
    {
        var match = Cases("matchCases").ToList();

        // A corpus of only-allowed or only-refused cases would pass against an
        // implementation that answered one way unconditionally.
        Assert.Contains(match, c => c["allowed"]!.GetValue<bool>());
        Assert.Contains(match, c => !c["allowed"]!.GetValue<bool>());
        Assert.NotEmpty(Cases("rejectedEntries").ToList());
    }

    private static IEnumerable<JsonObject> Cases(string member)
    {
        var root = JsonNode.Parse(File.ReadAllText(CorpusPath))!.AsObject();
        return root[member]!.AsArray().Select(n => n!.AsObject());
    }
}
