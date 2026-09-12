using System.Text.Json.Nodes;

using MCPiler.Engine.Mcp;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>
/// Replays the authored output-schema envelope corpus shared with the MCPiler Platform suite.
/// </summary>
/// <remarks>
/// <para>
/// Two independent implementations shape every advertised output schema for the wire. Nothing
/// in either build stops them from drifting, because neither references the other; this corpus
/// is the mechanism that does. The expectations are authored from the specification, so a
/// disagreement is a defect in one implementation rather than a difference of opinion between
/// two recordings.
/// </para>
/// <para>
/// The Platform suite asserts the two copies of this file are byte-identical. A standalone
/// Engine checkout has no Platform tree beside it, so this suite replays its own copy and does
/// not pretend to compare them.
/// </para>
/// </remarks>
public sealed class OutputSchemaEnvelopeCorpusTests
{
    private static readonly string CorpusPath = TestRepository.Fixture("mcp", "output-schema-envelope.json");

    public static TheoryData<string> Cases()
    {
        var data = new TheoryData<string>();

        foreach (JsonObject entry in Corpus())
        {
            data.Add(entry["name"]!.GetValue<string>());
        }

        return data;
    }

    [Fact]
    public void The_corpus_exercises_every_keyword_position_the_traversal_descends()
    {
        // A corpus that exercises eleven of twenty-two positions proves eleven of them agree.
        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (JsonObject entry in Corpus())
        {
            Collect(entry["schema"], names);
        }

        Assert.All(
            OutputSchemaEnvelope.TraversalKeywords,
            keyword => Assert.True(names.Contains(keyword), $"No corpus case exercises '{keyword}'."));
    }

    [Fact]
    public void Every_case_states_a_reason_a_wrapped_flag_and_an_expectation()
    {
        foreach (JsonObject entry in Corpus())
        {
            string name = entry["name"]!.GetValue<string>();

            Assert.False(string.IsNullOrWhiteSpace(entry["why"]?.GetValue<string>()), $"Case '{name}' states no reason.");
            Assert.True(entry.ContainsKey("wrapped"), $"Case '{name}' states no wrapped flag.");
            Assert.True(entry.ContainsKey("expected"), $"Case '{name}' states no expectation.");
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_case_produces_what_it_states(string name)
    {
        JsonObject entry = Case(name);
        var shaped = OutputSchemaEnvelope.Shape(entry["schema"]!);

        Assert.Equal(entry["wrapped"]!.GetValue<bool>(), shaped.Wrapped);
        Assert.Equal(
            entry["expected"]!.ToJsonString(),
            shaped.Schema.ToJsonString());
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Shaping_never_mutates_the_authored_schema(string name)
    {
        JsonObject entry = Case(name);
        string before = entry["schema"]!.ToJsonString();

        _ = OutputSchemaEnvelope.Shape(entry["schema"]!);

        Assert.Equal(before, entry["schema"]!.ToJsonString());
    }

    private static void Collect(JsonNode? node, HashSet<string> names)
    {
        switch (node)
        {
            case JsonObject members:
                foreach (var (member, value) in members)
                {
                    names.Add(member);
                    Collect(value, names);
                }

                break;

            case JsonArray items:
                foreach (JsonNode? item in items)
                {
                    Collect(item, names);
                }

                break;
        }
    }

    private static JsonObject Case(string name)
        => Corpus().Single(entry => string.Equals(entry["name"]!.GetValue<string>(), name, StringComparison.Ordinal));

    private static IEnumerable<JsonObject> Corpus()
        => JsonNode.Parse(File.ReadAllText(CorpusPath))!
            .AsObject()["cases"]!
            .AsArray()
            .Select(static node => node!.AsObject());
}