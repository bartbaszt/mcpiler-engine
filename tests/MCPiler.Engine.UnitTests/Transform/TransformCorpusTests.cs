using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Transform;

using Xunit;

namespace MCPiler.Engine.UnitTests.Transform;

/// <summary>
/// Replays the authored transformation corpus shared with the MCPiler Platform suite.
/// </summary>
/// <remarks>
/// <para>
/// The same file, byte for byte, is replayed by the Platform's own evaluator, which asserts the
/// two copies are identical. Engine cannot reference Platform code, so a duplicated corpus with
/// hand-written expectations is the only mechanism that stops two independent evaluators from
/// drifting into two dialects of one grammar.
/// </para>
/// <para>
/// The expectations are authored from the specification rather than captured from a run. A
/// corpus generated from either implementation would record that implementation's beliefs, and
/// a disagreement would then be invisible by construction.
/// </para>
/// </remarks>
public sealed class TransformCorpusTests
{
    private static readonly string CorpusPath = TestRepository.Fixture("transform", "programs.json");

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
    public void The_corpus_covers_every_operation_in_the_vocabulary()
    {
        // A corpus that names eleven of nineteen operations proves eleven of them agree.
        var exercised = new HashSet<string>(StringComparer.Ordinal);

        foreach (JsonObject entry in Corpus())
        {
            Collect(entry["program"]!["steps"]!.AsArray(), exercised);
        }

        Assert.Equal(
            StepVocabulary.Names.OrderBy(static name => name, StringComparer.Ordinal),
            exercised.OrderBy(static name => name, StringComparer.Ordinal));
    }

    [Fact]
    public void Every_case_states_exactly_one_expectation()
    {
        foreach (JsonObject entry in Corpus())
        {
            string name = entry["name"]!.GetValue<string>();
            bool produces = entry.ContainsKey("output");
            bool aborts = entry.ContainsKey("abort");

            Assert.True(produces ^ aborts, $"Case '{name}' states both an output and an abort, or neither.");
            Assert.False(string.IsNullOrWhiteSpace(entry["why"]?.GetValue<string>()), $"Case '{name}' states no reason.");
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_case_produces_what_it_states(string name)
    {
        JsonObject entry = Case(name);
        TransformEvaluation evaluation = Run(entry);

        if (entry["abort"] is JsonObject abort)
        {
            Assert.Equal(abort["code"]!.GetValue<string>(), evaluation.Code);
            Assert.Equal(abort["step"]?.GetValue<int>(), evaluation.Step);

            // No partial document travels with a failure.
            Assert.Null(evaluation.Output);
            return;
        }

        Assert.True(evaluation.Succeeded, $"Case '{name}' aborted with {evaluation.Code}: {evaluation.Message}");
        Assert.Equal(
            JsonSerializer.Serialize(entry["output"]),
            JsonSerializer.Serialize(evaluation.Output));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_case_produces_the_same_bytes_under_another_host_culture(string name)
    {
        // A decimal comma and a different negative sign are how a culture reaches into a
        // program that reads and writes numbers. The culture is synthesized rather than named:
        // this build runs globalization-invariant, so a named culture is unavailable, and a
        // test that silently skipped would prove nothing about the property it claims.
        JsonObject entry = Case(name);

        string first = Render(Run(entry));
        string hostile = Under(Hostile(), () => Render(Run(entry)));

        Assert.Equal(first, hostile);
    }

    [Fact]
    public void The_hostile_culture_would_be_visible_if_anything_read_it()
    {
        // Guards the guard: if the synthesized culture had no effect on culture-sensitive
        // formatting, every case above would pass for the wrong reason.
        string invariant = 1.5.ToString("0.0#", CultureInfo.CurrentCulture);
        string hostile = Under(Hostile(), () => 1.5.ToString("0.0#", CultureInfo.CurrentCulture));

        Assert.NotEqual(invariant, hostile);
    }

    /// <summary>A culture whose number formatting disagrees with the invariant one.</summary>
    private static CultureInfo Hostile()
    {
        var culture = (CultureInfo)CultureInfo.InvariantCulture.Clone();
        culture.NumberFormat.NumberDecimalSeparator = ",";
        culture.NumberFormat.NumberGroupSeparator = ".";
        culture.NumberFormat.NegativeSign = "!";
        return culture;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Repeating_an_evaluation_changes_nothing(string name)
    {
        // The evaluator holds no state across calls and the document it was handed is not the
        // document it wrote to, so a second run of the same case is a run of the same inputs.
        JsonObject entry = Case(name);

        Assert.Equal(Render(Run(entry)), Render(Run(entry)));
    }

    private static string Render(TransformEvaluation evaluation)
        => evaluation.Succeeded
            ? "ok:" + JsonSerializer.Serialize(evaluation.Output)
            : $"{evaluation.Code}@{evaluation.Step?.ToString(CultureInfo.InvariantCulture) ?? "-"}";

    private static T Under<T>(CultureInfo culture, Func<T> action)
    {
        CultureInfo previousCulture = CultureInfo.CurrentCulture;
        CultureInfo previousUi = CultureInfo.CurrentUICulture;

        try
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = culture;
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = previousCulture;
            CultureInfo.CurrentUICulture = previousUi;
        }
    }

    private static TransformEvaluation Run(JsonObject entry)
    {
        (TransformProgram? program, IReadOnlyList<TransformFinding> findings) =
            TransformProgramReader.Read(entry["program"]!.AsObject());

        Assert.Empty(findings);
        Assert.NotNull(program);

        return TransformEvaluator.Evaluate(program, entry["document"]!.AsObject(), Programs.Ceiling);
    }

    private static void Collect(JsonArray steps, HashSet<string> exercised)
    {
        foreach (JsonNode? step in steps)
        {
            if (step is not JsonObject declared)
            {
                continue;
            }

            exercised.Add(declared["op"]!.GetValue<string>());

            foreach (string member in (string[])["steps", "elseSteps"])
            {
                if (declared[member] is JsonArray nested)
                {
                    Collect(nested, exercised);
                }
            }
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
