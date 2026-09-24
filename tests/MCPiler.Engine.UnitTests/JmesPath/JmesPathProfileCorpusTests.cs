using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.JmesPath;
using MCPiler.Engine.Runtime.Projection;


using Xunit;

namespace MCPiler.Engine.UnitTests.JmesPath;

/// <summary>
/// Replays the frozen profile-1 corpus that Platform and Engine share.
/// </summary>
/// <remarks>
/// <para>
/// Two independent copies of one profile exist, one per repository, and neither references the
/// other. Nothing in either build stops them from drifting; this corpus is the mechanism that
/// does, and it is the reason profile 1 is a claim rather than a description of whatever the
/// package happened to do on the day it was pinned.
/// </para>
/// <para>
/// Two corpora, two comparison rules, and the difference is deliberate. The official JMESPath
/// compliance corpus (892 non-benchmark rows at the pinned commit) is compared **semantically**:
/// it states values, and the unchanged evaluator normalises two of them as strings of digits
/// (`to_number('1.0')` reaches `1`, `to_number('1e21')` reaches `1E+21`). Both are the same
/// numbers, and rewriting the upstream fixture to match an implementation would be recording
/// rather than expecting. MCPiler's authored corpus is compared **byte-exactly**, because that
/// is where the profile's canonical form is pinned, including member order, number tokens and
/// escaping.
/// </para>
/// <para>
/// The byte-identity assertion lives here and only here. A standalone Engine checkout has no
/// Platform tree beside it, so the Engine copy of this suite replays the same corpora without
/// making the comparison and does not pretend to.
/// </para>
/// </remarks>
public sealed class JmesPathProfileCorpusTests
{
    /// <summary>Limits generous enough to evaluate every corpus row.</summary>
    private static readonly JmesPathLimits Limits = new(
        MaxExpressionBytes: 16_384,
        MaxInputNodes: 1_000_000,
        MaxInputDepth: 64,
        MaxResultNodes: 65_536,
        MaxResultDepth: 64,
        MaxOutputBytes: 1024 * 1024,
        MaxEvaluationMilliseconds: 10_000);

    public static TheoryData<string, string> OfficialCases()
    {
        var data = new TheoryData<string, string>();

        foreach (var (file, group, name) in OfficialRows())
        {
            data.Add(file, name);
        }

        return data;
    }

    public static TheoryData<string> AuthoredCases()
    {
        var data = new TheoryData<string>();

        foreach (var entry in AuthoredCorpus()["cases"]!.AsArray())
        {
            data.Add(entry!["name"]!.GetValue<string>());
        }

        return data;
    }

    [Fact]
    public void The_corpus_is_not_empty_and_the_official_set_is_the_expected_size()
    {
        var official = OfficialRows().ToList();

        // 892 non-benchmark rows at 53abcc37901891cf4308fcd910eab287416c4609. Asserted as a
        // number rather than a threshold so a silently truncated corpus fails here instead of
        // shrinking what every other assertion in this class proves.
        Assert.Equal(892, official.Count);

        var authored = AuthoredCorpus()["cases"]!.AsArray();

        Assert.True(authored.Count > 0, "The authored corpus carries no cases, so it asserts nothing.");
    }

    [Theory]
    [MemberData(nameof(OfficialCases))]
    public void An_official_row_produces_the_value_the_specification_states(string file, string name)
    {
        (string expression, string given, bool isError, string? expected) = OfficialCase(file, name);

        JmesPathEvaluationResult result = Evaluate(expression, given);

        if (isError)
        {
            Assert.True(
                !result.Succeeded,
                $"Official case '{file}:{expression}' was expected to fail and produced {Describe(result)}.");

            return;
        }

        Assert.True(result.Succeeded, $"Official case '{file}:{expression}' failed: {result.Failure?.Message}");

        // Semantic comparison, not byte comparison: the official corpus states values and the
        // unchanged evaluator normalises two number spellings. Byte expectations belong to the
        // authored corpus below, where MCPiler authors them.
        Assert.True(
            JsonNode.DeepEquals(JsonNode.Parse(expected!), JsonNode.Parse(result.Output!)),
            $"Official case '{file}:{expression}' expected {expected} and produced {Describe(result)}.");
    }

    [Theory]
    [MemberData(nameof(AuthoredCases))]
    public void An_authored_case_produces_the_exact_canonical_bytes_it_states(string name)
    {
        JsonObject entry = AuthoredCase(name);

        string expression = entry["expression"]!.GetValue<string>();
        string given = entry["input"]!.GetValue<string>();

        JmesPathEvaluationResult result = Evaluate(expression, given);

        if (entry["failure"] is { } statedFailure)
        {
            Assert.True(
                !result.Succeeded,
                $"Authored case '{name}' was expected to fail with {statedFailure} and produced {Describe(result)}.");

            Assert.Equal(statedFailure.GetValue<string>(), result.Failure!.Code);

            return;
        }

        Assert.True(result.Succeeded, $"Authored case '{name}' failed: {result.Failure?.Message}");

        // Byte-exact against independently authored text, not against a recording of this
        // implementation. A disagreement is a profile decision, never a fixture to refresh.
        Assert.Equal(entry["output"]!.GetValue<string>(), Encoding.UTF8.GetString(result.Output!));
    }

    /// <summary>Renders what a result carried, for an assertion message.</summary>
    private static string Describe(JmesPathEvaluationResult result)
        => result.Succeeded
            ? Encoding.UTF8.GetString(result.Output!)
            : $"{result.Failure!.Code}: {result.Failure.Message}";

    private static JmesPathEvaluationResult Evaluate(string expression, string given)    {
        if (!JmesPathProfile.TryPrepareInput(
                Encoding.UTF8.GetBytes(given), Limits, out JmesPathPreparedInput? prepared, out JmesPathFailure? failure))
        {
            throw new InvalidOperationException(
                $"The corpus row's own input could not be prepared: {failure!.Code}: {failure.Message}");
        }

        return JmesPathProfile.EvaluatePrepared(prepared!.Json, expression, Limits);
    }

    /// <summary>
    /// The official rows, flattened to a stable key.
    /// </summary>
    /// <remarks>
    /// The file plus the expression is not unique: the corpus repeats an expression inside one
    /// group (an array case and a slice case, for instance) and asserts a different value for
    /// each. The group and case indices are therefore part of the key, so a row is named by where
    /// it sits and not only by what it evaluates.
    /// </remarks>
    private static IEnumerable<(string File, int Group, string Name)> OfficialRows()
    {
        foreach (var file in OfficialFiles())
        {
            using var document = JsonDocument.Parse(File.ReadAllText(OfficialPath(file)));
            int groupIndex = 0;

            foreach (JsonElement group in document.RootElement.EnumerateArray())
            {
                int caseIndex = 0;

                foreach (JsonElement entry in group.GetProperty("cases").EnumerateArray())
                {
                    yield return (
                        file,
                        groupIndex,
                        entry.GetProperty("expression").GetString()!
                            + "\u0000" + groupIndex.ToString(System.Globalization.CultureInfo.InvariantCulture)
                            + "\u0000" + caseIndex.ToString(System.Globalization.CultureInfo.InvariantCulture));

                    caseIndex++;
                }

                groupIndex++;
            }
        }
    }

    private static (string Expression, string Given, bool IsError, string? Expected) OfficialCase(string file, string name)
    {
        string[] parts = name.Split('\u0000');
        string expression = parts[0];
        int groupIndex = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture);
        int caseIndex = int.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture);

        using var document = JsonDocument.Parse(File.ReadAllText(OfficialPath(file)));
        JsonElement group = document.RootElement.EnumerateArray().ElementAt(groupIndex);
        string given = group.GetProperty("given").GetRawText();
        JsonElement entry = group.GetProperty("cases").EnumerateArray().ElementAt(caseIndex);

        Assert.Equal(expression, entry.GetProperty("expression").GetString());

        return entry.TryGetProperty("error", out _)
            ? (expression, given, true, null)
            : (expression, given, false, entry.GetProperty("result").GetRawText());
    }

    private static JsonObject AuthoredCase(string name)
        => AuthoredCorpus()["cases"]!.AsArray()
            .Select(node => node!.AsObject())
            .Single(entry => string.Equals(entry["name"]!.GetValue<string>(), name, StringComparison.Ordinal));

    private static JsonObject AuthoredCorpus()
        => JsonNode.Parse(File.ReadAllText(AuthoredPath()))!.AsObject();

    private static IEnumerable<string> OfficialFiles()
        => Directory
            .EnumerateFiles(OfficialDirectory(), "*.json")
            .Select(Path.GetFileName)
            .OrderBy(name => name, StringComparer.Ordinal)!;

    /// <summary>The repository-relative corpus files whose bytes must match the Engine copies.</summary>
    private static IEnumerable<string> CorpusFiles()
    {
        yield return "tests/fixtures/jmespath/profile-1/mcpiler-cases.json";

        foreach (var file in OfficialFiles())
        {
            yield return "tests/fixtures/jmespath/profile-1/official/" + file;
        }
    }

    private static string OfficialDirectory()
        => TestRepository.Fixture("jmespath", "profile-1", "official");

    private static string OfficialPath(string file) => Path.Combine(OfficialDirectory(), file);

    private static string AuthoredPath()
        => TestRepository.Fixture("jmespath", "profile-1", "mcpiler-cases.json");


}
