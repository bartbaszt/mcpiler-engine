using System.Text.Json.Nodes;

using MCPiler.Engine.Transform;

using Xunit;

namespace MCPiler.Engine.UnitTests.Transform;

/// <summary>
/// Every reason code this build can emit has a program that provokes it.
/// </summary>
/// <remarks>
/// The per-code cases live in the other two classes and read as behaviour. This class exists
/// for the property those cannot state: that the set of codes and the set of cases are the
/// same set. A code added without a case is unreachable or untested and nothing would say
/// which, and a code removed while its case stays would leave a test asserting a contract that
/// no longer exists.
/// </remarks>
public sealed class TransformCodeCoverageTests
{
    /// <summary>One program refused by Tier 1 per load-time code, and how it is read.</summary>
    private static readonly Dictionary<string, (JsonObject Document, TransformDirection Read)> Provocations =
        new(StringComparer.Ordinal)
    {
        [TransformCodes.DirectionMismatch] =
            (Programs.Output(Programs.Copy(source: "/body/name", target: "/name")), TransformDirection.Input),
        [TransformCodes.UnsupportedVersion] = Envelope(version: 9),
        [TransformCodes.UnknownField] = Extra("script", "return 1;"),
        [TransformCodes.UnknownOperation] = Step(new JsonObject { ["op"] = "eval" }),
        [TransformCodes.MissingBound] = Step(new JsonObject
        {
            ["op"] = "mapArray",
            ["source"] = "/rows",
            ["target"] = "/body/rows",
            ["onMissing"] = "skip",
            ["steps"] = new JsonArray(),
        }),
        [TransformCodes.PointerSyntax] = Step(Programs.Copy(source: "body/name")),
        [TransformCodes.PointerRoot] = Step(Programs.Copy(target: "/status")),
        [TransformCodes.TemplatePattern] = Step(new JsonObject
        {
            ["op"] = "template",
            ["target"] = "/query/q",
            ["pattern"] = "{unbound}",
            ["arguments"] = new JsonArray(),
            ["onMissing"] = "skip",
        }),
        [TransformCodes.StepLimit] = Bounded(Flat(maxItems: 8), steps: 2),
        [TransformCodes.StaticDepth] = Bounded(Deep(maxItems: 2), depth: 1),
        [TransformCodes.StaticFanout] = Bounded(Flat(maxItems: 8), fanout: 2),
        [TransformCodes.FileHandle] = Step(new JsonObject
        {
            ["op"] = "setConstant",
            ["target"] = "/query/id",
            ["value"] = new string('b', 64),
        }),
        [TransformCodes.ContentTypeReserved] = Step(new JsonObject
        {
            ["op"] = "setConstant",
            ["target"] = "/headers/content-type",
            ["value"] = "text/plain",
        }),
    };

    /// <summary>One accepted program and one document per code the evaluator aborts with.</summary>
    /// <remarks>
    /// These evaluate directly rather than through a mount. Two of the runtime bounds cannot be
    /// reached through one, because the static estimate Tier 1 computes is an upper bound on
    /// what the evaluation does — which is asserted separately below rather than assumed.
    /// </remarks>
    private static readonly Dictionary<string, (JsonObject Program, JsonObject Document)> Aborts =
        new(StringComparer.Ordinal)
    {
        [TransformCodes.LimitSteps] = (
            Limited(Programs.Input(Programs.Copy(), Programs.Copy(target: "/query/again")), steps: 1),
            Agent()),
        [TransformCodes.LimitNodes] = (
            Limited(Programs.Input(Programs.Copy()), nodes: 1),
            Agent()),
        [TransformCodes.LimitDepth] = (
            Limited(Programs.Input(Constant("/query/a/b", "x")), depth: 1),
            new JsonObject()),
        [TransformCodes.LimitOutputBytes] = (
            Limited(Programs.Input(Constant("/query/a", new string('x', 64))), output: 8),
            new JsonObject()),
        [TransformCodes.LimitFanout] = (
            Limited(Programs.Input(Iteration("/rows", "/body/rows", 4, Programs.Copy("/raw", "/value"))), fanout: 1),
            new JsonObject { ["rows"] = new JsonArray(Row(), Row(), Row(), Row()) }),
        [TransformCodes.MissingSource] = (
            Programs.Input(Demanding(Programs.Copy(source: "/absent"))),
            Agent()),
        [TransformCodes.ConvertFailed] = (
            Programs.Input(new JsonObject
            {
                ["op"] = "convert",
                ["source"] = "/name",
                ["target"] = "/query/name",
                ["to"] = "number",
                ["onMissing"] = "skip",
            }),
            Agent()),
        [TransformCodes.StepFailed] = (
            Programs.Input(new JsonObject
            {
                ["op"] = "pick",
                ["source"] = "/name",
                ["members"] = new JsonArray("a"),
                ["target"] = "/query/picked",
                ["onMissing"] = "skip",
            }),
            Agent()),
    };

    public static TheoryData<string> Codes => [.. Provocations.Keys];

    public static TheoryData<string> AbortCodes => [.. Aborts.Keys];

    [Theory]
    [MemberData(nameof(Codes))]
    public void Each_code_is_reachable(string code)
    {
        (JsonObject document, TransformDirection read) = Provocations[code];
        IReadOnlyList<TransformFinding> findings = Programs.Validate(document, read);

        Assert.Contains(findings, finding => string.Equals(finding.Code, code, StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(AbortCodes))]
    public void Each_abort_is_reachable(string code)
    {
        (JsonObject document, JsonObject input) = Aborts[code];
        (TransformProgram? program, IReadOnlyList<TransformFinding> parsed) =
            TransformProgramReader.Read(document);

        // The program has to be well-formed, or the case would be proving the reader works.
        Assert.Empty(parsed);
        Assert.NotNull(program);

        TransformEvaluation evaluation = TransformEvaluator.Evaluate(program, input, Programs.Ceiling);

        Assert.Equal(code, evaluation.Code);
        Assert.Null(evaluation.Output);
    }

    [Fact]
    public void The_case_set_and_the_code_set_are_the_same_set()
    {
        Assert.Equal(
            TransformCodes.All.OrderBy(static code => code, StringComparer.Ordinal),
            Provocations.Keys
                .Concat(Aborts.Keys)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(static code => code, StringComparer.Ordinal));
    }

    [Fact]
    public void A_mounted_program_never_reaches_the_runtime_step_limit()
    {
        // The static estimate counts a nested list at its declared bound and a conditional at
        // its larger branch, so it is an upper bound on what any document can make the
        // evaluation do. The runtime check is defence in depth against an evaluator reached
        // without the gate, not a second gate — and this is the assertion that says so.
        JsonObject document = Limited(
            Programs.Input(Iteration("/rows", "/body/rows", 4, Programs.Copy("/raw", "/value"))),
            steps: 5);

        Assert.Empty(Programs.Validate(document));

        (TransformProgram? program, _) = TransformProgramReader.Read(document);
        var input = new JsonObject { ["rows"] = new JsonArray(Row(), Row(), Row(), Row()) };

        Assert.NotNull(program);
        Assert.True(TransformEvaluator.Evaluate(program, input, Programs.Ceiling).Succeeded);
    }

    /// <summary>Every case below reads in the direction its document declares but one.</summary>
    private static (JsonObject Document, TransformDirection Read) AsInput(JsonObject document)
        => (document, TransformDirection.Input);

    private static (JsonObject Document, TransformDirection Read) Envelope(int version)
    {
        JsonObject document = Programs.Input(Programs.Copy());
        document["transformVersion"] = version;
        return AsInput(document);
    }

    private static (JsonObject Document, TransformDirection Read) Extra(string member, string value)
    {
        JsonObject document = Programs.Input(Programs.Copy());
        document[member] = value;
        return AsInput(document);
    }

    private static (JsonObject Document, TransformDirection Read) Step(JsonObject step)
        => AsInput(Programs.Input(step));

    private static (JsonObject Document, TransformDirection Read) Bounded(
        JsonObject step,
        int steps = 64,
        int depth = 32,
        int fanout = 1024)
    {
        JsonObject document = Programs.Input(step);
        document["limits"] = Programs.Limits(steps: steps, depth: depth, fanout: fanout);
        return AsInput(document);
    }

    /// <summary>One iteration over an argument array.</summary>
    private static JsonObject Flat(int maxItems)
        => Iteration("/rows", "/body/rows", maxItems, Programs.Copy(source: "/raw", target: "/value"));

    /// <summary>An iteration inside an iteration, which is what depth measures.</summary>
    private static JsonObject Deep(int maxItems)
        => Iteration(
            "/rows",
            "/body/rows",
            maxItems,
            Iteration("/cells", "/cells", maxItems, Programs.Copy(source: "/raw", target: "/value")));

    /// <summary>An agent-side document with one scalar the cases read.</summary>
    private static JsonObject Agent() => new() { ["name"] = "pico" };

    /// <summary>One iteration item.</summary>
    private static JsonObject Row() => new() { ["raw"] = 1 };

    /// <summary>A program with one or more bounds narrowed below the format's defaults.</summary>
    private static JsonObject Limited(
        JsonObject document,
        int steps = 64,
        int depth = 32,
        int nodes = 8192,
        long output = 256L * 1024,
        int fanout = 1024)
    {
        document["limits"] = Programs.Limits(steps, depth, nodes, output, fanout);
        return document;
    }

    private static JsonObject Constant(string target, JsonNode value)
        => new()
        {
            ["op"] = "setConstant",
            ["target"] = target,
            ["value"] = value,
        };

    /// <summary>The same step, but refusing to proceed when its source is absent.</summary>
    private static JsonObject Demanding(JsonObject step)
    {
        step["onMissing"] = "error";
        return step;
    }

    private static JsonObject Iteration(string source, string target, int maxItems, JsonObject nested)
        => new()
        {
            ["op"] = "mapArray",
            ["source"] = source,
            ["target"] = target,
            ["maxItems"] = maxItems,
            ["onMissing"] = "skip",
            ["steps"] = new JsonArray(nested),
        };
}
