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
    /// <summary>One provoking program per code.</summary>
    private static readonly Dictionary<string, JsonObject> Provocations = new(StringComparer.Ordinal)
    {
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

    public static TheoryData<string> Codes => [.. Provocations.Keys];

    [Theory]
    [MemberData(nameof(Codes))]
    public void Each_code_is_reachable(string code)
    {
        IReadOnlyList<TransformFinding> findings = Programs.Validate(Provocations[code]);

        Assert.Contains(findings, finding => string.Equals(finding.Code, code, StringComparison.Ordinal));
    }

    [Fact]
    public void The_case_set_and_the_code_set_are_the_same_set()
    {
        Assert.Equal(
            TransformCodes.All.OrderBy(static code => code, StringComparer.Ordinal),
            Provocations.Keys.OrderBy(static code => code, StringComparer.Ordinal));
    }

    private static JsonObject Envelope(int version)
    {
        JsonObject document = Programs.Input(Programs.Copy());
        document["transformVersion"] = version;
        return document;
    }

    private static JsonObject Extra(string member, string value)
    {
        JsonObject document = Programs.Input(Programs.Copy());
        document[member] = value;
        return document;
    }

    private static JsonObject Step(JsonObject step) => Programs.Input(step);

    private static JsonObject Bounded(
        JsonObject step,
        int steps = 64,
        int depth = 32,
        int fanout = 1024)
    {
        JsonObject document = Programs.Input(step);
        document["limits"] = Programs.Limits(steps: steps, depth: depth, fanout: fanout);
        return document;
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
