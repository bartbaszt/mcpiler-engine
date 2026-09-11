using System.Text.Json.Nodes;

using MCPiler.Engine.Transform;

namespace MCPiler.Engine.UnitTests.Transform;

/// <summary>
/// Builds program documents for the Tier-1 cases.
/// </summary>
/// <remarks>
/// Programs are assembled as JSON rather than as model objects on purpose. Tier 1 exists
/// because a program arrives as a document somebody else wrote, and a test that constructs the
/// typed model has already skipped the parsing this gate is mostly made of.
/// </remarks>
internal static class Programs
{
    /// <summary>The ceiling the manifest format defaults to.</summary>
    internal static TransformCeilingValues Ceiling { get; } = new(64, 32, 8192, 256L * 1024, 1024);

    /// <summary>No operation declares a file slot.</summary>
    internal static IReadOnlySet<string> NoFiles { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>A well-formed envelope wrapping <paramref name="steps"/>.</summary>
    internal static JsonObject Program(string direction, params JsonObject[] steps)
        => new()
        {
            ["transformVersion"] = 1,
            ["direction"] = direction,
            ["base"] = "passthrough",
            ["limits"] = Limits(),
            ["steps"] = new JsonArray([.. steps.Select(static step => (JsonNode)step)]),
        };

    /// <summary>An input-direction envelope, the common case.</summary>
    internal static JsonObject Input(params JsonObject[] steps) => Program("input", steps);

    /// <summary>An output-direction envelope.</summary>
    internal static JsonObject Output(params JsonObject[] steps) => Program("output", steps);

    /// <summary>A limits block, defaulting to the format's own values.</summary>
    internal static JsonObject Limits(
        int steps = 64,
        int depth = 32,
        int nodes = 8192,
        long output = 256L * 1024,
        int fanout = 1024)
        => new()
        {
            ["maxSteps"] = steps,
            ["maxDepth"] = depth,
            ["maxNodes"] = nodes,
            ["maxOutputBytes"] = output,
            ["maxArrayFanout"] = fanout,
        };

    /// <summary>A copy from the agent document into a request part.</summary>
    internal static JsonObject Copy(string source = "/name", string target = "/query/name")
        => new()
        {
            ["op"] = "copy",
            ["source"] = source,
            ["target"] = target,
            ["onMissing"] = "skip",
        };

    /// <summary>Validates a document against the default ceiling and no file slots.</summary>
    internal static IReadOnlyList<TransformFinding> Validate(JsonObject document)
        => TransformValidation.Validate(document, Ceiling, NoFiles);

    /// <summary>Validates a document against a stated ceiling.</summary>
    internal static IReadOnlyList<TransformFinding> Validate(
        JsonObject document,
        TransformCeilingValues ceiling)
        => TransformValidation.Validate(document, ceiling, NoFiles);

    /// <summary>Validates a document for an operation whose named arguments are file slots.</summary>
    internal static IReadOnlyList<TransformFinding> Validate(JsonObject document, params string[] files)
        => TransformValidation.Validate(
            document,
            Ceiling,
            new HashSet<string>(files, StringComparer.Ordinal));

    /// <summary>The single finding, asserting there is exactly one.</summary>
    internal static TransformFinding Only(IReadOnlyList<TransformFinding> findings)
        => findings.Count == 1
            ? findings[0]
            : throw new InvalidOperationException(
                $"Expected one finding, got {findings.Count}: " +
                string.Join("; ", findings.Select(static finding => $"{finding.Code} at {finding.Pointer}")));
}
