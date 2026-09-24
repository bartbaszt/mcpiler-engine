using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.JmesPath;

/// <summary>
/// Writes a parsed JSON value as the profile's canonical bytes, charging declared bounds.
/// </summary>
/// <remarks>
/// <para>
/// Canonicalization here is about the value, not the source text: object members are emitted in
/// UTF-16 code-unit ordinal name order — the same rule <c>Manifest.Canonical.CanonicalJson</c>
/// applies, and the reason a permuted upstream body reaches the evaluator in one deterministic
/// order — while arrays keep their order because it is semantic. Scalars are re-encoded from
/// their parsed value, so two source spellings of the same string produce the same bytes, and
/// numbers keep their original lexical token because a number's spelling is part of the value a
/// caller reads back.
/// </para>
/// <para>
/// Duplicate member names are preserved and stay in source order among themselves, because
/// ordering is a stable sort. Collapsing them would silently pick one of two values.
/// </para>
/// <para>
/// The writer is bounded rather than truncating: a value that does not fit is refused with its
/// own class, never emitted partially. The same walk charges node count and depth, so an
/// over-budget value is refused while it is being written and nothing oversized is handed back.
/// </para>
/// </remarks>
internal static class JmesPathCanonicalizer
{
    /// <summary>
    /// Canonicalizes <paramref name="element"/> under one declared budget.
    /// </summary>
    /// <param name="element">The parsed value to write.</param>
    /// <param name="budget">Which bounds this walk is charged against.</param>
    /// <param name="maxNodes">The node bound.</param>
    /// <param name="maxDepth">The depth bound.</param>
    /// <param name="maxBytes">
    /// The serialized byte bound. For a result this is the declared output bound; for a body
    /// being prepared it is the transport frame cap.
    /// </param>
    /// <param name="bytes">The canonical bytes, or null when the walk refused.</param>
    /// <param name="metrics">The measured shape when the walk completed.</param>
    /// <param name="failure">The refusal when the walk aborted.</param>
    internal static bool TryCanonicalize(
        JsonElement element,
        JmesPathBudget budget,
        long maxNodes,
        int maxDepth,
        long maxBytes,
        [NotNullWhen(true)] out byte[]? bytes,
        out JmesPathValueMetrics metrics,
        [NotNullWhen(false)] out JmesPathFailure? failure)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxNodes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxDepth, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 1);

        bytes = null;
        metrics = default;
        failure = null;

        using var buffer = new BoundedJsonBuffer(maxBytes);
        var state = new WalkState(budget, maxNodes, maxDepth);

        try
        {
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
            {
                Indented = false,
                SkipValidation = false,
                MaxDepth = Math.Min(maxDepth + 1, 1000),
            }))
            {
                failure = Write(writer, element, depth: 1, state);

                if (failure is not null)
                {
                    return false;
                }
            }
        }
        catch (BoundedJsonBuffer.BufferFullException)
        {
            failure = OverBytes(budget, maxBytes);
            return false;
        }

        bytes = buffer.ToArray();
        metrics = new JmesPathValueMetrics(state.Nodes, state.Deepest);
        return true;
    }

    private static JmesPathFailure? Write(
        Utf8JsonWriter writer,
        JsonElement element,
        int depth,
        WalkState state)
    {
        state.Nodes++;

        if (state.Nodes > state.MaxNodes)
        {
            return new JmesPathFailure(
                state.Budget == JmesPathBudget.Input
                    ? JmesPathFailureClass.InputTooManyNodes
                    : JmesPathFailureClass.ResultTooManyNodes,
                string.Create(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $"The value has more than {state.MaxNodes} nodes."));
        }

        if (depth > state.MaxDepth)
        {
            return new JmesPathFailure(
                state.Budget == JmesPathBudget.Input
                    ? JmesPathFailureClass.InputTooDeep
                    : JmesPathFailureClass.ResultTooDeep,
                string.Create(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $"The value nests deeper than {state.MaxDepth} levels."));
        }

        if (depth > state.Deepest)
        {
            state.Deepest = depth;
        }

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();

                // Stable sort: duplicate names keep their relative order.
                foreach (JsonProperty member in element.EnumerateObject().OrderBy(
                    static member => member.Name,
                    StringComparer.Ordinal))
                {
                    writer.WritePropertyName(member.Name);

                    if (Write(writer, member.Value, depth + 1, state) is { } nested)
                    {
                        return nested;
                    }
                }

                writer.WriteEndObject();
                return null;

            case JsonValueKind.Array:
                writer.WriteStartArray();

                foreach (JsonElement item in element.EnumerateArray())
                {
                    if (Write(writer, item, depth + 1, state) is { } nested)
                    {
                        return nested;
                    }
                }

                writer.WriteEndArray();
                return null;

            default:
                // Scalars keep their parsed value; WriteTo re-encodes deterministically.
                element.WriteTo(writer);
                return null;
        }
    }

    private static JmesPathFailure OverBytes(JmesPathBudget budget, long maxBytes)
        => budget == JmesPathBudget.Input
            ? new JmesPathFailure(
                JmesPathFailureClass.InputNotJson,
                string.Create(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $"The body is larger than the {maxBytes}-byte transport frame cap once normalized."))
            : new JmesPathFailure(
                JmesPathFailureClass.OutputTooManyBytes,
                string.Create(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $"The projected value is larger than maxOutputBytes={maxBytes} bytes."));

    private sealed class WalkState(JmesPathBudget budget, long maxNodes, int maxDepth)
    {
        internal JmesPathBudget Budget { get; } = budget;

        internal long MaxNodes { get; } = maxNodes;

        internal int MaxDepth { get; } = maxDepth;

        internal long Nodes { get; set; }

        internal int Deepest { get; set; }
    }
}
