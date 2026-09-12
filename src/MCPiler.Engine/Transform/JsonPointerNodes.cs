using System.Globalization;
using System.Text.Json.Nodes;

namespace MCPiler.Engine.Transform;

/// <summary>
/// Reading and writing a mutable JSON document through RFC 6901 pointers.
/// </summary>
/// <remarks>
/// <para>
/// Two features address a document this way: a transformation program's steps and a compound
/// workflow's input mappings. They are the same pointer vocabulary over the same part-scoped
/// documents, so they resolve through one implementation. Two would agree on the ordinary
/// cases and diverge on the ones nobody writes a test for first — a missing intermediate, a
/// numeric segment against an object, an append at the end of an array.
/// </para>
/// <para>
/// A failure is reported rather than thrown, because the two callers classify it differently:
/// a transformation step names a program code, and a compound mapping names the step whose
/// document could not be assembled.
/// </para>
/// </remarks>
internal static class JsonPointerNodes
{
    /// <summary>Extends <paramref name="target"/> with one escaped reference token.</summary>
    internal static string Join(string target, string name)
        => target + "/" + name.Replace("~", "~0", StringComparison.Ordinal).Replace("/", "~1", StringComparison.Ordinal);

    /// <summary>Splits a pointer into its unescaped reference tokens.</summary>
    internal static string[] Segments(string pointer)
        => pointer.Length == 0
            ? []
            : [.. pointer[1..]
                .Split('/')
                .Select(static segment => segment
                    .Replace("~1", "/", StringComparison.Ordinal)
                    .Replace("~0", "~", StringComparison.Ordinal))];

    /// <summary>Resolves a pointer, returning null when it addresses nothing.</summary>
    /// <remarks>
    /// A JSON null is nothing. An object member holding null and an array element holding null
    /// resolve the same way, because a caller asking whether a value is there gets one answer
    /// regardless of which container it sits in.
    /// </remarks>
    internal static JsonNode? Read(JsonNode root, string pointer)
    {
        JsonNode current = root;

        foreach (string segment in Segments(pointer))
        {
            switch (current)
            {
                case JsonObject members:
                    if (!members.TryGetPropertyValue(segment, out JsonNode? next) || next is null)
                    {
                        return null;
                    }

                    current = next;
                    break;

                case JsonArray array when int.TryParse(segment, NumberStyles.None, CultureInfo.InvariantCulture, out int at):
                    if (at < 0 || at >= array.Count || array[at] is not { } element)
                    {
                        return null;
                    }

                    current = element;
                    break;

                default:
                    return null;
            }
        }

        return current;
    }

    /// <summary>
    /// Writes <paramref name="value"/> at <paramref name="pointer"/>, creating missing
    /// intermediate objects.
    /// </summary>
    /// <param name="root">The document written into. Never replaced; see the remarks.</param>
    /// <param name="pointer">A non-empty pointer.</param>
    /// <param name="value">The value written at the leaf.</param>
    /// <param name="onNode">
    /// Called once per visited or created node, so a caller that accounts for document size
    /// counts the same nodes this walk touches.
    /// </param>
    /// <param name="failure">Why the pointer does not address a writable place.</param>
    /// <remarks>
    /// The empty pointer addresses the document itself and cannot be served through a node
    /// reference, so it is the caller's to handle. Every caller that permits replacing a root
    /// owns a holder for it; a caller that does not permit it refuses the empty pointer
    /// instead of silently writing somewhere else.
    /// </remarks>
    internal static bool TryWrite(
        JsonNode root,
        string pointer,
        JsonNode? value,
        Action onNode,
        out string? failure)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(onNode);

        string[] segments = Segments(pointer);

        if (segments.Length == 0)
        {
            failure = $"The target path '{pointer}' addresses the document itself.";
            return false;
        }

        JsonNode current = root;

        for (int index = 0; index < segments.Length - 1; index++)
        {
            string segment = segments[index];
            onNode();

            switch (current)
            {
                case JsonObject members:
                    if (!members.TryGetPropertyValue(segment, out JsonNode? child) || child is null)
                    {
                        child = new JsonObject();
                        members[segment] = child;
                        onNode();
                    }

                    current = child;
                    break;

                case JsonArray array
                    when int.TryParse(segment, NumberStyles.None, CultureInfo.InvariantCulture, out int at)
                        && at >= 0
                        && at < array.Count
                        && array[at] is { } element:
                    current = element;
                    break;

                default:
                    failure = $"The target path '{pointer}' cannot be created: '{segment}' does not address a container.";
                    return false;
            }
        }

        string leaf = segments[^1];
        onNode();

        if (current is JsonObject target)
        {
            target[leaf] = value;
            failure = null;
            return true;
        }

        if (current is JsonArray sequence
            && int.TryParse(leaf, NumberStyles.None, CultureInfo.InvariantCulture, out int position)
            && position >= 0
            && position <= sequence.Count)
        {
            if (position == sequence.Count)
            {
                sequence.Add(value);
            }
            else
            {
                sequence[position] = value;
            }

            failure = null;
            return true;
        }

        failure = $"The target path '{pointer}' does not address a writable container.";
        return false;
    }
}
