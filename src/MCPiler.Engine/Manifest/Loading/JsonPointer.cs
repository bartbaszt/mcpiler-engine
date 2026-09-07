using System.Text;
using System.Text.Json.Nodes;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// RFC 6901 JSON Pointer helpers used for diagnostic locations and local schema references.
/// </summary>
/// <remarks>
/// Escaping matters for both jobs. A diagnostic pointing at a member named <c>a/b</c> must
/// escape the slash or the location it reports is a different node, and a reference resolver
/// that skips unescaping silently fails to find a legitimately named component.
/// </remarks>
public static class JsonPointer
{
    /// <summary>The fragment prefix a manifest-local reference must start with.</summary>
    public const string LocalFragmentPrefix = "#";

    /// <summary>Escapes one reference token for inclusion in a pointer.</summary>
    public static string Escape(string token)
    {
        ArgumentNullException.ThrowIfNull(token);

        // Order is normative: '~' first, otherwise an escaped '/' would be re-escaped.
        return token
            .Replace("~", "~0", StringComparison.Ordinal)
            .Replace("/", "~1", StringComparison.Ordinal);
    }

    /// <summary>Unescapes one reference token read from a pointer.</summary>
    public static string Unescape(string token)
    {
        ArgumentNullException.ThrowIfNull(token);

        return token
            .Replace("~1", "/", StringComparison.Ordinal)
            .Replace("~0", "~", StringComparison.Ordinal);
    }

    /// <summary>Builds a pointer from already-unescaped tokens.</summary>
    public static string Build(params string[] tokens)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        if (tokens.Length == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();

        foreach (var token in tokens)
        {
            builder.Append('/').Append(Escape(token));
        }

        return builder.ToString();
    }

    /// <summary>
    /// True when <paramref name="pointer"/> is a syntactically valid RFC 6901 pointer.
    /// </summary>
    /// <remarks>
    /// A pointer is either empty or begins with <c>/</c>, and every <c>~</c> must introduce a
    /// valid escape. A malformed escape is refused rather than passed through, because
    /// <c>~2</c> would otherwise silently address a member nobody declared.
    /// </remarks>
    public static bool IsSyntacticallyValid(string? pointer)
    {
        if (pointer is null)
        {
            return false;
        }

        if (pointer.Length == 0)
        {
            return true;
        }

        if (pointer[0] != '/')
        {
            return false;
        }

        for (var index = 0; index < pointer.Length; index++)
        {
            if (pointer[index] != '~')
            {
                continue;
            }

            if (index + 1 >= pointer.Length || pointer[index + 1] is not ('0' or '1'))
            {
                return false;
            }

            index++;
        }

        return true;
    }

    /// <summary>
    /// True when <paramref name="reference"/> is a fragment-only reference into the same
    /// document.
    /// </summary>
    /// <remarks>
    /// Anything else, including a bare relative path or an absolute URL, is refused. There is
    /// no base URI and no document graph in the manifest format, so a non-local reference has
    /// nothing to resolve against and must never trigger a fetch.
    /// </remarks>
    public static bool IsLocalFragment(string? reference)
        => reference is not null
            && reference.StartsWith(LocalFragmentPrefix, StringComparison.Ordinal);

    /// <summary>
    /// Resolves a fragment-only reference against <paramref name="document"/>.
    /// </summary>
    /// <param name="document">The section document the reference lives in.</param>
    /// <param name="reference">A reference such as <c>#/components/schemas/Pet</c>.</param>
    /// <param name="target">The resolved node, when the pointer resolves.</param>
    public static bool TryResolve(JsonNode document, string? reference, out JsonNode? target)
    {
        ArgumentNullException.ThrowIfNull(document);

        target = null;

        if (!IsLocalFragment(reference))
        {
            return false;
        }

        var pointer = reference![LocalFragmentPrefix.Length..];

        if (pointer.Length == 0)
        {
            target = document;
            return true;
        }

        if (pointer[0] != '/')
        {
            // "#Pet" is a plain-name fragment, not a pointer. It is refused rather than
            // guessed at, because guessing would make two documents resolve differently.
            return false;
        }

        var current = document;

        foreach (var raw in pointer[1..].Split('/'))
        {
            var token = Unescape(raw);

            switch (current)
            {
                case JsonObject obj when obj.TryGetPropertyValue(token, out var next) && next is not null:
                    current = next;
                    break;

                case JsonArray array when int.TryParse(token, out var index)
                    && index >= 0
                    && index < array.Count
                    && array[index] is { } element:
                    current = element;
                    break;

                default:
                    return false;
            }
        }

        target = current;
        return true;
    }
}
