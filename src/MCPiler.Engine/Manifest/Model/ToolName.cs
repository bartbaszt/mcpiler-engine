using System.Text;

namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// Deterministic advertised tool names.
/// </summary>
/// <remarks>
/// <para>
/// A tool name derives from the operation slug and from nothing else. It never derives from
/// an authoring identifier, an upstream operation identifier, or a source operation key.
/// The slug is already the manifest-local identity and is already unique, so the derivation
/// is stable against reordering, renaming a display name, and re-export.
/// </para>
/// <para>
/// Sanitisation can still collapse two distinct slugs onto one name, so allocation applies a
/// numeric suffix. Suffixes are assigned in slug ordinal order rather than in advertisement
/// order, which keeps a name attached to its operation when the exposure list is reordered.
/// </para>
/// </remarks>
public static class ToolName
{
    /// <summary>The fallback name for a slug that sanitises to nothing usable.</summary>
    public const string Fallback = "operation";

    /// <summary>
    /// Sanitises one slug to the permitted tool-name character set and length.
    /// </summary>
    /// <param name="slug">The operation slug.</param>
    /// <param name="maxLength">The maximum advertised name length.</param>
    /// <returns>A name matching <c>[A-Za-z0-9_.-]{1,maxLength}</c>.</returns>
    public static string Sanitize(string slug, int maxLength = ManifestTool.MaxNameLength)
    {
        ArgumentNullException.ThrowIfNull(slug);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxLength, 1);

        var builder = new StringBuilder(slug.Length);
        foreach (var character in slug)
        {
            builder.Append(char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.'
                ? character
                : '_');
        }

        var sanitized = builder.ToString().Trim('_');
        if (sanitized.Length == 0)
        {
            sanitized = Fallback;
        }

        return Truncate(sanitized, maxLength);
    }

    /// <summary>
    /// Allocates a unique advertised name for every supplied slug.
    /// </summary>
    /// <param name="slugs">The operation slugs to name.</param>
    /// <param name="maxLength">The maximum advertised name length.</param>
    /// <returns>A slug-keyed name map, ordinal.</returns>
    public static IReadOnlyDictionary<string, string> Allocate(
        IEnumerable<string> slugs,
        int maxLength = ManifestTool.MaxNameLength)
    {
        ArgumentNullException.ThrowIfNull(slugs);

        var allocated = new Dictionary<string, string>(StringComparer.Ordinal);
        var used = new HashSet<string>(StringComparer.Ordinal);

        // Ordinal slug order, not advertisement order: the exposure list is allowed to
        // change without silently moving a bare name from one operation to another.
        foreach (var slug in slugs.Distinct(StringComparer.Ordinal).OrderBy(static slug => slug, StringComparer.Ordinal))
        {
            var baseName = Sanitize(slug, maxLength);
            var candidate = baseName;
            var suffix = 2;
            while (!used.Add(candidate))
            {
                candidate = Truncate($"{baseName}_{suffix}", maxLength);
                suffix++;
            }

            allocated[slug] = candidate;
        }

        return allocated;
    }

    /// <summary>True when the name is within the advertised character set and length.</summary>
    /// <param name="name">The candidate name.</param>
    /// <param name="maxLength">The maximum advertised name length.</param>
    public static bool IsWellFormed(string? name, int maxLength = ManifestTool.MaxNameLength)
        => name is { Length: > 0 }
            && name.Length <= maxLength
            && name.All(static character =>
                char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.');

    private static string Truncate(string name, int maxLength)
        => name.Length <= maxLength ? name : name[..maxLength];
}
