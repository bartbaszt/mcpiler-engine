namespace MCPiler.Engine.Manifest.Loading;

/// <summary>Why a section path was accepted or refused.</summary>
public enum ManifestPathVerdict
{
    /// <summary>The path is a safe bundle-relative reference.</summary>
    Accepted,

    /// <summary>The path is empty or whitespace.</summary>
    Empty,

    /// <summary>The path is absolute, rooted, or names a drive or share.</summary>
    Absolute,

    /// <summary>The path is a URI rather than a bundle-relative path.</summary>
    Uri,

    /// <summary>The path uses a backslash separator and is therefore not portable.</summary>
    BackslashSeparator,

    /// <summary>The path contains a <c>..</c> segment.</summary>
    ParentSegment,

    /// <summary>The path leaves the bundle directory after normalization.</summary>
    EscapesBundle,
}

/// <summary>
/// The only reference-resolution surface in the manifest format.
/// </summary>
/// <remarks>
/// <para>
/// A section path is deliberately not a URI and deliberately not resolved by a general
/// resolver. It is a relative path inside one directory, and everything else is refused. That
/// keeps the format's entire external-reference attack surface to this one type.
/// </para>
/// <para>
/// A backslash separator is refused rather than translated. A bundle authored on Windows with
/// <c>sections\operations.json</c> would silently fail to resolve on Linux, so the format
/// requires forward slashes and says so at load time instead of producing a
/// "section file missing" mystery on the other platform.
/// </para>
/// </remarks>
public static class ManifestPathPolicy
{
    /// <summary>The separator a section path must use.</summary>
    public const char Separator = '/';

    /// <summary>
    /// Validates <paramref name="declaredPath"/> and resolves it against
    /// <paramref name="bundleDirectory"/>.
    /// </summary>
    /// <param name="declaredPath">The path as written in the section index.</param>
    /// <param name="bundleDirectory">
    /// The absolute directory containing the root document. Every section must resolve inside
    /// it.
    /// </param>
    /// <param name="resolvedPath">
    /// The absolute resolved path when the verdict is
    /// <see cref="ManifestPathVerdict.Accepted"/>, otherwise <c>null</c>.
    /// </param>
    public static ManifestPathVerdict Resolve(
        string? declaredPath,
        string bundleDirectory,
        out string? resolvedPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        resolvedPath = null;

        if (string.IsNullOrWhiteSpace(declaredPath))
        {
            return ManifestPathVerdict.Empty;
        }

        if (declaredPath.Contains('\\', StringComparison.Ordinal))
        {
            return ManifestPathVerdict.BackslashSeparator;
        }

        if (Path.IsPathRooted(declaredPath) || declaredPath.StartsWith(Separator))
        {
            return ManifestPathVerdict.Absolute;
        }

        // A scheme-qualified value is a URI, not a bundle path. This check follows the rooted
        // test so a filesystem path such as "/etc/passwd" cannot be reinterpreted as a URI.
        if (Uri.TryCreate(declaredPath, UriKind.Absolute, out _))
        {
            return ManifestPathVerdict.Uri;
        }

        var segments = declaredPath.Split(Separator);

        foreach (var segment in segments)
        {
            if (string.Equals(segment, "..", StringComparison.Ordinal))
            {
                return ManifestPathVerdict.ParentSegment;
            }
        }

        var root = Path.GetFullPath(bundleDirectory);
        var candidate = Path.GetFullPath(Path.Combine(root, declaredPath));

        // Normalization is not enough on its own: a symlink or a case-insensitive filesystem
        // can still land outside, so containment is asserted on the normalized result rather
        // than inferred from the absence of "..".
        if (!IsContained(candidate, root))
        {
            return ManifestPathVerdict.EscapesBundle;
        }

        resolvedPath = candidate;
        return ManifestPathVerdict.Accepted;
    }

    /// <summary>Explains a verdict for a diagnostic message.</summary>
    public static string Explain(ManifestPathVerdict verdict) => verdict switch
    {
        ManifestPathVerdict.Accepted => "the path is a valid bundle-relative reference",
        ManifestPathVerdict.Empty => "a section path must be a non-empty relative path",
        ManifestPathVerdict.Absolute => "a section path must be relative, not absolute",
        ManifestPathVerdict.Uri => "a section path must be a relative path, not a URI",
        ManifestPathVerdict.BackslashSeparator =>
            "a section path must use '/' separators so the bundle resolves on every platform",
        ManifestPathVerdict.ParentSegment => "a section path must not contain a '..' segment",
        ManifestPathVerdict.EscapesBundle => "a section path must resolve inside the bundle directory",
        _ => "the path was refused",
    };

    private static bool IsContained(string candidate, string root)
    {
        var normalizedRoot = root.EndsWith(Path.DirectorySeparatorChar)
            ? root
            : root + Path.DirectorySeparatorChar;

        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        return candidate.StartsWith(normalizedRoot, comparison);
    }
}
