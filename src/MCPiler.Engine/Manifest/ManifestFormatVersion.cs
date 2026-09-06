using System.Globalization;

namespace MCPiler.Engine.Manifest;

/// <summary>
/// The format version of a MCPiler Manifest, expressed as <c>MAJOR.MINOR</c>.
/// </summary>
/// <remarks>
/// The manifest format is versioned independently of the Engine product version. Engine
/// supports a bounded range of format versions and refuses anything outside it, stating
/// both the observed version and the supported range so the refusal is actionable.
/// </remarks>
public readonly record struct ManifestFormatVersion
{
    /// <summary>Creates a manifest format version.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Either component is negative.</exception>
    public ManifestFormatVersion(int major, int minor)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(major);
        ArgumentOutOfRangeException.ThrowIfNegative(minor);

        Major = major;
        Minor = minor;
    }

    /// <summary>Major component. A change signals an intentionally breaking format revision.</summary>
    public int Major { get; }

    /// <summary>Minor component. A change signals a backward-compatible format addition.</summary>
    public int Minor { get; }

    /// <summary>
    /// Parses a strict <c>MAJOR.MINOR</c> value. Leading zeros, signs, whitespace, a third
    /// component, and any non-digit character are rejected: the manifest format has one
    /// spelling per version so two manifests cannot disagree about their own version.
    /// </summary>
    public static bool TryParse(string? value, out ManifestFormatVersion version)
    {
        version = default;

        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        var separator = value.IndexOf('.', StringComparison.Ordinal);
        if (separator <= 0 || separator == value.Length - 1)
        {
            return false;
        }

        var majorText = value.AsSpan(0, separator);
        var minorText = value.AsSpan(separator + 1);

        if (!TryParseComponent(majorText, out var major) || !TryParseComponent(minorText, out var minor))
        {
            return false;
        }

        version = new ManifestFormatVersion(major, minor);
        return true;
    }

    private static bool TryParseComponent(ReadOnlySpan<char> text, out int value)
    {
        value = 0;

        if (text.IsEmpty || text.Length > 9)
        {
            return false;
        }

        // Reject a leading zero on a multi-digit component so "0.01" cannot masquerade as "0.1".
        if (text.Length > 1 && text[0] == '0')
        {
            return false;
        }

        foreach (var c in text)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>Returns true when this version is at least <paramref name="other"/>.</summary>
    public bool IsAtLeast(ManifestFormatVersion other)
        => Major != other.Major ? Major > other.Major : Minor >= other.Minor;

    /// <summary>Returns true when this version is at most <paramref name="other"/>.</summary>
    public bool IsAtMost(ManifestFormatVersion other)
        => Major != other.Major ? Major < other.Major : Minor <= other.Minor;

    /// <inheritdoc />
    public override string ToString()
        => string.Create(CultureInfo.InvariantCulture, $"{Major}.{Minor}");
}
