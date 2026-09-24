using System.Globalization;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest;

/// <summary>Why a declared manifest format version was accepted or refused.</summary>
public enum ManifestFormatCompatibility
{
    /// <summary>The version is inside the supported range.</summary>
    Supported,

    /// <summary>No format version was declared. Engine fails closed rather than guessing.</summary>
    Missing,

    /// <summary>A value was declared but is not a strict <c>MAJOR.MINOR</c> version.</summary>
    Malformed,

    /// <summary>A valid version outside the supported range.</summary>
    Unsupported,
}

/// <summary>The outcome of checking a declared manifest format version.</summary>
/// <param name="Compatibility">Closed classification of the outcome.</param>
/// <param name="Version">The parsed version, or <c>null</c> when it was missing or malformed.</param>
/// <param name="Message">
/// An operator-facing explanation. It always names the supported range so a refusal tells
/// the reader what to do next, and it never echoes unbounded input back to the caller.
/// </param>
public sealed record ManifestFormatEvaluation(
    ManifestFormatCompatibility Compatibility,
    ManifestFormatVersion? Version,
    string Message)
{
    /// <summary>True only when the manifest may be loaded.</summary>
    public bool IsSupported => Compatibility == ManifestFormatCompatibility.Supported;
}

/// <summary>
/// The range of MCPiler Manifest format versions this Engine build understands.
/// </summary>
/// <remarks>
/// Engine fails closed on a missing, malformed or out-of-range format version. During
/// alpha the format stays in the <c>0.x</c> range and no compatibility is promised
/// across minor versions.
/// </remarks>
public static class ManifestFormatSupport
{
    /// <summary>Oldest manifest format version this Engine build accepts.</summary>
    /// <remarks>
    /// The range is a single version. While the major version is 0 a minor bump may be
    /// breaking, so a 0.1 manifest is refused rather than migrated: it is expected to be
    /// re-exported.
    /// </remarks>
    public static ManifestFormatVersion Minimum { get; } = new(0, 3);

    /// <summary>Newest manifest format version this Engine build accepts.</summary>
    public static ManifestFormatVersion Maximum { get; } = new(0, 3);

    /// <summary>Human-readable description of the supported range, for diagnostics.</summary>
    public static string SupportedRange { get; } =
        Minimum == Maximum
            ? Minimum.ToString()
            : string.Create(CultureInfo.InvariantCulture, $"{Minimum} to {Maximum}");

    /// <summary>Oldest authentication section version this Engine build accepts.</summary>
    /// <remarks>
    /// Section versions are independent of the root: a section gains a version when its
    /// closed vocabulary grows. While the format is pre-1.0, a superseded section version
    /// is refused rather than migrated: producers re-export. The supported range is exactly
    /// the current version, pinned by the section-version matrix tests so widening it stays
    /// a decision rather than an accident.
    /// </remarks>
    public static int AuthenticationFormatVersionMinimum => Model.AuthenticationSection.FormatVersion;

    /// <summary>Newest authentication section version this Engine build accepts.</summary>
    public static int AuthenticationFormatVersionMaximum => Model.AuthenticationSection.FormatVersion;

    /// <summary>Oldest credentials section version this Engine build accepts.</summary>
    public static int CredentialsFormatVersionMinimum => Model.CredentialsSection.FormatVersion;

    /// <summary>Newest credentials section version this Engine build accepts.</summary>
    public static int CredentialsFormatVersionMaximum => Model.CredentialsSection.FormatVersion;

    /// <summary>Returns true when <paramref name="version"/> is inside the supported range.</summary>
    public static bool IsSupported(ManifestFormatVersion version)
        => version.IsAtLeast(Minimum) && version.IsAtMost(Maximum);

    /// <summary>
    /// Classifies a declared format version and produces an actionable message.
    /// </summary>
    /// <param name="declaredVersion">
    /// The raw value read from the manifest root, or <c>null</c> when the manifest declared none.
    /// </param>
    public static ManifestFormatEvaluation Evaluate(string? declaredVersion)
    {
        if (string.IsNullOrWhiteSpace(declaredVersion))
        {
            return new ManifestFormatEvaluation(
                ManifestFormatCompatibility.Missing,
                Version: null,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The manifest does not declare a format version. This Engine supports manifest format {SupportedRange}."));
        }

        if (!ManifestFormatVersion.TryParse(declaredVersion, out var version))
        {
            return new ManifestFormatEvaluation(
                ManifestFormatCompatibility.Malformed,
                Version: null,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The manifest declares format version '{Echo(declaredVersion)}', which is not a MAJOR.MINOR version. This Engine supports manifest format {SupportedRange}."));
        }

        if (!IsSupported(version))
        {
            var direction = version.IsAtLeast(Minimum) ? "newer" : "older";

            return new ManifestFormatEvaluation(
                ManifestFormatCompatibility.Unsupported,
                version,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The manifest declares format version {version}, which is {direction} than this Engine supports. This Engine supports manifest format {SupportedRange}."));
        }

        return new ManifestFormatEvaluation(
            ManifestFormatCompatibility.Supported,
            version,
            string.Create(CultureInfo.InvariantCulture, $"Manifest format {version} is supported."));
    }

    private static string Echo(string value) => DiagnosticText.Echo(value);
}
