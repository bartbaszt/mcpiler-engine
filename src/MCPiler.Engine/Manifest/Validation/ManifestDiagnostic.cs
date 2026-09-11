using System.Globalization;

namespace MCPiler.Engine.Manifest.Validation;

/// <summary>How severely a diagnostic affects loading.</summary>
public enum DiagnosticSeverity
{
    /// <summary>
    /// The manifest is unusable as declared. Loading fails closed.
    /// </summary>
    Error,

    /// <summary>
    /// The manifest loads, but something an operator should know about is true of it.
    /// </summary>
    Warning,
}

/// <summary>
/// One finding about a manifest, located precisely enough to act on.
/// </summary>
/// <param name="Code">
/// A stable identifier from <see cref="ManifestDiagnosticCodes"/>. Part of the public
/// contract; the message text is not.
/// </param>
/// <param name="Severity">Whether this blocks loading.</param>
/// <param name="Message">
/// An operator-facing explanation naming the failing invariant. Never a bare
/// "manifest invalid", and never carrying a secret value.
/// </param>
/// <param name="Section">
/// The section name this finding belongs to, or <c>null</c> for a root-level finding.
/// </param>
/// <param name="Pointer">
/// A JSON Pointer into the offending document, or <c>null</c> when the whole document is at
/// fault.
/// </param>
public sealed record ManifestDiagnostic(
    string Code,
    DiagnosticSeverity Severity,
    string Message,
    string? Section = null,
    string? Pointer = null)
{
    /// <summary>
    /// The reason code from a nested grammar's own vocabulary, or <c>null</c> when the finding
    /// belongs entirely to the manifest format.
    /// </summary>
    /// <remarks>
    /// A transformation program is a separately versioned contract carried inside a manifest,
    /// and it states its own reasons. Without this, every way a program can be wrong would
    /// arrive as one manifest code and the specific, machine-readable reason the format
    /// promises would exist only in the message - which this record says is not contractual.
    /// </remarks>
    public string? ProgramCode { get; init; }

    /// <summary>True when this finding blocks loading.</summary>
    public bool IsError => Severity == DiagnosticSeverity.Error;

    /// <summary>Creates an error.</summary>
    public static ManifestDiagnostic Error(
        string code,
        string message,
        string? section = null,
        string? pointer = null)
        => new(code, DiagnosticSeverity.Error, message, section, pointer);

    /// <summary>Creates a warning.</summary>
    public static ManifestDiagnostic Warning(
        string code,
        string message,
        string? section = null,
        string? pointer = null)
        => new(code, DiagnosticSeverity.Warning, message, section, pointer);

    /// <summary>Renders the finding for a log line or CLI output.</summary>
    public override string ToString()
    {
        var location = (Section, Pointer) switch
        {
            (null, null) => "(root)",
            ({ } section, null) => section,
            (null, { } pointer) => pointer,
            ({ } section, { } pointer) => string.Create(CultureInfo.InvariantCulture, $"{section}{pointer}"),
        };

        var code = ProgramCode is null
            ? Code
            : string.Create(CultureInfo.InvariantCulture, $"{Code} ({ProgramCode})");

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{Severity.ToString().ToLowerInvariant()} {code} at {location}: {Message}");
    }
}

/// <summary>
/// Text rules shared by every diagnostic producer.
/// </summary>
public static class DiagnosticText
{
    /// <summary>
    /// Maximum characters of a rejected input value echoed back into a message.
    /// </summary>
    /// <remarks>
    /// A diagnostic is an operator-facing string that ends up in logs. Echoing an unbounded
    /// value from a hostile manifest turns a validation message into a log-injection and
    /// memory-amplification vector, so every producer truncates through
    /// <see cref="Echo"/> rather than interpolating raw input.
    /// </remarks>
    public const int MaxEchoedLength = 32;

    /// <summary>The marker appended to a truncated value.</summary>
    public const string TruncationMarker = "\u2026";

    /// <summary>Truncates <paramref name="value"/> for safe inclusion in a message.</summary>
    public static string Echo(string? value)
    {
        if (value is null)
        {
            return "(none)";
        }

        return value.Length <= MaxEchoedLength
            ? value
            : string.Concat(value.AsSpan(0, MaxEchoedLength), TruncationMarker);
    }

    /// <summary>Renders a closed vocabulary for an "expected one of" message.</summary>
    public static string List(IEnumerable<string> values)
        => string.Join(", ", values);
}
