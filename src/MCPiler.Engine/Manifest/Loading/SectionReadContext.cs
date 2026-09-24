using System.Globalization;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// The one strict JSON reading implementation every manifest reader uses.
/// </summary>
/// <remarks>
/// <para>
/// Two properties matter more than convenience here. First, a member whose JSON type is
/// wrong must produce a diagnostic rather than silently read as absent: a
/// <c>"required": "yes"</c> that quietly becomes <c>false</c> turns an authoring typo into a
/// changed contract. Second, every reader must spell a refusal the same way, so the rules
/// live in one type instead of being reimplemented per section.
/// </para>
/// <para>
/// The context accumulates diagnostics rather than throwing. A hand-authored manifest is
/// most useful when one pass reports every problem, so the reader is also the authoring
/// tool.
/// </para>
/// </remarks>
public sealed class SectionReadContext
{
    private readonly ICollection<ManifestDiagnostic> _diagnostics;

    /// <summary>Creates a context that reports against <paramref name="section"/>.</summary>
    /// <param name="section">The section being read, or <c>null</c> for the manifest root.</param>
    /// <param name="diagnostics">The collection findings are appended to.</param>
    public SectionReadContext(string? section, ICollection<ManifestDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);

        Section = section;
        _diagnostics = diagnostics;
    }

    /// <summary>The section this context reports against, or <c>null</c> for the root.</summary>
    public string? Section { get; }

    /// <summary>True when at least one error has been reported through this context.</summary>
    public bool HasErrors { get; private set; }

    /// <summary>
    /// Returns a context over the same diagnostics that reports against another section.
    /// </summary>
    public SectionReadContext ForSection(string? section) => new(section, _diagnostics);

    /// <summary>Reports an error.</summary>
    public void Error(string code, string message, string pointer = "")
    {
        _diagnostics.Add(ManifestDiagnostic.Error(code, message, Section, pointer));
        HasErrors = true;
    }

    /// <summary>Reports a warning.</summary>
    public void Warning(string code, string message, string pointer = "")
        => _diagnostics.Add(ManifestDiagnostic.Warning(code, message, Section, pointer));

    /// <summary>
    /// Reports every member of <paramref name="document"/> that this format version does not
    /// define at <paramref name="pointer"/>.
    /// </summary>
    public void RejectUnknownMembers(JsonObject document, IReadOnlyList<string> allowed, string pointer)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(allowed);

        foreach (var (name, _) in document)
        {
            if (allowed.Contains(name, StringComparer.Ordinal))
            {
                continue;
            }

            Error(
                ManifestDiagnosticCodes.UnknownMember,
                $"'{DiagnosticText.Echo(name)}' is not a member this manifest format defines here. Expected one of: {DiagnosticText.List(allowed)}.",
                Child(pointer, name));
        }
    }

    /// <summary>
    /// Reads the section payload as an object, reporting when it is absent or not an object.
    /// </summary>
    public bool TryReadSectionRoot(JsonNode? document, out JsonObject root)
    {
        if (document is JsonObject parsed)
        {
            root = parsed;
            return true;
        }

        Error(
            ManifestDiagnosticCodes.SectionNotAnObject,
            document is null
                ? "The section payload is absent."
                : "The section payload must be a JSON object.");

        root = [];
        return false;
    }

    /// <summary>
    /// Verifies the optional <c>formatVersion</c> member against the version this build
    /// implements.
    /// </summary>
    /// <remarks>
    /// The member is optional so a hand-authored minimal manifest does not have to repeat a
    /// constant in every section. When it is present it is checked exactly, because a
    /// declared version Engine does not implement is a statement the author expects to be
    /// honored.
    /// </remarks>
    public bool VerifySectionFormatVersion(JsonObject root, int supported)
    {
        ArgumentNullException.ThrowIfNull(root);

        if (root["formatVersion"] is null)
        {
            return true;
        }

        var declared = Integer(root, "formatVersion", string.Empty);

        if (declared is null)
        {
            return false;
        }

        if (declared.Value == supported)
        {
            return true;
        }

        Error(
            ManifestDiagnosticCodes.SectionFormatVersionUnsupported,
            string.Create(
                CultureInfo.InvariantCulture,
                $"Section format version {declared.Value} is not supported. This Engine implements version {supported}."),
            "/formatVersion");

        return false;
    }

    /// <summary>
    /// Verifies the optional <c>formatVersion</c> member against an inclusive supported range.
    /// Sections whose closed vocabulary grew carry the range so older documents keep loading;
    /// vocabulary newer than the declared version is refused separately, at the member that
    /// uses it.
    /// </summary>
    public bool VerifySectionFormatVersionRange(JsonObject root, int minimum, int maximum)
    {
        ArgumentNullException.ThrowIfNull(root);

        if (root["formatVersion"] is null)
        {
            return true;
        }

        var declared = Integer(root, "formatVersion", string.Empty);

        if (declared is null)
        {
            return false;
        }

        if (declared.Value >= minimum && declared.Value <= maximum)
        {
            return true;
        }

        Error(
            ManifestDiagnosticCodes.SectionFormatVersionUnsupported,
            minimum == maximum
                ? string.Create(
                    CultureInfo.InvariantCulture,
                    $"Section format version {declared.Value} is not supported. This Engine implements version {minimum}.")
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"Section format version {declared.Value} is not supported. This Engine implements versions {minimum} to {maximum}."),
            "/formatVersion");

        return false;
    }

    /// <summary>Reads an optional object member.</summary>
    public JsonObject? Object(JsonObject parent, string member, string pointer)
    {
        ArgumentNullException.ThrowIfNull(parent);

        if (parent[member] is null)
        {
            return null;
        }

        if (parent[member] is JsonObject value)
        {
            return value;
        }

        TypeError(member, "an object", pointer);
        return null;
    }

    /// <summary>Reads an optional array member.</summary>
    public JsonArray? Array(JsonObject parent, string member, string pointer)
    {
        ArgumentNullException.ThrowIfNull(parent);

        if (parent[member] is null)
        {
            return null;
        }

        if (parent[member] is JsonArray value)
        {
            return value;
        }

        TypeError(member, "an array", pointer);
        return null;
    }

    /// <summary>
    /// Reads an optional string member without reporting anything, for a caller that raises
    /// its own domain-specific diagnostic.
    /// </summary>
    public static string? TextOrNull(JsonObject parent, string member)
    {
        ArgumentNullException.ThrowIfNull(parent);

        return parent[member] is JsonValue value && value.TryGetValue<string>(out var text)
            ? text
            : null;
    }

    /// <summary>Reads an optional string member.</summary>
    public string? Text(JsonObject parent, string member, string pointer)
    {
        ArgumentNullException.ThrowIfNull(parent);

        if (parent[member] is null)
        {
            return null;
        }

        if (parent[member] is JsonValue value && value.TryGetValue<string>(out var text))
        {
            return text;
        }

        TypeError(member, "a string", pointer);
        return null;
    }

    /// <summary>Reads a required, non-empty string member.</summary>
    public string? RequiredText(JsonObject parent, string member, string pointer)
    {
        ArgumentNullException.ThrowIfNull(parent);

        if (parent[member] is null)
        {
            Error(
                ManifestDiagnosticCodes.MemberRequired,
                $"'{member}' is required here.",
                Child(pointer, member));
            return null;
        }

        var text = Text(parent, member, pointer);

        if (text is null)
        {
            return null;
        }

        if (text.Length == 0)
        {
            Error(
                ManifestDiagnosticCodes.MemberRequired,
                $"'{member}' is required here and must not be empty.",
                Child(pointer, member));
            return null;
        }

        return text;
    }

    /// <summary>Reads an optional boolean member, falling back to <paramref name="fallback"/>.</summary>
    public bool Flag(JsonObject parent, string member, string pointer, bool fallback = false)
    {
        ArgumentNullException.ThrowIfNull(parent);

        if (parent[member] is null)
        {
            return fallback;
        }

        if (parent[member] is JsonValue value && value.TryGetValue<bool>(out var flag))
        {
            return flag;
        }

        TypeError(member, "a boolean", pointer);
        return fallback;
    }

    /// <summary>Reads an optional 32-bit integer member.</summary>
    public int? Integer(JsonObject parent, string member, string pointer)
    {
        ArgumentNullException.ThrowIfNull(parent);

        if (parent[member] is null)
        {
            return null;
        }

        if (parent[member] is JsonValue value && value.TryGetValue<int>(out var number))
        {
            return number;
        }

        TypeError(member, "a 32-bit integer", pointer);
        return null;
    }

    /// <summary>Reads an optional 64-bit integer member.</summary>
    public long? Integer64(JsonObject parent, string member, string pointer)
    {
        ArgumentNullException.ThrowIfNull(parent);

        if (parent[member] is null)
        {
            return null;
        }

        if (parent[member] is JsonValue value && value.TryGetValue<long>(out var number))
        {
            return number;
        }

        TypeError(member, "a 64-bit integer", pointer);
        return null;
    }

    /// <summary>Reads an optional number member as a duration in seconds.</summary>
    public TimeSpan? Seconds(JsonObject parent, string member, string pointer)
    {
        ArgumentNullException.ThrowIfNull(parent);

        if (parent[member] is null)
        {
            return null;
        }

        if (parent[member] is not JsonValue value || !value.TryGetValue<double>(out var seconds))
        {
            TypeError(member, "a number of seconds", pointer);
            return null;
        }

        if (double.IsNaN(seconds) || double.IsInfinity(seconds) || seconds <= 0 || seconds > 86_400)
        {
            Error(
                ManifestDiagnosticCodes.LimitOutOfRange,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'{member}' must be a positive number of seconds no greater than 86400, but {seconds} was declared."),
                Child(pointer, member));
            return null;
        }

        return TimeSpan.FromSeconds(seconds);
    }

    /// <summary>Reads an optional array of strings, defaulting to an empty list.</summary>
    public IReadOnlyList<string> TextArray(JsonObject parent, string member, string pointer)
    {
        ArgumentNullException.ThrowIfNull(parent);

        var array = Array(parent, member, pointer);

        if (array is null)
        {
            return [];
        }

        var items = new List<string>(array.Count);
        var index = 0;

        foreach (var element in array)
        {
            if (element is JsonValue value && value.TryGetValue<string>(out var text))
            {
                items.Add(text);
            }
            else
            {
                Error(
                    ManifestDiagnosticCodes.MemberTypeInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'{member}' must contain only strings, but element {index} is not a string."),
                    Child(pointer, member) + "/" + index.ToString(CultureInfo.InvariantCulture));
            }

            index++;
        }

        return items;
    }

    /// <summary>
    /// Enumerates the elements of an array member as objects, reporting any element that is
    /// not an object.
    /// </summary>
    public IReadOnlyList<(JsonObject Element, string Pointer)> ObjectArray(
        JsonObject parent,
        string member,
        string pointer)
    {
        ArgumentNullException.ThrowIfNull(parent);

        var array = Array(parent, member, pointer);

        if (array is null)
        {
            return [];
        }

        var basePointer = Child(pointer, member);
        var items = new List<(JsonObject, string)>(array.Count);
        var index = 0;

        foreach (var element in array)
        {
            var elementPointer = basePointer + "/" + index.ToString(CultureInfo.InvariantCulture);

            if (element is JsonObject value)
            {
                items.Add((value, elementPointer));
            }
            else
            {
                Error(
                    ManifestDiagnosticCodes.MemberTypeInvalid,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'{member}' must contain only objects, but element {index} is not an object."),
                    elementPointer);
            }

            index++;
        }

        return items;
    }

    /// <summary>
    /// Requires that <paramref name="value"/> is at least <paramref name="minimum"/>.
    /// </summary>
    public bool RequireAtLeast(long value, long minimum, string member, string pointer)
    {
        if (value >= minimum)
        {
            return true;
        }

        Error(
            ManifestDiagnosticCodes.LimitOutOfRange,
            string.Create(
                CultureInfo.InvariantCulture,
                $"'{member}' must be at least {minimum}, but {value} was declared."),
            Child(pointer, member));

        return false;
    }

    /// <summary>Appends an escaped member name to a JSON Pointer.</summary>
    public static string Child(string pointer, string member)
        => pointer + "/" + JsonPointer.Escape(member);

    private void TypeError(string member, string expected, string pointer)
        => Error(
            ManifestDiagnosticCodes.MemberTypeInvalid,
            $"'{member}' must be {expected}.",
            Child(pointer, member));
}
