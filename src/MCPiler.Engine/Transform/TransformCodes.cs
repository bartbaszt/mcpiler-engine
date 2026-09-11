namespace MCPiler.Engine.Transform;

/// <summary>
/// The machine-readable reasons Tier-1 transform validation refuses a program.
/// </summary>
/// <remarks>
/// <para>
/// These are a different vocabulary from <c>ManifestDiagnosticCodes</c> and deliberately so.
/// A transformation program is its own versioned contract: it is authored, copied and edited
/// independently of the manifest that carries it, and the same program refused here must be
/// refused for the same stated reason wherever else it is validated. Folding these into the
/// manifest vocabulary would give one condition two names and make the two implementations
/// disagree silently.
/// </para>
/// <para>
/// Only the Tier-1 codes appear here. The runtime limit codes belong to the evaluator and
/// arrive with it; a code declared before anything can emit it is a contract nothing honours.
/// </para>
/// </remarks>
internal static class TransformCodes
{
    /// <summary>The program declares a <c>transformVersion</c> this build does not implement.</summary>
    internal const string UnsupportedVersion = "E_UNSUPPORTED_TRANSFORM_VERSION";

    /// <summary>A member is not part of the envelope, the step or the predicate it appears in.</summary>
    internal const string UnknownField = "E_UNKNOWN_FIELD";

    /// <summary>An <c>op</c> outside the closed vocabulary.</summary>
    internal const string UnknownOperation = "E_UNKNOWN_OPERATION";

    /// <summary>An iteration or truncation step declares no explicit bound.</summary>
    internal const string MissingBound = "E_MISSING_BOUND";

    /// <summary>A pointer is not a syntactically valid RFC 6901 JSON Pointer.</summary>
    internal const string PointerSyntax = "E_POINTER_SYNTAX";

    /// <summary>A pointer is rooted outside the set permitted for its direction and position.</summary>
    internal const string PointerRoot = "E_POINTER_ROOT";

    /// <summary>A template pattern carries something other than literal text and bound placeholders.</summary>
    internal const string TemplatePattern = "E_TEMPLATE_PATTERN";

    /// <summary>The static worst-case array fan-out exceeds the effective limit.</summary>
    internal const string StaticFanout = "E_STATIC_FANOUT";

    /// <summary>The static worst-case nesting depth exceeds the effective limit.</summary>
    internal const string StaticDepth = "E_STATIC_DEPTH";

    /// <summary>The static worst-case step count exceeds the effective limit.</summary>
    internal const string StepLimit = "E_STEP_LIMIT";

    /// <summary>A program attempts to construct or convert a file handle.</summary>
    internal const string FileHandle = "E_FILE_HANDLE";

    /// <summary>A program writes the content type, which the request compiler owns.</summary>
    internal const string ContentTypeReserved = "E_CONTENT_TYPE_RESERVED";

    /// <summary>Every code this build can emit, for the guard that each one is reachable.</summary>
    internal static IReadOnlySet<string> All { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        UnsupportedVersion,
        UnknownField,
        UnknownOperation,
        MissingBound,
        PointerSyntax,
        PointerRoot,
        TemplatePattern,
        StaticFanout,
        StaticDepth,
        StepLimit,
        FileHandle,
        ContentTypeReserved,
    };
}

/// <summary>
/// One Tier-1 finding: why the program is refused and where.
/// </summary>
/// <param name="Code">A stable identifier from <see cref="TransformCodes"/>.</param>
/// <param name="Message">
/// An operator-facing explanation. Never contractual, and never carrying an unbounded value
/// read out of the program.
/// </param>
/// <param name="Step">
/// The index of the <em>top-level</em> step the finding belongs to, or <c>null</c> for an
/// envelope-level finding. A finding inside a nested step list reports the top-level index,
/// because that is the index every other surface counts in; <see cref="Pointer"/> carries the
/// rest of the path.
/// </param>
/// <param name="Pointer">
/// A JSON Pointer into the program document, locating the offending member exactly, including
/// through nested step lists.
/// </param>
/// <remarks>
/// There is no severity. Tier 1 is a hard gate and every finding it produces refuses the load;
/// a severity member with one possible value is an invitation to add a second and then to
/// wonder which ones still fail closed.
/// </remarks>
internal sealed record TransformFinding(
    string Code,
    string Message,
    int? Step = null,
    string Pointer = "");
