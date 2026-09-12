namespace MCPiler.Engine.Transform;

/// <summary>
/// The machine-readable reasons a transformation program is refused or aborted.
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
/// Both halves live here: the load-time codes Tier 1 produces and the codes the evaluator
/// aborts with. Two of them belong to both halves, because a template pattern and a file
/// handle are checked statically and again while running — and one condition with two names
/// is exactly what this type exists to prevent.
/// </para>
/// <para>
/// Every code an evaluator emits is declared. The alternative, a string literal at the
/// throwing site, produces codes nothing enumerates, which is how a caller ends up matching
/// on an identifier no list admits exists.
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

    /// <summary>
    /// A program declares a direction other than the one the member it occupies is read in.
    /// </summary>
    /// <remarks>
    /// The pointer-root gate is keyed off the declared direction, so a program sitting in the
    /// wrong member is measured against the wrong set of roots. That makes the gate
    /// meaningless rather than merely wrong, which is why this is refused at load instead of
    /// being tolerated as an authoring slip.
    /// </remarks>
    internal const string DirectionMismatch = "E_DIRECTION_MISMATCH";

    /// <summary>The evaluation executed more steps than the effective step limit allows.</summary>
    internal const string LimitSteps = "E_LIMIT_STEPS";

    /// <summary>The evaluation materialized more nodes than the effective node limit allows.</summary>
    internal const string LimitNodes = "E_LIMIT_NODES";

    /// <summary>The working document nested deeper than the effective depth limit allows.</summary>
    internal const string LimitDepth = "E_LIMIT_DEPTH";

    /// <summary>The produced document is larger than the effective output-size limit allows.</summary>
    internal const string LimitOutputBytes = "E_LIMIT_OUTPUT_BYTES";

    /// <summary>The evaluation iterated more items than the effective fan-out limit allows.</summary>
    internal const string LimitFanout = "E_LIMIT_FANOUT";

    /// <summary>A step declaring <c>onMissing: error</c> found nothing at its source.</summary>
    internal const string MissingSource = "E_MISSING_SOURCE";

    /// <summary>A <c>convert</c> step met a value the target type cannot represent.</summary>
    internal const string ConvertFailed = "E_CONVERT_FAILED";

    /// <summary>
    /// A step failed for a reason the vocabulary does not name — a source of the wrong JSON
    /// kind, or a target path that addresses no writable container.
    /// </summary>
    internal const string StepFailed = "E_STEP_FAILED";

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
        DirectionMismatch,
        LimitSteps,
        LimitNodes,
        LimitDepth,
        LimitOutputBytes,
        LimitFanout,
        MissingSource,
        ConvertFailed,
        StepFailed,
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
