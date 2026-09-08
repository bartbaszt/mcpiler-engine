namespace MCPiler.Engine.Manifest.Validation;

/// <summary>
/// Every diagnostic code the manifest loader and validator can produce.
/// </summary>
/// <remarks>
/// <para>
/// Codes are a versioned public contract from the first release. Automation, CI checks and
/// operator runbooks branch on them, so a code is never renamed or repurposed within a
/// manifest MAJOR version; a new condition gets a new code. Message text is explicitly not
/// contractual.
/// </para>
/// <para>
/// The shape is <c>group/kebab-case-detail</c>. The group names the area a reader has to
/// look at, which is what makes a refusal actionable without reading Engine source.
/// </para>
/// </remarks>
public static class ManifestDiagnosticCodes
{
    // ---- format and packaging -------------------------------------------------------

    /// <summary>The root declares no format version. Engine does not guess one.</summary>
    public const string FormatVersionMissing = "manifest/format-version-missing";

    /// <summary>The declared format version is not a strict <c>MAJOR.MINOR</c> value.</summary>
    public const string FormatVersionMalformed = "manifest/format-version-malformed";

    /// <summary>The declared format version is valid but outside the supported range.</summary>
    public const string FormatVersionUnsupported = "manifest/format-version-unsupported";

    /// <summary>The root document is not a JSON object.</summary>
    public const string RootNotAnObject = "manifest/root-not-an-object";

    /// <summary>A member appears that this format version does not define.</summary>
    public const string UnknownMember = "manifest/unknown-member";

    /// <summary>A member this format version requires here is absent or empty.</summary>
    public const string MemberRequired = "manifest/member-required";

    /// <summary>
    /// A member's JSON type is not the type this format version defines here.
    /// </summary>
    /// <remarks>
    /// This is a distinct condition from an unknown member. Reading a wrongly typed member as
    /// if it were absent would turn an authoring typo into a silently changed contract, so a
    /// type mismatch is reported instead of defaulted.
    /// </remarks>
    public const string MemberTypeInvalid = "manifest/member-type-invalid";

    /// <summary>A section payload parses as JSON but is not a JSON object.</summary>
    public const string SectionNotAnObject = "manifest/section-not-an-object";

    /// <summary>A section name appears that this format version does not define.</summary>
    public const string SectionUnknown = "manifest/section-unknown";

    /// <summary>A required section is absent.</summary>
    public const string SectionMissing = "manifest/section-missing";

    /// <summary>A section entry declares both an inline payload and a path.</summary>
    public const string SectionBothInlineAndPath = "manifest/section-both-inline-and-path";

    /// <summary>A section entry declares neither an inline payload nor a path.</summary>
    public const string SectionNeitherInlineNorPath = "manifest/section-neither-inline-nor-path";

    /// <summary>A section path is absolute, a URI, or escapes the bundle directory.</summary>
    public const string SectionPathEscapesBundle = "manifest/section-path-escapes-bundle";

    /// <summary>A referenced section file does not exist.</summary>
    public const string SectionFileMissing = "manifest/section-file-missing";

    /// <summary>A section payload is not parseable JSON.</summary>
    public const string SectionUnparseable = "manifest/section-unparseable";

    /// <summary>A section payload does not match its declared digest.</summary>
    public const string SectionHashMismatch = "manifest/section-hash-mismatch";

    /// <summary>A section payload does not match its declared length.</summary>
    public const string SectionSizeMismatch = "manifest/section-size-mismatch";

    /// <summary>A section declares a section format version Engine does not support.</summary>
    public const string SectionFormatVersionUnsupported = "manifest/section-format-version-unsupported";

    /// <summary>A section must be external but was declared inline.</summary>
    public const string SectionMustBeExternal = "manifest/section-must-be-external";

    /// <summary>The completeness seal does not match the section index.</summary>
    public const string CompletenessMismatch = "manifest/completeness-mismatch";

    /// <summary>The completeness seal names an algorithm this format version does not define.</summary>
    public const string CompletenessAlgorithmUnknown = "manifest/completeness-algorithm-unknown";

    /// <summary>Warning: the manifest carries no seal, so corruption is undetectable.</summary>
    public const string Unsealed = "manifest/unsealed";

    /// <summary>A seal was required by configuration but the manifest carries none.</summary>
    public const string SealRequired = "manifest/seal-required";

    // ---- schema and references ------------------------------------------------------

    /// <summary>A <c>$ref</c> is not a fragment-only pointer into the same document.</summary>
    public const string RefNotLocal = "schema/ref-not-local";

    /// <summary>A <c>$ref</c> pointer does not resolve.</summary>
    public const string RefUnresolvable = "schema/ref-unresolvable";

    /// <summary>Reference resolution exceeded a configured bound.</summary>
    public const string SchemaBoundExceeded = "schema/bound-exceeded";

    /// <summary>A schema is not a valid schema document.</summary>
    public const string SchemaInvalid = "schema/invalid";

    // ---- operations -----------------------------------------------------------------

    /// <summary>Two operations declare the same execution key.</summary>
    public const string DuplicateOperationKey = "operations/duplicate-key";

    /// <summary>An execution key disagrees with its declared method and path.</summary>
    public const string KeyDisagreesWithMethodPath = "operations/key-disagrees-with-method-path";

    /// <summary>A parameter declares a location this format version does not support.</summary>
    public const string UnsupportedParameterLocation = "operations/unsupported-parameter-location";

    /// <summary>A parameter declares a serialization style outside the vocabulary.</summary>
    public const string UnknownParameterStyle = "operations/unknown-style";

    /// <summary>Warning: an operation declares no response, which changes runtime behavior.</summary>
    public const string NoResponsesDeclared = "operations/no-responses-declared";

    // ---- agent surface and bindings -------------------------------------------------

    /// <summary>Two agent operations declare the same slug.</summary>
    public const string DuplicateAgentSlug = "agent/duplicate-slug";

    /// <summary>An operation names a group the section does not declare.</summary>
    public const string UnknownGroup = "agent/unknown-group";

    /// <summary>A declared operation kind contradicts its binding shape.</summary>
    public const string KindBindingMismatch = "agent/kind-binding-mismatch";

    /// <summary>A binding names an execution key the operations section does not declare.</summary>
    public const string BindingOperationKeyUnknown = "binding/operation-key-unknown";

    /// <summary>A compound step names an agent slug the surface does not declare.</summary>
    public const string CompoundStepUnknownOperation = "binding/compound-step-unknown-operation";

    /// <summary>A compound step references another compound operation. Nesting is forbidden.</summary>
    public const string CompoundNested = "binding/compound-nested";

    /// <summary>Two steps of one compound workflow declare the same step identifier.</summary>
    /// <remarks>
    /// A duplicate identifier makes every later <c>fromStep</c> reference ambiguous, and
    /// resolving it by position would make the workflow's meaning depend on declaration order.
    /// </remarks>
    public const string DuplicateStepId = "binding/duplicate-step-id";

    /// <summary>
    /// A mapping reads from a step that is not declared, or that is declared later.
    /// </summary>
    public const string StepReferenceUnknown = "binding/step-reference-unknown";

    /// <summary>A compound binding declares an unsupported binding grammar version.</summary>
    public const string CompoundBindingVersionUnsupported = "binding/compound-binding-version-unsupported";

    /// <summary>A binding shape outside the three the format defines.</summary>
    public const string BindingTypeUnknown = "binding/type-unknown";

    /// <summary>A transformation program is invalid. Carries the underlying transform code.</summary>
    public const string TransformInvalid = "binding/transform-invalid";

    /// <summary>A mapping pointer does not start at a permitted scope root.</summary>
    public const string PointerRootNotAllowed = "binding/pointer-root-not-allowed";

    // ---- surfaces -------------------------------------------------------------------

    /// <summary>Two surfaces declare the same slug.</summary>
    public const string DuplicateSurfaceSlug = "surface/duplicate-slug";

    /// <summary>More than one surface is marked default.</summary>
    public const string MultipleDefaultSurfaces = "surface/multiple-defaults";

    /// <summary>No surface is marked default, so the bare connector route cannot be served.</summary>
    public const string NoDefaultSurface = "surface/no-default";

    /// <summary>A surface exposes an agent slug the surface section does not declare.</summary>
    public const string SurfaceOperationUnknown = "surface/operation-unknown";

    /// <summary>Warning: a surface exposes no operation, so it advertises nothing useful.</summary>
    public const string SurfaceHasNoOperations = "surface/no-operations";

    /// <summary>One surface lists the same agent operation more than once.</summary>
    /// <remarks>
    /// Two entries for one operation can declare different exposures, and resolving that by
    /// position would let declaration order decide whether an operation is advertised.
    /// </remarks>
    public const string DuplicateSurfaceOperation = "surface/duplicate-operation";

    // ---- policy ---------------------------------------------------------------------

    /// <summary>The base URL is absent or not an absolute HTTP or HTTPS URL.</summary>
    public const string BaseUrlInvalid = "policy/base-url-invalid";

    /// <summary>An allowed-origin entry is not a valid origin.</summary>
    public const string OriginInvalid = "policy/origin-invalid";

    /// <summary>Local configuration attempts to widen a compiled limit or the perimeter.</summary>
    public const string LimitWidened = "policy/limit-widened";

    /// <summary>A declared limit is outside the range this format version permits.</summary>
    public const string LimitOutOfRange = "policy/limit-out-of-range";

    /// <summary>
    /// A compiled destination lies outside the allowed-origin perimeter, so every request to
    /// it fails closed.
    /// </summary>
    /// <remarks>
    /// This covers the base URL and any per-operation server URL. It is reported at load
    /// rather than left to the first invocation because the affected operations can never
    /// execute: the manifest advertises tools that are guaranteed to fail. Distinguishing it
    /// from <see cref="OriginInvalid"/> matters — the perimeter entries are well formed here,
    /// they simply do not cover the destination the manifest routes to.
    /// </remarks>
    public const string DestinationNotAllowed = "policy/destination-not-allowed";

    // ---- credentials ----------------------------------------------------------------

    /// <summary>A credential declares a scheme outside the vocabulary.</summary>
    public const string CredentialSchemeUnknown = "credential/scheme-unknown";

    /// <summary>A credential declares a location that is invalid for its scheme.</summary>
    public const string CredentialLocationInvalid = "credential/location-invalid";

    /// <summary>A credential slot is absent or invalid for its scheme.</summary>
    public const string CredentialSlotInvalid = "credential/slot-invalid";

    /// <summary>A credential value reference could not be resolved. An auth fault, not a network fault.</summary>
    public const string CredentialReferenceUnresolved = "credential/reference-unresolved";

    /// <summary>An inline secret was declared without the explicit opt-in.</summary>
    public const string CredentialInlineNotPermitted = "credential/inline-not-permitted";

    /// <summary>Warning: an inline secret is present. Prefer a reference.</summary>
    public const string CredentialInlineDiscouraged = "credential/inline-discouraged";

    /// <summary>A credential value declares more than one source, or none.</summary>
    public const string CredentialReferenceAmbiguous = "credential/reference-ambiguous";

    /// <summary>Two credentials target the same destination slot.</summary>
    /// <remarks>
    /// Credentials are applied in order, so a duplicate slot means the value that reaches the
    /// upstream service depends on declaration order rather than on anything the author
    /// stated. For a header slot the outcome is worse than ambiguous: two values may be sent.
    /// </remarks>
    public const string DuplicateCredentialSlot = "credential/slot-duplicate";

    // ---- derivation and optional sections -------------------------------------------

    /// <summary>An explicit tool section disagrees with what derivation produces.</summary>
    public const string ToolDerivationMismatch = "tools/derivation-mismatch";

    /// <summary>A tool without an operation identity is not named as a Navigator tool.</summary>
    public const string NavigatorNameRequired = "tools/navigator-name-required";

    /// <summary>Two tools on one surface declare the same advertised name.</summary>
    public const string DuplicateToolName = "tools/duplicate-name";

    /// <summary>An advertised tool name is empty, too long, or outside the permitted characters.</summary>
    /// <remarks>
    /// The name is what a caller writes to invoke the tool, so a name the protocol cannot
    /// carry produces a tool that is advertised and unusable.
    /// </remarks>
    public const string ToolNameInvalid = "tools/name-invalid";

    /// <summary>A declared tool set names a surface the server section does not declare.</summary>
    public const string ToolSurfaceUnknown = "tools/surface-unknown";

    /// <summary>A declared tool names an operation the surface does not expose directly.</summary>
    /// <remarks>
    /// Distinct from an unknown surface exposure entry: here the exposure list is fine and
    /// the pinned tool set is what disagrees with it, so the fix is in a different place.
    /// </remarks>
    public const string ToolOperationUnknown = "tools/operation-unknown";

    /// <summary>An explicit search section disagrees with what derivation produces.</summary>
    public const string SearchDerivationMismatch = "search/derivation-mismatch";

    /// <summary>Warning: the vector matrix could not be read. Ranking degrades to lexical.</summary>
    public const string VectorsUnreadable = "vectors/unreadable";

    /// <summary>Warning: the vector matrix dimension does not match the query model.</summary>
    public const string VectorsDimensionMismatch = "vectors/dimension-mismatch";

    /// <summary>Every code this Engine build can produce.</summary>
    public static IReadOnlySet<string> All { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        FormatVersionMissing,
        FormatVersionMalformed,
        FormatVersionUnsupported,
        RootNotAnObject,
        UnknownMember,
        MemberRequired,
        MemberTypeInvalid,
        SectionNotAnObject,
        SectionUnknown,
        SectionMissing,
        SectionBothInlineAndPath,
        SectionNeitherInlineNorPath,
        SectionPathEscapesBundle,
        SectionFileMissing,
        SectionUnparseable,
        SectionHashMismatch,
        SectionSizeMismatch,
        SectionFormatVersionUnsupported,
        SectionMustBeExternal,
        CompletenessMismatch,
        CompletenessAlgorithmUnknown,
        Unsealed,
        SealRequired,
        RefNotLocal,
        RefUnresolvable,
        SchemaBoundExceeded,
        SchemaInvalid,
        DuplicateOperationKey,
        KeyDisagreesWithMethodPath,
        UnsupportedParameterLocation,
        UnknownParameterStyle,
        NoResponsesDeclared,
        DuplicateAgentSlug,
        UnknownGroup,
        KindBindingMismatch,
        BindingOperationKeyUnknown,
        CompoundStepUnknownOperation,
        CompoundNested,
        DuplicateStepId,
        StepReferenceUnknown,
        CompoundBindingVersionUnsupported,
        BindingTypeUnknown,
        TransformInvalid,
        PointerRootNotAllowed,
        DuplicateSurfaceSlug,
        MultipleDefaultSurfaces,
        NoDefaultSurface,
        SurfaceOperationUnknown,
        SurfaceHasNoOperations,
        DuplicateSurfaceOperation,
        BaseUrlInvalid,
        OriginInvalid,
        LimitWidened,
        LimitOutOfRange,
        DestinationNotAllowed,
        CredentialSchemeUnknown,
        CredentialLocationInvalid,
        CredentialSlotInvalid,
        CredentialReferenceUnresolved,
        CredentialInlineNotPermitted,
        CredentialInlineDiscouraged,
        CredentialReferenceAmbiguous,
        DuplicateCredentialSlot,
        ToolDerivationMismatch,
        NavigatorNameRequired,
        DuplicateToolName,
        ToolNameInvalid,
        ToolSurfaceUnknown,
        ToolOperationUnknown,
        SearchDerivationMismatch,
        VectorsUnreadable,
        VectorsDimensionMismatch,
    };

    /// <summary>
    /// The codes that are always reported as warnings and therefore never block loading.
    /// </summary>
    /// <remarks>
    /// These are the two deliberately degrading paths plus the informational findings. Every
    /// other code fails closed.
    /// </remarks>
    public static IReadOnlySet<string> AlwaysWarning { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        Unsealed,
        NoResponsesDeclared,
        SurfaceHasNoOperations,
        CredentialInlineDiscouraged,
        VectorsUnreadable,
        VectorsDimensionMismatch,
    };

    /// <summary>The group prefixes the code shape permits.</summary>
    public static IReadOnlySet<string> Groups { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        "manifest",
        "schema",
        "operations",
        "agent",
        "binding",
        "surface",
        "policy",
        "credential",
        "tools",
        "search",
        "vectors",
    };
}
