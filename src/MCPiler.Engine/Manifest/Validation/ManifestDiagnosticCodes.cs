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

    /// <summary>
    /// An operation's response-cache policy is malformed or unsupported for its effective
    /// binding.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The policy is load-time valid or invalid; whether a request that could execute it is
    /// served from cache is a runtime admission question answered from current caller authority,
    /// upstream authentication state and response headers. Refusing at load keeps a manifest
    /// that can never cache anything from being served with a silent no-op.
    /// </para>
    /// <para>
    /// One code covers the whole policy: a TTL outside 1..86,400, a missing or non-integral TTL,
    /// a compound binding, or an effective method other than GET/HEAD. The JSON Pointer names
    /// the exact member, so the message does not have to carry the location.
    /// </para>
    /// </remarks>
    public const string ResponseCachePolicyInvalid = "agent/response-cache-policy-invalid";

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

    /// <summary>Two mappings in one list write to the same pointer.</summary>
    /// <remarks>
    /// The format defines no merge, so one of the two values is discarded and which one depends
    /// on declaration order. A workflow whose request changes when its mappings are reordered
    /// has no single meaning, and the author cannot see which half was dropped.
    /// </remarks>
    public const string DuplicateMappingTarget = "binding/duplicate-mapping-target";

    /// <summary>
    /// A compound step reaches an operation the surface exposing the compound excludes.
    /// </summary>
    /// <remarks>
    /// The exclusion is the perimeter, and a composition may not widen one. Without this the
    /// compound is a tunnel: an operation withheld from a surface is reachable from that
    /// surface by naming the workflow that contains it.
    /// </remarks>
    public const string CompoundStepExcluded = "binding/compound-step-excluded";

    /// <summary>A compound binding declares an unsupported binding grammar version.</summary>
    public const string CompoundBindingVersionUnsupported = "binding/compound-binding-version-unsupported";

    /// <summary>A binding shape outside the three the format defines.</summary>
    public const string BindingTypeUnknown = "binding/type-unknown";

    /// <summary>A transformation program is invalid. Carries the underlying transform code.</summary>
    public const string TransformInvalid = "binding/transform-invalid";

    /// <summary>A mapping pointer does not start at a permitted scope root.</summary>
    public const string PointerRootNotAllowed = "binding/pointer-root-not-allowed";

    // ---- output projection and pagination --------------------------------------------

    /// <summary>An output projection or pagination policy declares a member this format defines nowhere.</summary>
    public const string ProjectionUnknownMember = "agent/projection-unknown-member";

    /// <summary>A projection source kind, value mode, relation, scalar type or conversion is outside the closed vocabulary.</summary>
    public const string ProjectionUnknownValue = "agent/projection-unknown-value";

    /// <summary>A projection pointer is malformed or is the document root where a non-root pointer is required.</summary>
    public const string ProjectionPointerInvalid = "agent/projection-pointer-invalid";

    /// <summary>Two projection/pagination targets overlap, so one would silently overwrite the other.</summary>
    public const string ProjectionTargetOverlap = "agent/projection-target-overlap";

    /// <summary>A selected header source is classified sensitive and cannot be agent-visible.</summary>
    public const string ProjectionHeaderSensitive = "agent/projection-header-sensitive";

    /// <summary>A response header source name is empty or not a printable ASCII token.</summary>
    public const string ProjectionHeaderNameInvalid = "agent/projection-header-name-invalid";

    /// <summary>A URL-derived argument mapping is declared without a URL-valued pagination source.</summary>
    public const string ProjectionUrlSourceRequired = "agent/projection-url-source-required";

    /// <summary>A required projection member is absent or empty.</summary>
    public const string ProjectionShapeInvalid = "agent/projection-shape-invalid";

    /// <summary>A projected envelope or pagination state is incompatible with its declared output schema.</summary>
    public const string ProjectionOutputSchemaInvalid = "agent/projection-output-schema-invalid";

    /// <summary>A pagination policy names a next-operation slug the surface does not declare.</summary>
    public const string ProjectionTargetUnknown = "agent/projection-target-unknown";

    /// <summary>A pagination policy names a next operation that is not HTTP-backed.</summary>
    public const string ProjectionTargetNotHttp = "agent/projection-target-not-http";

    /// <summary>A surface that publishes the paginating source does not expose its cross-operation target.</summary>
    public const string ProjectionTargetUnreachable = "agent/projection-target-unreachable";

    /// <summary>A mapped next-argument target is absent from the target operation's input schema.</summary>
    public const string ProjectionMappingInvalid = "agent/projection-mapping-invalid";

    /// <summary>The mappings cannot supply every required input of the resolved target operation.</summary>
    public const string ProjectionMappingIncomplete = "agent/projection-mapping-incomplete";

    /// <summary>A binding references a credential id the credentials section does not declare.</summary>
    /// <remarks>
    /// Reported at load rather than at invocation because the operation can never execute as
    /// authored: it either sends nothing where a secret was intended, or it would have to guess
    /// which credential the author meant.
    /// </remarks>
    public const string BindingCredentialRefUnknown = "binding/credential-ref-unknown";

    /// <summary>A binding references one half of a basic credential pair without the other.</summary>
    /// <remarks>
    /// A user name without a password cannot produce a basic authorization header, so the
    /// reference is incomplete rather than merely unusual. The pair is checked per binding, not
    /// per section, because only the binding decides which halves travel together.
    /// </remarks>
    public const string BindingCredentialBasicIncomplete = "binding/credential-basic-incomplete";

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

    /// <summary>
    /// A surface declares required scopes on a mount that requires no authentication.
    /// </summary>
    /// <remarks>
    /// A scope restricts a token, so it is meaningful only where a token is required. The
    /// combination is refused rather than resolved: reading scopes as an implication of
    /// protection would give the format two ways to say "protected", which is the ambiguity
    /// the mount-level <c>authenticationRequired</c> member exists to remove.
    /// </remarks>
    public const string ScopesWithoutAuthentication = "surface/scopes-without-authentication";

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

    /// <summary>A credential id is absent or not well formed.</summary>
    public const string CredentialIdInvalid = "credential/id-invalid";

    /// <summary>Two credentials declare the same id.</summary>
    /// <remarks>
    /// A duplicate id makes every reference to it ambiguous, and resolving it by position would
    /// let declaration order decide which secret an operation sends.
    /// </remarks>
    public const string DuplicateCredentialId = "credential/duplicate-id";

    /// <summary>Warning: a declared credential is referenced by no binding.</summary>
    /// <remarks>
    /// Not an error, because a manifest may legitimately declare a credential ahead of the
    /// operation that will use it. It is worth reporting because the far more likely cause is
    /// an operation that was meant to be authenticated and is not: the fail-safe default means
    /// that mistake is silent at the wire.
    /// </remarks>
    public const string CredentialUnreferenced = "credential/unreferenced";

    /// <summary>
    /// One binding references two credentials that target the same destination slot.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Credentials are applied in order, so contention on one slot means the value that reaches
    /// the upstream service depends on reference order rather than on anything the author
    /// stated. For a header slot the outcome is worse than ambiguous: two values may be sent.
    /// </para>
    /// <para>
    /// The invariant is per binding. Two credentials may share a destination slot across the
    /// section — that is exactly how one manifest addresses two upstreams that both expect an
    /// <c>Authorization</c> header — and the contention only becomes real when a single
    /// executing binding authorizes both.
    /// </para>
    /// <para>
    /// This code previously described the section-wide condition. Redefining it is permitted
    /// while the format's major version is 0 and no release exists; the format's versioning
    /// policy freezes a code's meaning from the first release onward.
    /// </para>
    /// </remarks>
    public const string DuplicateCredentialSlot = "credential/slot-duplicate";

    /// <summary>A credential declares a managed-provider reference outside managed mode.</summary>
    /// <remarks>
    /// File mode has no provider secret set, so the reference could never resolve. It is a
    /// distinct condition from a malformed key: the shape may be perfectly valid and the
    /// deployment mode is still wrong.
    /// </remarks>
    public const string CredentialProviderNotPermitted = "credential/provider-not-permitted";

    /// <summary>A managed-provider key is empty, over-long, or outside the permitted characters.</summary>
    public const string CredentialProviderKeyInvalid = "credential/provider-key-invalid";

    // ---- authentication -------------------------------------------------------------

    /// <summary>An authentication profile id is absent or not well formed.</summary>
    public const string AuthenticationIdInvalid = "authentication/id-invalid";

    /// <summary>Two authentication profiles declare the same id.</summary>
    public const string DuplicateAuthenticationId = "authentication/duplicate-id";

    /// <summary>A profile declares a strategy kind outside the closed vocabulary.</summary>
    public const string AuthenticationKindUnknown = "authentication/kind-unknown";

    /// <summary>
    /// A profile declares a vocabulary kind this Engine build cannot execute.
    /// </summary>
    /// <remarks>
    /// Distinct from an unknown kind: the spelling is recognized, but no accepted artifact
    /// defines its runtime semantics, so accepting it would describe an execution path that
    /// does not exist. It is refused before any secret is resolved rather than at invocation.
    /// </remarks>
    public const string AuthenticationKindNotExecutable = "authentication/kind-not-executable";

    /// <summary>A strategy configuration is absent, wrongly shaped, or names an unknown member.</summary>
    public const string AuthenticationConfigurationInvalid = "authentication/configuration-invalid";

    /// <summary>
    /// A strategy configuration carries an executable-looking member or value.
    /// </summary>
    /// <remarks>
    /// Closed configuration may never smuggle arbitrary behavior across the boundary. A
    /// member named <c>script</c>, <c>regex</c>, <c>template</c> or similar is refused wherever
    /// it appears in the configuration, at any depth.
    /// </remarks>
    public const string AuthenticationExecutableMember = "authentication/executable-member";

    /// <summary>An authentication or destination origin is not a canonical http(s) origin.</summary>
    public const string AuthenticationOriginInvalid = "authentication/origin-invalid";

    /// <summary>An authentication profile declares no credential reference, or an unknown one.</summary>
    public const string AuthenticationCredentialUnknown = "authentication/credential-unknown";

    /// <summary>A profile's credential reference does not fit its strategy kind.</summary>
    public const string AuthenticationCredentialIncompatible = "authentication/credential-incompatible";

    /// <summary>A profile declares a scope fingerprint that is not a lowercase hex digest.</summary>
    public const string AuthenticationScopeFingerprintInvalid = "authentication/scope-fingerprint-invalid";

    /// <summary>
    /// An authentication profile declares a mutable slot without usable authority state.
    /// </summary>
    public const string AuthenticationSlotInvalid = "authentication/slot-invalid";

    /// <summary>Two profiles declare the same mutable slot identity.</summary>
    public const string DuplicateAuthenticationSlot = "authentication/slot-duplicate";

    /// <summary>A binding references an authentication profile the section does not declare.</summary>
    public const string BindingAuthenticationRefUnknown = "binding/authentication-ref-unknown";

    /// <summary>Warning: a declared authentication profile is referenced by no binding.</summary>
    public const string AuthenticationUnreferenced = "authentication/unreferenced";
    /// <summary>A profile names a reviewed signer kind the closed registry does not implement.</summary>
    public const string AuthenticationSignerUnknown = "authentication/signer-unknown";

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

    /// <summary>
    /// Warning: the search index was produced by an index builder this Engine does not
    /// implement, so the index is ignored and rebuilt.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="SearchDerivationMismatch"/> on purpose. This condition
    /// recovers — Engine rebuilds and discovery continues — whereas a content disagreement
    /// does not, because the declared index is what gets used. One code carrying both
    /// severities would leave an operator unable to tell from the code whether anything was
    /// lost.
    /// </remarks>
    public const string SearchBuilderVersionUnsupported = "search/builder-version-unsupported";

    /// <summary>Warning: the vector matrix could not be read. Ranking degrades to lexical.</summary>
    public const string VectorsUnreadable = "vectors/unreadable";

    /// <summary>Warning: the vector matrix dimension does not match the query model.</summary>
    public const string VectorsDimensionMismatch = "vectors/dimension-mismatch";

    /// <summary>
    /// Warning: the vector matrix describes operations other than the ones being served.
    /// Ranking degrades to lexical.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="VectorsUnreadable"/> and <see cref="VectorsDimensionMismatch"/>
    /// because it sends an operator somewhere else. The bytes parse and the shape is right;
    /// what is wrong is that the matrix was compiled from a different operation set, which is
    /// fixed by re-exporting the bundle rather than by re-embedding at another dimension.
    /// </remarks>
    public const string VectorsOperationMismatch = "vectors/operation-mismatch";

    // The archive group describes the transport container, never the manifest document inside
    // it. Keeping it separate means an operator reading an archive code knows immediately that
    // the bundle never got as far as being parsed as a manifest.

    /// <summary>The archive could not be read as a manifest archive.</summary>
    public const string ArchiveUnreadable = "archive/unreadable";

    /// <summary>The archive carries an entry that is neither a regular file nor a directory.</summary>
    public const string ArchiveEntryTypeUnsupported = "archive/entry-type-unsupported";

    /// <summary>An archive entry name does not resolve safely inside the destination.</summary>
    public const string ArchiveEntryPathUnsafe = "archive/entry-path-unsafe";

    /// <summary>An entry name exceeds what the archive format can represent portably.</summary>
    public const string ArchiveEntryNameTooLong = "archive/entry-name-too-long";

    /// <summary>The archive exceeds an entry-count or total-size bound.</summary>
    public const string ArchiveLimitExceeded = "archive/limit-exceeded";

    /// <summary>The unpack destination already holds content.</summary>
    public const string ArchiveDestinationNotEmpty = "archive/destination-not-empty";

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
        ResponseCachePolicyInvalid,
        BindingOperationKeyUnknown,
        CompoundStepUnknownOperation,
        CompoundNested,
        DuplicateStepId,
        DuplicateMappingTarget,
        CompoundStepExcluded,
        StepReferenceUnknown,
        CompoundBindingVersionUnsupported,
        BindingTypeUnknown,
        TransformInvalid,
        PointerRootNotAllowed,
        ProjectionUnknownMember,
        ProjectionUnknownValue,
        ProjectionPointerInvalid,
        ProjectionTargetOverlap,
        ProjectionHeaderSensitive,
        ProjectionHeaderNameInvalid,
        ProjectionUrlSourceRequired,
        ProjectionShapeInvalid,
        ProjectionOutputSchemaInvalid,
        ProjectionTargetUnknown,
        ProjectionTargetNotHttp,
        ProjectionTargetUnreachable,
        ProjectionMappingInvalid,
        ProjectionMappingIncomplete,
        BindingCredentialRefUnknown,
        BindingCredentialBasicIncomplete,
        DuplicateSurfaceSlug,
        MultipleDefaultSurfaces,
        NoDefaultSurface,
        SurfaceOperationUnknown,
        SurfaceHasNoOperations,
        DuplicateSurfaceOperation,
        ScopesWithoutAuthentication,
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
        CredentialIdInvalid,
        DuplicateCredentialId,
        CredentialUnreferenced,
        DuplicateCredentialSlot,
        CredentialProviderNotPermitted,
        CredentialProviderKeyInvalid,
        AuthenticationIdInvalid,
        DuplicateAuthenticationId,
        AuthenticationKindUnknown,
        AuthenticationKindNotExecutable,
        AuthenticationConfigurationInvalid,
        AuthenticationExecutableMember,
        AuthenticationOriginInvalid,
        AuthenticationCredentialUnknown,
        AuthenticationCredentialIncompatible,
        AuthenticationScopeFingerprintInvalid,
        AuthenticationSlotInvalid,
        DuplicateAuthenticationSlot,
        BindingAuthenticationRefUnknown,
        AuthenticationUnreferenced,
        AuthenticationSignerUnknown,
        ToolDerivationMismatch,
        NavigatorNameRequired,
        DuplicateToolName,
        ToolNameInvalid,
        ToolSurfaceUnknown,
        ToolOperationUnknown,
        SearchDerivationMismatch,
        SearchBuilderVersionUnsupported,
        VectorsUnreadable,
        VectorsDimensionMismatch,
        VectorsOperationMismatch,
        ArchiveUnreadable,
        ArchiveEntryTypeUnsupported,
        ArchiveEntryPathUnsafe,
        ArchiveEntryNameTooLong,
        ArchiveLimitExceeded,
        ArchiveDestinationNotEmpty,
    };

    /// <summary>
    /// The codes that are always reported as warnings and therefore never block loading.
    /// </summary>
    /// <remarks>
    /// These are the deliberately degrading paths plus the informational findings. Every other
    /// code fails closed.
    /// </remarks>
    public static IReadOnlySet<string> AlwaysWarning { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        Unsealed,
        NoResponsesDeclared,
        SurfaceHasNoOperations,
        CredentialInlineDiscouraged,
        CredentialUnreferenced,
        SearchBuilderVersionUnsupported,
        VectorsUnreadable,
        VectorsDimensionMismatch,
        VectorsOperationMismatch,
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
        "authentication",
        "tools",
        "search",
        "vectors",
        "archive",
    };
}
