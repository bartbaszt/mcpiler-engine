using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.Runtime;

/// <summary>
/// One Manifest to serve and the prefix it answers on.
/// </summary>
/// <remarks>
/// <para>
/// Narrowing is expressed by bound name rather than by a typed record so that a host can
/// carry an operator's settings without naming a manifest type. The permitted names are
/// exactly the protected bounds the library already enumerates; an unrecognized name is
/// refused by name at startup rather than ignored, because a setting that silently does
/// nothing is worse than one that is rejected.
/// </para>
/// <para>
/// <see cref="AllowedOrigins"/> replaces the compiled perimeter and may only remove from it.
/// It is separate from <see cref="Narrowing"/> because a perimeter is a set, not a number,
/// and the comparison that makes narrowing safe is not the same comparison.
/// </para>
/// </remarks>
/// <param name="Prefix">The route prefix this Manifest answers on, without a trailing slash.</param>
/// <param name="Path">The Manifest file or bundle directory.</param>
public sealed record MountRequest(string Prefix, string Path)
{
    /// <summary>Bound name to requested value, in the units the bound is declared in.</summary>
    public IReadOnlyDictionary<string, string> Narrowing { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>A replacement perimeter, or null to keep the compiled one.</summary>
    public IReadOnlyList<string>? AllowedOrigins { get; init; }
}

/// <summary>
/// Everything a host may configure.
/// </summary>
/// <remarks>
/// <para>
/// The absences are the specification. There is no base URL, no origin to add, no credential,
/// and no way to raise a bound: those are compiled into a Manifest, and a host that could
/// restate them would be a second place the truth lives. A deployment changes them by
/// changing the Manifest, which is the artifact that was reviewed.
/// </para>
/// <para>
/// <see cref="Floors"/> and a mount's own narrowing differ in one way that matters. A mount's
/// narrowing is a statement about that Manifest, so asking for more than it compiled is an
/// error worth refusing. A floor is a statement about the process, so a Manifest already
/// tighter than the floor simply keeps its own value and nothing is wrong.
/// </para>
/// </remarks>
/// <param name="Mounts">The Manifests to serve. An empty set is refused.</param>
/// <param name="FileStoreRoot">Where issued file handles keep their content.</param>
public sealed record RuntimeOptions(IReadOnlyList<MountRequest> Mounts, string FileStoreRoot)
{
    /// <summary>Refuse any Manifest that carries no completeness seal. Process-wide.</summary>
    public bool RequireSealed { get; init; }

    /// <summary>Permit a literal secret in a credentials section. Process-wide.</summary>
    public bool AllowInlineSecrets { get; init; }

    /// <summary>Bound name to value, applied to every mount as a ceiling it may not exceed.</summary>
    public IReadOnlyDictionary<string, string> Floors { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Directories this process serves to clients; the file-store root must be outside them.</summary>
    public IReadOnlyList<string> ServedContentRoots { get; init; } = [];

    /// <summary>
    /// Where runtime-owned mutable authentication state is encrypted at rest. Null keeps it in
    /// memory only.
    /// </summary>
    /// <remarks>
    /// This state exists for one class of value: a credential the upstream replaces when it is
    /// used, where losing the replacement makes the deployment unable to authenticate. It is
    /// deliberately separate from <see cref="FileStoreRoot"/>: that one holds client-visible
    /// content, while this one holds a secret and never serves anything.
    /// </remarks>
    public string? RuntimeStateRoot { get; init; }

    /// <summary>
    /// How a manifest's JMESPath expressions are classified at load, or null when this process
    /// cannot confine an evaluation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Loading a manifest with a JMESPath projection means compiling the expression, and the
    /// profile forbids compiling one in the process that answers. A host that owns the confined
    /// worker supplies this; a host that does not leaves it null, and a manifest carrying a
    /// projection is then refused rather than checked here. That refusal is the intended
    /// outcome, not a degraded one: a manifest admitted without its expression ever being
    /// compiled is a manifest whose projections fail at the first call.
    /// </para>
    /// <para>
    /// The port is deliberately synchronous because loading is: a manifest is read, validated
    /// and mounted before a listener exists.
    /// </para>
    /// </remarks>
    public IProjectionExpressionValidator? ExpressionValidator { get; init; }

    /// <summary>
    /// The confined evaluator an output projection is invoked through.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="ExpressionValidator"/> because the two answer different
    /// questions. Loading asks whether an expression compiles; execution asks what it produces
    /// for a real body, and the second one runs untrusted work that must not happen in the
    /// serving process. A host normally supplies one pool for both so the confinement is one
    /// mechanism rather than two; a process with no worker refuses a JMESPath projection rather
    /// than evaluating it in place.
    /// </remarks>
    public IProjectionWorker? ProjectionWorker { get; init; }

    /// <summary>
    /// The file holding the Engine runtime-state key. Required exactly when
    /// <see cref="RuntimeStateRoot"/> is set.
    /// </summary>
    /// <remarks>
    /// Engine's own key, never the Platform master key. A configured root with no key — or the
    /// reverse — is refused rather than resolved to a default, because either half alone would
    /// silently produce a deployment that cannot read what it wrote.
    /// </remarks>
    public string? RuntimeStateKeyFile { get; init; }

    /// <summary>
    /// Host-only response-cache ceilings. These never enter a Manifest or managed desired state.
    /// </summary>
    public ResponseCacheOptions ResponseCache { get; init; } = ResponseCacheOptions.Default;
}
