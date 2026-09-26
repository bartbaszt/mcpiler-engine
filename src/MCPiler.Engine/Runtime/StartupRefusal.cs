using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Mcp.Navigator;
using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.Runtime;

/// <summary>
/// Why the process will not start.
/// </summary>
/// <remarks>
/// <para>
/// A refusal names the Manifest it concerns. With one mount that is redundant; with several
/// it is the only thing that makes the diagnostic actionable, and the cost of always naming
/// it is one field.
/// </para>
/// <para>
/// <see cref="Setting"/>, <see cref="Compiled"/> and <see cref="Attempted"/> are separate from
/// <see cref="Message"/> so a caller can render them without parsing prose. They are null for
/// a refusal that is not about a bound at all, such as a Manifest that does not load.
/// </para>
/// </remarks>
/// <param name="Mount">The mount prefix, or the empty string for a process-level refusal.</param>
/// <param name="Code">The diagnostic code, from the same catalogue loading uses.</param>
/// <param name="Message">What went wrong, in terms of what an operator controls.</param>
public sealed record StartupRefusal(string Mount, string Code, string Message)
{
    /// <summary>The Manifest path, when the refusal concerns one.</summary>
    public string? Manifest { get; init; }

    /// <summary>The section the refusal belongs to.</summary>
    public string? Section { get; init; }

    /// <summary>
    /// The reason code from a nested grammar carried inside the Manifest, when there is one.
    /// </summary>
    /// <remarks>
    /// A transformation program states its own reasons, and one Manifest code covers every way
    /// a program can be wrong. Dropping the inner code at this seam would leave an operator
    /// told that a program is invalid and nothing else, which is the diagnostic the format
    /// exists to avoid.
    /// </remarks>
    public string? ProgramCode { get; init; }

    /// <summary>The configuration name at fault.</summary>
    public string? Setting { get; init; }

    /// <summary>What the Manifest compiled, rendered.</summary>
    public string? Compiled { get; init; }

    /// <summary>What configuration asked for, rendered.</summary>
    public string? Attempted { get; init; }
}

/// <summary>
/// One addressable surface of a mounted Manifest, described without manifest types.
/// </summary>
/// <remarks>
/// <para>
/// The tools are carried as protocol-neutral values, not as manifest types and not as
/// protocol types. Everything a listing shows is decided here; a transport maps these onto
/// whatever its SDK wants and has nothing left to choose.
/// </para>
/// <para>
/// The <see cref="Fingerprint"/> covers everything advertised, so two surfaces that
/// fingerprint alike list alike, and an inspection surface can prove agreement without
/// rendering the protocol payload it would otherwise have to compare.
/// </para>
/// </remarks>
/// <param name="Slug">The surface identifier, which is also the last route segment.</param>
/// <param name="DisplayName">The surface's declared name, defaulting to its slug.</param>
/// <param name="IsDefault">Whether the mount prefix alone addresses this surface.</param>
/// <param name="RequiredScopes">Scopes a token must carry to reach this surface.</param>
/// <param name="Tools">Every advertised tool, in advertisement order.</param>
/// <param name="Fingerprint">A canonical digest of everything the surface advertises.</param>
public sealed record MountedSurface(
    string Slug,
    string DisplayName,
    bool IsDefault,
    IReadOnlyList<string> RequiredScopes,
    IReadOnlyList<CatalogueTool> Tools,
    string Fingerprint)
{
    /// <summary>
    /// Every operation the Navigator may resolve here, in exposure order.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A superset of <see cref="Tools"/>, and the reason it is a separate list: the operations
    /// a surface exposes only through the Navigator appear in no listing, so a set derived
    /// from what is advertised cannot resolve them. Keyed by operation, not by tool name,
    /// because that is the identifier discovery hands back.
    /// </para>
    /// <para>
    /// Internal, and empty by default so a constructed surface that advertises nothing also
    /// reaches nothing. A surface built for a mount is given the real set.
    /// </para>
    /// </remarks>
    internal IReadOnlyList<CatalogueTool> Navigable { get; init; } = [];

    /// <summary>How this surface introduces itself to a client that connects to it.</summary>
    /// <remarks>
    /// Per surface rather than per Manifest, because a client addresses a surface. Two
    /// surfaces of one Manifest hold different tools and answer at different addresses; giving
    /// them one indistinguishable identity would leave a client unable to tell which of the
    /// two it is talking to, which is the same complaint one level down.
    /// </remarks>
    public ServerIdentity Identity { get; init; } = ServerIdentity.Undeclared;

    /// <summary>Every advertised tool name, in advertisement order.</summary>
    /// <remarks>
    /// Read from <see cref="Tools"/> rather than stored beside it. Two lists that must agree
    /// are two lists that eventually will not, and the one an operator reads is the one that
    /// would go stale silently.
    /// </remarks>
    public IReadOnlyList<string> ToolNames => [.. Tools.Select(static tool => tool.Name)];

    /// <summary>The advertised tool with this exact name, or <c>null</c>.</summary>
    /// <remarks>
    /// <para>
    /// Ordinal, because a tool name is exact. A case-insensitive lookup would let a name
    /// differing only in case reach a tool the caller did not name.
    /// </para>
    /// <para>
    /// Internal on purpose. Resolving a called name decides whether a call is refused, and a
    /// refusal that discloses whether a name exists is an oracle for what a surface holds. One
    /// component owns that answer, and it is not the transport.
    /// </para>
    /// </remarks>
    internal CatalogueTool? Find(string name)
        => Tools.FirstOrDefault(tool => string.Equals(tool.Name, name, StringComparison.Ordinal));

    /// <summary>The Navigator-reachable operation with this exact identifier, or <c>null</c>.</summary>
    /// <remarks>
    /// Ordinal for the same reason <see cref="Find"/> is, and internal for a stronger one: an
    /// answer here distinguishes an operation that exists from one that does not, and the
    /// whole point of Navigator exposure is that the distinction does not leave this library.
    /// </remarks>
    internal CatalogueTool? FindNavigable(string operation)
        => Navigable.FirstOrDefault(tool => string.Equals(tool.Operation, operation, StringComparison.Ordinal));
}

/// <summary>
/// One Manifest, loaded, narrowed, and with every surface already derived.
/// </summary>
/// <remarks>
/// <para>
/// The document is not exposed. A host serves a Manifest by asking this library what to
/// serve, never by reading the document and deciding for itself; keeping the document
/// internal is what makes that a fact rather than a convention.
/// </para>
/// <para>
/// Surfaces are derived during startup rather than on first request. Two reasons, and the
/// second is the one that matters: a derivation failure becomes a refusal to start instead of
/// an error the first client sees, and an inspection verb and a serving verb read the same
/// value, so the preview cannot disagree with what would be served.
/// </para>
/// </remarks>
public sealed class MountedManifest
{
    internal MountedManifest(
        string prefix,
        string path,
        ManifestDocument document,
        PolicySection policy,
        IReadOnlyList<MountedSurface> surfaces,
        NavigatorIndex index)
    {
        Prefix = prefix;
        Path = path;
        Document = document;
        Policy = policy;
        Surfaces = surfaces;
        Index = index;
        RequiresAuthorization = document.Server.AuthenticationRequired;
    }

    /// <summary>The route prefix this Manifest answers on.</summary>
    public string Prefix { get; }

    /// <summary>The Manifest bundle directory it was loaded from.</summary>
    public string Path { get; }

    /// <summary>The server name the Manifest declares.</summary>
    public string ServerName => Document.Server.Name;

    /// <summary>Every enabled surface, in declaration order.</summary>
    public IReadOnlyList<MountedSurface> Surfaces { get; }

    /// <summary>
    /// Whether this mount is an OAuth 2.1 protected resource.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Read from the Manifest's own declared member (<c>server.authenticationRequired</c>,
    /// absent meaning protected) at load, so a host that serves this mount and a host that
    /// reports on it cannot disagree about the answer.
    /// </para>
    /// <para>
    /// One value per mount by construction. A surface is not the unit an authorization decision
    /// is made about: every surface answers under one prefix, and the format therefore does not
    /// let a mount protect one surface and leave a sibling open. A surface's declared scopes
    /// restrict a token; they never decide whether one is required.
    /// </para>
    /// </remarks>
    public bool RequiresAuthorization { get; }

    internal ManifestDocument Document { get; }

    internal PolicySection Policy { get; }

    /// <summary>The lexical index every surface of this Manifest ranks from.</summary>
    /// <remarks>
    /// One index per Manifest, not per surface: the index documents operations, and a surface
    /// decides which of them it exposes at the moment it is queried. Building one per surface
    /// would bake an exposure decision into an artifact and make the query-time filter — the
    /// only check that does not trust the index — redundant with it.
    /// </remarks>
    internal NavigatorIndex Index { get; }
}

/// <summary>
/// The outcome of bringing a process up to the point just before it would listen.
/// </summary>
/// <remarks>
/// Either every mount is ready or none is. A partially mounted process answers some requests
/// and refuses others in a way indistinguishable from an upstream fault, and the operator's
/// own configuration is the last place they will look.
/// </remarks>
public sealed class RuntimeStartResult
{
    private RuntimeStartResult(IReadOnlyList<MountedManifest> mounts, IReadOnlyList<StartupRefusal> refusals, IReadOnlyList<StartupRefusal> warnings)
    {
        Mounts = mounts;
        Refusals = refusals;
        Warnings = warnings;
    }

    /// <summary>
    /// The verified file-handle store, present once the process may start.
    /// </summary>
    /// <remarks>
    /// The store startup verified is the store execution uses. Constructing a second one at
    /// invocation time would mean the thing that was proven usable and the thing that is used
    /// are two objects, and only the first was checked.
    /// </remarks>
    internal FileHandleStore? Files { get; private init; }

    /// <summary>Whether inline credential material was permitted for this process.</summary>
    /// <remarks>
    /// Carried from the options rather than re-read, so what loading accepted and what
    /// execution resolves cannot disagree about the same switch.
    /// </remarks>
    internal bool AllowInlineSecrets { get; private init; }

    /// <summary>
    /// The opened runtime-state directory, present once the process may start. Null keeps
    /// runtime-owned mutable state in memory only.
    /// </summary>
    /// <remarks>
    /// Carried because the directory startup verified is the directory execution writes through.
    /// Reopening it per invocation would re-read a key and re-check a root that was already
    /// accepted, and the object that was checked would not be the object that stores anything.
    /// </remarks>
    internal RuntimeStateLocation? RuntimeState { get; private init; }

    /// <summary>The effective host-only response-cache ceilings reported at startup.</summary>
    public ResponseCacheOptions ResponseCache { get; private init; } = ResponseCacheOptions.Default;

    /// <summary>
    /// The confined evaluator every JMESPath output projection is invoked through.
    /// </summary>
    /// <remarks>
    /// Carried from the options the runtime was started with, so the pool an operator configured
    /// is the pool the served projections use. Null means the process has none, and an operation
    /// declaring JMESPath is then refused at invocation rather than evaluated in place.
    /// </remarks>
    internal IProjectionWorker? ProjectionWorker { get; private init; }

    /// <summary>Every mount, in configuration order. Empty when the process is refused.</summary>
    public IReadOnlyList<MountedManifest> Mounts { get; }

    /// <summary>
    /// Whether runtime-owned mutable authentication state survives a restart.
    /// </summary>
    /// <remarks>
    /// Public because it is the one fact about the runtime-state configuration an operator needs
    /// at startup: a deployment that leaves a rotating refresh token in memory loses it on
    /// restart and must reauthorize, and that is a supported choice rather than a defect. Naming
    /// it in the startup report is what keeps the choice visible.
    /// </remarks>
    public bool DurableRuntimeState => RuntimeState is not null;

    /// <summary>Every reason the process will not start. Empty on success.</summary>
    public IReadOnlyList<StartupRefusal> Refusals { get; }

    /// <summary>Findings that do not prevent starting, such as an inline secret that was permitted.</summary>
    public IReadOnlyList<StartupRefusal> Warnings { get; }

    /// <summary>Whether the process may open a listener.</summary>
    public bool Started => Refusals.Count == 0;

    internal static RuntimeStartResult Ready(
        IReadOnlyList<MountedManifest> mounts,
        IReadOnlyList<StartupRefusal> warnings,
        FileHandleStore files,
        bool allowInlineSecrets,
        RuntimeStateLocation? runtimeState,
        ResponseCacheOptions responseCache,
        IProjectionWorker? projectionWorker = null)
        => new(mounts, [], warnings)
        {
            Files = files,
            AllowInlineSecrets = allowInlineSecrets,
            RuntimeState = runtimeState,
            ResponseCache = responseCache,
            ProjectionWorker = projectionWorker,
        };

    internal static RuntimeStartResult Refused(IReadOnlyList<StartupRefusal> refusals, IReadOnlyList<StartupRefusal> warnings)
        => new([], refusals, warnings);
}
