using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Manifest.Model;

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
        IReadOnlyList<MountedSurface> surfaces)
    {
        Prefix = prefix;
        Path = path;
        Document = document;
        Policy = policy;
        Surfaces = surfaces;
    }

    /// <summary>The route prefix this Manifest answers on.</summary>
    public string Prefix { get; }

    /// <summary>The Manifest bundle directory it was loaded from.</summary>
    public string Path { get; }

    /// <summary>The server name the Manifest declares.</summary>
    public string ServerName => Document.Server.Name;

    /// <summary>Every enabled surface, in declaration order.</summary>
    public IReadOnlyList<MountedSurface> Surfaces { get; }

    internal ManifestDocument Document { get; }

    internal PolicySection Policy { get; }
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

    /// <summary>Every mount, in configuration order. Empty when the process is refused.</summary>
    public IReadOnlyList<MountedManifest> Mounts { get; }

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
        bool allowInlineSecrets)
        => new(mounts, [], warnings) { Files = files, AllowInlineSecrets = allowInlineSecrets };

    internal static RuntimeStartResult Refused(IReadOnlyList<StartupRefusal> refusals, IReadOnlyList<StartupRefusal> warnings)
        => new([], refusals, warnings);
}
