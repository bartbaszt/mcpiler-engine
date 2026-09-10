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
/// One Manifest, loaded and narrowed, ready to have a surface derived from it.
/// </summary>
/// <remarks>
/// The document is not exposed. A host serves a Manifest by asking this library what to
/// serve, never by reading the document and deciding for itself; keeping the document
/// internal is what makes that a fact rather than a convention.
/// </remarks>
public sealed class MountedManifest
{
    internal MountedManifest(string prefix, string path, ManifestDocument document, PolicySection policy)
    {
        Prefix = prefix;
        Path = path;
        Document = document;
        Policy = policy;
    }

    /// <summary>The route prefix this Manifest answers on.</summary>
    public string Prefix { get; }

    /// <summary>The Manifest file or bundle directory it was loaded from.</summary>
    public string Path { get; }

    /// <summary>The server name the Manifest declares.</summary>
    public string ServerName => Document.Server.Name;

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

    /// <summary>Every mount, in configuration order. Empty when the process is refused.</summary>
    public IReadOnlyList<MountedManifest> Mounts { get; }

    /// <summary>Every reason the process will not start. Empty on success.</summary>
    public IReadOnlyList<StartupRefusal> Refusals { get; }

    /// <summary>Findings that do not prevent starting, such as an inline secret that was permitted.</summary>
    public IReadOnlyList<StartupRefusal> Warnings { get; }

    /// <summary>Whether the process may open a listener.</summary>
    public bool Started => Refusals.Count == 0;

    internal static RuntimeStartResult Ready(IReadOnlyList<MountedManifest> mounts, IReadOnlyList<StartupRefusal> warnings)
        => new(mounts, [], warnings);

    internal static RuntimeStartResult Refused(IReadOnlyList<StartupRefusal> refusals, IReadOnlyList<StartupRefusal> warnings)
        => new([], refusals, warnings);
}
