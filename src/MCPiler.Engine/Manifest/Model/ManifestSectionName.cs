namespace MCPiler.Engine.Manifest.Model;

/// <summary>The closed set of manifest section names.</summary>
/// <remarks>
/// An unknown section name is refused rather than ignored. A misspelled section would
/// otherwise silently fall back to a derived or default value, and for
/// <see cref="Policy"/> or <see cref="Credentials"/> that means a silently wrong security
/// perimeter.
/// </remarks>
public static class ManifestSectionName
{
    /// <summary>Display identity and the surfaces that define routing and exposure.</summary>
    public const string Server = "server";

    /// <summary>Outbound execution policy, runtime limits, and evaluation bounds.</summary>
    public const string Policy = "policy";

    /// <summary>Credential slot declarations holding references, never secret values.</summary>
    public const string Credentials = "credentials";

    /// <summary>
    /// Generic authentication profiles: closed strategy configuration, origins, credential
    /// references, and mutable-slot authority state.
    /// </summary>
    public const string Authentication = "authentication";

    /// <summary>The effective HTTP operation model and its local schema components.</summary>
    public const string Operations = "operations";

    /// <summary>Agent operations, groups, bindings, annotations, and search metadata.</summary>
    public const string AgentSurface = "agentSurface";

    /// <summary>The compiled advertised tool set per surface. Optional and derivable.</summary>
    public const string Tools = "tools";

    /// <summary>The lexical search index. Optional and derivable.</summary>
    public const string Search = "search";

    /// <summary>The packed embedding matrix. Optional, external-only, degrades silently.</summary>
    public const string Vectors = "vectors";

    /// <summary>Every recognized section name, in load order.</summary>
    public static IReadOnlyList<string> All { get; } =
    [
        Server,
        Policy,
        Credentials,
        Authentication,
        Operations,
        AgentSurface,
        Tools,
        Search,
        Vectors,
    ];

    /// <summary>
    /// Sections whose payload MUST live in a separate file and is never inline.
    /// </summary>
    /// <remarks>
    /// The vector matrix is binary. Embedding it as base64 in the index would bloat the
    /// document that a human edits and would drag a non-deterministic artifact into the
    /// byte-determinism contract.
    /// </remarks>
    public static IReadOnlySet<string> ExternalOnly { get; } =
        new HashSet<string>(StringComparer.Ordinal) { Vectors };

    /// <summary>Returns true when <paramref name="name"/> is a recognized section name.</summary>
    public static bool IsKnown(string? name)
        => name is not null && All.Contains(name, StringComparer.Ordinal);
}
