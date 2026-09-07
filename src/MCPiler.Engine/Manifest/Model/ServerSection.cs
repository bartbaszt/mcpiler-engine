namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The <c>server</c> section: display identity plus the surfaces that define routing and
/// exposure.
/// </summary>
/// <param name="Name">
/// Required. Used as the MCP server display name and as the outbound HTTP client name.
/// </param>
/// <param name="Description">Optional MCP server description.</param>
/// <param name="Version">Optional upstream API version, for MCP server info.</param>
/// <param name="Surfaces">
/// The declared surfaces. An empty list means the minimal manifest applies and Engine
/// synthesizes one default surface; see <see cref="ManifestSurface.Synthesize"/>.
/// </param>
public sealed record ServerSection(
    string Name,
    string? Description = null,
    string? Version = null,
    IReadOnlyList<ManifestSurface> Surfaces = null!)
{
    /// <summary>The section format version this model represents.</summary>
    public const int FormatVersion = 1;

    /// <summary>The declared surfaces, never null.</summary>
    public IReadOnlyList<ManifestSurface> Surfaces { get; init; } = Surfaces ?? [];

    /// <summary>True when no surface was declared and one must be synthesized.</summary>
    public bool IsMinimal => Surfaces.Count == 0;

    /// <summary>Returns the surface with the given slug, or <c>null</c>.</summary>
    public ManifestSurface? Surface(string slug)
        => Surfaces.FirstOrDefault(surface => string.Equals(surface.Slug, slug, StringComparison.Ordinal));

    /// <summary>Returns the default surface, or <c>null</c> when none is marked default.</summary>
    public ManifestSurface? DefaultSurface
        => Surfaces.FirstOrDefault(static surface => surface.IsDefault);
}

/// <summary>
/// One MCP surface: a route, its exposure decisions, and its protocol policy.
/// </summary>
/// <param name="Slug">
/// Required. The route segment served at <c>/mcp/{connector}/{slug}</c>.
/// </param>
/// <param name="Operations">
/// The single runtime exposure authority. An operation is invocable on this surface if and
/// only if it appears here with exposure <see cref="OperationExposure.Direct"/> or
/// <see cref="OperationExposure.Navigator"/>.
/// </param>
/// <param name="Name">Display name. Defaults to <paramref name="Slug"/>.</param>
/// <param name="IsDefault">
/// Whether this surface also serves <c>/mcp/{connector}</c>. Exactly one surface must be
/// default.
/// </param>
/// <param name="Enabled">
/// Whether the surface is resolvable. A disabled surface discloses nothing, matching the
/// current published-surface status behavior.
/// </param>
/// <param name="RequiredScopes">
/// OAuth scopes required in addition to the byte-exact audience binding.
/// </param>
/// <param name="Navigator">Navigator settings for this surface.</param>
/// <param name="OutputSchemas">
/// Whether this surface may advertise output schemas at all. An operation's own policy can
/// only narrow this, never widen it.
/// </param>
public sealed record ManifestSurface(
    string Slug,
    IReadOnlyList<SurfaceOperation> Operations = null!,
    string? Name = null,
    bool IsDefault = false,
    bool Enabled = true,
    IReadOnlyList<string> RequiredScopes = null!,
    NavigatorSettings? Navigator = null,
    bool OutputSchemas = false)
{
    /// <summary>The exposure list, never null.</summary>
    public IReadOnlyList<SurfaceOperation> Operations { get; init; } = Operations ?? [];

    /// <summary>The required scopes, never null.</summary>
    public IReadOnlyList<string> RequiredScopes { get; init; } = RequiredScopes ?? [];

    /// <summary>The effective display name.</summary>
    public string DisplayName => Name ?? Slug;

    /// <summary>The effective Navigator settings.</summary>
    public NavigatorSettings EffectiveNavigator => Navigator ?? NavigatorSettings.Disabled;

    /// <summary>
    /// Builds the single surface implied by a manifest that declares no surface at all.
    /// </summary>
    /// <param name="serverName">The <c>server.name</c> value, used as the display name.</param>
    /// <param name="directOperationSlugs">
    /// Every agent-surface operation slug, exposed directly. A minimal manifest has no
    /// curation input, so every declared operation is advertised.
    /// </param>
    public static ManifestSurface Synthesize(
        string serverName,
        IEnumerable<string> directOperationSlugs)
        => new(
            Slug: "default",
            Operations: [.. directOperationSlugs.Select(static slug => new SurfaceOperation(slug, OperationExposure.Direct))],
            Name: serverName,
            IsDefault: true,
            Enabled: true,
            RequiredScopes: [],
            Navigator: NavigatorSettings.Disabled,
            OutputSchemas: false);

    /// <summary>
    /// Returns the exposure of <paramref name="operationSlug"/> on this surface, or
    /// <c>null</c> when the operation is not listed and therefore not invocable.
    /// </summary>
    public OperationExposure? ExposureOf(string operationSlug)
        => Operations
            .FirstOrDefault(entry => string.Equals(entry.Operation, operationSlug, StringComparison.Ordinal))
            ?.Exposure;

    /// <summary>True when <paramref name="operationSlug"/> may be invoked on this surface.</summary>
    public bool InvocationAllowed(string operationSlug)
        => ExposureOf(operationSlug) is OperationExposure.Direct or OperationExposure.Navigator;
}

/// <summary>Navigator defaults, declared outside the record so they can be parameter defaults.</summary>
public static class NavigatorDefaults
{
    /// <summary>The discovery page size used when none is declared.</summary>
    public const int PageSize = 25;
}

/// <summary>Navigator behavior for one surface.</summary>
/// <param name="Enabled">Whether the Navigator tool trio is advertised.</param>
/// <param name="PageSize">Default page size for Navigator discovery.</param>
public sealed record NavigatorSettings(bool Enabled = false, int PageSize = NavigatorDefaults.PageSize)
{
    /// <summary>Navigator turned off, which is the default for an undeclared surface.</summary>
    public static NavigatorSettings Disabled { get; } = new(Enabled: false);
}

/// <summary>One exposure decision on one surface.</summary>
/// <param name="Operation">An <c>agentSurface</c> operation slug.</param>
/// <param name="Exposure">How the operation may be reached.</param>
public sealed record SurfaceOperation(string Operation, OperationExposure Exposure);
