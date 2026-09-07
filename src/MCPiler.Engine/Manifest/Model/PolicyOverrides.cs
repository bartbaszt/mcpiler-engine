namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// Operator-supplied narrowing of a compiled <see cref="PolicySection"/>.
/// </summary>
/// <remarks>
/// <para>
/// Per the accepted split decision, local configuration MAY reduce any compiled bound and MAY
/// remove an allowed origin, but MUST NOT increase a bound and MUST NOT add an origin. An
/// attempt to widen is refused at startup rather than clamped silently, because a silent
/// clamp leaves an operator believing in a perimeter or a budget that is not deployed.
/// </para>
/// <para>
/// The shape is deliberately flat rather than mirroring the nested policy structure. Each
/// property maps one-to-one onto a single compiled bound, so a configuration binder cannot
/// produce a partially populated nested object whose absent members would be indistinguishable
/// from "no override".
/// </para>
/// <para>
/// Nothing here can change what a manifest means: no override introduces a destination,
/// an operation, a credential, or a tool.
/// </para>
/// </remarks>
public sealed record PolicyOverrides
{
    /// <summary>No local narrowing.</summary>
    public static PolicyOverrides None { get; } = new();

    /// <summary>
    /// A replacement perimeter. Every entry MUST already appear in the compiled perimeter;
    /// this can only remove origins.
    /// </summary>
    public IReadOnlyList<string>? AllowedOrigins { get; init; }

    /// <summary>Narrowed TCP/TLS connect budget.</summary>
    public TimeSpan? UpstreamConnectTimeout { get; init; }

    /// <summary>Narrowed whole-request budget.</summary>
    public TimeSpan? UpstreamRequestTimeout { get; init; }

    /// <summary>Narrowed bounded response read limit.</summary>
    public long? UpstreamResponseSizeLimitBytes { get; init; }

    /// <summary>Narrowed redirect hop limit.</summary>
    public int? RedirectHopLimit { get; init; }

    /// <summary>Narrowed per-connector concurrency.</summary>
    public int? Concurrency { get; init; }

    /// <summary>Narrowed inbound MCP request body limit.</summary>
    public long? McpRequestSizeLimitBytes { get; init; }

    /// <summary>Narrowed transformation step ceiling.</summary>
    public int? TransformMaxSteps { get; init; }

    /// <summary>Narrowed transformation depth ceiling.</summary>
    public int? TransformMaxDepth { get; init; }

    /// <summary>Narrowed transformation node ceiling.</summary>
    public int? TransformMaxNodes { get; init; }

    /// <summary>Narrowed transformation output ceiling.</summary>
    public long? TransformMaxOutputBytes { get; init; }

    /// <summary>Narrowed transformation array fan-out ceiling.</summary>
    public int? TransformMaxArrayFanout { get; init; }

    /// <summary>Narrowed compound total response budget.</summary>
    public long? CompoundMaxTotalResponseBytes { get; init; }

    /// <summary>Narrowed compound workflow budget.</summary>
    public TimeSpan? CompoundWorkflowTimeout { get; init; }

    /// <summary>Narrowed schema resolution depth bound.</summary>
    public int? SchemaMaxDepth { get; init; }

    /// <summary>Narrowed schema resolution node bound.</summary>
    public int? SchemaMaxNodes { get; init; }

    /// <summary>Narrowed per-level property bound.</summary>
    public int? SchemaMaxPropertiesPerLevel { get; init; }

    /// <summary>Narrowed file handle lifetime.</summary>
    public TimeSpan? FileHandleLifetime { get; init; }

    /// <summary>Narrowed upload size limit.</summary>
    public long? FileUploadSizeLimitBytes { get; init; }

    /// <summary>
    /// Magic-byte mismatch rejection. Only <c>true</c> is a narrowing; turning a compiled
    /// <c>true</c> into <c>false</c> accepts payloads whose content contradicts their declared
    /// media type and is therefore a widening.
    /// </summary>
    public bool? FileRejectMagicMismatch { get; init; }
}
