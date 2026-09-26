namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The <c>policy</c> section: outbound execution policy and evaluation bounds.
/// </summary>
/// <remarks>
/// <para>
/// This is the highest-risk section after <c>credentials</c>. It is a separate section
/// precisely so a security review can be scoped to it.
/// </para>
/// <para>
/// Every nested value carries the current Platform default, so the whole object is omittable
/// except <see cref="BaseUrl"/>. Engine local configuration may only *narrow* these values;
/// an attempt to widen one is a startup refusal rather than a silent clamp, because a silent
/// clamp hides an operator's incorrect belief about the deployed perimeter.
/// </para>
/// </remarks>
/// <param name="BaseUrl">Required. The upstream base address.</param>
/// <param name="AllowedOrigins">
/// The outbound perimeter. Defaults to the single origin of <paramref name="BaseUrl"/>. A
/// malformed entry rejects the section rather than being skipped.
/// </param>
/// <param name="Limits">Transport limits.</param>
/// <param name="TransformCeiling">Upper bound on any transformation program's own limits.</param>
/// <param name="JmesPathCeiling">Upper bound on any JMESPath projection's own limits.</param>
/// <param name="Compound">Compound workflow bounds.</param>
/// <param name="SchemaBounds">Bounds on schema reference resolution.</param>
/// <param name="Files">File handle and upload behavior.</param>
public sealed record PolicySection(
    Uri BaseUrl,
    IReadOnlyList<string> AllowedOrigins = null!,
    ExecutionLimits? Limits = null,
    TransformCeiling? TransformCeiling = null,
    JmesPathCeiling? JmesPathCeiling = null,
    CompoundBounds? Compound = null,
    SchemaBounds? SchemaBounds = null,
    FilePolicy? Files = null)
{
    /// <summary>The section format version this model represents.</summary>
    /// <remarks>
    /// Version 2 adds <c>jmesPathCeiling</c>: the bounds a JMESPath projection's own explicit
    /// limits are measured against, and which local configuration may narrow but not widen.
    /// </remarks>
    public const int FormatVersion = 2;

    /// <summary>
    /// The declared origins, or the single origin derived from <see cref="BaseUrl"/>.
    /// </summary>
    public IReadOnlyList<string> AllowedOrigins { get; init; } =
        AllowedOrigins is { Count: > 0 } declared ? declared : [OriginOf(BaseUrl)];

    /// <summary>The effective transport limits.</summary>
    public ExecutionLimits EffectiveLimits => Limits ?? ExecutionLimits.Default;

    /// <summary>The effective transformation ceiling.</summary>
    public TransformCeiling EffectiveTransformCeiling => TransformCeiling ?? TransformCeiling.Default;

    /// <summary>The effective JMESPath projection ceiling.</summary>
    public JmesPathCeiling EffectiveJmesPathCeiling => JmesPathCeiling ?? JmesPathCeiling.Default;

    /// <summary>The effective compound bounds.</summary>
    public CompoundBounds EffectiveCompound => Compound ?? CompoundBounds.Default;

    /// <summary>The effective schema resolution bounds.</summary>
    public SchemaBounds EffectiveSchemaBounds => SchemaBounds ?? SchemaBounds.Default;

    /// <summary>The effective file policy.</summary>
    public FilePolicy EffectiveFiles => Files ?? FilePolicy.Default;

    /// <summary>
    /// Renders the scheme-host-port origin of <paramref name="uri"/> in the form used in
    /// <see cref="AllowedOrigins"/>.
    /// </summary>
    public static string OriginOf(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return uri.GetLeftPart(UriPartial.Authority);
    }
}

/// <summary>Transport limits applied to every upstream request.</summary>
/// <param name="UpstreamConnectTimeout">TCP/TLS connect budget.</param>
/// <param name="UpstreamRequestTimeout">Whole-request budget.</param>
/// <param name="UpstreamResponseSizeLimitBytes">Bounded response read limit.</param>
/// <param name="RedirectHopLimit">Maximum redirects followed under the origin allow-list.</param>
/// <param name="Concurrency">Maximum concurrent upstream requests for this connector.</param>
/// <param name="McpRequestSizeLimitBytes">Maximum inbound MCP request body size.</param>
public sealed record ExecutionLimits(
    TimeSpan UpstreamConnectTimeout,
    TimeSpan UpstreamRequestTimeout,
    long UpstreamResponseSizeLimitBytes,
    int RedirectHopLimit,
    int Concurrency,
    long McpRequestSizeLimitBytes)
{
    /// <summary>The current Platform defaults.</summary>
    public static ExecutionLimits Default { get; } = new(
        UpstreamConnectTimeout: TimeSpan.FromSeconds(10),
        UpstreamRequestTimeout: TimeSpan.FromSeconds(100),
        UpstreamResponseSizeLimitBytes: 50L * 1024 * 1024,
        RedirectHopLimit: 5,
        Concurrency: 8,
        McpRequestSizeLimitBytes: 1L * 1024 * 1024);
}

/// <summary>
/// The upper bound a transformation program's own declared limits may not exceed.
/// </summary>
/// <param name="MaxSteps">Maximum program steps.</param>
/// <param name="MaxDepth">Maximum document depth touched.</param>
/// <param name="MaxNodes">Maximum nodes produced.</param>
/// <param name="MaxOutputBytes">Maximum serialized output size.</param>
/// <param name="MaxArrayFanout">Maximum array expansion.</param>
public sealed record TransformCeiling(
    int MaxSteps,
    int MaxDepth,
    int MaxNodes,
    long MaxOutputBytes,
    int MaxArrayFanout)
{
    /// <summary>The current Platform transformation defaults.</summary>
    public static TransformCeiling Default { get; } = new(
        MaxSteps: 64,
        MaxDepth: 32,
        MaxNodes: 8192,
        MaxOutputBytes: 256L * 1024,
        MaxArrayFanout: 1024);
}

/// <summary>
/// The upper bound a JMESPath projection's own declared limits may not exceed.
/// </summary>
/// <remarks>
/// <para>
/// The seven dimensions are exactly the ones a projection declares, deliberately. A ceiling
/// that bounded something a projection cannot state would be enforcing a limit nothing can
/// request; a dimension a projection can state and no ceiling bounds would be a widening path
/// the format forgot to close.
/// </para>
/// <para>
/// The evaluation deadline is a wall budget rather than a language bound: it is what terminates
/// an expression whose cost the evaluator cannot be asked about, so it is a ceiling like the
/// others and narrows the same way.
/// </para>
/// </remarks>
/// <param name="MaxExpressionBytes">Maximum expression UTF-8 bytes.</param>
/// <param name="MaxInputNodes">Maximum nodes in the parsed response body.</param>
/// <param name="MaxInputDepth">Maximum nesting depth of the parsed response body.</param>
/// <param name="MaxResultNodes">Maximum nodes in the completed result value.</param>
/// <param name="MaxResultDepth">Maximum nesting depth of the completed result value.</param>
/// <param name="MaxOutputBytes">Maximum serialized projected result bytes.</param>
/// <param name="MaxEvaluationMilliseconds">Maximum worker call wall budget.</param>
public sealed record JmesPathCeiling(
    int MaxExpressionBytes,
    long MaxInputNodes,
    int MaxInputDepth,
    long MaxResultNodes,
    int MaxResultDepth,
    long MaxOutputBytes,
    int MaxEvaluationMilliseconds)
{
    /// <summary>The current Platform projection defaults.</summary>
    /// <remarks>
    /// These are the calibrated administrator ceilings from the profile research, not the
    /// conservative values a new projection starts with. The two are separate so a new
    /// projection does not silently consume the ceiling's headroom.
    /// </remarks>
    public static JmesPathCeiling Default { get; } = new(
        MaxExpressionBytes: 16384,
        MaxInputNodes: 1_000_000,
        MaxInputDepth: 64,
        MaxResultNodes: 65_536,
        MaxResultDepth: 64,
        MaxOutputBytes: 1L * 1024 * 1024,
        MaxEvaluationMilliseconds: 60_000);
}

/// <summary>Bounds applied to a compound workflow as a whole.</summary>
/// <param name="MaxTotalResponseBytes">Total response bytes across all steps.</param>
/// <param name="WorkflowTimeout">Whole-workflow budget.</param>
public sealed record CompoundBounds(long MaxTotalResponseBytes, TimeSpan WorkflowTimeout)
{
    /// <summary>The compound defaults the manifest format fixes; see <c>docs/manifest.md</c>.</summary>
    public static CompoundBounds Default { get; } = new(
        MaxTotalResponseBytes: 100L * 1024 * 1024,
        WorkflowTimeout: TimeSpan.FromSeconds(120));
}

/// <summary>
/// Bounds on local schema reference resolution. These are the anti-amplification limits that
/// make a bounded <c>$ref</c> safe in a future-public runtime.
/// </summary>
/// <param name="MaxDepth">Maximum resolution depth.</param>
/// <param name="MaxNodes">Maximum resolved node count.</param>
/// <param name="MaxPropertiesPerLevel">Maximum properties materialized at one level.</param>
public sealed record SchemaBounds(int MaxDepth, int MaxNodes, int MaxPropertiesPerLevel)
{
    /// <summary>The current Platform schema-flattening defaults.</summary>
    public static SchemaBounds Default { get; } = new(
        MaxDepth: 32,
        MaxNodes: 2048,
        MaxPropertiesPerLevel: 256);
}

/// <summary>File handle lifetime and upload behavior.</summary>
/// <param name="HandleLifetime">How long a transfer handle stays resolvable.</param>
/// <param name="UploadSizeLimitBytes">Maximum accepted upload size.</param>
/// <param name="RejectMagicMismatch">
/// Whether a declared media type that disagrees with the payload's magic bytes is rejected.
/// </param>
public sealed record FilePolicy(
    TimeSpan HandleLifetime,
    long UploadSizeLimitBytes,
    bool RejectMagicMismatch)
{
    /// <summary>The current Platform file defaults.</summary>
    public static FilePolicy Default { get; } = new(
        HandleLifetime: TimeSpan.FromHours(24),
        UploadSizeLimitBytes: 100L * 1024 * 1024,
        RejectMagicMismatch: true);
}
