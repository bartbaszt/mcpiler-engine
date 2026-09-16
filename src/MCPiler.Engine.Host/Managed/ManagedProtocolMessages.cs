using System.Text.Json.Serialization;

namespace MCPiler.Engine.Host.Managed;

/// <summary>
/// The managed synchronization wire contract, as the Platform producer writes it.
/// </summary>
/// <remarks>
/// <para>
/// Member names are pinned to the shared fixture rather than to C# conventions: the fixture is
/// the contract two repositories agreed on, and a serializer setting that quietly renamed a
/// member would move the agreement without either side noticing until a deployment.
/// </para>
/// <para>
/// Nothing here is secret. The values a generation carries live in <see cref="Secrets"/> and are
/// never written anywhere by this process; everything else is already visible in the Platform's
/// own management protocol.
/// </para>
/// </remarks>
public sealed class ManagedGenerationMessage
{
    /// <summary>The protocol version the producer wrote.</summary>
    [JsonPropertyName("protocolVersion")]
    public int ProtocolVersion { get; set; }

    /// <summary>The producer's deterministic generation identity.</summary>
    [JsonPropertyName("generationId")]
    public string GenerationId { get; set; } = string.Empty;

    /// <summary>Every mount of the generation, in delivery order.</summary>
    [JsonPropertyName("mounts")]
    public List<ManagedMountMessage> Mounts { get; set; } = [];

    /// <summary>
    /// Provider key to value. Delivered separately from the Manifests because the Manifests
    /// carry only references; a value here never becomes part of a Manifest byte.
    /// </summary>
    [JsonPropertyName("secrets")]
    public Dictionary<string, string> Secrets { get; set; } = new(StringComparer.Ordinal);

    /// <summary>Correlation metadata; none of it changes what is served.</summary>
    [JsonPropertyName("metadata")]
    public ManagedMetadataMessage Metadata { get; set; } = new();
}

/// <summary>One mount of the delivered generation.</summary>
public sealed class ManagedMountMessage
{
    /// <summary>The route prefix this mount is served under.</summary>
    [JsonPropertyName("prefix")]
    public string Prefix { get; set; } = string.Empty;

    /// <summary>The packed Manifest bundle, base64.</summary>
    [JsonPropertyName("bundle")]
    public string Bundle { get; set; } = string.Empty;
}

/// <summary>Producer metadata carried for correlation and diagnostics.</summary>
public sealed class ManagedMetadataMessage
{
    /// <summary>The producer's desired revision identity.</summary>
    [JsonPropertyName("desiredRevisionId")]
    public string? DesiredRevisionId { get; set; }

    /// <summary>The producer's Engine version, for diagnostics only.</summary>
    [JsonPropertyName("engineVersion")]
    public string? EngineVersion { get; set; }
}

/// <summary>
/// What one poll tells the Platform, and what the Platform answers with.
/// </summary>
/// <remarks>
/// The two shapes live in one file because they are one exchange: a request that named a field
/// the Platform does not read, or a response the request side parsed differently, is the same
/// defect seen from two ends.
/// </remarks>
public sealed class ManagedPollRequestMessage
{
    /// <summary>The protocol version this Engine speaks.</summary>
    [JsonPropertyName("protocolVersion")]
    public int ProtocolVersion { get; set; }

    /// <summary>This Engine's build identity.</summary>
    [JsonPropertyName("engineVersion")]
    public string? EngineVersion { get; set; }

    /// <summary>The Manifest format range this Engine implements.</summary>
    [JsonPropertyName("supportedManifestRange")]
    public string? SupportedManifestRange { get; set; }

    /// <summary>The generation currently active, or null before the first activation.</summary>
    [JsonPropertyName("activeGenerationId")]
    public string? ActiveGenerationId { get; set; }

    /// <summary>The last generation this Engine activated, even if superseded.</summary>
    [JsonPropertyName("deliveredGenerationId")]
    public string? DeliveredGenerationId { get; set; }

    /// <summary>The outcome of the previous candidate, when one failed.</summary>
    [JsonPropertyName("lastCandidateOutcome")]
    public string? LastCandidateOutcome { get; set; }

    /// <summary>The previous candidate's sanitized diagnostics.</summary>
    [JsonPropertyName("lastCandidateDiagnostics")]
    public List<ManagedDiagnosticMessage> LastCandidateDiagnostics { get; set; } = [];

    /// <summary>Rotations this Engine committed locally and has not seen the Platform accept.</summary>
    [JsonPropertyName("pendingReconciliationCount")]
    public int PendingReconciliationCount { get; set; }

    /// <summary>
    /// A random identity minted once per Engine process, so the Platform can order reports within
    /// one process and recognize a restarted one.
    /// </summary>
    [JsonPropertyName("engineInstanceId")]
    public string? EngineInstanceId { get; set; }

    /// <summary>
    /// This process's report counter, incremented for every poll it sends. Combined with
    /// <see cref="EngineInstanceId"/> it gives every report a total order, which is what lets the
    /// Platform refuse a delayed request rather than record it over a newer observation.
    /// </summary>
    [JsonPropertyName("engineReportSequence")]
    public long EngineReportSequence { get; set; }
}

/// <summary>One bounded, sanitized diagnostic.</summary>
public sealed class ManagedDiagnosticMessage
{
    /// <summary>The stable code.</summary>
    [JsonPropertyName("code")]
    public string Code { get; set; } = string.Empty;

    /// <summary>The human-readable message; never a secret.</summary>
    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// The conditional rotation report: what this Engine committed locally and wants Platform to hold.
/// </summary>
/// <remarks>
/// Every member except <see cref="Value"/> is a concurrency field. Platform applies the
/// replacement only when all of them still match, so a report from an authority epoch an operator
/// has since replaced is refused rather than applied.
/// </remarks>
public sealed class RuntimeSecretReconciliationMessage
{
    /// <summary>The mount the rotation happened under; selects the connector's profile.</summary>
    [JsonPropertyName("mount")]
    public string Mount { get; set; } = string.Empty;

    /// <summary>The manifest-local profile identity.</summary>
    [JsonPropertyName("profileId")]
    public string ProfileId { get; set; } = string.Empty;

    /// <summary>The rotated slot, for example <c>refreshToken</c>.</summary>
    [JsonPropertyName("slot")]
    public string Slot { get; set; } = string.Empty;

    /// <summary>The authority epoch the rotation happened under.</summary>
    [JsonPropertyName("authorityEpoch")]
    public long AuthorityEpoch { get; set; }

    /// <summary>The runtime revision before the rotation.</summary>
    [JsonPropertyName("previousRuntimeRevision")]
    public long PreviousRuntimeRevision { get; set; }

    /// <summary>The runtime revision the rotation established.</summary>
    [JsonPropertyName("runtimeRevision")]
    public long RuntimeRevision { get; set; }

    /// <summary>The scope fingerprint the rotation happened under.</summary>
    [JsonPropertyName("scopeFingerprint")]
    public string? ScopeFingerprint { get; set; }

    /// <summary>The replacement credential value.</summary>
    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;
}
