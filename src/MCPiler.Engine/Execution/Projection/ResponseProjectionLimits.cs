namespace MCPiler.Engine.Execution.Projection;

/// <summary>
/// The fixed response-metadata ceilings of the <c>agentSurface</c> v5 contract.
/// </summary>
/// <remarks>
/// <para>
/// These are deliberate MCPiler security/compatibility policy defaults, not HTTP limits and not
/// limits derived from HTTP: RFC 9110 defines no universal byte ceiling for response fields. The
/// operation cannot raise them, and the values are mirrored on the Platform side so preview and
/// runtime refuse the same bytes.
/// </para>
/// <para>
/// The aggregate budgets are enforced on what a projection actually adds to the agent result: a
/// raw-header breach drops every header-derived mapping, and a serialized breach drops them as
/// well while pagination keeps its own independent object ceiling.
/// </para>
/// </remarks>
internal static class ResponseProjectionLimits
{
    /// <summary>Per selected response-header field value.</summary>
    internal const int MaxHeaderValueBytes = 16 * 1024;

    /// <summary>Values consumed from one selected header.</summary>
    internal const int MaxHeaderValues = 32;

    /// <summary>Raw header bytes consumed by one output projection.</summary>
    internal const int MaxRawHeaderBytes = 32 * 1024;

    /// <summary>Parsed link-values from a configured Link source.</summary>
    internal const int MaxLinkValues = 128;

    /// <summary>One resolved continuation URL.</summary>
    internal const int MaxContinuationUrlBytes = 16 * 1024;

    /// <summary>The serialized normalized pagination object.</summary>
    internal const int MaxPaginationObjectBytes = 32 * 1024;

    /// <summary>Serialized generic metadata plus pagination added by one projection.</summary>
    internal const int MaxSerializedMetadataBytes = 64 * 1024;
}
