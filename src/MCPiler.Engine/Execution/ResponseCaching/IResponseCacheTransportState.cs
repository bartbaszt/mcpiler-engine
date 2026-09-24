namespace MCPiler.Engine.Execution.ResponseCaching;

/// <summary>
/// Optional adapter signal: whether the transport has request state not represented by the
/// compiled upstream request and its known defaults.
/// </summary>
internal interface IResponseCacheTransportState
{
    bool HasUnrepresentedRequestState { get; }
}
