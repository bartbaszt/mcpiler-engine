namespace MCPiler.Engine.Execution;

/// <summary>Stable request headers the Engine's HTTP adapter adds when callers omit them.</summary>
/// <remarks>
/// These values are shared by the HTTP adapter and response-cache identity construction. If
/// either changes, the adapter's request contract and cache key must move together.
/// </remarks>
internal static class UpstreamRequestDefaults
{
    internal const string UserAgent = "MCPiler-Engine/0.1";

    internal const string AcceptEncoding = "gzip, deflate";
}
