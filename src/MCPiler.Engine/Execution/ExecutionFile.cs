namespace MCPiler.Engine.Execution;

/// <summary>
/// One file value attached to an execution without materializing its content.
/// </summary>
/// <param name="WireHandle">The opaque capability value moved by <c>fileRef</c>.</param>
/// <param name="FileName">The safe declared file name.</param>
/// <param name="MediaType">The declared media type.</param>
/// <param name="Length">The stored byte length.</param>
/// <param name="Content">A replayable source that opens the content only while it is written.</param>
public sealed record ExecutionFile(
    string WireHandle,
    string FileName,
    string MediaType,
    long Length,
    ReplayableBodySource Content);
