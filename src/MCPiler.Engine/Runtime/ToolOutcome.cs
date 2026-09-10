namespace MCPiler.Engine.Runtime;

/// <summary>
/// What one tool call produced, described without a protocol type.
/// </summary>
/// <remarks>
/// <para>
/// A transport renders this and decides nothing. Whether a call was refused, whether an
/// upstream answer counts as a tool error, and what a caller is told are all product
/// questions answered before this value exists.
/// </para>
/// <para>
/// There is always text. A result with no content block would leave a caller unable to
/// distinguish an empty answer from a lost one, and every refusal has something to say about
/// itself even when it deliberately says very little.
/// </para>
/// <para>
/// <see cref="IsError"/> marks a failure of the call, not an unsuccessful upstream status. An
/// upstream that answers 404 answered: the status and the body are the result, and reporting
/// it as a tool error would tell a caller its request was malformed when it was not.
/// </para>
/// </remarks>
/// <param name="Text">What the caller is told.</param>
/// <param name="IsError">Whether the call itself failed.</param>
public sealed record ToolOutcome(string Text, bool IsError);
