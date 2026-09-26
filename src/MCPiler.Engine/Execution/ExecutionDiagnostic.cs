namespace MCPiler.Engine.Execution;

/// <summary>
/// One metadata-only finding of a single execution.
/// </summary>
/// <remarks>
/// <para>
/// A projection or pagination refusal is not an execution failure: the upstream body stays
/// available and the diagnostic explains what was withheld. It is carried beside the result so
/// the serving layer can attribute it to a mounted manifest and surface, which are facts the
/// execution does not own.
/// </para>
/// <para>
/// The code is the stable contract; the pointer is a bounded location inside the reviewed
/// policy, never a value. A diagnostic that echoed the refused value would be a second leak of
/// exactly what the refusal exists to contain.
/// </para>
/// </remarks>
/// <param name="Code">The stable diagnostic code.</param>
/// <param name="Pointer">The policy location the finding concerns, when one is known.</param>
public sealed record ExecutionDiagnostic(string Code, string? Pointer = null);
