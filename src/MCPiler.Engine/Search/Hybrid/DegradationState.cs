namespace MCPiler.Engine.Search.Hybrid;

/// <summary>
/// How usable a Manifest's vector matrix is for the operation set it accompanies.
/// </summary>
/// <remarks>
/// <para>
/// Four of these are the states that must stay distinguishable through ordinary operational
/// output rather than a user interface: nothing supplied, something unreadable, something
/// whose declared shape the bytes do not support, and something usable.
/// </para>
/// <para>
/// <see cref="OperationMismatch"/> is the fifth, and it exists because a matrix listing
/// operations other than the ones being served must be refused <em>and reported</em>.
/// Reporting it as <see cref="Unreadable"/> would name a defect the payload does not have,
/// and reporting it as <see cref="DimensionMismatch"/> would send an operator to check a
/// number that is correct. A code that carries two meanings leaves the reader unable to tell
/// which one they have.
/// </para>
/// <para>
/// Every state other than <see cref="Usable"/> ranks lexically, and none of them refuses a
/// mount. A matrix accelerates discovery; refusing to serve because an accelerator is stale
/// would withdraw search that works in order to punish search that would have worked better.
/// </para>
/// </remarks>
internal enum VectorAvailability
{
    /// <summary>The Manifest declares no vector payload. This is not an error.</summary>
    Absent,

    /// <summary>The payload is not a matrix this build can parse.</summary>
    Unreadable,

    /// <summary>The header's declared shape disagrees with the payload's length.</summary>
    DimensionMismatch,

    /// <summary>The matrix describes operations other than the ones being served.</summary>
    OperationMismatch,

    /// <summary>The matrix is usable, and ranking may draw on it.</summary>
    Usable,
}

/// <summary>What reading a Manifest's vector payload produced.</summary>
/// <param name="State">Which of the five conditions the payload is in.</param>
/// <param name="Matrix">The parsed matrix, present only when <paramref name="State"/> is usable.</param>
/// <param name="Detail">
/// An operator-facing sentence naming what disagreed, absent when nothing did.
/// </param>
/// <remarks>
/// A refused matrix is not carried. Handing back something unusable alongside a state saying
/// so invites a caller to read it anyway, and partial scoring over a matrix that does not
/// describe the served operations is the failure this whole type exists to prevent.
/// </remarks>
internal sealed record VectorMatrixResult(VectorAvailability State, VectorMatrix? Matrix, string? Detail)
{
    /// <summary>No payload was supplied.</summary>
    internal static VectorMatrixResult Absent { get; } = new(VectorAvailability.Absent, null, null);

    /// <summary>A payload was supplied and cannot be used, for the stated reason.</summary>
    internal static VectorMatrixResult Refused(VectorAvailability state, string detail)
        => new(state, null, detail);

    /// <summary>A payload was supplied and describes the operation set being served.</summary>
    internal static VectorMatrixResult Ready(VectorMatrix matrix)
        => new(VectorAvailability.Usable, matrix, null);
}
