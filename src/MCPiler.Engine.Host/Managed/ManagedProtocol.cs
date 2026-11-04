namespace MCPiler.Engine.Host.Managed;

/// <summary>
/// The values the managed protocol pins on the Engine side.
/// </summary>
/// <remarks>
/// These are restated here rather than taken from the Platform assembly, which Engine never
/// references. The shared fixture is the contract; a value that drifted on one side alone would
/// fail the fixture tests rather than a deployment.
/// </remarks>
internal static class ManagedProtocol
{
    /// <summary>The protocol version this Engine speaks.</summary>
    public const int Version = 3;

    /// <summary>Platform-issued fencing epoch carried on accepted managed polls.</summary>
    public const string SessionEpochHeader = "X-MCPiler-Managed-Session-Epoch";

    /// <summary>The outcome spelling for a candidate that became active.</summary>
    public const string Active = "active";

    /// <summary>The outcome spelling for a candidate that was refused.</summary>
    public const string CandidateFailed = "candidate-failed";

    /// <summary>The desired-state kind naming a complete generation.</summary>
    public const string KindGeneration = "generation";

    /// <summary>The desired-state kind naming an affirmative empty desired state.</summary>
    public const string KindEmpty = "empty";

    /// <summary>The desired-state kind used by a structured refusal.</summary>
    public const string KindRefusal = "refusal";

    /// <summary>Whether a value is a bounded, canonical desired-state revision identity.</summary>
    public static bool IsValidDesiredRevisionId(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (char character in value)
        {
            if (character is not (>= '0' and <= '9') && character is not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Whether a value is one of the applied desired-state kinds.</summary>
    public static bool IsValidDesiredKind(string? value)
        => value is KindGeneration or KindEmpty;
}
