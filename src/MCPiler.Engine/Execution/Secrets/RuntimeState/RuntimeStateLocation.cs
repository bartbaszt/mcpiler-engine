using MCPiler.Engine.Execution.RuntimeState;

namespace MCPiler.Engine.Execution.Secrets.RuntimeState;

/// <summary>
/// An opened runtime-state directory: the deployment's key, verified once, and the per-mount
/// stores that consume it.
/// </summary>
/// <remarks>
/// <para>
/// Opening is a startup concern. A root that cannot be created or a key that cannot be read is a
/// deployment fault, and finding it when the first refresh token rotates would mean the operator
/// discovers it during an authentication failure rather than at deploy time. This type therefore
/// does all the reading and checking once, up front, and hands out stores that cannot fail to
/// construct.
/// </para>
/// <para>
/// When no root or key is configured the process keeps an in-memory store. That is a supported
/// configuration — a deployment that does not need a rotating refresh token to survive a restart —
/// and it is deliberately not a silent downgrade of a configured one: a configured root or key
/// that is unusable refuses the process rather than falling back.
/// </para>
/// </remarks>
public sealed class RuntimeStateLocation
{
    private readonly string _root;
    private readonly byte[] _key;

    private RuntimeStateLocation(string root, byte[] key)
    {
        _root = root;
        _key = key;
    }

    /// <summary>The directory this state reads and writes.</summary>
    public string Root => _root;

    /// <summary>
    /// Opens the runtime-state directory, or reports why it cannot be used.
    /// </summary>
    /// <param name="root">The configured directory, or null when runtime state is not configured.</param>
    /// <param name="keyFile">The configured key file, or null when runtime state is not configured.</param>
    /// <param name="state">The opened state on success.</param>
    /// <param name="refusal">A bounded, non-secret reason on failure; null on success.</param>
    /// <returns>True when the state was opened.</returns>
    public static bool TryOpen(
        string? root,
        string? keyFile,
        out RuntimeStateLocation? state,
        out string? refusal)
    {
        state = null;

        var hasRoot = !string.IsNullOrWhiteSpace(root);
        var hasKey = !string.IsNullOrWhiteSpace(keyFile);

        if (!hasRoot && !hasKey)
        {
            // Unconfigured is a supported state: the process keeps its in-memory store.
            refusal = null;
            return true;
        }

        if (hasRoot != hasKey)
        {
            refusal =
                "Durable runtime state needs both a runtime-state root and a runtime-state key "
                + "file; configure both or neither.";
            return false;
        }

        if (!RuntimeStateKeyFile.TryRead(keyFile!, out var key, out var keyRefusal))
        {
            refusal = keyRefusal;
            return false;
        }

        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root!));

        try
        {
            Directory.CreateDirectory(normalized);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            refusal = $"The runtime-state root '{normalized}' could not be created or is not writable.";
            return false;
        }

        state = new RuntimeStateLocation(normalized, key);
        refusal = null;
        return true;
    }

    /// <summary>
    /// Creates the store one mount persists through.
    /// </summary>
    /// <remarks>
    /// A mount's identity is its prefix. Records are bound to it, so a record written for one
    /// mount cannot be used by another even if both declare the same profile and slot.
    /// </remarks>
    /// <param name="mountIdentity">The mount's stable identity.</param>
    public FileMutableSlotStore CreateForMount(string mountIdentity)
        => new(_root, mountIdentity, _key);
}
