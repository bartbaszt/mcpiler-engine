namespace MCPiler.Engine.Execution.Secrets.RuntimeState;

/// <summary>
/// A process-lifetime, OS-backed ownership lock for one durable runtime-state root.
/// The file is deliberately never removed: unlinking a live Unix lock file would let
/// a second process lock a different inode at the same name.
/// </summary>
/// <remarks>
/// <para>
/// Acquisition is one exclusive open of <c>.runtime-state-owner.lock</c> in the resolved
/// physical root; release is disposing the handle on normal shutdown or the OS closing it on
/// process termination. There is no PID marker, no existence test and no timeout: the handle
/// either exists or another owner holds it.
/// </para>
/// <para>
/// The supported boundary is a local filesystem: on Linux the effective root's longest mount
/// entry must name a known local filesystem type, and on Windows the spelling must be a local
/// drive letter. UNC spellings are refused before any probe. Mapped network drives cannot be
/// machine-distinguished from local drives without volume inspection, which the architecture
/// boundary forbids, so they are outside the documented supported boundary rather than
/// silently trusted; see <c>docs/runtime-state-ownership.md</c>.
/// </para>
/// </remarks>
public sealed class RuntimeStateOwnerLease : IDisposable
{
    private const string LockFileName = ".runtime-state-owner.lock";
    private readonly FileStream _handle;

    private RuntimeStateOwnerLease(FileStream handle) => _handle = handle;

    /// <summary>
    /// Refuses an overlapping owner or a filesystem whose locking/rename guarantees
    /// are outside the supported local-filesystem boundary. The caller must retain
    /// the returned lease until serving and all mutable operations have stopped.
    /// </summary>
    public static bool TryAcquire(string root, out RuntimeStateOwnerLease? lease, out string? refusal)
    {
        lease = null;
        refusal = null;
        FileStream? handle = null;

        if (string.IsNullOrWhiteSpace(root))
        {
            refusal = "A runtime-state root is required for exclusive ownership.";
            return false;
        }

        try
        {
            string normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));

            // Refuse an unsupported spelling before probing it: a network root must not be
            // opened, created or resolved, because those operations are themselves the
            // unreliable behavior this boundary exists to avoid.
            if (!IsSupportedLocalFilesystem(normalized))
            {
                refusal = "Runtime-state ownership requires a supported local filesystem; network or unrecognized mounts are refused.";
                return false;
            }

            Directory.CreateDirectory(normalized);
            normalized = ResolvePhysicalDirectory(normalized);

            // Opening the file through an alias/junction/symlink reaches the same
            // filesystem object, so lexical path spelling cannot create another owner.
            // Network and unrecognized mounts are excluded because file-share and
            // atomic-replacement semantics cannot be assumed there. The resolved target
            // decides: a link can point at a different filesystem than its spelling.
            if (!IsSupportedLocalFilesystem(normalized))
            {
                refusal = "Runtime-state ownership requires a supported local filesystem; network or unrecognized mounts are refused.";
                return false;
            }

            handle = new FileStream(
                Path.Combine(normalized, LockFileName), FileMode.OpenOrCreate,
                FileAccess.ReadWrite, FileShare.None);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(handle.Name, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            lease = new RuntimeStateOwnerLease(handle);
            handle = null;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            handle?.Dispose();
            refusal = "Runtime-state ownership is unavailable or held by another process. Stop the serving Engine before changing authorization state, then retry.";
            return false;
        }
    }

    private static string ResolvePhysicalDirectory(string fullPath)
    {
        // Resolve every component; ResolveLinkTarget on only the final directory
        // misses a junction/symlink in an intermediate parent.
        string baseRoot = Path.GetPathRoot(fullPath)!;
        string current = baseRoot;
        foreach (string component in Path.GetRelativePath(baseRoot, fullPath)
                     .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            FileSystemInfo? linkTarget = new DirectoryInfo(current).ResolveLinkTarget(returnFinalTarget: true);
            if (linkTarget is not null)
            {
                current = linkTarget.FullName;
            }
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(current));
    }

    private static bool IsSupportedLocalFilesystem(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            // The architecture boundary forbids volume inspection, so the supported boundary is
            // expressed in path terms. A drive-letter spelling is accepted; a UNC spelling is
            // refused before it is probed. A mapped network drive under a letter cannot be
            // distinguished without inspecting the volume, which this component is forbidden
            // from doing: mapped drives are outside the documented supported boundary, not
            // silently trusted.
            string? root = Path.GetPathRoot(path);
            return root is { Length: >= 2 }
                && char.IsAsciiLetter(root[0])
                && root[1] is ':';
        }

        if (!OperatingSystem.IsLinux() || !File.Exists("/proc/self/mountinfo"))
        {
            return false;
        }

        // Choose the longest mount-point prefix, not the parent device: bind/NFS
        // mounts may be nested beneath a local / or /tmp mount.
        int longest = -1;
        string? filesystem = null;
        foreach (string line in File.ReadLines("/proc/self/mountinfo"))
        {
            string[] halves = line.Split(" - ", 2, StringSplitOptions.None);
            if (halves.Length != 2)
            {
                return false;
            }

            string[] left = halves[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string[] right = halves[1].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (left.Length < 5 || right.Length < 1)
            {
                return false;
            }

            string mount = left[4].Replace("\\040", " ", StringComparison.Ordinal)
                .Replace("\\011", "\t", StringComparison.Ordinal)
                .Replace("\\012", "\n", StringComparison.Ordinal)
                .Replace("\\134", "\\", StringComparison.Ordinal);
            if (path.Equals(mount, StringComparison.Ordinal)
                || path.StartsWith(mount.EndsWith('/') ? mount : mount + '/', StringComparison.Ordinal))
            {
                if (mount.Length > longest)
                {
                    longest = mount.Length;
                    filesystem = right[0];
                }
            }
        }

        return filesystem is "ext4" or "xfs" or "btrfs" or "zfs" or "f2fs" or "tmpfs" or "overlay";
    }

    public void Dispose() => _handle.Dispose();
}
