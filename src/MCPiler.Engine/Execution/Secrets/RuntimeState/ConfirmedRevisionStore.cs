using System.Globalization;
using System.Text;

namespace MCPiler.Engine.Execution.Secrets.RuntimeState;

/// <summary>
/// Durably remembers, per mount/profile/slot, the highest runtime revision the Platform has
/// confirmed, so a restarted process bases a recovery report on what the peer actually holds rather
/// than on the revision declared by whichever generation it happens to be serving (R10.6).
/// </summary>
/// <remarks>
/// <para>
/// This carries only non-secret identity and revision numbers - the same associated data the
/// encrypted record already authenticates - never a value. It lives beside the encrypted records in
/// the runtime-state root and is written atomically (temp + rename).
/// </para>
/// <para>
/// A missing entry means "never confirmed": the caller falls back to the delivered generation's
/// declared revision, which is the case where several rotations coalesced before the first report
/// and the Platform is still at the declared revision.
/// </para>
/// <para>
/// A confirmation is only as good as its durability: when the journal cannot be written the change is
/// rolled back in memory and the caller is told, so an unwritten confirmation is never treated as
/// durable (R11.2). The journal is pruned to the active generation's declared slots so it is bounded
/// by the live slot set rather than by every identity ever confirmed (R11.7).
/// </para>
/// </remarks>
internal sealed class ConfirmedRevisionStore
{
    private const string FileName = "confirmed-revisions.txt";
    private const char FieldSeparator = '\t';

    private readonly string _path;
    private readonly object _sync = new();
    private Dictionary<string, (long Epoch, long Revision)>? _entries;

    /// <summary>
    /// Test seam: how the journal file is read. Overridable so a test can inject a transient read
    /// failure deterministically without depending on platform-specific file-locking behavior.
    /// </summary>
    internal Func<string, string[]> ReadAllLines { get; set; } = path => File.ReadAllLines(path);

    public ConfirmedRevisionStore(string root) => _path = Path.Combine(root, FileName);

    /// <summary>
    /// The revision the Platform last confirmed for one slot identity, or null when none has been
    /// confirmed yet. A journal that exists but cannot be read also returns null, so a caller degrades to
    /// the declared revision rather than to an unverified value.
    /// </summary>
    public (long Epoch, long Revision)? Read(string mount, string profileId, string slot)
    {
        lock (_sync)
        {
            var entries = TryLoad();
            return entries is not null
                && entries.TryGetValue(KeyFor(mount, profileId, slot), out var entry)
                ? entry
                : null;
        }
    }

    /// <summary>
    /// Records a confirmation, keeping the highest epoch/revision seen. Returns false when the
    /// confirmation could not be durably written; the in-memory state is rolled back so an unwritten
    /// confirmation is never mistaken for a durable one (R11.2).
    /// </summary>
    public bool Record(string mount, string profileId, string slot, long epoch, long revision)
    {
        lock (_sync)
        {
            var entries = TryLoad();
            if (entries is null)
            {
                // The journal exists but its current contents could not be read. Writing now would
                // overwrite confirmations that were never verified, so the write is refused and the caller
                // retries once the journal is readable (R12.4).
                return false;
            }

            var key = KeyFor(mount, profileId, slot);
            var had = entries.TryGetValue(key, out var existing);
            if (had && IsNotOlder(existing, epoch, revision))
            {
                return true;
            }

            entries[key] = (epoch, revision);
            try
            {
                Persist(entries);
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A "durable" confirmation whose write failed is not durable. Restore the previous
                // in-memory value (or drop the new key) and report the failure to the caller.
                if (had)
                {
                    entries[key] = existing;
                }
                else
                {
                    entries.Remove(key);
                }

                return false;
            }
        }
    }

    /// <summary>
    /// Removes confirmations for identities the active generation no longer declares, so the journal
    /// tracks the live slot set instead of every identity ever confirmed (R11.7). A failed prune is
    /// best-effort and leaves the in-memory confirmations intact.
    /// </summary>
    /// <param name="activeKeys">The identity keys (<see cref="KeyFor"/>) of the active slots.</param>
    public void Prune(IReadOnlyCollection<string> activeKeys)
    {
        lock (_sync)
        {
            var entries = TryLoad();
            if (entries is null)
            {
                // A journal that could not be read is left untouched rather than overwritten from an
                // unverified empty state (R12.4).
                return;
            }

            var stale = entries.Keys.Where(key => !activeKeys.Contains(key)).ToArray();
            if (stale.Length == 0)
            {
                return;
            }

            foreach (var key in stale)
            {
                entries.Remove(key);
            }

            try
            {
                Persist(entries);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Best-effort: a failed prune leaves a larger journal but must not drop a live
                // confirmation from memory.
            }
        }
    }

    internal static string KeyFor(string mount, string profileId, string slot)
        => string.Concat(mount, '\u001f', profileId, '\u001f', slot);

    private static bool IsNotOlder((long Epoch, long Revision) existing, long epoch, long revision)
        => existing.Epoch > epoch || (existing.Epoch == epoch && existing.Revision >= revision);

    /// <summary>
    /// Loads the journal, caching it once it has been read. Returns null when the journal file exists but
    /// could not be read, so callers never treat an unverified read as a valid empty journal. A missing
    /// file is a legitimate empty journal and is cached as empty (R12.4).
    /// </summary>
    private Dictionary<string, (long Epoch, long Revision)>? TryLoad()
    {
        if (_entries is not null)
        {
            return _entries;
        }

        if (!File.Exists(_path))
        {
            _entries = new Dictionary<string, (long, long)>(StringComparer.Ordinal);
            return _entries;
        }

        var entries = new Dictionary<string, (long, long)>(StringComparer.Ordinal);
        try
        {
            foreach (var line in ReadAllLines(_path))
            {
                if (TryParseLine(line, out var key, out var epoch, out var revision))
                {
                    entries[key] = (epoch, revision);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The file exists but its contents could not be verified. Do not cache an empty snapshot: a
            // later write must not overwrite a journal whose current contents are unknown (R12.4). The
            // state stays unset so the next call retries the read.
            return null;
        }

        _entries = entries;
        return entries;
    }

    /// <summary>
    /// Writes the journal atomically. Throws on a write failure so the caller can refuse to treat the
    /// confirmation as durable; <see cref="Record"/> translates that into a false result and a
    /// rollback (R11.2).
    /// </summary>
    private void Persist(Dictionary<string, (long Epoch, long Revision)> entries)
    {
        var builder = new StringBuilder();
        foreach (var pair in entries.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            builder.Append(pair.Key).Append(FieldSeparator)
                .Append(pair.Value.Epoch.ToString(CultureInfo.InvariantCulture)).Append(FieldSeparator)
                .Append(pair.Value.Revision.ToString(CultureInfo.InvariantCulture)).Append('\n');
        }

        var temporary = _path + ".tmp";
        File.WriteAllText(temporary, builder.ToString());
        File.Move(temporary, _path, overwrite: true);
    }

    private static bool TryParseLine(string line, out string key, out long epoch, out long revision)
    {
        key = string.Empty;
        epoch = 0;
        revision = 0;

        var parts = line.Split(FieldSeparator);
        return parts.Length == 3
            && long.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out epoch)
            && long.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out revision)
            && (key = parts[0]).Length > 0;
    }
}
