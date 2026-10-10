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
/// </remarks>
internal sealed class ConfirmedRevisionStore
{
    private const string FileName = "confirmed-revisions.txt";
    private const char FieldSeparator = '\t';

    private readonly string _path;
    private readonly object _sync = new();
    private Dictionary<string, (long Epoch, long Revision)>? _entries;

    public ConfirmedRevisionStore(string root) => _path = Path.Combine(root, FileName);

    /// <summary>
    /// The revision the Platform last confirmed for one slot identity, or null when none has been
    /// confirmed yet.
    /// </summary>
    public (long Epoch, long Revision)? Read(string mount, string profileId, string slot)
    {
        lock (_sync)
        {
            var entries = Load();
            return entries.TryGetValue(Key(mount, profileId, slot), out var entry) ? entry : null;
        }
    }

    /// <summary>Records a confirmation, keeping the highest epoch/revision seen.</summary>
    public void Record(string mount, string profileId, string slot, long epoch, long revision)
    {
        lock (_sync)
        {
            var entries = Load();
            var key = Key(mount, profileId, slot);
            if (entries.TryGetValue(key, out var existing) && IsNotOlder(existing, epoch, revision))
            {
                return;
            }

            entries[key] = (epoch, revision);
            Persist(entries);
        }
    }

    private static bool IsNotOlder((long Epoch, long Revision) existing, long epoch, long revision)
        => existing.Epoch > epoch || (existing.Epoch == epoch && existing.Revision >= revision);

    private static string Key(string mount, string profileId, string slot)
        => string.Concat(mount, '\u001f', profileId, '\u001f', slot);

    private Dictionary<string, (long Epoch, long Revision)> Load()
    {
        if (_entries is not null)
        {
            return _entries;
        }

        var entries = new Dictionary<string, (long, long)>(StringComparer.Ordinal);
        try
        {
            if (File.Exists(_path))
            {
                foreach (var line in File.ReadAllLines(_path))
                {
                    if (TryParseLine(line, out var key, out var epoch, out var revision))
                    {
                        entries[key] = (epoch, revision);
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // An unreadable confirmation journal degrades to "nothing confirmed": recovery then falls
            // back to the declared revision, never to a fabricated one.
            entries.Clear();
        }

        _entries = entries;
        return entries;
    }

    private void Persist(Dictionary<string, (long Epoch, long Revision)> entries)
    {
        try
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
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best-effort: a failed confirmation write degrades to the declared-revision fallback on the
            // next restart and never blocks the reconciliation that just succeeded.
        }
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
