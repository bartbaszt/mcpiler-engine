using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Execution.Secrets.RuntimeState;

/// <summary>
/// The outcome of reading the confirmation journal for one slot identity.
/// </summary>
internal enum ConfirmationState
{
    /// <summary>A durable confirmation exists for the slot's epoch.</summary>
    Confirmed,

    /// <summary>The journal was read and holds no confirmation for the slot.</summary>
    NotConfirmed,

    /// <summary>The journal could not be read, or failed its integrity check.</summary>
    Unavailable,
}

/// <summary>
/// The three-state result of a confirmation lookup. A caller must never treat
/// <see cref="ConfirmationState.Unavailable"/> as negative evidence: it means the journal could not be
/// verified, not that no confirmation exists (R13.1).
/// </summary>
/// <param name="State">Which of the three outcomes was observed.</param>
/// <param name="Epoch">The confirmed authority epoch; meaningful only when <paramref name="State"/> is <see cref="ConfirmationState.Confirmed"/>.</param>
/// <param name="Revision">The confirmed runtime revision; meaningful only when <paramref name="State"/> is <see cref="ConfirmationState.Confirmed"/>.</param>
internal readonly record struct ConfirmationLookup(ConfirmationState State, long Epoch, long Revision)
{
    /// <summary>The journal could not be read or verified.</summary>
    public static ConfirmationLookup Unavailable => new(ConfirmationState.Unavailable, 0, 0);

    /// <summary>The journal was read and holds no confirmation for the slot.</summary>
    public static ConfirmationLookup NotConfirmed => new(ConfirmationState.NotConfirmed, 0, 0);

    /// <summary>The journal was read and holds a confirmation for the slot.</summary>
    public static ConfirmationLookup Confirmed(long epoch, long revision)
        => new(ConfirmationState.Confirmed, epoch, revision);
}

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

    /// <summary>Marks a versioned (v2) journal whose body is protected by a checksum.</summary>
    private const string Magic = "#MCPilerConfirmedRevisions";

    /// <summary>The current on-disk format version.</summary>
    private const string CurrentFormatVersion = "2";

    private readonly string _path;
    private readonly object _sync = new();
    private Dictionary<string, (long Epoch, long Revision)>? _entries;
    private bool _integrityFailed;

    /// <summary>
    /// Test seam: how the journal file is read. Overridable so a test can inject a transient read
    /// failure deterministically without depending on platform-specific file-locking behavior. The
    /// default is <see cref="ReadJournalLines"/>, so the seam and the production open cannot diverge.
    /// </summary>
    internal Func<string, string[]> ReadAllLines { get; set; } = ReadJournalLines;

    /// <summary>
    /// Test seam: invoked after the journal temp is flushed to disk and before it is renamed over the
    /// journal, so a test can prove the flush happens before the publish (R15.10).
    /// </summary>
    internal Action? OnFlushedBeforeRename { get; set; }

    /// <summary>
    /// Opens the journal for reading with the share mode a serving Engine needs: while the journal is
    /// degraded every lookup, worker pass and health query re-reads it, so an operator reset's rename must
    /// not be blocked by an in-flight read. <see cref="FileShare.Read"/> would refuse that move while the
    /// read handle is open, making the documented reset fail intermittently with
    /// <see cref="JournalResetOutcome.Failed"/> even though it may run while the Engine is serving (R18.1).
    /// </summary>
    internal static FileStream OpenJournal(string path)
        => new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

    /// <summary>
    /// The default journal read: <see cref="OpenJournal"/>'s sharing plus the line semantics of
    /// <see cref="File.ReadAllLines(string)"/> (the v2 checksum is computed over the reconstructed lines, so
    /// the split and any BOM handling must not change). A named method so the open itself is testable.
    /// </summary>
    internal static string[] ReadJournalLines(string path)
    {
        using FileStream stream = OpenJournal(path);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var lines = new List<string>();
        while (reader.ReadLine() is { } line)
        {
            lines.Add(line);
        }

        return [.. lines];
    }

    /// <summary>
    /// Whether the journal exists but failed an integrity check (bad header, checksum mismatch, a corrupt
    /// record, or a zero-length file). Such a failure does not clear on its own; the Engine surfaces it as an
    /// operator-visible degraded state that only an explicit reset resolves (R15.12).
    /// </summary>
    internal bool IntegrityFailed
    {
        get
        {
            lock (_sync)
            {
                return _integrityFailed;
            }
        }
    }

    public ConfirmedRevisionStore(string root) => _path = Path.Combine(root, FileName);

    /// <summary>
    /// Re-evaluates whether the journal is currently an integrity failure, for an operator diagnostic and
    /// the managed health probe (R16.5/R16.7). While the store is known to be degraded it re-runs the load
    /// under the lock, so a reset performed by another process on the same path is observed rather than a
    /// stale in-memory failure; otherwise it answers from the validated cached snapshot and touches no disk.
    /// Only an integrity failure — never a transient read failure — is degraded, and this never persists.
    /// </summary>
    internal bool ReevaluateIntegrityFailed()
    {
        lock (_sync)
        {
            if (_integrityFailed)
            {
                // Re-read so a reset performed by another process clears the state instead of lingering. A
                // transient re-read leaves the state unknown, and the last verified state was an integrity
                // failure, so it must not be reported as recovered until a read proves otherwise (R17.2):
                // an unknown state is not a healthy one.
                _entries = null;
                _integrityFailed = false;
                var loaded = TryLoad();
                if (loaded is null && !_integrityFailed)
                {
                    _integrityFailed = true;
                }
            }
            else if (_entries is null)
            {
                // Not evaluated yet (or a transient failure left no snapshot): classify once so a first
                // evaluation after startup reports an already-corrupt journal. A transient failure here has
                // no previously verified failure to preserve, so it is not reported as degraded.
                TryLoad();
            }

            return _integrityFailed;
        }
    }

    /// <summary>
    /// Looks up the confirmation for one slot identity with an explicit availability state, so a caller can
    /// tell "verified absent" from "journal unavailable". Only <see cref="ConfirmationState.NotConfirmed"/>
    /// may trigger a fallback default; <see cref="ConfirmationState.Unavailable"/> must defer the decision
    /// and force a retry (R13.1).
    /// </summary>
    /// <param name="mount">The mount the slot belongs to.</param>
    /// <param name="profileId">The manifest-local profile identity.</param>
    /// <param name="slot">The slot identity.</param>
    public ConfirmationLookup Lookup(string mount, string profileId, string slot)
    {
        lock (_sync)
        {
            var entries = TryLoad();
            if (entries is null)
            {
                return ConfirmationLookup.Unavailable;
            }

            return entries.TryGetValue(KeyFor(mount, profileId, slot), out var entry)
                ? ConfirmationLookup.Confirmed(entry.Epoch, entry.Revision)
                : ConfirmationLookup.NotConfirmed;
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

            // A failed rename must not poison the cached journal that subsequent Record calls
            // use as their source. Publish a replacement cache only after durable replacement.
            var pruned = new Dictionary<string, (long Epoch, long Revision)>(entries, StringComparer.Ordinal);
            foreach (var key in stale)
            {
                pruned.Remove(key);
            }

            try
            {
                Persist(pruned);
                _entries = pruned;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Best-effort: a failed prune leaves a larger journal but must not drop a live
                // confirmation from memory.
            }
        }
    }

    /// <summary>
    /// The explicit operator reset for a permanently integrity-failed journal (R15.12, owner choice R15-A).
    /// It is refused while the journal is readable and valid, and also refused when the journal merely
    /// cannot be read right now (a transient fault that must not move a valid journal aside, R16.4). On a
    /// journal the fresh read positively classified integrity-failed it moves the file aside under a
    /// non-overwriting name and never deletes its bytes, so the operator can inspect it. After the reset the
    /// journal is absent: every slot reads <c>NotConfirmed</c> and reconciliation bases on the declared
    /// revision. Nothing here resets automatically.
    /// </summary>
    /// <param name="asidePath">The path the failed journal was moved to, when <see cref="JournalResetOutcome.Reset"/>.</param>
    public JournalResetOutcome ResetFailedJournal(out string? asidePath)
    {
        lock (_sync)
        {
            asidePath = null;

            if (!File.Exists(_path))
            {
                return JournalResetOutcome.Missing;
            }

            // Re-read from disk rather than trusting a cached snapshot, so the reset refuses a journal that is
            // currently valid even if a stale failure was observed earlier.
            var previousEntries = _entries;
            bool wasIntegrityFailed = _integrityFailed;
            _entries = null;
            _integrityFailed = false;

            // A fresh read must positively classify the journal as integrity-failed before any bytes are
            // moved. A transient read failure (I/O, permissions, a concurrent rename) leaves the file in
            // place: moving a valid but momentarily unreadable journal aside would lose every confirmation
            // and reintroduce the R10.6 stranding risk (R16.4). TryLoad sets _integrityFailed only for a bad
            // header, a checksum mismatch, a corrupt record or a zero-length file.
            if (TryLoad() is not null)
            {
                return JournalResetOutcome.RefusedValid;
            }

            if (!_integrityFailed)
            {
                // The refused reset must not change the degraded answer: a transient fault proves nothing, so
                // the integrity state that held before this attempt is restored. Otherwise the next
                // evaluation would report a known-failed journal as healthy while the fault lasts (R18.2).
                _entries = previousEntries;
                _integrityFailed = wasIntegrityFailed;
                return JournalResetOutcome.Unreadable;
            }

            string aside = _path + ".failed-" + DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ", CultureInfo.InvariantCulture);
            var collision = 0;
            while (File.Exists(aside))
            {
                aside = _path + ".failed-" + DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ", CultureInfo.InvariantCulture)
                    + "-" + (++collision).ToString(CultureInfo.InvariantCulture);
            }

            try
            {
                File.Move(_path, aside);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return JournalResetOutcome.Failed;
            }

            asidePath = aside;
            _entries = null;
            _integrityFailed = false;
            return JournalResetOutcome.Reset;
        }
    }

    internal static string KeyFor(string mount, string profileId, string slot)
        => string.Concat(mount, '\u001f', profileId, '\u001f', slot);

    private static bool IsNotOlder((long Epoch, long Revision) existing, long epoch, long revision)
        => existing.Epoch > epoch || (existing.Epoch == epoch && existing.Revision >= revision);

    /// <summary>
    /// Loads the journal, caching it once it has been read. Returns null when the journal file exists but
    /// could not be read or failed its integrity check, so callers never treat an unverified read as a
    /// valid empty journal. A missing file is a legitimate empty journal and is cached as empty (R12.4).
    /// </summary>
    /// <remarks>
    /// The current format is versioned and checksummed; a headerless journal is accepted as legacy v1 and
    /// parsed all-or-nothing. A record that cannot be parsed, in either format, is an integrity failure for
    /// the whole journal rather than a line to skip: skipping it and rewriting the file later would silently
    /// drop the confirmation it still held (R13.6).
    /// </remarks>
    private Dictionary<string, (long Epoch, long Revision)>? TryLoad()
    {
        if (_entries is not null)
        {
            return _entries;
        }

        if (!File.Exists(_path))
        {
            _integrityFailed = false;
            _entries = new Dictionary<string, (long, long)>(StringComparer.Ordinal);
            return _entries;
        }

        // An existing zero-length file is a torn or lost write, never a valid empty journal: the writer never
        // emits one (an empty v2 journal still carries its header), and the headerless v1 format was never
        // released. Treating it as empty would silently drop every confirmation (R15.10, owner choice R15-B).
        long length;
        try
        {
            length = new FileInfo(_path).Length;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The file disappeared or could not be measured between the existence check and this read, for
            // example a concurrent operator reset renaming it. Fail closed as an unreadable journal rather
            // than letting FileNotFoundException escape Lookup, Record or Prune in the running Engine (R16.4).
            return null;
        }

        if (length == 0)
        {
            _integrityFailed = true;
            return null;
        }

        string[] lines;
        try
        {
            lines = ReadAllLines(_path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The file exists but its contents could not be verified. Do not cache an empty snapshot: a
            // later write must not overwrite a journal whose current contents are unknown (R12.4). This is a
            // transient fault, so it does not set the persistent integrity-failed state; the next call
            // retries the read.
            return null;
        }

        var bodyLines = lines;

        // A versioned journal opens with a magic header carrying the format version and a checksum of the
        // body. An unrecognised header is an integrity failure, never an empty journal.
        if (lines.Length > 0 && lines[0].StartsWith(Magic + FieldSeparator, StringComparison.Ordinal))
        {
            var header = lines[0].Split(FieldSeparator);
            if (header.Length != 3 || !string.Equals(header[1], CurrentFormatVersion, StringComparison.Ordinal))
            {
                _integrityFailed = true;
                return null;
            }

            bodyLines = lines[1..];
            var actual = Checksum(ReconstructBody(bodyLines));
            if (!string.Equals(header[2], actual, StringComparison.OrdinalIgnoreCase))
            {
                _integrityFailed = true;
                return null;
            }
        }

        var entries = new Dictionary<string, (long, long)>(StringComparer.Ordinal);
        foreach (var line in bodyLines)
        {
            if (!TryParseLine(line, out var key, out var epoch, out var revision))
            {
                // A corrupt record is an integrity failure for the whole journal (R13.6).
                _integrityFailed = true;
                return null;
            }

            entries[key] = (epoch, revision);
        }

        _integrityFailed = false;
        _entries = entries;
        return entries;
    }

    /// <summary>
    /// Rebuilds the exact body text from the lines the reader returned, so the checksum is computed over the
    /// same bytes that were written. A trailing newline per record is what <see cref="Persist"/> emitted.
    /// </summary>
    private static string ReconstructBody(IReadOnlyList<string> bodyLines)
    {
        if (bodyLines.Count == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        foreach (var line in bodyLines)
        {
            builder.Append(line).Append('\n');
        }

        return builder.ToString();
    }

    private static string Checksum(string body)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body)));

    /// <summary>
    /// Writes the journal atomically in the versioned format: a magic header carrying the format version and
    /// a checksum of the body, followed by the records. Throws on a write failure so the caller can refuse to
    /// treat the confirmation as durable; <see cref="Record"/> translates that into a false result and a
    /// rollback (R11.2).
    /// </summary>
    private void Persist(Dictionary<string, (long Epoch, long Revision)> entries)
    {
        var body = new StringBuilder();
        foreach (var pair in entries.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            body.Append(pair.Key).Append(FieldSeparator)
                .Append(pair.Value.Epoch.ToString(CultureInfo.InvariantCulture)).Append(FieldSeparator)
                .Append(pair.Value.Revision.ToString(CultureInfo.InvariantCulture)).Append('\n');
        }

        var bodyText = body.ToString();

        var header = $"{Magic}{FieldSeparator}{CurrentFormatVersion}{FieldSeparator}{Checksum(bodyText)}\n";

        var temporary = _path + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(Encoding.UTF8.GetBytes(header + bodyText));
            // Flush to disk before the rename, mirroring FileMutableSlotStore: a successful confirmation is a
            // durable effect, and a power loss must not lose or tear a confirmation the worker already relied
            // on (R15.10).
            stream.Flush(flushToDisk: true);
        }

        OnFlushedBeforeRename?.Invoke();
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
