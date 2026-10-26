using System.IO;
using System.Security.Cryptography;
using System.Text;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Runtime;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Secrets.RuntimeState;

/// <summary>
/// Covers the durable confirmation journal: the non-secret companion that remembers which runtime
/// revision the Platform confirmed for a slot, so a restarted process bases recovery on what the peer
/// holds (R10.6/R11.2/R11.7/R12.4).
/// </summary>
public sealed class ConfirmedRevisionStoreTests : IDisposable
{
    private readonly List<string> _roots = [];

    public void Dispose()
    {
        foreach (var root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "confirmed-revisions-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        _roots.Add(root);
        return root;
    }

    [Fact]
    public void A_transient_read_failure_is_not_cached_and_does_not_drop_existing_confirmations()
    {
        var root = NewRoot();

        var seeded = new ConfirmedRevisionStore(root);
        Assert.True(seeded.Record("m", "p", "a", epoch: 1, revision: 1));
        Assert.True(seeded.Record("m", "p", "b", epoch: 1, revision: 2));

        // A fresh instance whose read fails transiently must not treat the existing journal as empty.
        var failing = new ConfirmedRevisionStore(root);
        failing.ReadAllLines = _ => throw new IOException("transient read failure");

        Assert.Equal(ConfirmationState.Unavailable, failing.Lookup("m", "p", "a").State);
        Assert.False(failing.Record("m", "p", "c", epoch: 1, revision: 3));

        // Access restored: the existing confirmations survive and the new one is merged instead of
        // overwriting a journal whose current contents were never verified (R12.4).
        var recovered = new ConfirmedRevisionStore(root);
        Assert.True(recovered.Record("m", "p", "c", epoch: 1, revision: 3));

        var a = recovered.Lookup("m", "p", "a");
        Assert.Equal(ConfirmationState.Confirmed, a.State);
        Assert.Equal(1, a.Epoch);
        Assert.Equal(1, a.Revision);

        var b = recovered.Lookup("m", "p", "b");
        Assert.Equal(ConfirmationState.Confirmed, b.State);
        Assert.Equal(1, b.Epoch);
        Assert.Equal(2, b.Revision);

        var c = recovered.Lookup("m", "p", "c");
        Assert.Equal(ConfirmationState.Confirmed, c.State);
        Assert.Equal(3, c.Revision);
    }

    [Fact]
    public void A_missing_journal_is_a_legitimate_empty_journal()
    {
        var store = new ConfirmedRevisionStore(NewRoot());

        Assert.Equal(ConfirmationState.NotConfirmed, store.Lookup("m", "p", "a").State);
        Assert.False(store.IntegrityFailed);
        Assert.True(store.Record("m", "p", "a", epoch: 2, revision: 9));

        var a = store.Lookup("m", "p", "a");
        Assert.Equal(ConfirmationState.Confirmed, a.State);
        Assert.Equal(2, a.Epoch);
        Assert.Equal(9, a.Revision);
    }

    // R13.1: an unreadable journal must not be reported as an absent confirmation.
    [Fact]
    public void Lookup_reports_absent_confirmed_and_unavailable_distinctly()
    {
        var root = NewRoot();
        var store = new ConfirmedRevisionStore(root);

        Assert.Equal(ConfirmationState.NotConfirmed, store.Lookup("m", "p", "a").State);

        Assert.True(store.Record("m", "p", "a", epoch: 1, revision: 4));
        ConfirmationLookup confirmed = store.Lookup("m", "p", "a");
        Assert.Equal(ConfirmationState.Confirmed, confirmed.State);
        Assert.Equal(1, confirmed.Epoch);
        Assert.Equal(4, confirmed.Revision);

        var failing = new ConfirmedRevisionStore(root);
        failing.ReadAllLines = _ => throw new IOException("transient read failure");
        Assert.Equal(ConfirmationState.Unavailable, failing.Lookup("m", "p", "a").State);
    }

    // R13.6: a corrupt record must fail the whole journal, never be skipped into a partial load.
    [Fact]
    public void A_corrupt_versioned_record_fails_the_whole_journal()
    {
        var root = NewRoot();
        var store = new ConfirmedRevisionStore(root);
        Assert.True(store.Record("m", "p", "a", epoch: 1, revision: 1));
        Assert.True(store.Record("m", "p", "b", epoch: 1, revision: 2));
        Assert.True(store.Record("m", "p", "c", epoch: 1, revision: 3));

        string path = Path.Combine(root, "confirmed-revisions.txt");
        string[] lines = File.ReadAllLines(path);

        // Corrupt one record's bytes, preserving LF endings so the checksum is the reason it fails.
        lines[2] += "CORRUPT";
        File.WriteAllText(path, string.Join('\n', lines) + "\n");

        var reopened = new ConfirmedRevisionStore(root);
        Assert.Equal(ConfirmationState.Unavailable, reopened.Lookup("m", "p", "a").State);
        Assert.Equal(ConfirmationState.Unavailable, reopened.Lookup("m", "p", "c").State);
        Assert.False(reopened.Record("m", "p", "d", epoch: 1, revision: 4));
    }

    // R13.6: a headerless journal is accepted as legacy v1 all-or-nothing and rewritten versioned.
    [Fact]
    public void A_legacy_headerless_journal_loads_all_or_nothing_and_is_rewritten_versioned()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        string keyA = ConfirmedRevisionStore.KeyFor("m", "p", "a");
        string keyC = ConfirmedRevisionStore.KeyFor("m", "p", "c");

        File.WriteAllText(path, keyA + "\t1\t5\n");

        var store = new ConfirmedRevisionStore(root);
        ConfirmationLookup entry = store.Lookup("m", "p", "a");
        Assert.Equal(ConfirmationState.Confirmed, entry.State);
        Assert.Equal(5, entry.Revision);

        // A write by the current version upgrades the file to the checksummed format.
        Assert.True(store.Record("m", "p", "b", epoch: 1, revision: 6));
        Assert.StartsWith("#MCPilerConfirmedRevisions", File.ReadAllLines(path)[0], StringComparison.Ordinal);

        var reopened = new ConfirmedRevisionStore(root);
        Assert.Equal(ConfirmationState.Confirmed, reopened.Lookup("m", "p", "a").State);
        Assert.Equal(ConfirmationState.Confirmed, reopened.Lookup("m", "p", "b").State);

        // A legacy journal with one unparseable record fails closed as a whole.
        File.WriteAllText(path, keyA + "\t1\t5\n" + keyC + "\tgarbage\t9\n");
        var legacyCorrupt = new ConfirmedRevisionStore(root);
        Assert.Equal(ConfirmationState.Unavailable, legacyCorrupt.Lookup("m", "p", "a").State);
    }

    // R15.10: the journal temp is flushed to disk before it is renamed over the journal, so a successful
    // confirmation is a durable effect. The seam proves the flush precedes the publish.
    [Fact]
    public void Failed_prune_preserves_cached_and_durable_confirmations_through_later_record()
    {
        var root = NewRoot();
        var store = new ConfirmedRevisionStore(root);
        Assert.True(store.Record("m", "p", "a", epoch: 1, revision: 3));
        Assert.True(store.Record("m", "p", "b", epoch: 1, revision: 4));

        store.OnFlushedBeforeRename = () => throw new IOException("injected prune rename failure");
        store.Prune([ConfirmedRevisionStore.KeyFor("m", "p", "a")]);

        Assert.Equal(ConfirmationState.Confirmed, store.Lookup("m", "p", "b").State);
        Assert.Equal(4, store.Lookup("m", "p", "b").Revision);
        Assert.Equal(ConfirmationState.Confirmed,
            new ConfirmedRevisionStore(root).Lookup("m", "p", "b").State);

        store.OnFlushedBeforeRename = null;
        Assert.True(store.Record("m", "p", "c", epoch: 1, revision: 5));
        var reopened = new ConfirmedRevisionStore(root);
        Assert.Equal(3, reopened.Lookup("m", "p", "a").Revision);
        Assert.Equal(4, reopened.Lookup("m", "p", "b").Revision);
        Assert.Equal(5, reopened.Lookup("m", "p", "c").Revision);
    }

    [Fact]
    public void Persist_flushes_to_disk_before_the_rename()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        var store = new ConfirmedRevisionStore(root);

        bool flushedBeforeRename = false;
        store.OnFlushedBeforeRename = () =>
        {
            // The journal must not yet exist at the final path; only the flushed temp does.
            flushedBeforeRename = !File.Exists(path);
        };

        Assert.True(store.Record("m", "p", "a", epoch: 1, revision: 1));
        Assert.True(flushedBeforeRename);
        Assert.True(File.Exists(path));
    }

    // R15.10 / R15-B: an existing zero-length journal is a torn write, not a valid empty journal. It is an
    // integrity failure that must not be cached, must not be overwritten, and follows the R15.12 recovery path.
    [Fact]
    public void An_existing_zero_length_journal_is_an_integrity_failure()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        File.WriteAllBytes(path, []);

        var store = new ConfirmedRevisionStore(root);
        Assert.Equal(ConfirmationState.Unavailable, store.Lookup("m", "p", "a").State);
        Assert.True(store.IntegrityFailed);
        Assert.False(store.Record("m", "p", "a", epoch: 1, revision: 1));
        Assert.Equal(0, new FileInfo(path).Length);

        // A reopened store still reads it as an integrity failure; no Record ever rewrites it as a fresh journal.
        var reopened = new ConfirmedRevisionStore(root);
        Assert.Equal(ConfirmationState.Unavailable, reopened.Lookup("m", "p", "a").State);
        Assert.True(reopened.IntegrityFailed);
    }

    // R15.10: a header-only v2 journal (an empty body with a valid checksum) is a valid empty journal.
    [Fact]
    public void A_header_only_journal_is_a_valid_empty_journal()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        var checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Empty)));
        File.WriteAllText(path, $"#MCPilerConfirmedRevisions\t2\t{checksum}\n");

        var store = new ConfirmedRevisionStore(root);
        Assert.Equal(ConfirmationState.NotConfirmed, store.Lookup("m", "p", "a").State);
        Assert.False(store.IntegrityFailed);
    }

    // R15.12: reset is refused while the journal is readable and valid.
    [Fact]
    public void Reset_is_refused_while_the_journal_is_valid()
    {
        var store = new ConfirmedRevisionStore(NewRoot());
        Assert.True(store.Record("m", "p", "a", epoch: 1, revision: 1));

        Assert.Equal(JournalResetOutcome.RefusedValid, store.ResetFailedJournal(out var aside));
        Assert.Null(aside);
    }

    // R15.12: reset reports Missing when no journal exists.
    [Fact]
    public void Reset_reports_missing_when_no_journal_exists()
    {
        var store = new ConfirmedRevisionStore(NewRoot());
        Assert.Equal(JournalResetOutcome.Missing, store.ResetFailedJournal(out var aside));
        Assert.Null(aside);
    }

    // R15.12 / R15-A: on an integrity-failed journal the reset moves it aside without deleting its bytes; the
    // next lookup is NotConfirmed and a later Record writes a fresh v2 journal, ending the stall.
    [Fact]
    public void Reset_moves_an_integrity_failed_journal_aside_without_deleting_it()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        File.WriteAllBytes(path, []);
        var store = new ConfirmedRevisionStore(root);
        Assert.Equal(ConfirmationState.Unavailable, store.Lookup("m", "p", "a").State);
        Assert.True(store.IntegrityFailed);

        Assert.Equal(JournalResetOutcome.Reset, store.ResetFailedJournal(out var aside));
        Assert.NotNull(aside);
        Assert.False(File.Exists(path));
        Assert.True(File.Exists(aside), "The corrupt journal must be preserved, never deleted.");

        Assert.Equal(ConfirmationState.NotConfirmed, store.Lookup("m", "p", "a").State);
        Assert.False(store.IntegrityFailed);

        Assert.True(store.Record("m", "p", "a", epoch: 1, revision: 1));
        Assert.StartsWith("#MCPilerConfirmedRevisions", File.ReadAllLines(path)[0], StringComparison.Ordinal);
    }

    // R16.4: the reset must move the journal aside only when a fresh read positively classifies it
    // integrity-failed. A transient read failure leaves a valid journal in place and is refused.
    [Fact]
    public void Reset_refuses_a_transiently_unreadable_journal_and_leaves_it_byte_identical()
    {
        var root = NewRoot();
        var seeded = new ConfirmedRevisionStore(root);
        Assert.True(seeded.Record("m", "p", "a", epoch: 1, revision: 1));
        string path = Path.Combine(root, "confirmed-revisions.txt");
        byte[] before = File.ReadAllBytes(path);

        var unreadable = new ConfirmedRevisionStore(root);
        unreadable.ReadAllLines = _ => throw new IOException("transient read failure");

        Assert.Equal(JournalResetOutcome.Unreadable, unreadable.ResetFailedJournal(out var aside));
        Assert.Null(aside);
        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.Empty(Directory.GetFiles(root, "confirmed-revisions.txt.failed-*"));

        // Once the fault clears the same journal reads as valid, so nothing was lost.
        unreadable.ReadAllLines = candidate => File.ReadAllLines(candidate);
        Assert.Equal(ConfirmationState.Confirmed, unreadable.Lookup("m", "p", "a").State);
    }

    // R16.4: an authorization fault is also transient, not an integrity failure.
    [Fact]
    public void Reset_refuses_a_journal_that_cannot_be_read_due_to_permissions()
    {
        var root = NewRoot();
        var seeded = new ConfirmedRevisionStore(root);
        Assert.True(seeded.Record("m", "p", "a", epoch: 1, revision: 1));

        var unreadable = new ConfirmedRevisionStore(root);
        unreadable.ReadAllLines = _ => throw new UnauthorizedAccessException("denied");

        Assert.Equal(JournalResetOutcome.Unreadable, unreadable.ResetFailedJournal(out var aside));
        Assert.Null(aside);
        Assert.True(File.Exists(Path.Combine(root, "confirmed-revisions.txt")));
    }

    // R16.4: a file that disappears between the existence check and the read must not let an exception
    // escape Lookup, Record or Prune.
    [Fact]
    public void A_journal_that_vanishes_mid_read_does_not_throw()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        File.WriteAllText(path, "x\n");

        var store = new ConfirmedRevisionStore(root);
        // The read seam deletes the file first, then reads it, reproducing a concurrent reset rename.
        store.ReadAllLines = candidate =>
        {
            File.Delete(candidate);
            return File.ReadAllLines(candidate);
        };

        Assert.Equal(ConfirmationState.Unavailable, store.Lookup("m", "p", "a").State);

        // Record and Prune must not throw when the journal could not be read; a later call that sees the
        // file gone simply starts a fresh journal.
        _ = store.Record("m", "p", "a", epoch: 1, revision: 1);
        store.Prune(["unused"]);
    }

    // R16.5: a checksum mismatch (not only a zero-length file) sets the integrity-failed state.
    [Fact]
    public void A_checksum_mismatch_journal_sets_the_integrity_failed_state()
    {
        var root = NewRoot();
        File.WriteAllText(
            Path.Combine(root, "confirmed-revisions.txt"),
            "#MCPilerConfirmedRevisions\t2\tDEADBEEF\n");

        var store = new ConfirmedRevisionStore(root);
        Assert.Equal(ConfirmationState.Unavailable, store.Lookup("m", "p", "a").State);
        Assert.True(store.IntegrityFailed);
    }

    // R16.5: a transient read failure leaves the integrity-failed state unset, and after the fault clears
    // a valid journal reads as empty, not failed.
    [Fact]
    public void A_transient_read_failure_does_not_set_the_integrity_failed_state()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        var checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Empty)));
        File.WriteAllText(path, $"#MCPilerConfirmedRevisions\t2\t{checksum}\n");

        var store = new ConfirmedRevisionStore(root);
        store.ReadAllLines = _ => throw new IOException("transient read failure");
        Assert.Equal(ConfirmationState.Unavailable, store.Lookup("m", "p", "a").State);
        Assert.False(store.IntegrityFailed);

        store.ReadAllLines = candidate => File.ReadAllLines(candidate);
        Assert.Equal(ConfirmationState.NotConfirmed, store.Lookup("m", "p", "a").State);
        Assert.False(store.IntegrityFailed);
    }

    // R16.5 / R16.7: the shared degraded-state evaluation answers from the validated cached snapshot while
    // healthy and re-reads only while degraded; it never writes; and a reset performed through a separate
    // instance on the same path is observed by the first instance.
    [Fact]
    public void The_degraded_evaluation_reads_only_while_degraded_and_never_writes()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");

        var valid = new ConfirmedRevisionStore(root);
        Assert.True(valid.Record("m", "p", "a", epoch: 1, revision: 1));
        byte[] bytes = File.ReadAllBytes(path);
        DateTime timestamp = File.GetLastWriteTimeUtc(path);

        // Healthy: two evaluations answer false and touch no disk.
        Assert.False(valid.ReevaluateIntegrityFailed());
        Assert.False(valid.ReevaluateIntegrityFailed());
        Assert.Equal(bytes, File.ReadAllBytes(path));
        Assert.Equal(timestamp, File.GetLastWriteTimeUtc(path));

        // A fresh instance over a checksum-mismatch journal classifies it degraded.
        File.WriteAllText(path, "#MCPilerConfirmedRevisions\t2\tDEADBEEF\n");
        var degraded = new ConfirmedRevisionStore(root);
        Assert.True(degraded.ReevaluateIntegrityFailed());

        byte[] corruptBytes = File.ReadAllBytes(path);
        DateTime corruptTimestamp = File.GetLastWriteTimeUtc(path);

        // While degraded it re-reads, but still never writes.
        Assert.True(degraded.ReevaluateIntegrityFailed());
        Assert.Equal(corruptBytes, File.ReadAllBytes(path));
        Assert.Equal(corruptTimestamp, File.GetLastWriteTimeUtc(path));

        // A reset through a separate instance is observed by the degraded instance, which writes nothing.
        var operatorStore = new ConfirmedRevisionStore(root);
        Assert.Equal(JournalResetOutcome.Reset, operatorStore.ResetFailedJournal(out var aside));
        Assert.NotNull(aside);

        Assert.False(degraded.ReevaluateIntegrityFailed());
        Assert.False(File.Exists(path));
        Assert.True(File.Exists(aside));
        Assert.True(new FileInfo(aside!).Length > 0);
    }

    // R17.2: a transient re-read must not clear a verified integrity failure. An unknown state is not a
    // healthy one, so the degraded answer persists until a read proves the journal valid or absent.
    [Fact]
    public void A_transient_re_read_does_not_clear_a_known_integrity_failure()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        File.WriteAllText(path, "#MCPilerConfirmedRevisions\t2\tDEADBEEF\n");
        byte[] before = File.ReadAllBytes(path);

        var store = new ConfirmedRevisionStore(root);
        Assert.True(store.ReevaluateIntegrityFailed());

        // The re-read fails transiently through the line read: the verified failure is preserved.
        store.ReadAllLines = _ => throw new IOException("transient read failure");
        Assert.True(store.ReevaluateIntegrityFailed());
        Assert.Equal(before, File.ReadAllBytes(path));

        // A permissions fault behaves the same way.
        store.ReadAllLines = _ => throw new UnauthorizedAccessException("denied");
        Assert.True(store.ReevaluateIntegrityFailed());
        Assert.Equal(before, File.ReadAllBytes(path));

        // Once readable again the journal is still integrity-failed.
        store.ReadAllLines = candidate => File.ReadAllLines(candidate);
        Assert.True(store.ReevaluateIntegrityFailed());
        Assert.Equal(before, File.ReadAllBytes(path));

        // Only a reset that makes the journal absent clears the degraded answer.
        var operatorStore = new ConfirmedRevisionStore(root);
        Assert.Equal(JournalResetOutcome.Reset, operatorStore.ResetFailedJournal(out var aside));
        Assert.False(store.ReevaluateIntegrityFailed());
        Assert.False(File.Exists(path));
        Assert.True(File.Exists(aside));
    }

    // R18.1: the production reader shares delete access, so an operator reset's rename is never blocked by
    // an in-flight read of a degraded journal (on Windows a FileShare.Read handle refuses the move). The
    // handle is opened exactly as the production read does, and the reset must still move the file aside.
    [Fact]
    public void Reset_moves_an_integrity_failed_journal_aside_while_the_production_reader_holds_it_open()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        File.WriteAllText(path, "#MCPilerConfirmedRevisions\t2\tDEADBEEF\n");
        byte[] before = File.ReadAllBytes(path);

        // Hold the journal open exactly as the production read opens it while a degraded Engine re-reads it.
        using FileStream held = ConfirmedRevisionStore.OpenJournal(path);

        var store = new ConfirmedRevisionStore(root);
        Assert.Equal(JournalResetOutcome.Reset, store.ResetFailedJournal(out var aside));
        Assert.NotNull(aside);
        Assert.False(File.Exists(path));
        Assert.Equal(before, File.ReadAllBytes(aside!));
        Assert.Equal(ConfirmationState.NotConfirmed, store.Lookup("m", "p", "a").State);

        // The path is free again even while the moved file is still held, so a fresh journal can start.
        File.WriteAllText(path, "fresh\n");
        Assert.True(File.Exists(path));
    }

    // R18.1: a Record that replaces the journal while a production read handle is open must either succeed
    // or fail closed with the journal byte-identical. It must never throw or leave a torn journal.
    [Fact]
    public void Record_replaces_the_journal_while_the_production_reader_holds_it_open()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        var seeded = new ConfirmedRevisionStore(root);
        Assert.True(seeded.Record("m", "p", "a", epoch: 1, revision: 1));

        using FileStream held = ConfirmedRevisionStore.OpenJournal(path);

        var writer = new ConfirmedRevisionStore(root);
        bool recorded = writer.Record("m", "p", "b", epoch: 1, revision: 2);

        if (recorded)
        {
            var replaced = new ConfirmedRevisionStore(root);
            Assert.Equal(ConfirmationState.Confirmed, replaced.Lookup("m", "p", "a").State);
            Assert.Equal(ConfirmationState.Confirmed, replaced.Lookup("m", "p", "b").State);
        }
        else
        {
            var unchanged = new ConfirmedRevisionStore(root);
            ConfirmationLookup a = unchanged.Lookup("m", "p", "a");
            Assert.Equal(ConfirmationState.Confirmed, a.State);
            Assert.Equal(1, a.Revision);
            Assert.Equal(ConfirmationState.NotConfirmed, unchanged.Lookup("m", "p", "b").State);
        }
    }

    // R18.2: a refused reset must not clear a known integrity failure. The reset's fresh read fails
    // transiently, so the state that held before the attempt survives on the same instance.
    [Fact]
    public void A_refused_reset_does_not_clear_a_known_integrity_failure()
    {
        var root = NewRoot();
        string path = Path.Combine(root, "confirmed-revisions.txt");
        File.WriteAllText(path, "#MCPilerConfirmedRevisions\t2\tDEADBEEF\n");
        byte[] before = File.ReadAllBytes(path);

        var store = new ConfirmedRevisionStore(root);
        Assert.True(store.ReevaluateIntegrityFailed());

        // The reset's fresh read fails transiently: refused as Unreadable, file untouched.
        store.ReadAllLines = _ => throw new IOException("transient read failure");
        Assert.Equal(JournalResetOutcome.Unreadable, store.ResetFailedJournal(out var aside));
        Assert.Null(aside);
        Assert.Equal(before, File.ReadAllBytes(path));

        // The known failure survives the refused reset: still reported while the fault lasts...
        Assert.True(store.ReevaluateIntegrityFailed());
        Assert.True(store.IntegrityFailed);

        // ...and after the fault clears, because the journal is still corrupt.
        store.ReadAllLines = candidate => File.ReadAllLines(candidate);
        Assert.True(store.ReevaluateIntegrityFailed());
        Assert.True(store.IntegrityFailed);
        Assert.Equal(before, File.ReadAllBytes(path));
    }
}
