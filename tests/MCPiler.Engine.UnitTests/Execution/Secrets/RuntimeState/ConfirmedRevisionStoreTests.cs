using System.IO;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
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

        Assert.Null(failing.Read("m", "p", "a"));
        Assert.False(failing.Record("m", "p", "c", epoch: 1, revision: 3));

        // Access restored: the existing confirmations survive and the new one is merged instead of
        // overwriting a journal whose current contents were never verified (R12.4).
        var recovered = new ConfirmedRevisionStore(root);
        Assert.True(recovered.Record("m", "p", "c", epoch: 1, revision: 3));

        var a = recovered.Read("m", "p", "a");
        Assert.NotNull(a);
        Assert.Equal(1, a.Value.Epoch);
        Assert.Equal(1, a.Value.Revision);

        var b = recovered.Read("m", "p", "b");
        Assert.NotNull(b);
        Assert.Equal(1, b.Value.Epoch);
        Assert.Equal(2, b.Value.Revision);

        var c = recovered.Read("m", "p", "c");
        Assert.NotNull(c);
        Assert.Equal(3, c.Value.Revision);
    }

    [Fact]
    public void A_missing_journal_is_a_legitimate_empty_journal()
    {
        var store = new ConfirmedRevisionStore(NewRoot());

        Assert.Null(store.Read("m", "p", "a"));
        Assert.True(store.Record("m", "p", "a", epoch: 2, revision: 9));

        var a = store.Read("m", "p", "a");
        Assert.NotNull(a);
        Assert.Equal(2, a.Value.Epoch);
        Assert.Equal(9, a.Value.Revision);
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
}
