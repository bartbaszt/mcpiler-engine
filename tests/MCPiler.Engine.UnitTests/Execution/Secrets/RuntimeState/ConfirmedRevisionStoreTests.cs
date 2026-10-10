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
}
