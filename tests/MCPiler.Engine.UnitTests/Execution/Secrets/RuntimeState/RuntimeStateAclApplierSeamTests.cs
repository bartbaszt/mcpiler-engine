using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using MCPiler.Engine.Execution.Secrets.RuntimeState;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Secrets.RuntimeState;

/// <summary>
/// The collection that owns the process-wide access-control applier seam.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="FileMutableSlotStore.WindowsAclApplierForTesting"/> is static, because the root is
/// restricted inside the constructor and an instance member cannot be set before that happens. A
/// static seam is process-wide, so a test that installs one is visible to every store any other
/// collection constructs while it is installed. This collection therefore runs in isolation:
/// while it holds the seam nothing else builds a store, and a case in another collection cannot
/// fail for a reason that belongs to this one.
/// </para>
/// <para>
/// Before this collection existed the seam leaked exactly that way under parallel collections, and
/// unrelated store tests failed intermittently with a refusal that named a substituted applier they
/// had never installed.
/// </para>
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class RuntimeStateStaticSeam
{
    /// <summary>The name test classes join to run in isolation.</summary>
    public const string Name = "runtime-state-static-seam";
}

/// <summary>
/// What the store does when the platform refuses to establish a restrictive mode.
/// </summary>
/// <remarks>
/// The seam stands in for a host whose access-control change fails, so the fail-closed path can be
/// exercised on a machine where the real change succeeds. It is the only reason this collection is
/// isolated; see <see cref="RuntimeStateStaticSeam"/>.
/// </remarks>
[Collection(RuntimeStateStaticSeam.Name)]
public sealed class RuntimeStateAclApplierSeamTests : IDisposable
{
    private static readonly byte[] Key = Convert.FromHexString(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    private readonly List<string> _roots = [];

    public void Dispose()
    {
        FileMutableSlotStore.WindowsAclApplierForTesting = null;

        foreach (string root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void An_unrestricted_directory_is_never_silently_accepted_on_windows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // A directory that keeps its inherited (unrestricted) ACEs is detected as non-conformant.
        string loose = Path.Combine(NewRoot(), "loose");
        Directory.CreateDirectory(loose);
        Assert.False(FileMutableSlotStore.IsRestrictiveWindowsAcl(loose, isDirectory: true));

        // And when the store cannot establish the contract it fails closed rather than opening an
        // unrestricted runtime-state directory. The refusal names the category, because an operator
        // reading it has to know whether to correct permissions, a policy, or the host.
        FileMutableSlotStore.WindowsAclApplierForTesting = (_, _) => false;
        try
        {
            string root = NewRoot();

            InvalidOperationException refusal = Assert.Throws<InvalidOperationException>(
                () => _ = new FileMutableSlotStore(root, "mount-a", Key));

            Assert.Contains("restrictive file mode", refusal.Message, StringComparison.Ordinal);
            Assert.Contains("refused it", refusal.Message, StringComparison.Ordinal);
        }
        finally
        {
            FileMutableSlotStore.WindowsAclApplierForTesting = null;
        }
    }

    private string NewRoot()
    {
        string root = Path.Combine(Path.GetTempPath(), "engine-acl-seam-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);
        return root;
    }
}
