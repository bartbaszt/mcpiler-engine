using System.Text;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Secrets.RuntimeState;

/// <summary>
/// Covers the durable runtime-state store: the bounded, encrypted file adapter, its key-file
/// loader and the directory that hands out per-mount stores.
/// </summary>
/// <remarks>
/// Every test that scans the directory does so for the plaintext canary, because the one
/// property this store cannot demonstrate by reading it back is that the value is not merely
/// recoverable but absent from disk in the clear.
/// </remarks>
public sealed class RuntimeSecretStoreTests : IDisposable
{
    private static readonly byte[] Key = Convert.FromHexString(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    private const string PlaintextCanary = "CANARY-refresh-token-7d21";

    private readonly List<string> _roots = [];

    public void Dispose()
    {
        foreach (var root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task A_record_round_trips_with_every_non_secret_identity()
    {
        var store = Store();
        var record = new MutableSlotRecord(
            "oauth",
            "refreshToken",
            "fingerprint-a",
            AuthorityEpoch: 3,
            RuntimeRevision: 7,
            PlaintextCanary);

        await store.ReplaceAsync(record, TestContext.Current.CancellationToken);
        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);

        Assert.NotNull(loaded);
        Assert.Equal(record.ProfileId, loaded!.ProfileId);
        Assert.Equal(record.Slot, loaded.Slot);
        Assert.Equal(record.ScopeFingerprint, loaded.ScopeFingerprint);
        Assert.Equal(record.AuthorityEpoch, loaded.AuthorityEpoch);
        Assert.Equal(record.RuntimeRevision, loaded.RuntimeRevision);
        Assert.Equal(PlaintextCanary, loaded.Value);
    }

    [Fact]
    public async Task A_missing_record_reads_as_absence_rather_than_a_failure()
    {
        var store = Store();

        Assert.Null(await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task An_absent_directory_of_records_reads_as_absence()
    {
        var store = Store();
        Directory.Delete(store.Root, recursive: true);

        Assert.Null(await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task The_plaintext_never_appears_on_disk()
    {
        var store = Store();

        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        var files = Directory.GetFiles(store.Root);

        Assert.NotEmpty(files);
        Assert.All(files, file => Assert.DoesNotContain(
            PlaintextCanary,
            Encoding.UTF8.GetString(File.ReadAllBytes(file)),
            StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_record_written_under_a_different_key_fails_closed()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        var other = new FileMutableSlotStore(store.Root, "mount-a", OtherKey());

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(
            () => other.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("cannot be authenticated", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(PlaintextCanary, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_record_belongs_to_one_mount_only()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        // The same root and key, a different mount: the record's file name differs, so this is
        // absence — not a cross-mount read.
        var other = new FileMutableSlotStore(store.Root, "mount-b", Key);

        Assert.Null(await other.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_record_copied_onto_another_mounts_name_fails_closed()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        // Copying the bytes to the name another mount would compute must not let them be read:
        // the mount identity is authenticated, not just used for the file name.
        var other = new FileMutableSlotStore(store.Root, "mount-b", Key);
        var source = Directory.GetFiles(store.Root).Single();
        var identity = string.Join('\u001f', "mount-b", "oauth", "refreshToken");
        var name = Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        File.Copy(source, Path.Combine(store.Root, name + FileMutableSlotStore.RecordExtension));

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(
            () => other.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("different mount", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_truncated_record_fails_closed()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        var file = Directory.GetFiles(store.Root).Single();
        var bytes = File.ReadAllBytes(file);
        File.WriteAllBytes(file, bytes[..(bytes.Length / 2)]);

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(
            () => store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("truncated", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unknown_format_byte_fails_closed()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        var file = Directory.GetFiles(store.Root).Single();
        var bytes = File.ReadAllBytes(file);
        bytes[0] = 0x7F;
        File.WriteAllBytes(file, bytes);

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(
            () => store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("supported format", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_tampered_ciphertext_fails_closed()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        var file = Directory.GetFiles(store.Root).Single();
        var bytes = File.ReadAllBytes(file);
        bytes[^1] ^= 0x01;
        File.WriteAllBytes(file, bytes);

        await Assert.ThrowsAsync<RuntimeStateStoreException>(
            () => store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task A_stale_epoch_is_returned_and_left_to_the_caller()
    {
        // The adapter answers "what is stored"; whether it may be used is the strategy's
        // decision, because only the strategy knows the epoch the active Manifest declares.
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 4, PlaintextCanary),
            TestContext.Current.CancellationToken);

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);

        Assert.NotNull(loaded);
        Assert.Equal(1, loaded!.AuthorityEpoch);
        Assert.Equal(4, loaded.RuntimeRevision);
    }

    [Fact]
    public async Task An_empty_value_still_round_trips()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", null, 1, 0, string.Empty),
            TestContext.Current.CancellationToken);

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);

        Assert.NotNull(loaded);
        Assert.Equal(string.Empty, loaded!.Value);
        Assert.Null(loaded.ScopeFingerprint);
    }

    [Fact]
    public async Task Replacement_replaces_the_previous_record()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, "T0"),
            TestContext.Current.CancellationToken);
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 1, "T1"),
            TestContext.Current.CancellationToken);

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);

        Assert.Equal("T1", loaded!.Value);
        Assert.Equal(1, loaded.RuntimeRevision);

        // One record per (mount, profile, slot); replacement never accumulates generations.
        Assert.Single(Directory.GetFiles(store.Root));
    }

    [Fact]
    public async Task A_record_for_another_profile_or_slot_is_a_separate_record()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, "first"),
            TestContext.Current.CancellationToken);
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "clientSecret", "fingerprint-b", 1, 0, "second"),
            TestContext.Current.CancellationToken);

        Assert.Equal(2, Directory.GetFiles(store.Root).Length);
        Assert.Equal(
            "first",
            (await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken))!.Value);
        Assert.Equal(
            "second",
            (await store.LoadAsync("oauth", "clientSecret", TestContext.Current.CancellationToken))!.Value);
    }

    [Fact]
    public async Task A_record_is_bound_to_its_profile_and_slot_names()
    {
        // Renaming the file to the name another profile would compute must not make it readable:
        // the profile and slot are authenticated, not merely the file path.
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        var source = Directory.GetFiles(store.Root).Single();
        var identity = string.Join('\u001f', "mount-a", "other", "refreshToken");
        var name = Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        File.Copy(source, Path.Combine(store.Root, name + FileMutableSlotStore.RecordExtension));

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(
            () => store.LoadAsync("other", "refreshToken", TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("different profile or slot", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_abandoned_temporary_file_is_never_read_as_the_record()
    {
        var store = Store();

        // A crash before the rename leaves a sibling temporary file. It is not the record, so
        // resolution reports absence rather than reading a half-written envelope.
        await File.WriteAllBytesAsync(
            Path.Combine(store.Root, "abandoned" + FileMutableSlotStore.RecordExtension + ".tmp-deadbeef"),
            Encoding.UTF8.GetBytes("not an envelope"),
            TestContext.Current.CancellationToken);

        Assert.Null(await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_failure_before_the_flush_leaves_the_previous_record_authoritative()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, "T0"),
            TestContext.Current.CancellationToken);

        store.TempWrittenBarrier = _ => throw new IOException("injected write failure");

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 1, "T1"),
            TestContext.Current.CancellationToken).AsTask());

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);

        Assert.Equal("T0", loaded!.Value);
        Assert.Equal(0, loaded.RuntimeRevision);
        Assert.Single(Directory.GetFiles(store.Root));
    }

    [Fact]
    public async Task A_failure_after_the_flush_leaves_the_previous_record_authoritative()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, "T0"),
            TestContext.Current.CancellationToken);

        store.TempFlushedBarrier = _ => throw new IOException("injected flush failure");

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 1, "T1"),
            TestContext.Current.CancellationToken).AsTask());

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);

        Assert.Equal("T0", loaded!.Value);
        Assert.Single(Directory.GetFiles(store.Root));
    }

    [Fact]
    public async Task A_committed_replacement_removes_its_temporary_sibling()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        Assert.DoesNotContain(
            Directory.GetFiles(store.Root),
            file => file.Contains(".tmp-", StringComparison.Ordinal));
    }

    [Fact]
    public void A_key_that_is_not_thirty_two_bytes_is_refused_by_the_adapter()
    {
        var root = NewRoot();

        Assert.Throws<ArgumentException>(
            () => new FileMutableSlotStore(root, "mount-a", new byte[31]));
    }

    [Fact]
    public void The_store_creates_a_root_that_does_not_exist_yet()
    {
        var root = Path.Combine(NewRoot(), "nested", "state");
        _roots.Add(root);

        var store = new FileMutableSlotStore(root, "mount-a", Key);

        Assert.True(Directory.Exists(store.Root));
    }

    [Theory]
    [InlineData(32)]
    [InlineData(64)]
    public void A_key_file_accepts_raw_bytes_and_their_hex_spelling(int length)
    {
        var path = WriteKeyFile(
            length == 32
                ? Key
                : Encoding.ASCII.GetBytes(Convert.ToHexString(Key)));

        Assert.True(RuntimeStateKeyFile.TryRead(path, out var key, out var refusal), refusal);
        Assert.Equal(Key, key);
    }

    [Fact]
    public void A_key_file_accepts_one_trailing_newline()
    {
        var path = WriteKeyFile([.. Encoding.ASCII.GetBytes(Convert.ToHexString(Key)), (byte)'\n']);

        Assert.True(RuntimeStateKeyFile.TryRead(path, out var key, out var refusal), refusal);
        Assert.Equal(Key, key);
    }

    [Theory]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("zz000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")]
    public void A_key_file_of_the_wrong_shape_is_refused_without_echoing_it(string text)
    {
        var path = WriteKeyFile(Encoding.ASCII.GetBytes(text));

        Assert.False(RuntimeStateKeyFile.TryRead(path, out _, out var refusal));
        Assert.NotNull(refusal);
        Assert.Contains(path, refusal, StringComparison.Ordinal);

        if (text.Length > 0)
        {
            Assert.DoesNotContain(text, refusal, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void A_missing_key_file_is_refused_by_name()
    {
        var path = Path.Combine(Path.GetTempPath(), "mcpiler-missing-" + Guid.NewGuid().ToString("N"));

        Assert.False(RuntimeStateKeyFile.TryRead(path, out _, out var refusal));
        Assert.Contains("does not exist", refusal!, StringComparison.Ordinal);
    }

    [Fact]
    public void Unconfigured_runtime_state_opens_as_memory_only()
    {
        Assert.True(RuntimeStateLocation.TryOpen(null, null, out var state, out var refusal), refusal);
        Assert.Null(state);
    }

    [Theory]
    [InlineData("root-only")]
    [InlineData("key-only")]
    public void A_half_configured_runtime_state_is_refused(string shape)
    {
        var root = NewRoot();
        var keyPath = WriteKeyFile(Key);

        var opened = shape == "root-only"
            ? RuntimeStateLocation.TryOpen(root, null, out var state, out var refusal)
            : RuntimeStateLocation.TryOpen(null, keyPath, out state, out refusal);

        Assert.False(opened);
        Assert.Null(state);
        Assert.Contains("both", refusal!, StringComparison.Ordinal);
    }

    [Fact]
    public void A_configured_root_without_a_usable_key_is_refused()
    {
        var root = NewRoot();
        var keyPath = WriteKeyFile(Encoding.ASCII.GetBytes("not-a-key"));

        Assert.False(RuntimeStateLocation.TryOpen(root, keyPath, out _, out var refusal));
        Assert.Contains("key file", refusal!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_opened_directory_hands_out_stores_that_share_the_root()
    {
        var root = Path.Combine(NewRoot(), "state");
        _roots.Add(root);
        var keyPath = WriteKeyFile(Key);

        Assert.True(RuntimeStateLocation.TryOpen(root, keyPath, out var state, out var refusal), refusal);

        var store = state!.CreateForMount("/mcp/one");
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, PlaintextCanary),
            TestContext.Current.CancellationToken);

        var reloaded = state.CreateForMount("/mcp/one");
        var loaded = await reloaded.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);

        Assert.Equal(PlaintextCanary, loaded!.Value);

        // Another mount over the same directory sees its own (empty) section.
        Assert.Null(await state.CreateForMount("/mcp/two")
            .LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
    }

    private FileMutableSlotStore Store()
    {
        var root = Path.Combine(NewRoot(), "mount-a");
        _roots.Add(root);
        return new FileMutableSlotStore(root, "mount-a", Key);
    }

    private string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "mcpiler-runtime-state-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        _roots.Add(root);
        return root;
    }

    private string WriteKeyFile(byte[] contents)
    {
        var path = Path.Combine(NewRoot(), "runtime-state.key");
        File.WriteAllBytes(path, contents);
        return path;
    }

    private static byte[] OtherKey()
    {
        var key = Key.ToArray();
        key[0] ^= 0xFF;
        return key;
    }
}
