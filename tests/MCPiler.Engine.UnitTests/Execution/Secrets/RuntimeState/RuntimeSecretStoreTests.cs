using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
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

    [Fact]
    public async Task Runtime_state_owner_lease_is_exclusive_and_released_without_deleting_lock_file()
    {
        string root = Path.Combine(Path.GetTempPath(), "engine-owner-unit-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);

        Assert.True(RuntimeStateOwnerLease.TryAcquire(root, out var owner, out var refusal), refusal);
        using (owner!)
        {
            Assert.False(RuntimeStateOwnerLease.TryAcquire(root, out var contender, out var conflict));
            Assert.Null(contender);
            Assert.Contains("ownership is unavailable or held", conflict, StringComparison.Ordinal);

            var store = new FileMutableSlotStore(root, "mount", Key);
            Assert.Null(await store.LoadDecisionAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
        }

        Assert.True(RuntimeStateOwnerLease.TryAcquire(root, out var successor, out var recovered), recovered);
        using (successor!)
        {
            Assert.True(File.Exists(Path.Combine(root, ".runtime-state-owner.lock")));
        }
    }

    [Fact]
    public void Runtime_state_owner_lease_refuses_a_network_root_without_probing_it()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // A UNC spelling is refused by the supported-filesystem boundary itself, before any
        // directory probe, lock open or path resolution could touch the remote share.
        string root = @"\\engine-unsupported-host.invalid\state\" + Guid.NewGuid().ToString("N");

        Assert.False(RuntimeStateOwnerLease.TryAcquire(root, out var lease, out var refusal));
        Assert.Null(lease);
        Assert.Contains("supported local filesystem", refusal, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        foreach (var root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static MutableSlotDecision Decision(
        long epoch, MutableSlotDecisionKind kind = MutableSlotDecisionKind.Authorized,
        long revision = 0, string? value = PlaintextCanary,
        string declaration = "manifest-declaration-a", string configuration = "oauth-config-a")
        => new("oauth", "refreshToken", "scope-a", declaration, configuration,
            epoch, revision, kind,
            kind == MutableSlotDecisionKind.Cleared ? null : value);

    [Fact]
    public async Task Memory_store_legacy_same_revision_replacement_invalidates_observed_cas_version()
    {
        var store = new InMemoryMutableSlotStore();
        var ct = TestContext.Current.CancellationToken;
        await store.ReplaceAsync(new MutableSlotRecord("oauth", "refreshToken", "scope-a", 2, 7, "v1"), ct);
        var observed = (await store.LoadDecisionAsync("oauth", "refreshToken", ct))!;
        await store.ReplaceAsync(new MutableSlotRecord("oauth", "refreshToken", "scope-a", 2, 7, "v2"), ct);

        var current = (await store.LoadDecisionAsync("oauth", "refreshToken", ct))!;
        Assert.NotEqual(observed.Version, current.Version);
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            Decision(3), observed.Version, 2, ct).AsTask());
        var committed = await store.CompareAndCommitAsync(Decision(3), current.Version, 2, ct);
        Assert.Equal(1, store.Count);
        Assert.Equal(committed, await store.LoadDecisionAsync("oauth", "refreshToken", ct));
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "scope-a", 4, 0, "resurrection"), ct).AsTask());
    }

    [Fact]
    public async Task Invalid_legacy_epoch_cannot_be_adopted_as_v2_authority()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        await store.ReplaceAsync(new MutableSlotRecord(
            "oauth", "refreshToken", "scope-a", -1, 0, PlaintextCanary), ct);

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.LoadDecisionAsync(
            "oauth", "refreshToken", ct).AsTask());
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            Decision(2), null, 1, ct).AsTask());
    }

    [Fact]
    public async Task Legacy_v1_writer_preserves_original_header_shape_without_v2_fields()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        await store.ReplaceAsync(new MutableSlotRecord(
            "oauth", "refreshToken", "scope-a", 1, 2, PlaintextCanary), ct);

        var envelope = File.ReadAllBytes(Assert.Single(Directory.GetFiles(store.Root, "*.rstate")));
        Assert.Equal(FileMutableSlotStore.FormatVersion, envelope[0]);
        var length = envelope[1] | envelope[2] << 8;
        using var header = JsonDocument.Parse(envelope.AsMemory(3, length));
        Assert.Equal(7, header.RootElement.EnumerateObject().Count());
        Assert.False(header.RootElement.TryGetProperty("DecisionKind", out _));
        Assert.False(header.RootElement.TryGetProperty("DeclarationFingerprint", out _));
        Assert.False(header.RootElement.TryGetProperty("ConfigurationFingerprint", out _));
        Assert.Equal(PlaintextCanary,
            (await new FileMutableSlotStore(store.Root, "mount-a", Key)
                .LoadDecisionAsync("oauth", "refreshToken", ct))!.RefreshToken);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Authenticated_v2_duplicate_binding_or_invalid_cleared_revision_is_refused(bool duplicateField)
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        var authorized = await store.CompareAndCommitAsync(
            Decision(2, MutableSlotDecisionKind.Cleared), null, 1, ct);
        var path = Assert.Single(Directory.GetFiles(store.Root, "*.rstate"));
        var original = File.ReadAllBytes(path);
        byte[] malformed = RewriteAuthenticatedV2Header(original, value => duplicateField
            ? value.Replace("\"DecisionKind\":\"cleared\"",
                "\"DecisionKind\":\"cleared\",\"DecisionKind\":\"authorized\"", StringComparison.Ordinal)
            : value.Replace("\"RuntimeRevision\":0", "\"RuntimeRevision\":1", StringComparison.Ordinal));
        File.WriteAllBytes(path, malformed);

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.LoadDecisionAsync(
            "oauth", "refreshToken", ct).AsTask());
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            Decision(3), authorized.Version, 1, ct).AsTask());
        Assert.Equal(malformed, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task Oversized_v2_header_refuses_commit_and_preserves_predecessor()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        var original = await store.CompareAndCommitAsync(Decision(2), null, 1, ct);
        string path = Assert.Single(Directory.GetFiles(store.Root, "*.rstate"));
        byte[] bytes = File.ReadAllBytes(path);

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            Decision(3, declaration: new string('A', 70_000)), original.Version, 1, ct).AsTask());

        Assert.Equal(bytes, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(store.Root));
        Assert.Equal(original, await new FileMutableSlotStore(store.Root, "mount-a", Key)
            .LoadDecisionAsync("oauth", "refreshToken", ct));
    }

    [Fact]
    public async Task V2_canceled_precommit_does_not_leave_a_temporary_file_or_replace_clear()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        var original = await store.CompareAndCommitAsync(
            Decision(2, MutableSlotDecisionKind.Cleared), null, 1, ct);
        store.TempFlushedBarrier = _ => throw new OperationCanceledException("injected cancellation");

        await Assert.ThrowsAsync<OperationCanceledException>(() => store.CompareAndCommitAsync(
            Decision(3), original.Version, 1, ct).AsTask());

        Assert.Single(Directory.GetFiles(store.Root));
        Assert.Equal(original, await new FileMutableSlotStore(store.Root, "mount-a", Key)
            .LoadDecisionAsync("oauth", "refreshToken", ct));
    }

    [Fact]
    public async Task V2_shared_root_keeps_cleared_and_authorized_mounts_isolated()
    {
        var first = Store();
        var second = new FileMutableSlotStore(first.Root, "mount-b", Key);
        var ct = TestContext.Current.CancellationToken;
        var cleared = await first.CompareAndCommitAsync(
            Decision(3, MutableSlotDecisionKind.Cleared), null, 2, ct);
        var authorized = await second.CompareAndCommitAsync(Decision(5), null, 4, ct);

        Assert.Equal(cleared, await first.LoadDecisionAsync("oauth", "refreshToken", ct));
        Assert.Equal(authorized, await second.LoadDecisionAsync("oauth", "refreshToken", ct));
        Assert.Equal(2, Directory.GetFiles(first.Root, "*.rstate").Length);
        var rotated = await second.CompareAndCommitAsync(Decision(5, revision: 1), authorized.Version, 4, ct);
        Assert.Equal(cleared, await new FileMutableSlotStore(first.Root, "mount-a", Key)
            .LoadDecisionAsync("oauth", "refreshToken", ct));
        Assert.Equal(rotated, await new FileMutableSlotStore(first.Root, "mount-b", Key)
            .LoadDecisionAsync("oauth", "refreshToken", ct));
    }

    [Fact]
    public async Task V2_refuses_delimited_identities_that_alias_other_mount_profile_slot_tuples()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        var malformedProfile = Decision(2) with { ProfileId = "oauth\u001fother" };
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            malformedProfile, null, 1, ct).AsTask());
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.LoadDecisionAsync(
            "oauth\u001fother", "refreshToken", ct).AsTask());

        var malformedMount = new FileMutableSlotStore(store.Root, "mount-a\u001fother", Key);
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => malformedMount.CompareAndCommitAsync(
            Decision(2), null, 1, ct).AsTask());
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => malformedMount.LoadDecisionAsync(
            "oauth", "refreshToken", ct).AsTask());
        Assert.Empty(Directory.GetFiles(store.Root, "*.rstate"));
    }

    [Fact]
    public async Task V2_file_permission_refusal_preserves_existing_authority_and_no_temporary()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        var original = await store.CompareAndCommitAsync(
            Decision(2, MutableSlotDecisionKind.Cleared), null, 1, ct);
        string record = Assert.Single(Directory.GetFiles(store.Root, "*.rstate"));
        byte[] before = File.ReadAllBytes(record);
        store.PermissionSetter = _ => false;
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            Decision(3), original.Version, 1, ct).AsTask());

        Assert.Equal(before, File.ReadAllBytes(record));
        Assert.Single(Directory.GetFiles(store.Root));
        Assert.Equal(original, await new FileMutableSlotStore(store.Root, "mount-a", Key)
            .LoadDecisionAsync("oauth", "refreshToken", ct));
        if (OperatingSystem.IsWindows())
        {
            Assert.True(FileMutableSlotStore.IsRestrictiveWindowsAcl(record, isDirectory: false));
        }
        else
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(record));
        }
    }

    [Fact]
    public async Task Compaction_never_deletes_a_corrupted_cleared_floor_when_another_slot_commits()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        await store.CompareAndCommitAsync(Decision(2, MutableSlotDecisionKind.Cleared), null, 1, ct);
        string clearedPath = Assert.Single(Directory.GetFiles(store.Root, "*.rstate"));
        byte[] tampered = File.ReadAllBytes(clearedPath);
        int headerLength = tampered[1] | tampered[2] << 8;
        string original = Encoding.UTF8.GetString(tampered, 3, headerLength);
        string changed = original.Replace("\"Profile\":\"oauth\"", "\"Profile\":\"aouth\"",
            StringComparison.Ordinal);
        Assert.NotEqual(original, changed);
        Encoding.UTF8.GetBytes(changed).CopyTo(tampered.AsSpan(3, headerLength));
        File.WriteAllBytes(clearedPath, tampered);

        // Committing a different slot triggers best-effort compaction; a plaintext JSON identity
        // mismatch must never allow deletion of ciphertext that fails authentication.
        var unrelated = Decision(2) with { Slot = "otherRefresh" };
        await store.CompareAndCommitAsync(unrelated, null, 1, ct);
        Assert.True(File.Exists(clearedPath));
        Assert.Equal(tampered, File.ReadAllBytes(clearedPath));
        Assert.Equal(2, Directory.GetFiles(store.Root, "*.rstate").Length);
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => new FileMutableSlotStore(
            store.Root, "mount-a", Key).LoadDecisionAsync("oauth", "refreshToken", ct).AsTask());
    }

    private static byte[] RewriteAuthenticatedV2Header(byte[] source, Func<string, string> modify)
    {
        int oldLength = source[1] | source[2] << 8;
        int nonceOffset = 3 + oldLength;
        var plaintext = new byte[source.Length - nonceOffset - FileMutableSlotStore.NonceLength
            - FileMutableSlotStore.TagLength];
        using (var aes = new AesGcm(Key, FileMutableSlotStore.TagLength))
        {
            aes.Decrypt(source.AsSpan(nonceOffset, FileMutableSlotStore.NonceLength),
                source.AsSpan(nonceOffset + FileMutableSlotStore.NonceLength, plaintext.Length),
                source.AsSpan(source.Length - FileMutableSlotStore.TagLength), plaintext,
                source.AsSpan(0, nonceOffset));
        }

        byte[] newHeader = Encoding.UTF8.GetBytes(modify(Encoding.UTF8.GetString(source, 3, oldLength)));
        var result = new byte[3 + newHeader.Length + FileMutableSlotStore.NonceLength
            + plaintext.Length + FileMutableSlotStore.TagLength];
        result[0] = FileMutableSlotStore.AuthorityFormatVersion;
        result[1] = (byte)newHeader.Length;
        result[2] = (byte)(newHeader.Length >> 8);
        newHeader.CopyTo(result.AsSpan(3));
        int newNonceOffset = 3 + newHeader.Length;
        RandomNumberGenerator.Fill(result.AsSpan(newNonceOffset, FileMutableSlotStore.NonceLength));
        using (var aes = new AesGcm(Key, FileMutableSlotStore.TagLength))
        {
            aes.Encrypt(result.AsSpan(newNonceOffset, FileMutableSlotStore.NonceLength), plaintext,
                result.AsSpan(newNonceOffset + FileMutableSlotStore.NonceLength, plaintext.Length),
                result.AsSpan(result.Length - FileMutableSlotStore.TagLength),
                result.AsSpan(0, newNonceOffset));
        }

        return result;
    }

    [Fact]
    public async Task Legacy_v1_decision_can_be_superseded_atomically_by_bound_v2_authority()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        await store.ReplaceAsync(new MutableSlotRecord(
            "oauth", "refreshToken", "scope-a", 2, 7, "CANARY-legacy-v1"), ct);

        MutableSlotDecision legacy = Assert.IsType<MutableSlotDecision>(
            await store.LoadDecisionAsync("oauth", "refreshToken", ct));
        Assert.True(legacy.IsLegacy);
        Assert.Null(legacy.DeclarationFingerprint);
        Assert.Equal("CANARY-legacy-v1", legacy.RefreshToken);

        MutableSlotDecision written = await store.CompareAndCommitAsync(
            Decision(3), legacy.Version, declaredEpoch: 2, ct);
        Assert.False(written.IsLegacy);
        Assert.NotEmpty(written.Version);

        var fresh = new FileMutableSlotStore(store.Root, "mount-a", Key);
        Assert.Equal(written, await fresh.LoadDecisionAsync("oauth", "refreshToken", ct));
        Assert.Equal(FileMutableSlotStore.AuthorityFormatVersion,
            File.ReadAllBytes(Assert.Single(Directory.GetFiles(store.Root, "*.rstate")))[0]);
        Assert.DoesNotContain(PlaintextCanary,
            Encoding.UTF8.GetString(File.ReadAllBytes(Assert.Single(Directory.GetFiles(store.Root, "*.rstate")))),
            StringComparison.Ordinal);
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => fresh.LoadAsync(
            "oauth", "refreshToken", ct).AsTask());
    }

    [Fact]
    public async Task Cleared_v2_decision_survives_restart_and_changed_manifest_epoch_and_binding()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        MutableSlotDecision authorized = await store.CompareAndCommitAsync(Decision(4), null, 3, ct);
        MutableSlotDecision cleared = await store.CompareAndCommitAsync(
            Decision(5, MutableSlotDecisionKind.Cleared), authorized.Version, 3, ct);

        var reopened = new FileMutableSlotStore(store.Root, "mount-a", Key);
        MutableSlotDecision current = Assert.IsType<MutableSlotDecision>(
            await reopened.LoadDecisionAsync("oauth", "refreshToken", ct));
        Assert.Equal(cleared, current);
        Assert.Equal(MutableSlotDecisionKind.Cleared, current.Kind);
        Assert.Null(current.RefreshToken);

        // Even a newer Manifest declaration cannot silently overwrite the authenticated floor.
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => reopened.CompareAndCommitAsync(
            Decision(5, declaration: "changed", configuration: "changed"), current.Version, 10, ct).AsTask());
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => reopened.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "scope-a", 12, 0, "CANARY-resurrection"), ct).AsTask());
        Assert.Equal(cleared, await reopened.LoadDecisionAsync("oauth", "refreshToken", ct));
    }

    [Fact]
    public async Task Competing_authorization_uses_exact_observed_version_and_refuses_stale_commit()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        MutableSlotDecision first = await store.CompareAndCommitAsync(Decision(2), null, 1, ct);
        var other = new FileMutableSlotStore(store.Root, "mount-a", Key);
        MutableSlotDecision winner = await other.CompareAndCommitAsync(
            Decision(3, value: "CANARY-winner"), first.Version, 1, ct);
        byte[] before = File.ReadAllBytes(Assert.Single(Directory.GetFiles(store.Root, "*.rstate")));

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            Decision(4, value: "CANARY-loser"), first.Version, 1, ct).AsTask());

        Assert.Equal(before, File.ReadAllBytes(Assert.Single(Directory.GetFiles(store.Root, "*.rstate"))));
        Assert.Equal(winner, await store.LoadDecisionAsync("oauth", "refreshToken", ct));
    }

    [Fact]
    public async Task Bound_refresh_advances_once_and_refuses_changed_config_and_nonsequential_revision()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        MutableSlotDecision authorized = await store.CompareAndCommitAsync(Decision(2), null, 1, ct);
        var next = await store.CompareAndCommitAsync(
            Decision(2, revision: 1, value: "CANARY-rotated"), authorized.Version, 1, ct);

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            Decision(2, revision: 2, value: "CANARY-config-change", configuration: "changed"),
            next.Version, 1, ct).AsTask());
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            Decision(2, revision: 3, value: "CANARY-skipped-revision"), next.Version, 1, ct).AsTask());

        Assert.Equal(next, await new FileMutableSlotStore(store.Root, "mount-a", Key)
            .LoadDecisionAsync("oauth", "refreshToken", ct));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task V2_corruption_or_wrong_key_refuses_cas_without_mutation(bool wrongKey)
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        MutableSlotDecision authorized = await store.CompareAndCommitAsync(Decision(2), null, 1, ct);
        string path = Assert.Single(Directory.GetFiles(store.Root, "*.rstate"));
        if (!wrongKey)
        {
            byte[] tampered = File.ReadAllBytes(path);
            tampered[^1] ^= 0x01;
            File.WriteAllBytes(path, tampered);
        }

        byte[] before = File.ReadAllBytes(path);
        var reader = new FileMutableSlotStore(store.Root, "mount-a", wrongKey ? OtherKey() : Key);
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => reader.LoadDecisionAsync(
            "oauth", "refreshToken", ct).AsTask());
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => reader.CompareAndCommitAsync(
            Decision(3), authorized.Version, 1, ct).AsTask());
        Assert.Equal(before, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task V2_precommit_failure_retains_floor_and_postcommit_failure_keeps_successor()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        MutableSlotDecision original = await store.CompareAndCommitAsync(
            Decision(2, MutableSlotDecisionKind.Cleared), null, 1, ct);
        store.TempFlushedBarrier = _ => throw new IOException("injected pre-commit");
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.CompareAndCommitAsync(
            Decision(3), original.Version, 1, ct).AsTask());
        Assert.Equal(original, await new FileMutableSlotStore(store.Root, "mount-a", Key)
            .LoadDecisionAsync("oauth", "refreshToken", ct));

        store.TempFlushedBarrier = null;
        store.CompactionBarrier = () => throw new IOException("injected post-commit");
        MutableSlotDecision succeeded = await store.CompareAndCommitAsync(Decision(3), original.Version, 1, ct);
        Assert.Equal(succeeded, await new FileMutableSlotStore(store.Root, "mount-a", Key)
            .LoadDecisionAsync("oauth", "refreshToken", ct));
    }

    [Fact]
    public async Task Precommit_flush_failure_preserves_previous_authenticated_record_on_fresh_open()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        await store.ReplaceAsync(new MutableSlotRecord(
            "oauth", "refreshToken", "fingerprint-a", 3, 4, PlaintextCanary), ct);

        store.TempFlushedBarrier = _ => throw new IOException("injected before atomic replacement");

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 3, 5, "CANARY-successor"),
            ct).AsTask());

        var reopened = new FileMutableSlotStore(store.Root, "mount-a", Key);
        var committed = await reopened.LoadAsync("oauth", "refreshToken", ct);
        Assert.NotNull(committed);
        Assert.Equal(4, committed!.RuntimeRevision);
        Assert.Equal(PlaintextCanary, committed.Value);
        Assert.Single(Directory.GetFiles(store.Root, "*" + FileMutableSlotStore.RecordExtension));
        Assert.DoesNotContain("CANARY-successor", Encoding.UTF8.GetString(
            File.ReadAllBytes(Assert.Single(Directory.GetFiles(store.Root, "*" + FileMutableSlotStore.RecordExtension)))),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Postcommit_compaction_failure_does_not_undo_commit_or_report_false_failure()
    {
        var store = Store();
        var ct = TestContext.Current.CancellationToken;
        await store.ReplaceAsync(new MutableSlotRecord(
            "oauth", "refreshToken", "fingerprint-a", 3, 4, PlaintextCanary), ct);
        store.CompactionBarrier = () => throw new IOException("injected after atomic replacement");

        await store.ReplaceAsync(new MutableSlotRecord(
            "oauth", "refreshToken", "fingerprint-a", 3, 5, "CANARY-successor"), ct);

        var reopened = new FileMutableSlotStore(store.Root, "mount-a", Key);
        var committed = await reopened.LoadAsync("oauth", "refreshToken", ct);
        Assert.NotNull(committed);
        Assert.Equal(5, committed!.RuntimeRevision);
        Assert.Equal("CANARY-successor", committed.Value);
        Assert.Single(Directory.GetFiles(store.Root, "*" + FileMutableSlotStore.RecordExtension));
        Assert.DoesNotContain("CANARY-successor", Encoding.UTF8.GetString(
            File.ReadAllBytes(Assert.Single(Directory.GetFiles(store.Root, "*" + FileMutableSlotStore.RecordExtension)))),
            StringComparison.Ordinal);
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
    public async Task Stale_temporary_files_are_removed_when_the_store_is_opened()
    {
        // MTH-SECRET-2: an abandoned temp is never authoritative, so opening the store reclaims it
        // once it is older than the write grace.
        var root = Path.Combine(NewRoot(), "mount-a");
        _roots.Add(root);
        Directory.CreateDirectory(root);
        var orphan = Path.Combine(root, "orphan" + FileMutableSlotStore.RecordExtension + ".tmp-deadbeef");
        await File.WriteAllBytesAsync(orphan, Encoding.UTF8.GetBytes("partial"), TestContext.Current.CancellationToken);
        File.SetLastWriteTimeUtc(orphan, DateTime.UtcNow - TimeSpan.FromHours(2));

        var store = new FileMutableSlotStore(root, "mount-a", Key);

        Assert.False(File.Exists(orphan));
        Assert.Null(await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_fresh_abandoned_temp_is_kept_because_a_concurrent_writer_may_own_it()
    {
        // A temp younger than the grace threshold may be an in-flight replacement, so it is left.
        var root = Path.Combine(NewRoot(), "mount-a");
        _roots.Add(root);
        Directory.CreateDirectory(root);
        var fresh = Path.Combine(root, "inflight" + FileMutableSlotStore.RecordExtension + ".tmp-beefcafe");
        await File.WriteAllBytesAsync(fresh, Encoding.UTF8.GetBytes("partial"), TestContext.Current.CancellationToken);

        var store = new FileMutableSlotStore(root, "mount-a", Key);

        Assert.True(File.Exists(fresh));
    }

    [Fact]
    public async Task A_restrictive_mode_failure_refuses_to_publish_and_keeps_the_previous_record()
    {
        // MTH-SECRET-3: a committed secret whose file mode cannot be tightened must fail closed.
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, "T0"),
            TestContext.Current.CancellationToken);

        store.PermissionSetter = _ => false;

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 1, "T1"),
            TestContext.Current.CancellationToken).AsTask());

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal("T0", loaded!.Value);
        Assert.Single(Directory.GetFiles(store.Root));
    }

    [Fact]
    public async Task Repeated_rotations_do_not_accumulate_obsolete_records_and_keep_the_newest()
    {
        // MTH-SECRET-1: repeated rotations of one slot stay within the bounded lifecycle and the
        // newest authority is preserved (exactly one live record per slot identity).
        var store = Store();

        for (var revision = 0; revision < 6; revision++)
        {
            await store.ReplaceAsync(
                new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, revision, "value-" + revision),
                TestContext.Current.CancellationToken);
        }

        Assert.Single(Directory.GetFiles(store.Root, "*" + FileMutableSlotStore.RecordExtension));

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal("value-5", loaded!.Value);
        Assert.Equal(5, loaded.RuntimeRevision);
    }

    [Fact]
    public async Task The_retention_cap_refuses_a_new_identity_and_preserves_every_live_record()
    {
        // MTH-SECRET-1: the declared bound is enforced without ever evicting a live identity. A
        // replacement of an existing identity is always admitted; a new identity at the cap is
        // refused fail-closed with a non-secret diagnostic.
        var store = Store();
        store.MaximumRecords = 3;

        for (var index = 0; index < 3; index++)
        {
            await store.ReplaceAsync(
                new MutableSlotRecord("oauth", "slot-" + index, "fingerprint-a", 1, 0, "value-" + index),
                TestContext.Current.CancellationToken);
        }

        // Replacing an existing identity succeeds and changes nothing about the other identities.
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "slot-1", "fingerprint-a", 1, 1, "value-1-rotated"),
            TestContext.Current.CancellationToken);

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "slot-3", "fingerprint-a", 1, 0, "value-3"),
            TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("bounded capacity", failure.Message, StringComparison.Ordinal);
        Assert.Equal(3, Directory.GetFiles(store.Root, "*" + FileMutableSlotStore.RecordExtension).Length);
        Assert.Equal(
            "value-1-rotated",
            (await store.LoadAsync("oauth", "slot-1", TestContext.Current.CancellationToken))!.Value);
        Assert.Null(await store.LoadAsync("oauth", "slot-3", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Concurrent_new_slot_creations_cannot_exceed_the_mount_capacity()
    {
        // R10.3: the capacity cap is a count over the mount, so two writers creating two different new
        // slots must not both pass the one-free-slot check. The per-slot write lock alone let both
        // observe the pre-write count, and the mount ended one record over its cap.
        var ct = TestContext.Current.CancellationToken;
        var root = NewRoot();
        _roots.Add(root);
        var store = new FileMutableSlotStore(root, "mount-a", Key);
        store.MaximumRecords = 2;

        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "slot-0", null, 1, 0, "v0"), ct);

        // Writer A pauses after its temp bytes are written and before the rename, while holding the mount
        // gate. Writer B then attempts to take the last free slot.
#pragma warning disable VSTHRD003 // Deliberate test barrier: the writer waits for the test's signal.
        var paused = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        store.TempWrittenBarrier = async _ =>
        {
            paused.TrySetResult();
            await release.Task.ConfigureAwait(false);
        };
#pragma warning restore VSTHRD003

        Task writerA = Task.Run(
            () => store.ReplaceAsync(new MutableSlotRecord("oauth", "slot-A", null, 1, 0, "vA"), ct).AsTask(),
            ct);

        await paused.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);

        Task writerB = Task.Run(
            () => store.ReplaceAsync(new MutableSlotRecord("oauth", "slot-B", null, 1, 0, "vB"), ct).AsTask(),
            ct);

        // B is serialized behind A's mount gate; releasing A lets B reach the now-full capacity check.
        await Task.Delay(TimeSpan.FromMilliseconds(100), ct);
        release.SetResult();

        RuntimeStateStoreException? refusal = null;
        try
        {
            await Task.WhenAll(writerA, writerB);
        }
        catch (RuntimeStateStoreException exception)
        {
            // A commits the last free slot; B is refused at the cap.
            refusal = exception;
        }

        Assert.NotNull(refusal);
        Assert.Contains("bounded capacity", refusal!.Message, StringComparison.Ordinal);
        Assert.Equal(2, Directory.GetFiles(store.Root, "*" + FileMutableSlotStore.RecordExtension).Length);
        Assert.NotNull(await store.LoadAsync("oauth", "slot-A", ct));
        Assert.Null(await store.LoadAsync("oauth", "slot-B", ct));
    }

    [Fact]
    public async Task Identity_gates_do_not_accumulate_for_distinct_or_refused_identities()
    {
        // R10.7: the gate map must not grow for the process lifetime. A gate created before capacity
        // admission - including for an identity refused at the cap - must be removed once it is idle.
        var ct = TestContext.Current.CancellationToken;
        var root = NewRoot();
        _roots.Add(root);
        var store = new FileMutableSlotStore(root, "mount-a", Key);
        store.MaximumRecords = 3;

        for (var index = 0; index < 3; index++)
        {
            await store.ReplaceAsync(
                new MutableSlotRecord("oauth", "slot-" + index, null, 1, 0, "v" + index), ct);
        }

        // Distinct identities refused at the cap must not leave a gate behind.
        for (var index = 10; index < 60; index++)
        {
            await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
                new MutableSlotRecord("oauth", "slot-" + index, null, 1, 0, "v"), ct).AsTask());
        }

        Assert.Equal(0, FileMutableSlotStore.TrackedIdentityGateCountForRoot(root));
    }

    [Fact]
    public async Task Rotations_in_one_mount_do_not_delete_another_mounts_live_record()
    {
        // MTH-SECRET-1: every managed auth-code mount shares one root and the same profile/slot, so
        // maintenance keyed on anything less than (mount, profile, slot) deletes a peer's live record.
        var root = NewRoot();
        _roots.Add(root);
        var mountA = new FileMutableSlotStore(root, "mount-a", Key);
        var mountB = new FileMutableSlotStore(root, "mount-b", Key);

        await mountB.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-b", 1, 0, "B-0"),
            TestContext.Current.CancellationToken);

        for (var revision = 1; revision <= 4; revision++)
        {
            await mountA.ReplaceAsync(
                new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, revision, "A-" + revision),
                TestContext.Current.CancellationToken);
        }

        var loadedB = await mountB.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.NotNull(loadedB);
        Assert.Equal("B-0", loadedB!.Value);
        Assert.Equal(0, loadedB.RuntimeRevision);

        var loadedA = await mountA.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal("A-4", loadedA!.Value);
    }

    [Fact]
    public async Task An_in_flight_replacement_survives_another_store_opening_the_root()
    {
        // MTH-SECRET-2: stores are constructed for every reconcile read and generation build. A
        // second store opening the root between the first store's temp write and its rename must not
        // delete the in-flight temp.
        var root = NewRoot();
        _roots.Add(root);
        var mountA = new FileMutableSlotStore(root, "mount-a", Key);
        await mountA.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, "T0"),
            TestContext.Current.CancellationToken);

        mountA.TempFlushedBarrier = ct =>
        {
            // Deterministic seam: the temp exists and has not been renamed yet.
            var second = new FileMutableSlotStore(root, "mount-a", Key);
            Assert.NotNull(second);
            return ValueTask.CompletedTask;
        };

        await mountA.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 1, "T1"),
            TestContext.Current.CancellationToken);

        var loaded = await mountA.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal("T1", loaded!.Value);
    }

    [Fact]
    public async Task A_compaction_failure_after_a_committed_write_does_not_fail_the_write()
    {
        var store = Store();
        store.CompactionBarrier = () => throw new InvalidOperationException("injected compaction failure");

        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 0, "T0"),
            TestContext.Current.CancellationToken);

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal("T0", loaded!.Value);
    }

    [Fact]
    public async Task A_failure_before_the_flush_leaves_the_previous_record_authoritative()    {
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

    [Fact]
    public async Task A_regressive_revision_is_refused_and_keeps_the_newer_record()
    {
        // R4.3: the durable store enforces monotonicity. An older writer that finishes after a newer
        // one must not overwrite the newer refresh credential, which the provider has already retired.
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 11, "newer-value"),
            TestContext.Current.CancellationToken);

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 10, "stale-value"),
            TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("not newer", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("stale-value", failure.Message, StringComparison.Ordinal);

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal(11, loaded!.RuntimeRevision);
        Assert.Equal("newer-value", loaded.Value);
    }

    [Fact]
    public async Task An_equal_revision_replacement_commits_the_newest_value()
    {
        // The revision is derived from the declared generation, so two rotations can carry the same
        // declared revision before reconciliation. An equal revision is not older and the later
        // commit is the newer credential, so it replaces the previous value in place.
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 3, "first"),
            TestContext.Current.CancellationToken);

        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 3, "second"),
            TestContext.Current.CancellationToken);

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal("second", loaded!.Value);
        Assert.Equal(3, loaded.RuntimeRevision);
    }

    [Fact]
    public async Task A_lower_authority_epoch_is_refused()
    {
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", AuthorityEpoch: 3, RuntimeRevision: 9, "epoch-3"),
            TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", AuthorityEpoch: 2, RuntimeRevision: 100, "epoch-2"),
            TestContext.Current.CancellationToken).AsTask());

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal(3, loaded!.AuthorityEpoch);
        Assert.Equal("epoch-3", loaded.Value);
    }

    [Fact]
    public async Task A_newer_authority_epoch_supersedes_a_higher_revision()
    {
        // The revision counter is scoped to its epoch, so an explicit operator epoch advance
        // supersedes regardless of the previous epoch's revision.
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", AuthorityEpoch: 1, RuntimeRevision: 9, "epoch-1"),
            TestContext.Current.CancellationToken);

        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", AuthorityEpoch: 2, RuntimeRevision: 0, "epoch-2"),
            TestContext.Current.CancellationToken);

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal(2, loaded!.AuthorityEpoch);
        Assert.Equal(0, loaded.RuntimeRevision);
        Assert.Equal("epoch-2", loaded.Value);
    }

    [Fact]
    public async Task Concurrent_replacements_of_one_identity_advance_to_the_newest_revision()
    {
        // R4.3: replacements for one identity are serialized, so a newer writer cannot interleave
        // with an older one and leave the older revision authoritative.
        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 5, "base"),
            TestContext.Current.CancellationToken);

        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        var first = 1;
        store.TempFlushedBarrier = ct =>
        {
            if (Interlocked.Exchange(ref first, 0) == 1)
            {
                entered.Set();
                release.Wait(ct);
            }

            return ValueTask.CompletedTask;
        };

        var older = Task.Run(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 6, "v6"),
            TestContext.Current.CancellationToken).AsTask(), TestContext.Current.CancellationToken);
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));

        var newer = Task.Run(() => store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 7, "v7"),
            TestContext.Current.CancellationToken).AsTask(), TestContext.Current.CancellationToken);

        // While the older writer holds the identity gate, the newer writer cannot have committed.
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.False(newer.IsCompleted);

        release.Set();
        await older;
        await newer;

        var loaded = await store.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.Equal(7, loaded!.RuntimeRevision);
        Assert.Equal("v7", loaded.Value);
    }

    [Fact]
    public void The_runtime_state_directory_is_restricted_on_windows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var store = Store();

        Assert.True(FileMutableSlotStore.IsRestrictiveWindowsAcl(store.Root, isDirectory: true));
    }

    [Fact]
    public async Task A_committed_record_file_is_restricted_on_windows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var store = Store();
        await store.ReplaceAsync(
            new MutableSlotRecord("oauth", "refreshToken", "fingerprint-a", 1, 1, PlaintextCanary),
            TestContext.Current.CancellationToken);

        var recordPath = Directory
            .GetFiles(store.Root, "*" + FileMutableSlotStore.RecordExtension)
            .Single();

        Assert.True(FileMutableSlotStore.IsRestrictiveWindowsAcl(recordPath, isDirectory: false));
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
