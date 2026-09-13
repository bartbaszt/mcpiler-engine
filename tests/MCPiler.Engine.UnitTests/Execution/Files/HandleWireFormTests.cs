using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Serialization;
using MCPiler.Engine.Files;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Files;

/// <summary>
/// The wire form of a handle: what it looks like, what it cannot reveal, and how the store
/// resolves it.
/// </summary>
/// <remarks>
/// A handle crossing the protocol boundary is a capability, not a name. The wire form therefore
/// carries nothing a reader could recover: not the storage location, not the content hash, not
/// the scope, not an ordinal that relates two handles issued in sequence.
/// </remarks>
public sealed class HandleWireFormTests : IDisposable
{
    private readonly List<string> _roots = [];

    [Fact]
    public async Task A_wire_form_carries_nothing_recoverable()
    {
        var store = Store();
        var payload = RandomNumberGenerator.GetBytes(3000);

        var reference = await store.IssueAsync(
            new MemoryStream(payload), "payload.bin", "application/octet-stream", "a-connector",
            TestContext.Current.CancellationToken);
        string wire = store.WireFormFor(reference.Id);

        Assert.True(HandleCodec.IsWireForm(wire));
        Assert.DoesNotContain(reference.Id, wire, StringComparison.Ordinal);
        Assert.DoesNotContain(reference.StoragePointer, wire, StringComparison.Ordinal);
        Assert.DoesNotContain(reference.ContentHash, wire, StringComparison.Ordinal);
        Assert.DoesNotContain(reference.Scope, wire, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToHexStringLower(payload[0..16]), wire, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Handles_issued_in_sequence_share_no_recoverable_relation()
    {
        var store = Store();
        var forms = new List<string>();

        for (var index = 0; index < 8; index++)
        {
            var issued = await Issue(store, "payload.bin", "a-connector");
            forms.Add(store.WireFormFor(issued.Id));
        }

        // All unrelated, and no form is derived from the one issued before it.
        Assert.Equal(8, forms.Distinct(StringComparer.Ordinal).Count());

        var decoded = forms
            .Select(static form => System.Convert.FromBase64String(
                form.Replace('-', '+').Replace('_', '/') + new string('=', (4 - form.Length % 4) % 4)))
            .ToList();

        for (var index = 1; index < decoded.Count; index++)
        {
            Assert.Equal(32, decoded[index].Length);
            Assert.False(decoded[index].AsSpan().SequenceEqual(decoded[index - 1]));
        }
    }

    [Fact]
    public void The_wire_shape_is_pinned()
    {
        Assert.True(HandleCodec.IsWireForm(new string('A', 43)));
        Assert.True(HandleCodec.IsWireForm(new string('-', 43)));
        Assert.True(HandleCodec.IsWireForm(new string('_', 43)));
        Assert.False(HandleCodec.IsWireForm(new string('A', 42)));
        Assert.False(HandleCodec.IsWireForm(new string('A', 44)));
        Assert.False(HandleCodec.IsWireForm(null));
        Assert.False(HandleCodec.IsWireForm(string.Empty));
        Assert.False(HandleCodec.IsWireForm(new string('A', 43) + "="));
        Assert.False(HandleCodec.IsWireForm(new string('+', 43)));
        Assert.False(HandleCodec.IsWireForm(new string('/', 43)));
    }

    [Fact]
    public async Task The_wire_form_and_the_store_identifier_are_distinct_namespaces()
    {
        var store = Store();
        var reference = await Issue(store, "payload.bin", "a-connector");
        string wire = store.WireFormFor(reference.Id);

        Assert.False(HandleCodec.IsWireForm(reference.Id));
        Assert.False(FileHandleStore.IsWellFormedId(wire));
    }

    [Fact]
    public async Task The_store_resolves_its_own_wire_form_back_to_the_handle()
    {
        var store = Store();
        var payload = RandomNumberGenerator.GetBytes(4000);
        var reference = await store.IssueAsync(
            new MemoryStream(payload), "payload.bin", "application/octet-stream", "scope-a",
            TestContext.Current.CancellationToken);
        string wire = store.WireFormFor(reference.Id);

        var resolved = await store.TryResolveWire(wire, TestContext.Current.CancellationToken);

        Assert.Equal(reference.Id, resolved.Reference!.Id);
        Assert.Equal("scope-a", resolved.Reference.Scope);
    }

    [Fact]
    public async Task A_wire_form_another_store_never_issued_resolves_to_nothing()
    {
        var first = Store();
        var second = Store();
        var reference = await Issue(first, "payload.bin", "a-connector");
        string wire = first.WireFormFor(reference.Id);

        Assert.Equal(FileHandleStatus.NotFound, (await second.TryResolveWire(wire, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task A_removed_handle_answers_as_never_issued_after_a_restart()
    {
        var store = Store(out var root);
        var reference = await Issue(store, "payload.bin", "a-connector");
        string wire = store.WireFormFor(reference.Id);

        await store.RemoveAsync(reference.Id, TestContext.Current.CancellationToken);

        var restarted = NewStore(root);

        Assert.Equal(FileHandleStatus.NotFound, (await restarted.TryResolveWire(wire, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task The_wire_capability_is_not_persisted_in_the_internal_file_record()
    {
        var store = Store(out var root);
        var reference = await Issue(store, "payload.bin", "a-connector");
        string wire = store.WireFormFor(reference.Id);

        string recordText = await File.ReadAllTextAsync(
            Path.Combine(root, reference.Id + FileHandleStore.RecordExtension),
            TestContext.Current.CancellationToken);

        Assert.DoesNotContain(wire, recordText, StringComparison.Ordinal);
        Assert.DoesNotContain("wireHandle", recordText, StringComparison.Ordinal);

        // The internal reference remains durable, but its protocol capability is session/process
        // state and is intentionally absent after restart.
        var restarted = NewStore(root);
        Assert.Equal(FileHandleStatus.Available, (await restarted.OpenAsync(reference.Id, TestContext.Current.CancellationToken)).Status);
        Assert.Equal(FileHandleStatus.NotFound, (await restarted.TryResolveWire(wire, TestContext.Current.CancellationToken)).Status);
        Assert.Equal(string.Empty, restarted.WireFormFor(reference.Id));
    }

    [Fact]
    public async Task A_swept_handle_stops_resolving_while_its_neighbour_survives()
    {
        var store = Store();
        var kept = await Issue(store, "kept.bin", "a-connector");
        var swept = await Issue(store, "swept.bin", "a-connector");
        string keptWire = store.WireFormFor(kept.Id);
        string sweptWire = store.WireFormFor(swept.Id);

        await store.RemoveAsync(swept.Id, TestContext.Current.CancellationToken);

        var resolved = await store.TryResolveWire(keptWire, TestContext.Current.CancellationToken);

        Assert.Equal(kept.Id, resolved.Reference!.Id);
        Assert.Equal(FileHandleStatus.NotFound, (await store.TryResolveWire(sweptWire, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public void A_value_without_the_wire_shape_resolves_to_nothing()
    {
        var store = Store();

        Assert.Equal(string.Empty, store.WireFormFor(new string('a', 64)));
    }

    [Fact]
    public async Task Redemption_refuses_a_handle_from_another_scope_exactly_as_a_never_issued_one()
    {
        var store = Store();
        var theirs = await Issue(store, "payload.bin", "other-mount");
        var mine = await Issue(store, "mine.bin", "this-mount");
        string theirsWire = store.WireFormFor(theirs.Id);
        string mineWire = store.WireFormFor(mine.Id);

        var wrongScope = await RedemptionAuthorization.RedeemAsync(
            store, theirsWire, "this-mount", TestContext.Current.CancellationToken);
        var neverIssued = await RedemptionAuthorization.RedeemAsync(
            store, HandleCodec.NewWire(), "this-mount", TestContext.Current.CancellationToken);
        var own = await RedemptionAuthorization.RedeemAsync(
            store, mineWire, "this-mount", TestContext.Current.CancellationToken);

        Assert.True(own.Succeeded);
        Assert.NotNull(own.File);
        Assert.Null(own.File.Content.BufferedBytes);
        using var buffer = new MemoryStream();
        await own.File.Content.CopyToAsync(buffer, TestContext.Current.CancellationToken);
        Assert.Equal("payload for mine.bin", System.Text.Encoding.UTF8.GetString(buffer.ToArray()));
        await own.File.Content.DisposeAsync();

        // The oracle: a wrong-scope handle is indistinguishable from one that never existed.
        Assert.False(wrongScope.Succeeded);
        Assert.Equal(FileRedemptionRefusalKind.Unknown, wrongScope.Refusal);
        Assert.False(neverIssued.Succeeded);
        Assert.Equal(FileRedemptionRefusalKind.Unknown, neverIssued.Refusal);
    }

    [Fact]
    public async Task An_expired_handle_is_distinguishable_from_a_never_issued_one()
    {
        var root = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), "mcpiler-wire-" + Guid.NewGuid().ToString("N")));
        _roots.Add(root.FullName);

        var clock = new MutableClock(DateTimeOffset.UtcNow);
        var issuingStore = new FileHandleStore(
            new FileHandleStoreOptions(root.FullName, TimeSpan.FromMinutes(1), 1024 * 1024, false, [], TimeSpan.FromMinutes(5)),
            clock);

        var reference = await Issue(issuingStore, "payload.bin", "a-connector");
        string wire = issuingStore.WireFormFor(reference.Id);

        clock.Now = clock.GetUtcNow().AddHours(2);

        var expired = await RedemptionAuthorization.RedeemAsync(
            issuingStore, wire, "a-connector", TestContext.Current.CancellationToken);
        var neverIssued = await RedemptionAuthorization.RedeemAsync(
            issuingStore, HandleCodec.NewWire(), "a-connector", TestContext.Current.CancellationToken);

        // Expiry is a fact about a handle the caller was given; absence is the only other
        // answer, and the two stay distinguishable.
        Assert.False(expired.Succeeded);
        Assert.Equal(FileRedemptionRefusalKind.Expired, expired.Refusal);
        Assert.False(neverIssued.Succeeded);
        Assert.Equal(FileRedemptionRefusalKind.Unknown, neverIssued.Refusal);
    }

    [Fact]
    public void A_refusal_never_carries_a_presented_form()
    {
        var wire = HandleCodec.NewWire();

        Assert.DoesNotContain(wire, RedemptionAuthorization.UnknownMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_store_backed_raw_binary_body_stays_streaming_through_serialization()
    {
        const string Payload = "raw-store-backed-payload";
        var store = Store();
        FileHandleReference reference = await store.IssueAsync(
            new MemoryStream(Encoding.UTF8.GetBytes(Payload)),
            "payload.bin",
            "application/octet-stream",
            "scope-a",
            TestContext.Current.CancellationToken);
        string wire = store.WireFormFor(reference.Id);
        FileRedemption redemption = await RedemptionAuthorization.RedeemAsync(
            store,
            wire,
            "scope-a",
            TestContext.Current.CancellationToken);
        ExecutionFile file = Assert.IsType<ExecutionFile>(redemption.File);

        var serialized = BodySerializer.Serialize(
            "application/octet-stream",
            new ManifestMediaType("application/octet-stream"),
            JsonValue.Create(wire),
            new Dictionary<string, ExecutionFile>(StringComparer.Ordinal) { ["body"] = file });

        Assert.Null(serialized.Body);
        ReplayableBodySource source = Assert.IsAssignableFrom<ReplayableBodySource>(serialized.BodySource);
        Assert.Null(source.BufferedBytes);

        using MemoryStream output = new();
        await source.CopyToAsync(output, TestContext.Current.CancellationToken);
        Assert.Equal(Payload, Encoding.UTF8.GetString(output.ToArray()));
        await source.DisposeAsync();
    }

    [Fact]
    public async Task A_store_backed_multipart_part_stays_streaming_through_serialization()
    {
        const string Payload = "multipart-store-backed-payload";
        var store = Store();
        FileHandleReference reference = await store.IssueAsync(
            new MemoryStream(Encoding.UTF8.GetBytes(Payload)),
            "payload.bin",
            "application/octet-stream",
            "scope-a",
            TestContext.Current.CancellationToken);
        string wire = store.WireFormFor(reference.Id);
        FileRedemption redemption = await RedemptionAuthorization.RedeemAsync(
            store,
            wire,
            "scope-a",
            TestContext.Current.CancellationToken);
        ExecutionFile file = Assert.IsType<ExecutionFile>(redemption.File);

        var serialized = BodySerializer.Serialize(
            "multipart/form-data",
            new ManifestMediaType("multipart/form-data"),
            new JsonObject { ["attachment"] = wire },
            new Dictionary<string, ExecutionFile>(StringComparer.Ordinal) { ["attachment"] = file },
            boundaryProvider: new FixedBoundaryProvider("STORE-BOUNDARY"));

        Assert.Null(serialized.Body);
        ReplayableBodySource source = Assert.IsAssignableFrom<ReplayableBodySource>(serialized.BodySource);
        Assert.Null(file.Content.BufferedBytes);

        using MemoryStream output = new();
        await source.CopyToAsync(output, TestContext.Current.CancellationToken);
        string rendered = Encoding.UTF8.GetString(output.ToArray());
        Assert.Contains(Payload, rendered, StringComparison.Ordinal);
        Assert.Contains("--STORE-BOUNDARY", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(wire, rendered, StringComparison.Ordinal);
        await source.DisposeAsync();
        await file.Content.DisposeAsync();
    }

    private sealed class MutableClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private FileHandleStore Store()
    {
        var root = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), "mcpiler-wire-" + Guid.NewGuid().ToString("N")));
        _roots.Add(root.FullName);

        return NewStore(root.FullName);
    }

    private FileHandleStore Store(out string root)
    {
        var directory = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), "mcpiler-wire-" + Guid.NewGuid().ToString("N")));
        _roots.Add(directory.FullName);
        root = directory.FullName;

        return NewStore(root);
    }

    private static FileHandleStore NewStore(string root)
        => new(new FileHandleStoreOptions(
            root,
            TimeSpan.FromHours(1),
            1024 * 1024,
            RejectMagicMismatch: false,
            ServedContentRoots: [],
            OrphanGrace: TimeSpan.FromMinutes(5)));

    private static async Task<FileHandleReference> Issue(FileHandleStore store, string name, string scope)
        => await store.IssueAsync(
            new MemoryStream(System.Text.Encoding.UTF8.GetBytes("payload for " + name)),
            name,
            "application/octet-stream",
            scope,
            TestContext.Current.CancellationToken);

    public void Dispose()
    {
        foreach (var root in _roots)
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
