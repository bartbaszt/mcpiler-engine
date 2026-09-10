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
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Files;

/// <summary>
/// The file handle store: what it admits, what it refuses, what survives a failure, and what a
/// sweep reclaims.
/// </summary>
/// <remarks>
/// <para>
/// This is Engine's first durable state, so the failure cases matter more than the success
/// case. A filesystem offers ordering and nothing else, so the tests that earn their keep are
/// the ones that interrupt an admission and then read through the ordinary lookup path from a
/// fresh instance — asserting the state a caller would observe rather than the directory
/// listing an author expected.
/// </para>
/// <para>
/// Every test uses its own root, so nothing here depends on execution order.
/// </para>
/// </remarks>
public sealed class FileHandleStoreTests : IDisposable
{
    private static readonly byte[] PngHeader = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    private readonly List<string> _roots = [];

    [Fact]
    public async Task An_admitted_payload_is_returned_byte_identically()
    {
        var store = Store(out _);
        var payload = RandomNumberGenerator.GetBytes(200_000);

        var reference = await store.IssueAsync(
            new MemoryStream(payload),
            "report.bin",
            "application/octet-stream",
            "connector-a",
            TestContext.Current.CancellationToken);

        var lookup = await store.OpenAsync(reference.Id, TestContext.Current.CancellationToken);

        Assert.Equal(FileHandleStatus.Available, lookup.Status);
        Assert.Equal(payload, await ReadAll(lookup.Content!));
        Assert.Equal(payload.Length, reference.Length);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(payload)), reference.ContentHash);
        Assert.Equal("connector-a", reference.Scope);
    }

    [Fact]
    public async Task An_identifier_is_generated_and_unguessable()
    {
        var store = Store(out _);

        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < 20; index++)
        {
            var reference = await Issue(store, "x", name: "same-name.txt");
            Assert.True(FileHandleStore.IsWellFormedId(reference.Id));
            Assert.True(identifiers.Add(reference.Id));
        }

        // Twenty payloads with one declared name produced twenty handles. A store that derived
        // its identifier from anything the caller supplied would have collided on the first.
        Assert.Equal(20, identifiers.Count);
    }

    [Theory]
    [InlineData("../../etc/passwd", "passwd")]
    [InlineData("..\\..\\windows\\system32\\config", "config")]
    [InlineData("C:\\secrets\\key.pem", "key.pem")]
    [InlineData("/absolute/path.txt", "path.txt")]
    [InlineData("trailing.", "trailing")]
    [InlineData("trailing...  ", "trailing")]
    [InlineData("bad\u0000name.txt", "badname.txt")]
    [InlineData("with\r\nnewline.txt", "withnewline.txt")]
    [InlineData("", "download")]
    [InlineData("   ", "download")]
    [InlineData("...", "download")]
    public async Task A_hostile_declared_name_changes_neither_the_path_nor_the_recorded_name(
        string declared,
        string expectedRecordedName)
    {
        var store = Store(out var root);

        var reference = await Issue(store, "payload", name: declared);

        // The storage name is entropy, so what the declared name contains is irrelevant to
        // where the bytes land. Asserting that is the point: it removes the whole class of
        // questions about separators, device names and control characters.
        Assert.Equal(reference.Id + FileHandleStore.ContentExtension, reference.StoragePointer);
        Assert.Equal(expectedRecordedName, reference.FileName);

        var files = Directory.GetFiles(root, "*", SearchOption.AllDirectories);
        Assert.All(files, path => Assert.Equal(root, Path.GetDirectoryName(path)));
    }

    [Fact]
    public async Task Content_is_written_before_its_record()
    {
        var store = Store(out var root);
        var observed = new List<bool>();

        store.RecordWriteBarrier = (id, _) =>
        {
            observed.Add(File.Exists(Path.Combine(root, id + FileHandleStore.ContentExtension)));
            observed.Add(File.Exists(Path.Combine(root, id + FileHandleStore.RecordExtension)));
            return Task.CompletedTask;
        };

        await Issue(store, "payload");

        // Content present, record absent. The reverse order would create a handle that resolves
        // to content that does not exist yet.
        Assert.Equal([true, false], observed);
    }

    [Fact]
    public async Task A_failure_between_the_two_writes_leaves_no_resolvable_handle()
    {
        var root = NewRoot();
        string? issuedId = null;

        var writing = new FileHandleStore(FileHandleStoreOptions.For(root))
        {
            RecordWriteBarrier = (id, _) =>
            {
                issuedId = id;
                throw new InvalidOperationException("the process died here");
            },
        };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Issue(writing, "payload"));

        Assert.NotNull(issuedId);

        // A fresh instance, and the ordinary lookup path. Inspecting the directory would assert
        // what this test's author expected the store to write; reading through the lookup asserts
        // what a caller holding that handle would actually observe.
        var reopened = new FileHandleStore(FileHandleStoreOptions.For(root));

        var lookup = await reopened.OpenAsync(issuedId!, TestContext.Current.CancellationToken);
        Assert.Equal(FileHandleStatus.NotFound, lookup.Status);
        Assert.Null(lookup.Content);

        var described = await reopened.DescribeAsync(issuedId!, TestContext.Current.CancellationToken);
        Assert.Equal(FileHandleStatus.NotFound, described.Status);

        // No record, and the compensation removed the content it had already written.
        Assert.Empty(Directory.GetFiles(root, "*" + FileHandleStore.RecordExtension));
        Assert.Empty(Directory.GetFiles(root, "*" + FileHandleStore.ContentExtension));
    }

    [Fact]
    public async Task Content_left_by_an_admission_that_never_compensated_is_unreachable_and_reclaimed()
    {
        // A killed process runs no compensation, so this is the state a crash between the two
        // writes leaves behind: content with no record, which the store must treat as absent and
        // the sweep must reclaim.
        var root = NewRoot();
        var orphanId = new string('a', 64);
        var orphanPath = Path.Combine(root, orphanId + FileHandleStore.ContentExtension);
        await File.WriteAllBytesAsync(orphanPath, [1, 2, 3], TestContext.Current.CancellationToken);

        var store = new FileHandleStore(FileHandleStoreOptions.For(root, orphanGrace: TimeSpan.Zero));

        var lookup = await store.OpenAsync(orphanId, TestContext.Current.CancellationToken);
        Assert.Equal(FileHandleStatus.NotFound, lookup.Status);

        var reclaimed = await store.SweepAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1, reclaimed);
        Assert.False(File.Exists(orphanPath));
    }

    [Fact]
    public async Task Fresh_orphan_content_is_left_alone_by_the_sweep()
    {
        // Content is written before its record, so an orphan is the normal appearance of an
        // admission in flight. A sweep with no grace would race the writer.
        var root = NewRoot();
        await File.WriteAllBytesAsync(
            Path.Combine(root, new string('b', 64) + FileHandleStore.ContentExtension),
            [1],
            TestContext.Current.CancellationToken);

        var store = new FileHandleStore(FileHandleStoreOptions.For(root, orphanGrace: TimeSpan.FromMinutes(5)));

        Assert.Equal(0, await store.SweepAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_handle_read_after_its_lifetime_is_refused_with_the_sweep_never_invoked()
    {
        var clock = new AdvanceableClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var store = Store(
            out _,
            policy: FilePolicy.Default with { HandleLifetime = TimeSpan.FromMinutes(10) },
            clock: clock);

        var reference = await Issue(store, "payload");
        clock.Advance(TimeSpan.FromMinutes(11));

        var lookup = await store.OpenAsync(reference.Id, TestContext.Current.CancellationToken);

        // Expiry is enforced on the read itself. A store that only expired on a sweep would
        // honour every handle in the window between its lifetime ending and the next pass,
        // making the configured lifetime a lower bound rather than the limit it states.
        Assert.Equal(FileHandleStatus.Expired, lookup.Status);
        Assert.Null(lookup.Content);
        Assert.Equal(reference.Id, lookup.Reference!.Id);
    }

    [Fact]
    public async Task An_expired_read_removes_the_content_and_the_record_together()
    {
        var clock = new AdvanceableClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var audit = new RecordingAudit();
        var store = Store(
            out var root,
            policy: FilePolicy.Default with { HandleLifetime = TimeSpan.FromMinutes(1) },
            clock: clock,
            audit: audit);

        var reference = await Issue(store, "payload");
        clock.Advance(TimeSpan.FromMinutes(2));

        await store.OpenAsync(reference.Id, TestContext.Current.CancellationToken);

        Assert.Empty(Directory.GetFiles(root, reference.Id + ".*"));
        Assert.Contains(
            audit.Events,
            entry => entry.Action == FileHandleAuditAction.Expired && entry.HandleId == reference.Id);
    }

    [Fact]
    public async Task A_non_positive_lifetime_means_the_handle_does_not_expire()
    {
        var clock = new AdvanceableClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var store = Store(out _, policy: FilePolicy.Default with { HandleLifetime = TimeSpan.Zero }, clock: clock);

        var reference = await Issue(store, "payload");
        clock.Advance(TimeSpan.FromDays(3650));

        var lookup = await store.OpenAsync(reference.Id, TestContext.Current.CancellationToken);

        Assert.Null(reference.ExpiresAtUtc);
        Assert.Equal(FileHandleStatus.Available, lookup.Status);
        await lookup.Content!.DisposeAsync();
    }

    [Fact]
    public async Task Removal_takes_the_content_and_the_record_and_is_audited()
    {
        var audit = new RecordingAudit();
        var store = Store(out var root, audit: audit);

        var reference = await Issue(store, "payload");

        Assert.True(await store.RemoveAsync(reference.Id, TestContext.Current.CancellationToken));
        Assert.Empty(Directory.GetFiles(root, reference.Id + ".*"));
        Assert.Equal(
            FileHandleStatus.NotFound,
            (await store.OpenAsync(reference.Id, TestContext.Current.CancellationToken)).Status);

        Assert.Contains(
            audit.Events,
            entry => entry.Action == FileHandleAuditAction.Removed && entry.HandleId == reference.Id);
    }

    [Fact]
    public async Task Removing_an_unknown_handle_reports_that_rather_than_failing()
    {
        var store = Store(out _);

        Assert.False(await store.RemoveAsync(new string('c', 64), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task The_sweep_removes_an_expired_handle()
    {
        var clock = new AdvanceableClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var store = Store(
            out var root,
            policy: FilePolicy.Default with { HandleLifetime = TimeSpan.FromMinutes(1) },
            clock: clock);

        var reference = await Issue(store, "payload");
        clock.Advance(TimeSpan.FromMinutes(2));

        Assert.Equal(1, await store.SweepAsync(TestContext.Current.CancellationToken));
        Assert.Empty(Directory.GetFiles(root, reference.Id + ".*"));
    }

    [Fact]
    public async Task The_sweep_removes_a_record_whose_content_is_absent()
    {
        var store = Store(out var root);
        var reference = await Issue(store, "payload");

        File.Delete(Path.Combine(root, reference.StoragePointer));

        Assert.Equal(
            FileHandleStatus.NotFound,
            (await store.OpenAsync(reference.Id, TestContext.Current.CancellationToken)).Status);

        Assert.Equal(1, await store.SweepAsync(TestContext.Current.CancellationToken));
        Assert.Empty(Directory.GetFiles(root, "*" + FileHandleStore.RecordExtension));
    }

    [Fact]
    public async Task A_payload_over_the_ceiling_is_refused_and_leaves_nothing_behind()
    {
        var store = Store(out var root, policy: FilePolicy.Default with { UploadSizeLimitBytes = 1024 });

        var failure = await Assert.ThrowsAsync<FileRuntimeException>(() => store.IssueAsync(
            new MemoryStream(RandomNumberGenerator.GetBytes(4096)),
            "big.bin",
            "application/octet-stream",
            "connector-a",
            TestContext.Current.CancellationToken));

        Assert.Contains("size limit", failure.Message, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(root));
    }

    [Fact]
    public async Task A_declared_type_contradicting_the_content_is_refused_under_the_rejecting_policy()
    {
        var store = Store(out var root);

        var failure = await Assert.ThrowsAsync<FileRuntimeException>(() => store.IssueAsync(
            new MemoryStream(Encoding.UTF8.GetBytes("this is not a png")),
            "image.png",
            "image/png",
            "connector-a",
            TestContext.Current.CancellationToken));

        Assert.Contains("image/png", failure.Message, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(root));
    }

    [Fact]
    public async Task A_contradiction_is_recorded_rather_than_refused_when_the_policy_allows_it()
    {
        var store = Store(out _, policy: FilePolicy.Default with { RejectMagicMismatch = false });

        var reference = await store.IssueAsync(
            new MemoryStream(Encoding.UTF8.GetBytes("this is not a png")),
            "image.png",
            "image/png",
            "connector-a",
            TestContext.Current.CancellationToken);

        Assert.Equal(SignatureVerdict.Conflict, reference.SignatureVerdict);
    }

    [Fact]
    public async Task Matching_content_records_a_signature_match()
    {
        var store = Store(out _);

        var reference = await store.IssueAsync(
            new MemoryStream([.. PngHeader, .. RandomNumberGenerator.GetBytes(64)]),
            "image.png",
            "image/png",
            "connector-a",
            TestContext.Current.CancellationToken);

        Assert.Equal(SignatureVerdict.Match, reference.SignatureVerdict);
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData("application/json; charset=utf-8")]
    [InlineData("APPLICATION/JSON")]
    public async Task A_media_type_is_compared_by_its_essence_and_recorded_that_way(string declared)
    {
        var store = Store(out _);

        var reference = await store.IssueAsync(
            new MemoryStream(Encoding.UTF8.GetBytes("{}")),
            "body.json",
            declared,
            "connector-a",
            TestContext.Current.CancellationToken);

        // Parameters and case say nothing about how the bytes begin. Comparing the whole header
        // value would make one payload conflict or match depending on whether a charset was
        // mentioned.
        Assert.Equal("application/json", reference.MediaType);
        Assert.Equal(SignatureVerdict.Match, reference.SignatureVerdict);
    }

    [Fact]
    public async Task With_no_scanner_the_record_says_no_scan_was_performed()
    {
        var store = Store(out _);

        var reference = await Issue(store, "payload");

        // Not Clean. A store with no scanner that recorded a clean verdict would tell every
        // later reader that the payload passed a check nobody ran, and an operator auditing
        // what was admitted could not distinguish the two.
        Assert.Equal(FileScanVerdict.NotScanned, reference.ScanVerdict);
    }

    [Fact]
    public async Task A_scanners_verdict_is_recorded_as_the_scanner_returned_it()
    {
        var store = Store(out _, scanner: new FixedScanner(FileScanVerdict.Unknown));

        var reference = await Issue(store, "payload");

        Assert.Equal(FileScanVerdict.Unknown, reference.ScanVerdict);
    }

    [Fact]
    public async Task A_clean_verdict_is_recorded_only_when_a_scanner_returned_it()
    {
        var store = Store(out _, scanner: new FixedScanner(FileScanVerdict.Clean));

        Assert.Equal(FileScanVerdict.Clean, (await Issue(store, "payload")).ScanVerdict);
    }

    [Fact]
    public async Task An_infected_payload_is_refused_and_leaves_nothing_behind()
    {
        var store = Store(out var root, scanner: new FixedScanner(FileScanVerdict.Infected));

        var failure = await Assert.ThrowsAsync<FileRuntimeException>(() => Issue(store, "payload"));

        Assert.Contains("malicious", failure.Message, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(root));
    }

    [Fact]
    public async Task A_record_survives_a_restart_with_every_field_intact()
    {
        var root = NewRoot();
        var writing = new FileHandleStore(FileHandleStoreOptions.For(root));

        var reference = await writing.IssueAsync(
            new MemoryStream([.. PngHeader, 1, 2, 3]),
            "chart.png",
            "image/png",
            "connector-b",
            TestContext.Current.CancellationToken);

        var reopened = new FileHandleStore(FileHandleStoreOptions.For(root));
        var lookup = await reopened.DescribeAsync(reference.Id, TestContext.Current.CancellationToken);

        Assert.Equal(FileHandleStatus.Available, lookup.Status);
        Assert.Equal(reference, lookup.Reference);
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("..\\escape")]
    [InlineData("/etc/passwd")]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("ZZZZ")]
    public async Task An_identifier_that_is_not_one_this_store_generates_resolves_to_nothing(string id)
    {
        var store = Store(out _);

        // Answered as unknown rather than refused. A different answer for a malformed
        // identifier would confirm which shapes exist, and a path is never built from it at all.
        Assert.False(FileHandleStore.IsWellFormedId(id));
        Assert.Equal(
            FileHandleStatus.NotFound,
            (await store.OpenAsync(id, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task A_record_pointing_outside_the_root_is_refused_after_normalization()
    {
        var store = Store(out var root);
        var id = new string('d', 64);

        // Hand-written, because no admission can produce it. The escape has to be refused on
        // the resolved path: before normalization it looks like an ordinary relative name.
        await WriteRecord(root, id, "../escape.bin");

        await Assert.ThrowsAsync<FileRuntimeException>(
            () => store.OpenAsync(id, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_record_pointing_inside_the_root_by_a_redundant_path_is_accepted()
    {
        var store = Store(out var root);
        var id = new string('e', 64);
        var real = id + FileHandleStore.ContentExtension;

        await File.WriteAllBytesAsync(Path.Combine(root, real), [7], TestContext.Current.CancellationToken);
        await WriteRecord(root, id, "./nested/.././" + real);

        var lookup = await store.OpenAsync(id, TestContext.Current.CancellationToken);

        // Redundant separators and dot segments are what normalization exists to collapse. A
        // path that lands inside the root after collapsing is inside the root.
        Assert.Equal(FileHandleStatus.Available, lookup.Status);
        Assert.Equal([7], await ReadAll(lookup.Content!));
    }

    [Fact]
    public void A_root_that_does_not_exist_is_refused_at_construction()
    {
        var absent = Path.Combine(Path.GetTempPath(), "mcpiler-absent-" + Guid.NewGuid().ToString("N"));

        var failure = Assert.Throws<FileRuntimeException>(
            () => new FileHandleStore(FileHandleStoreOptions.For(absent)));

        Assert.Contains("does not exist", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_root_that_cannot_be_written_to_is_refused_at_construction()
    {
        var root = NewRoot();

        // A directory where the probe file must go. Filesystem permissions differ per platform
        // and per privilege level; a name collision is the portable way to make one write fail.
        Directory.CreateDirectory(Path.Combine(root, FileHandleStore.WriteProbeName));

        var failure = Assert.Throws<FileRuntimeException>(
            () => new FileHandleStore(FileHandleStoreOptions.For(root)));

        Assert.Contains("not writable", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_root_inside_a_served_content_root_is_refused_at_construction()
    {
        var served = NewRoot();
        var root = Path.Combine(served, "handles");
        Directory.CreateDirectory(root);

        var failure = Assert.Throws<FileRuntimeException>(() => new FileHandleStore(
            FileHandleStoreOptions.For(root, servedContentRoots: [served])));

        Assert.Contains("overlaps served content root", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_served_content_root_inside_the_store_root_is_refused_at_construction()
    {
        var root = NewRoot();
        var served = Path.Combine(root, "public");
        Directory.CreateDirectory(served);

        // The other direction. A served root inside the store means the store serves itself,
        // and an unguessable handle stops being the only way to reach a payload.
        var failure = Assert.Throws<FileRuntimeException>(() => new FileHandleStore(
            FileHandleStoreOptions.For(root, servedContentRoots: [served])));

        Assert.Contains("overlaps served content root", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_root_equal_to_a_served_content_root_is_refused_at_construction()
    {
        var root = NewRoot();

        Assert.Throws<FileRuntimeException>(() => new FileHandleStore(
            FileHandleStoreOptions.For(root, servedContentRoots: [root])));
    }

    [Fact]
    public void An_unrelated_served_content_root_is_accepted()
    {
        var root = NewRoot();
        var served = NewRoot();

        var store = new FileHandleStore(FileHandleStoreOptions.For(root, servedContentRoots: [served]));

        Assert.Equal(Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)), store.Root);
    }

    public void Dispose()
    {
        foreach (var root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private FileHandleStore Store(
        out string root,
        FilePolicy? policy = null,
        TimeProvider? clock = null,
        IFileContentScanner? scanner = null,
        IFileHandleAuditSink? audit = null)
    {
        root = NewRoot();
        return new FileHandleStore(FileHandleStoreOptions.For(root, policy), clock, scanner, audit);
    }

    private string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "mcpiler-handles-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        _roots.Add(root);
        return root;
    }

    private static Task<FileHandleReference> Issue(
        FileHandleStore store,
        string payload,
        string name = "payload.bin",
        string mediaType = "application/octet-stream")
        => store.IssueAsync(
            new MemoryStream(Encoding.UTF8.GetBytes(payload)),
            name,
            mediaType,
            "connector-a",
            TestContext.Current.CancellationToken);

    private static async Task<byte[]> ReadAll(Stream stream)
    {
        await using (stream)
        {
            using var buffer = new MemoryStream();
            await stream.CopyToAsync(buffer, TestContext.Current.CancellationToken);
            return buffer.ToArray();
        }
    }

    private static Task WriteRecord(string root, string id, string storagePointer)
    {
        var record = new JsonObject
        {
            ["id"] = id,
            ["fileName"] = "hand-written.bin",
            ["mediaType"] = "application/octet-stream",
            ["length"] = 1,
            ["contentHash"] = string.Empty,
            ["storagePointer"] = storagePointer,
            ["scope"] = "connector-a",
            ["expiresAtUtc"] = null,
            ["scanVerdict"] = nameof(FileScanVerdict.NotScanned),
            ["signatureVerdict"] = nameof(SignatureVerdict.Undefined),
        };

        return File.WriteAllTextAsync(
            Path.Combine(root, id + FileHandleStore.RecordExtension),
            record.ToJsonString(),
            TestContext.Current.CancellationToken);
    }

    private sealed class AdvanceableClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan amount) => _now += amount;
    }

    private sealed class FixedScanner(FileScanVerdict verdict) : IFileContentScanner
    {
        public ValueTask<FileScanVerdict> ScanAsync(
            Stream content,
            string fileName,
            string mediaType,
            CancellationToken cancellationToken)
            => ValueTask.FromResult(verdict);
    }

    private sealed class RecordingAudit : IFileHandleAuditSink
    {
        public List<FileHandleAuditEvent> Events { get; } = [];

        public void Record(FileHandleAuditEvent record) => Events.Add(record);
    }
}
