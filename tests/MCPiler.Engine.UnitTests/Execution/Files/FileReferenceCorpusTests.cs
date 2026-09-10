using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;

using Xunit;

namespace MCPiler.Engine.UnitTests.Execution.Files;

/// <summary>
/// Replays the shared file-reference corpus against the Engine handle store.
/// </summary>
/// <remarks>
/// <para>
/// The same bytes with the same declared name and media type must produce the same filename,
/// media type, byte length and content hash on either side. The corpus is authored rather than
/// generated, because a corpus generated from one store records that store's beliefs and a rule
/// both sides get wrong the same way would be invisible in two green suites at once.
/// </para>
/// <para>
/// The handle identifier and the storage pointer are deliberately not in the corpus. The
/// identifier is meant to differ. The pointer is implementation-defined: this store names
/// content by entropy and the other addresses it by hash.
/// </para>
/// </remarks>
public sealed class FileReferenceCorpusTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-engine-ref-corpus", Guid.NewGuid().ToString("N"));

    public FileReferenceCorpusTests() => Directory.CreateDirectory(_root);

    [Fact]
    public async Task Every_authored_case_produces_the_reference_the_corpus_states()
    {
        var store = new FileHandleStore(FileHandleStoreOptions.For(_root));

        foreach (var entry in Cases())
        {
            var name = entry["name"]!.GetValue<string>();
            var expected = entry["reference"]!.AsObject();
            var payload = Convert.FromBase64String(entry["payloadBase64"]!.GetValue<string>());

            var reference = await store.IssueAsync(
                new MemoryStream(payload),
                entry["declaredFileName"]!.GetValue<string>(),
                entry["declaredMediaType"]!.GetValue<string>(),
                scope: "corpus",
                TestContext.Current.CancellationToken);

            Assert.Equal(expected["fileName"]!.GetValue<string>(), reference.FileName);
            Assert.Equal(expected["mediaType"]!.GetValue<string>(), reference.MediaType);
            Assert.Equal(expected["length"]!.GetValue<long>(), reference.Length);
            Assert.Equal(expected["contentHash"]!.GetValue<string>(), reference.ContentHash);

            Assert.False(string.IsNullOrEmpty(name));
        }
    }

    /// <summary>
    /// Two cases with the same bytes and different declared names are two handles.
    /// </summary>
    /// <remarks>
    /// Worth asserting here and not on the other side, because the two stores differ exactly
    /// here: content addressing collapses identical payloads onto one blob, entropy naming does
    /// not. The corpus stays silent about the pointer for that reason, and this test states what
    /// the silence costs.
    /// </remarks>
    [Fact]
    public async Task Identical_bytes_under_different_names_are_distinct_handles()
    {
        var store = new FileHandleStore(FileHandleStoreOptions.For(_root));
        var payload = new byte[] { 1, 2, 3, 4 };

        var first = await store.IssueAsync(new MemoryStream(payload), "a.bin", "application/octet-stream", "corpus", TestContext.Current.CancellationToken);
        var second = await store.IssueAsync(new MemoryStream(payload), "b.bin", "application/octet-stream", "corpus", TestContext.Current.CancellationToken);

        Assert.NotEqual(first.Id, second.Id);
        Assert.Equal(first.ContentHash, second.ContentHash);
    }

    [Fact]
    public void The_corpus_is_complete_and_covers_more_than_the_ordinary_case()
    {
        var cases = Cases().ToList();

        Assert.True(cases.Count >= 10, $"The corpus has shrunk to {cases.Count} cases.");

        foreach (var entry in cases)
        {
            var name = entry["name"]?.GetValue<string>();
            Assert.False(string.IsNullOrWhiteSpace(name), "A case has no name.");
            Assert.False(string.IsNullOrWhiteSpace(entry["why"]?.GetValue<string>()), $"Case '{name}' states no reason.");

            var reference = Assert.IsType<JsonObject>(entry["reference"]);
            foreach (var field in new[] { "fileName", "mediaType", "length", "contentHash" })
            {
                Assert.True(reference.ContainsKey(field), $"Case '{name}' states no {field}.");
            }
        }

        var names = cases.Select(entry => entry["reference"]!["fileName"]!.GetValue<string>()).Distinct(StringComparer.Ordinal).ToList();
        Assert.True(names.Count >= 5, "Every case resolves to nearly the same filename, so the sanitizer is barely exercised.");
        Assert.Contains("download", names, StringComparer.Ordinal);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static IEnumerable<JsonObject> Cases()
    {
        var path = Path.Combine(TestRepository.Fixture("files"), "reference-cases.json");
        var document = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        return document["cases"]!.AsArray().Select(node => node!.AsObject());
    }
}
