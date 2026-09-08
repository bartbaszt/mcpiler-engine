using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Sealing;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// The transport archive is a byte contract shared with the generator that produces manifests.
/// </summary>
/// <remarks>
/// <para>
/// That generator lives in a repository this one cannot reference, so the two packers are
/// independent implementations of one specified byte layout. They are reconciled through the
/// golden archive in <c>tests/fixtures/manifests/archive/</c>, which is duplicated
/// byte-identically in both trees: each side asserts it produces exactly those bytes, so a
/// divergence fails on whichever side changed.
/// </para>
/// <para>
/// Agreeing on bytes is not enough on its own, because two packers could agree on a byte
/// pattern that is not a loadable bundle. The round trip below therefore also unpacks the
/// golden archive and loads the result.
/// </para>
/// </remarks>
public sealed class ArchiveByteContractTests
{
    private const string BundleName = "sealed-bundle";
    private const string ArchiveName = "sealed-bundle.mcpiler-manifest";

    [Fact]
    public void Packing_the_shared_bundle_produces_the_golden_archive()
    {
        var expected = File.ReadAllBytes(TestRepository.Fixture("manifests", "archive", ArchiveName));

        using var buffer = new MemoryStream();
        var result = ManifestArchive.Pack(TestRepository.Fixture("manifests", BundleName), buffer);

        Assert.True(result.Succeeded, Describe(result));
        Assert.Equal(expected, buffer.ToArray());
    }

    [Fact]
    public void The_golden_archive_unpacks_into_the_bundle_it_was_packed_from()
    {
        var bundle = TestRepository.Fixture("manifests", BundleName);
        var destination = Path.Combine(Path.GetTempPath(), $"mcpiler-archive-{Guid.NewGuid():N}");

        try
        {
            using var source = File.OpenRead(TestRepository.Fixture("manifests", "archive", ArchiveName));
            var result = ManifestArchive.Unpack(source, destination);

            Assert.True(result.Succeeded, Describe(result));

            var original = Inventory(bundle);
            var extracted = Inventory(destination);

            Assert.Equal(original.Keys.Order(StringComparer.Ordinal), extracted.Keys.Order(StringComparer.Ordinal));

            foreach (var (path, bytes) in original)
            {
                Assert.Equal(bytes, extracted[path]);
            }
        }
        finally
        {
            Delete(destination);
        }
    }

    [Fact]
    public void The_unpacked_golden_archive_loads_as_a_sealed_manifest()
    {
        // Two packers can agree on bytes that are not a manifest. This is what makes the
        // golden archive evidence about the product rather than about a byte pattern.
        var destination = Path.Combine(Path.GetTempPath(), $"mcpiler-archive-{Guid.NewGuid():N}");

        try
        {
            using var source = File.OpenRead(TestRepository.Fixture("manifests", "archive", ArchiveName));
            Assert.True(ManifestArchive.Unpack(source, destination).Succeeded);

            var read = ManifestReader.Read(
                new DirectoryManifestSource(destination),
                ManifestLoadOptions.Default with { RequireSealed = true });

            Assert.True(read.Succeeded, string.Join(" | ", read.Diagnostics.Select(d => d.ToString())));
            Assert.NotNull(read.Manifest);
            Assert.Equal("Sealed Example", read.Manifest!.Server.Name);
        }
        finally
        {
            Delete(destination);
        }
    }

    [Fact]
    public void The_golden_archive_holds_only_what_the_index_declares()
    {
        var destination = Path.Combine(Path.GetTempPath(), $"mcpiler-archive-{Guid.NewGuid():N}");

        try
        {
            using var source = File.OpenRead(TestRepository.Fixture("manifests", "archive", ArchiveName));
            var result = ManifestArchive.Unpack(source, destination);

            Assert.Equal(
                ["manifest.json", "sections/", "sections/agentSurface.json", "sections/credentials.json",
                 "sections/operations.json", "sections/policy.json", "sections/server.json"],
                result.Entries);
        }
        finally
        {
            Delete(destination);
        }
    }

    private static Dictionary<string, byte[]> Inventory(string directory)
    {
        var root = Path.GetFullPath(directory);

        return Directory
            .EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .ToDictionary(
                path => Path.GetRelativePath(root, path).Replace('\\', '/'),
                File.ReadAllBytes,
                StringComparer.Ordinal);
    }

    private static void Delete(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch (IOException)
        {
            // Best effort: a leftover temp directory is not a test failure.
        }
    }

    private static string Describe(ManifestArchiveResult result)
        => string.Join(" | ", result.Diagnostics.Select(diagnostic => diagnostic.ToString()));
}
