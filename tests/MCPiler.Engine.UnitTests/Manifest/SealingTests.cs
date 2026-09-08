using System.Formats.Tar;
using System.Text;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Sealing;
using MCPiler.Engine.Manifest.Validation;

using Xunit;

namespace MCPiler.Engine.UnitTests.Manifest;

/// <summary>
/// Sealing and archiving behaviour.
/// </summary>
/// <remarks>
/// Two properties carry most of the weight here. Sealing must be reproducible, or the seal
/// value says more about the machine that produced it than about the manifest. Unpacking must
/// be hostile-safe, because an archive is the one manifest artifact that arrives as a single
/// opaque file from somewhere else.
/// </remarks>
public sealed class SealingTests
{
    private const string SealedBundle = "sealed-bundle";

    [Fact]
    public void SealingAnAlreadySealedCanonicalManifestChangesNothing()
    {
        using var bundle = TempBundle.From(SealedBundle);

        var first = ManifestSealer.SealDirectory(bundle.Path);

        Assert.True(first.Succeeded);

        var second = ManifestSealer.SealDirectory(bundle.Path);

        Assert.True(second.Succeeded);
        Assert.False(second.Changed);
        Assert.Equal(first.Root, second.Root);
        Assert.Equal(first.Completeness, second.Completeness);
    }

    [Fact]
    public void SealingIsByteStableAcrossIndependentBundles()
    {
        using var one = TempBundle.From(SealedBundle);
        using var two = TempBundle.From(SealedBundle);

        // Written at different moments into different directories: nothing about when or
        // where a bundle was sealed may reach the sealed bytes.
        var first = ManifestSealer.SealDirectory(one.Path);
        var second = ManifestSealer.SealDirectory(two.Path);

        Assert.Equal(first.Root, second.Root);
    }

    [Fact]
    public void SealingRepairsAStaleSectionDigest()
    {
        using var bundle = TempBundle.From(SealedBundle);

        var section = Path.Combine(bundle.Path, "sections", "server.json");
        var original = File.ReadAllText(section);
        var edited = original.Replace("Sealed Example", "Sealed Example v2", StringComparison.Ordinal);

        Assert.NotEqual(original, edited);
        File.WriteAllText(section, edited);

        Assert.False(
            ManifestReader.Read(new DirectoryManifestSource(bundle.Path)).Succeeded,
            "the edited bundle must fail before sealing, or this test proves nothing");

        var result = ManifestSealer.SealDirectory(bundle.Path);

        Assert.True(result.Succeeded);
        Assert.True(result.Changed);
        Assert.True(ManifestReader.Read(
            new DirectoryManifestSource(bundle.Path),
            ManifestLoadOptions.Default with { RequireSealed = true }).Succeeded);
    }

    [Fact]
    public void SealingAddsDigestsThatWereNeverDeclared()
    {
        using var bundle = TempBundle.From(SealedBundle);

        var root = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(bundle.Path, "manifest.json")))!;
        var sections = (JsonObject)root["sections"]!;

        foreach (var member in sections)
        {
            var entry = (JsonObject)member.Value!;
            entry.Remove("sha256");
            entry.Remove("bytes");
        }

        root.Remove("completeness");
        File.WriteAllText(Path.Combine(bundle.Path, "manifest.json"), root.ToJsonString());

        var result = ManifestSealer.SealDirectory(bundle.Path);

        Assert.True(result.Succeeded);

        var resealed = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(bundle.Path, "manifest.json")))!;

        Assert.All(
            (JsonObject)resealed["sections"]!,
            member =>
            {
                var entry = (JsonObject)member.Value!;
                Assert.NotNull(entry["sha256"]);
                Assert.NotNull(entry["bytes"]);
            });

        Assert.Equal(result.Completeness, (string?)resealed["completeness"]!["value"]);
    }

    [Fact]
    public void TheSealSurvivesReformattingOfTheRootDocument()
    {
        using var bundle = TempBundle.From(SealedBundle);

        ManifestSealer.SealDirectory(bundle.Path);

        var rootPath = Path.Combine(bundle.Path, "manifest.json");
        var root = JsonNode.Parse(File.ReadAllText(rootPath))!;

        // Indentation and member order are formatting, and the loader canonicalizes the index
        // before hashing it, so neither may invalidate a seal.
        File.WriteAllText(
            rootPath,
            root.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));

        var result = ManifestReader.Read(
            new DirectoryManifestSource(bundle.Path),
            ManifestLoadOptions.Default with { RequireSealed = true });

        Assert.True(result.Succeeded);
        Assert.DoesNotContain(
            result.Diagnostics,
            diagnostic => diagnostic.Code == ManifestDiagnosticCodes.CompletenessMismatch);
    }

    [Fact]
    public void SealingRefusesADigestOnAnInlinePayload()
    {
        var document = """
        {
          "manifestFormatVersion": "0.1",
          "sections": {
            "server": { "inline": { "name": "Example" }, "sha256": "00" }
          }
        }
        """;

        var result = ManifestSealer.Seal(InMemoryManifestSource.FromText(document));

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, error => error.Code == ManifestDiagnosticCodes.UnknownMember);
    }

    [Fact]
    public void ARefusedSealLeavesTheBundleUntouched()
    {
        using var bundle = TempBundle.From(SealedBundle);

        var rootPath = Path.Combine(bundle.Path, "manifest.json");
        var before = File.ReadAllBytes(rootPath);

        File.Delete(Path.Combine(bundle.Path, "sections", "policy.json"));

        var result = ManifestSealer.SealDirectory(bundle.Path);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, error => error.Code == ManifestDiagnosticCodes.SectionFileMissing);

        // A half-sealed index would claim digests for the sections that happened to be read
        // before the failure, which is worse than the stale index it replaced.
        Assert.Equal(before, File.ReadAllBytes(rootPath));
    }

    [Fact]
    public void SealingAnAllInlineManifestProducesAVerifiableSeal()
    {
        var document = File.ReadAllText(TestRepository.Fixture("manifests", "minimal", "manifest.json"));

        var result = ManifestSealer.Seal(InMemoryManifestSource.FromText(document));

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Completeness);

        var reread = ManifestReader.Read(
            InMemoryManifestSource.FromText(Encoding.UTF8.GetString(result.Root!)),
            ManifestLoadOptions.Default with { RequireSealed = true });

        Assert.True(reread.Succeeded);
    }

    [Fact]
    public void PackingIsByteReproducible()
    {
        using var bundle = TempBundle.From(SealedBundle);

        Assert.Equal(Pack(bundle.Path), Pack(bundle.Path));
    }

    [Fact]
    public void PackingIgnoresFileTimestamps()
    {
        using var one = TempBundle.From(SealedBundle);
        using var two = TempBundle.From(SealedBundle);

        foreach (var file in Directory.EnumerateFiles(two.Path, "*", SearchOption.AllDirectories))
        {
            File.SetLastWriteTimeUtc(file, new DateTime(1999, 12, 31, 23, 59, 59, DateTimeKind.Utc));
        }

        Assert.Equal(Pack(one.Path), Pack(two.Path));
    }

    [Fact]
    public void PackingCarriesTheRootFirstAndThenSectionsInOrdinalOrder()
    {
        using var bundle = TempBundle.From(SealedBundle);
        using var stream = new MemoryStream();

        var result = ManifestArchive.Pack(bundle.Path, stream);

        Assert.True(result.Succeeded);

        var files = result.Entries.Where(name => !name.EndsWith('/')).ToList();

        Assert.Equal("manifest.json", files[0]);
        Assert.Equal(files.Skip(1).Order(StringComparer.Ordinal), files.Skip(1));
    }

    [Fact]
    public void PackingCarriesOnlyDeclaredSections()
    {
        using var bundle = TempBundle.From(SealedBundle);

        File.WriteAllText(Path.Combine(bundle.Path, "editor-backup.json"), "{}");
        File.WriteAllText(Path.Combine(bundle.Path, "sections", "notes.txt"), "scratch");

        using var stream = new MemoryStream();
        var result = ManifestArchive.Pack(bundle.Path, stream);

        Assert.True(result.Succeeded);
        Assert.DoesNotContain("editor-backup.json", result.Entries);
        Assert.DoesNotContain("sections/notes.txt", result.Entries);
    }

    [Fact]
    public void PackingFixesEveryHeaderFieldThatWouldOtherwiseRecordTheBuildEnvironment()
    {
        using var bundle = TempBundle.From(SealedBundle);
        using var stream = new MemoryStream(Pack(bundle.Path));
        using var reader = new TarReader(stream);

        var inspected = 0;

        while (reader.GetNextEntry(copyData: false) is { } entry)
        {
            inspected++;

            Assert.Equal(TarEntryFormat.Ustar, entry.Format);
            Assert.Equal(DateTimeOffset.UnixEpoch, entry.ModificationTime);
            Assert.Equal(0, entry.Uid);
            Assert.Equal(0, entry.Gid);

            Assert.Equal(
                entry.EntryType == TarEntryType.Directory
                    ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                      | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                      | UnixFileMode.OtherRead | UnixFileMode.OtherExecute
                    : UnixFileMode.UserRead | UnixFileMode.UserWrite
                      | UnixFileMode.GroupRead | UnixFileMode.OtherRead,
                entry.Mode);
        }

        Assert.True(inspected > 1);
    }

    [Fact]
    public void PackingRefusesABundleWhoseSectionFileIsMissing()
    {
        using var bundle = TempBundle.From(SealedBundle);

        File.Delete(Path.Combine(bundle.Path, "sections", "operations.json"));

        using var stream = new MemoryStream();
        var result = ManifestArchive.Pack(bundle.Path, stream);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, error => error.Code == ManifestDiagnosticCodes.SectionFileMissing);
        Assert.Equal(0, stream.Length);
    }

    [Fact]
    public void APackUnpackRoundTripPreservesEveryPayloadByte()
    {
        using var bundle = TempBundle.From(SealedBundle);
        using var destination = TempBundle.Empty();
        using var stream = new MemoryStream(Pack(bundle.Path));

        var unpacked = ManifestArchive.Unpack(stream, destination.Path);

        Assert.True(unpacked.Succeeded);

        var original = Digests(bundle.Path);
        var restored = Digests(destination.Path);

        Assert.Equal(original, restored);

        var result = ManifestReader.Read(
            new DirectoryManifestSource(destination.Path),
            ManifestLoadOptions.Default with { RequireSealed = true });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void UnpackingRefusesADestinationThatAlreadyHoldsContent()
    {
        using var bundle = TempBundle.From(SealedBundle);
        using var destination = TempBundle.Empty();
        using var stream = new MemoryStream(Pack(bundle.Path));

        File.WriteAllText(Path.Combine(destination.Path, "existing.txt"), "in the way");

        var result = ManifestArchive.Unpack(stream, destination.Path);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            error => error.Code == ManifestDiagnosticCodes.ArchiveDestinationNotEmpty);
    }

    [Theory]
    [InlineData("../escape.json")]
    [InlineData("sections/../../escape.json")]
    [InlineData("/etc/manifest.json")]
    [InlineData("sections\\windows.json")]
    public void UnpackingRefusesAnEntryThatDoesNotResolveInsideTheDestination(string name)
    {
        using var destination = TempBundle.Empty();
        using var stream = new MemoryStream(Hostile(TarEntryType.RegularFile, name));

        var result = ManifestArchive.Unpack(stream, destination.Path);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, error => error.Code == ManifestDiagnosticCodes.ArchiveEntryPathUnsafe);
        Assert.Empty(Directory.EnumerateFileSystemEntries(destination.Path));
    }

    [Fact]
    public void UnpackingRefusesAnEntryThatIsNotContent()
    {
        using var destination = TempBundle.Empty();
        using var stream = new MemoryStream(Hostile(TarEntryType.SymbolicLink, "manifest.json", "/etc/passwd"));

        var result = ManifestArchive.Unpack(stream, destination.Path);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            error => error.Code == ManifestDiagnosticCodes.ArchiveEntryTypeUnsupported);
    }

    [Fact]
    public void UnpackingRefusesAnArchiveWithTooManyEntries()
    {
        using var destination = TempBundle.Empty();
        using var archive = new MemoryStream();

        using (var writer = new TarWriter(archive, TarEntryFormat.Ustar, leaveOpen: true))
        {
            for (var index = 0; index < 8; index++)
            {
                var entry = new UstarTarEntry(TarEntryType.RegularFile, $"file-{index}.json")
                {
                    DataStream = new MemoryStream("{}"u8.ToArray(), writable: false),
                };

                writer.WriteEntry(entry);
            }
        }

        archive.Position = 0;

        var result = ManifestArchive.Unpack(
            archive,
            destination.Path,
            new ManifestArchiveOptions(MaxEntries: 4, MaxTotalBytes: 1024));

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, error => error.Code == ManifestDiagnosticCodes.ArchiveLimitExceeded);
    }

    [Fact]
    public void UnpackingRefusesAnArchiveThatExceedsTheTotalSizeBound()
    {
        using var destination = TempBundle.Empty();
        using var archive = new MemoryStream();

        using (var writer = new TarWriter(archive, TarEntryFormat.Ustar, leaveOpen: true))
        {
            var entry = new UstarTarEntry(TarEntryType.RegularFile, "big.json")
            {
                DataStream = new MemoryStream(new byte[4096], writable: false),
            };

            writer.WriteEntry(entry);
        }

        archive.Position = 0;

        var result = ManifestArchive.Unpack(
            archive,
            destination.Path,
            new ManifestArchiveOptions(MaxEntries: 64, MaxTotalBytes: 1024));

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, error => error.Code == ManifestDiagnosticCodes.ArchiveLimitExceeded);
    }

    [Fact]
    public void UnpackingReportsACorruptArchiveRatherThanThrowing()
    {
        using var destination = TempBundle.Empty();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 2048)));

        var result = ManifestArchive.Unpack(stream, destination.Path);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, error => error.Code == ManifestDiagnosticCodes.ArchiveUnreadable);
    }

    [Fact]
    public void EveryArchiveCodeIsInTheCatalogue()
    {
        foreach (var code in new[]
                 {
                     ManifestDiagnosticCodes.ArchiveUnreadable,
                     ManifestDiagnosticCodes.ArchiveEntryTypeUnsupported,
                     ManifestDiagnosticCodes.ArchiveEntryPathUnsafe,
                     ManifestDiagnosticCodes.ArchiveEntryNameTooLong,
                     ManifestDiagnosticCodes.ArchiveLimitExceeded,
                     ManifestDiagnosticCodes.ArchiveDestinationNotEmpty,
                 })
        {
            Assert.Contains(code, ManifestDiagnosticCodes.All);
            Assert.Contains(code.Split('/')[0], ManifestDiagnosticCodes.Groups);
            Assert.DoesNotContain(code, ManifestDiagnosticCodes.AlwaysWarning);
        }
    }

    private static byte[] Pack(string bundleDirectory)
    {
        using var stream = new MemoryStream();

        var result = ManifestArchive.Pack(bundleDirectory, stream);

        Assert.True(result.Succeeded, string.Join("; ", result.Errors.Select(error => error.ToString())));

        return stream.ToArray();
    }

    private static byte[] Hostile(TarEntryType type, string name, string? linkName = null)
    {
        using var archive = new MemoryStream();

        using (var writer = new TarWriter(archive, TarEntryFormat.Ustar, leaveOpen: true))
        {
            var entry = new UstarTarEntry(type, name);

            if (linkName is not null)
            {
                entry.LinkName = linkName;
            }
            else
            {
                entry.DataStream = new MemoryStream("{}"u8.ToArray(), writable: false);
            }

            writer.WriteEntry(entry);
        }

        return archive.ToArray();
    }

    private static SortedDictionary<string, string> Digests(string directory)
    {
        var digests = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var root = Path.GetFullPath(directory);

        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            digests[relative] = CanonicalJson.ComputeHash(File.ReadAllBytes(file));
        }

        return digests;
    }

    private sealed class TempBundle : IDisposable
    {
        private TempBundle(string path) => Path = path;

        public string Path { get; }

        public static TempBundle Empty()
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "mcpiler-manifest-" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(path);
            return new TempBundle(path);
        }

        public static TempBundle From(string fixtureName)
        {
            var bundle = Empty();
            var origin = System.IO.Path.GetFullPath(TestRepository.Fixture("manifests", fixtureName));

            foreach (var file in Directory.EnumerateFiles(origin, "*", SearchOption.AllDirectories))
            {
                var relative = System.IO.Path.GetRelativePath(origin, file);
                var target = System.IO.Path.Combine(bundle.Path, relative);

                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(target)!);
                File.Copy(file, target);
            }

            return bundle;
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
                // A leftover temp directory is noise, not a test failure.
            }
        }
    }
}
