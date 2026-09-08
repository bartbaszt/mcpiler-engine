using System.Formats.Tar;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Sealing;

/// <summary>Bounds applied while packing or unpacking an archive.</summary>
/// <param name="MaxEntries">Refuse an archive with more entries than this.</param>
/// <param name="MaxTotalBytes">Refuse an archive whose entries total more than this.</param>
/// <remarks>
/// An archive is an untrusted container: a small file can declare an enormous payload, so the
/// reader bounds what it will materialize rather than trusting the header.
/// </remarks>
public sealed record ManifestArchiveOptions(int MaxEntries = 64, long MaxTotalBytes = 512L * 1024 * 1024)
{
    /// <summary>The defaults.</summary>
    public static ManifestArchiveOptions Default { get; } = new();
}

/// <summary>The outcome of a pack or unpack.</summary>
/// <param name="Entries">The entry names written or extracted, in archive order.</param>
/// <param name="Diagnostics">Everything the operation found.</param>
public sealed record ManifestArchiveResult(
    IReadOnlyList<string> Entries,
    IReadOnlyList<ManifestDiagnostic> Diagnostics)
{
    /// <summary>True when the operation completed without a refusal.</summary>
    public bool Succeeded => !Diagnostics.Any(diagnostic => diagnostic.IsError);

    /// <summary>The refusals.</summary>
    public IReadOnlyList<ManifestDiagnostic> Errors
        => [.. Diagnostics.Where(diagnostic => diagnostic.IsError)];
}

/// <summary>
/// The deterministic transport wrapper around a manifest bundle directory.
/// </summary>
/// <remarks>
/// <para>
/// The directory is the canonical physical form; this type only moves one around. Every
/// header field that would otherwise record when and where the archive was built is fixed:
/// entry order, modification time, owner ids and names, and permissions. Two bundles with
/// identical content therefore produce identical archive bytes on any machine, which is what
/// lets an archive digest mean something.
/// </para>
/// <para>
/// Only the root document and the section payloads the index actually declares are packed.
/// Sweeping in every file found in the directory would let an unrelated editor backup or a
/// stray note change the archive digest, and would ship content nothing references.
/// </para>
/// <para>
/// Content is copied verbatim in both directions. Packing does not canonicalize and unpacking
/// does not rewrite, so a bundle loaded from a directory and the same bundle loaded after a
/// pack/unpack round trip are byte-identical to the loader.
/// </para>
/// </remarks>
public static class ManifestArchive
{
    /// <summary>The conventional archive file extension.</summary>
    public const string FileExtension = ".mcpiler-manifest";

    /// <summary>
    /// The longest entry name the archive format stores portably in a single header field.
    /// </summary>
    /// <remarks>
    /// Longer names are refused rather than encoded through a format extension, because every
    /// extension mechanism reintroduces a header whose contents differ between writers and
    /// therefore breaks byte reproducibility.
    /// </remarks>
    public const int MaxEntryNameLength = 100;

    private const UnixFileMode FileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    private const UnixFileMode DirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
        | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    private const string SectionsMember = "sections";
    private const string PathMember = "path";

    /// <summary>Packs a bundle directory into <paramref name="destination"/>.</summary>
    public static ManifestArchiveResult Pack(
        string bundleDirectory,
        Stream destination,
        string rootFileName = DirectoryManifestSource.RootFileName,
        ManifestArchiveOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentException.ThrowIfNullOrWhiteSpace(rootFileName);

        var effective = options ?? ManifestArchiveOptions.Default;
        var diagnostics = new List<ManifestDiagnostic>();
        var source = new DirectoryManifestSource(bundleDirectory, rootFileName);

        if (!TryReadRoot(source, diagnostics, out var rootBytes, out var root))
        {
            return new ManifestArchiveResult([], diagnostics);
        }

        // The root name goes through the same path rule as every section, so "what may appear
        // in a bundle" is one rule rather than one rule for sections and an assumption for the
        // root.
        var rootVerdict = ManifestPathPolicy.Resolve(rootFileName, bundleDirectory, out _);

        if (rootVerdict != ManifestPathVerdict.Accepted)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.ArchiveEntryPathUnsafe,
                $"The root document name '{DiagnosticText.Echo(rootFileName)}' was refused: {ManifestPathPolicy.Explain(rootVerdict)}."));
            return new ManifestArchiveResult([], diagnostics);
        }

        var payloads = new List<(string Name, ReadOnlyMemory<byte> Bytes)>
        {
            (rootFileName, rootBytes),
        };

        foreach (var declaredPath in DeclaredSectionPaths(root))
        {
            if (!source.TryReadSection(declaredPath, out var payload, out var failure))
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SectionFileMissing,
                    $"'{DiagnosticText.Echo(declaredPath)}' could not be packed: {failure.Reason}.",
                    pointer: "/" + SectionsMember));
                continue;
            }

            payloads.Add((declaredPath, payload));
        }

        if (diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return new ManifestArchiveResult([], diagnostics);
        }

        if (!WithinBounds(payloads.Count, payloads.Sum(entry => (long)entry.Bytes.Length), effective, diagnostics))
        {
            return new ManifestArchiveResult([], diagnostics);
        }

        var written = new List<string>();
        var directories = new HashSet<string>(StringComparer.Ordinal);

        using var writer = new TarWriter(destination, TarEntryFormat.Ustar, leaveOpen: true);

        foreach (var (name, bytes) in payloads)
        {
            if (!IsNameWritable(name, diagnostics))
            {
                return new ManifestArchiveResult([], diagnostics);
            }

            foreach (var ancestor in Ancestors(name))
            {
                if (!directories.Add(ancestor))
                {
                    continue;
                }

                if (!IsNameWritable(ancestor, diagnostics))
                {
                    return new ManifestArchiveResult([], diagnostics);
                }

                writer.WriteEntry(Fixed(new UstarTarEntry(TarEntryType.Directory, ancestor), DirectoryMode));
                written.Add(ancestor);
            }

            var entry = Fixed(new UstarTarEntry(TarEntryType.RegularFile, name), FileMode);
            entry.DataStream = new MemoryStream(bytes.ToArray(), writable: false);
            writer.WriteEntry(entry);
            written.Add(name);
        }

        return new ManifestArchiveResult(written, diagnostics);
    }

    /// <summary>Unpacks an archive into <paramref name="destinationDirectory"/>.</summary>
    /// <remarks>
    /// The destination must not already hold content. Extraction that may overwrite is how a
    /// hostile archive turns into a modified deployment, and refusing is both safer and easier
    /// for an operator to reason about than a merge.
    /// </remarks>
    public static ManifestArchiveResult Unpack(
        Stream source,
        string destinationDirectory,
        ManifestArchiveOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationDirectory);

        var effective = options ?? ManifestArchiveOptions.Default;
        var diagnostics = new List<ManifestDiagnostic>();
        var destination = Path.GetFullPath(destinationDirectory);

        if (Directory.Exists(destination) && Directory.EnumerateFileSystemEntries(destination).Any())
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.ArchiveDestinationNotEmpty,
                "The unpack destination already holds content; unpack into an empty or new directory."));
            return new ManifestArchiveResult([], diagnostics);
        }

        Directory.CreateDirectory(destination);

        var extracted = new List<string>();
        var totalBytes = 0L;

        try
        {
            using var reader = new TarReader(source, leaveOpen: true);

            while (reader.GetNextEntry(copyData: false) is { } entry)
            {
                if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile
                    or TarEntryType.Directory))
                {
                    // A symlink, hard link, or device entry is not content: it is an
                    // instruction to the extractor about something outside the archive.
                    diagnostics.Add(ManifestDiagnostic.Error(
                        ManifestDiagnosticCodes.ArchiveEntryTypeUnsupported,
                        $"Entry '{DiagnosticText.Echo(entry.Name)}' is a {entry.EntryType}; only regular files and directories are permitted."));
                    return new ManifestArchiveResult(extracted, diagnostics);
                }

                // The entry name is checked exactly as it was written. A backslash is a legal
                // filename character on POSIX, so translating it here would turn an entry the
                // path rule refuses into one it accepts.
                var verdict = ManifestPathPolicy.Resolve(entry.Name, destination, out var target);

                if (verdict != ManifestPathVerdict.Accepted || target is null)
                {
                    diagnostics.Add(ManifestDiagnostic.Error(
                        ManifestDiagnosticCodes.ArchiveEntryPathUnsafe,
                        $"Entry '{DiagnosticText.Echo(entry.Name)}' was refused: {ManifestPathPolicy.Explain(verdict)}."));
                    return new ManifestArchiveResult(extracted, diagnostics);
                }

                totalBytes += Math.Max(entry.Length, 0);

                if (!WithinBounds(extracted.Count + 1, totalBytes, effective, diagnostics))
                {
                    return new ManifestArchiveResult(extracted, diagnostics);
                }

                if (entry.EntryType == TarEntryType.Directory)
                {
                    Directory.CreateDirectory(target);
                    extracted.Add(entry.Name);
                    continue;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(target)!);

                using (var file = File.Create(target))
                {
                    entry.DataStream?.CopyTo(file);
                }

                extracted.Add(entry.Name);
            }
        }
        catch (InvalidDataException exception)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.ArchiveUnreadable,
                $"The archive could not be read: {exception.Message}"));
        }
        catch (EndOfStreamException exception)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.ArchiveUnreadable,
                $"The archive ended unexpectedly: {exception.Message}"));
        }

        return new ManifestArchiveResult(extracted, diagnostics);
    }

    private static bool TryReadRoot(
        DirectoryManifestSource source,
        List<ManifestDiagnostic> diagnostics,
        out ReadOnlyMemory<byte> rootBytes,
        out JsonObject root)
    {
        rootBytes = default;
        root = [];

        try
        {
            rootBytes = source.ReadRoot();
        }
        catch (IOException exception)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionFileMissing,
                $"The manifest root could not be read: {exception.Message}"));
            return false;
        }

        try
        {
            if (CanonicalJson.Parse(rootBytes.Span) is not JsonObject parsed)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.RootNotAnObject,
                    "The manifest root must be a JSON object."));
                return false;
            }

            root = parsed;
            return true;
        }
        catch (JsonException exception)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.RootNotAnObject,
                $"The manifest root is not valid JSON: {exception.Message}"));
            return false;
        }
    }

    // Ordinal ordering, taken from the index rather than from a directory listing, is what
    // makes the entry sequence a property of the manifest instead of a property of the
    // filesystem that happens to be underneath it.
    private static IEnumerable<string> DeclaredSectionPaths(JsonObject root)
    {
        if (root[SectionsMember] is not JsonObject sections)
        {
            return [];
        }

        return sections
            .Select(member => (member.Value as JsonObject)?[PathMember])
            .OfType<JsonValue>()
            .Select(value => value.TryGetValue<string>(out var path) ? path : null)
            .OfType<string>()
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);
    }

    private static UstarTarEntry Fixed(UstarTarEntry entry, UnixFileMode mode)
    {
        entry.Mode = mode;
        entry.ModificationTime = DateTimeOffset.UnixEpoch;
        entry.Uid = 0;
        entry.Gid = 0;
        entry.UserName = string.Empty;
        entry.GroupName = string.Empty;
        return entry;
    }

    private static IEnumerable<string> Ancestors(string name)
    {
        var segments = name.Split(ManifestPathPolicy.Separator);

        for (var index = 1; index < segments.Length; index++)
        {
            yield return string.Join(ManifestPathPolicy.Separator, segments[..index])
                + ManifestPathPolicy.Separator;
        }
    }

    private static bool IsNameWritable(string name, List<ManifestDiagnostic> diagnostics)
    {
        if (name.Length <= MaxEntryNameLength)
        {
            return true;
        }

        diagnostics.Add(ManifestDiagnostic.Error(
            ManifestDiagnosticCodes.ArchiveEntryNameTooLong,
            string.Create(
                CultureInfo.InvariantCulture,
                $"Entry name '{DiagnosticText.Echo(name)}' is {name.Length} characters, which exceeds the {MaxEntryNameLength} character archive limit.")));

        return false;
    }

    private static bool WithinBounds(
        int entries,
        long totalBytes,
        ManifestArchiveOptions options,
        List<ManifestDiagnostic> diagnostics)
    {
        if (entries > options.MaxEntries)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.ArchiveLimitExceeded,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The archive holds more than the permitted {options.MaxEntries} entries.")));
            return false;
        }

        if (totalBytes > options.MaxTotalBytes)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.ArchiveLimitExceeded,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The archive totals more than the permitted {options.MaxTotalBytes} bytes.")));
            return false;
        }

        return true;
    }
}
