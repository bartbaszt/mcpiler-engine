using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// A manifest bundle held as a directory, which is the canonical physical form.
/// </summary>
/// <remarks>
/// An archive is only a transport wrapper: it is unpacked to a directory and then loaded
/// through this source, so pack and unpack cannot change what Engine sees.
/// </remarks>
public sealed class DirectoryManifestSource : IManifestSource
{
    /// <summary>The conventional root document file name inside a bundle directory.</summary>
    public const string RootFileName = "manifest.json";

    private readonly string _bundleDirectory;
    private readonly string _rootPath;
    private readonly long _maxSectionBytes;

    /// <summary>Creates a source over a bundle directory.</summary>
    /// <param name="bundleDirectory">The directory containing the root document.</param>
    /// <param name="rootFileName">The root document file name.</param>
    /// <param name="maxSectionBytes">
    /// Refuse a section payload larger than this. See
    /// <see cref="ManifestLoadOptions.MaxSectionBytes"/> for why the loader has a size bound
    /// at all.
    /// </param>
    public DirectoryManifestSource(
        string bundleDirectory,
        string rootFileName = RootFileName,
        long maxSectionBytes = ManifestLoadOptions.DefaultMaxSectionBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(rootFileName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxSectionBytes);

        _bundleDirectory = Path.GetFullPath(bundleDirectory);
        _rootPath = Path.Combine(_bundleDirectory, rootFileName);
        _maxSectionBytes = maxSectionBytes;
    }

    /// <summary>Creates a source over the directory containing a root document file.</summary>
    public static DirectoryManifestSource ForRootFile(
        string rootFilePath,
        long maxSectionBytes = ManifestLoadOptions.DefaultMaxSectionBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootFilePath);

        var full = Path.GetFullPath(rootFilePath);
        var directory = Path.GetDirectoryName(full)
            ?? throw new ArgumentException("The root document must live inside a directory.", nameof(rootFilePath));

        return new DirectoryManifestSource(directory, Path.GetFileName(full), maxSectionBytes);
    }

    /// <inheritdoc />
    public string Description => _bundleDirectory;

    /// <inheritdoc />
    public ReadOnlyMemory<byte> ReadRoot() => File.ReadAllBytes(_rootPath);

    /// <inheritdoc />
    public bool TryReadSection(
        string declaredPath,
        out ReadOnlyMemory<byte> payload,
        [NotNullWhen(false)] out ManifestSourceFailure? failure)
    {
        payload = default;

        var verdict = ManifestPathPolicy.Resolve(declaredPath, _bundleDirectory, out var resolved);

        if (verdict != ManifestPathVerdict.Accepted || resolved is null)
        {
            failure = new ManifestSourceFailure(verdict, ManifestPathPolicy.Explain(verdict));
            return false;
        }

        var info = new FileInfo(resolved);

        if (!info.Exists)
        {
            failure = new ManifestSourceFailure(
                ManifestPathVerdict.Accepted,
                "the referenced section file does not exist in the bundle");
            return false;
        }

        if (info.Length > _maxSectionBytes)
        {
            failure = new ManifestSourceFailure(
                ManifestPathVerdict.Accepted,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"the section payload is {info.Length} bytes, which exceeds the {_maxSectionBytes} byte load limit"));
            return false;
        }

        payload = File.ReadAllBytes(resolved);
        failure = null;
        return true;
    }
}
