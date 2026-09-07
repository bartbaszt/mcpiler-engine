using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// A manifest bundle held in memory.
/// </summary>
/// <remarks>
/// This exists so hostile-bundle behavior can be exercised without writing anything to disk.
/// It enforces the same path policy as the directory source, using a virtual bundle root, so
/// a test cannot accidentally prove a containment rule that the real source does not apply.
/// </remarks>
public sealed class InMemoryManifestSource : IManifestSource
{
    private const string VirtualRoot = "/mcpiler-manifest-bundle";

    private readonly ReadOnlyMemory<byte> _root;
    private readonly Dictionary<string, ReadOnlyMemory<byte>> _sections;
    private readonly long _maxSectionBytes;

    /// <summary>Creates an in-memory bundle.</summary>
    /// <param name="root">The root document bytes.</param>
    /// <param name="sections">Section payloads keyed by their bundle-relative path.</param>
    /// <param name="maxSectionBytes">Refuse a section payload larger than this.</param>
    public InMemoryManifestSource(
        ReadOnlyMemory<byte> root,
        IReadOnlyDictionary<string, ReadOnlyMemory<byte>>? sections = null,
        long maxSectionBytes = ManifestLoadOptions.DefaultMaxSectionBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxSectionBytes);

        _root = root;
        _maxSectionBytes = maxSectionBytes;
        _sections = sections is null
            ? new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal)
            : new Dictionary<string, ReadOnlyMemory<byte>>(sections, StringComparer.Ordinal);
    }

    /// <summary>Creates an in-memory bundle from UTF-8 text.</summary>
    public static InMemoryManifestSource FromText(
        string root,
        IReadOnlyDictionary<string, string>? sections = null)
    {
        ArgumentNullException.ThrowIfNull(root);

        var payloads = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal);

        if (sections is not null)
        {
            foreach (var (path, text) in sections)
            {
                payloads[path] = Encoding.UTF8.GetBytes(text);
            }
        }

        return new InMemoryManifestSource(Encoding.UTF8.GetBytes(root), payloads);
    }

    /// <inheritdoc />
    public string Description => "(in memory)";

    /// <inheritdoc />
    public ReadOnlyMemory<byte> ReadRoot() => _root;

    /// <inheritdoc />
    public bool TryReadSection(
        string declaredPath,
        out ReadOnlyMemory<byte> payload,
        [NotNullWhen(false)] out ManifestSourceFailure? failure)
    {
        payload = default;

        var verdict = ManifestPathPolicy.Resolve(declaredPath, VirtualRoot, out _);

        if (verdict != ManifestPathVerdict.Accepted)
        {
            failure = new ManifestSourceFailure(verdict, ManifestPathPolicy.Explain(verdict));
            return false;
        }

        if (!_sections.TryGetValue(declaredPath, out var found))
        {
            failure = new ManifestSourceFailure(
                ManifestPathVerdict.Accepted,
                "the referenced section file does not exist in the bundle");
            return false;
        }

        if (found.Length > _maxSectionBytes)
        {
            failure = new ManifestSourceFailure(
                ManifestPathVerdict.Accepted,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"the section payload is {found.Length} bytes, which exceeds the {_maxSectionBytes} byte load limit"));
            return false;
        }

        payload = found;
        failure = null;
        return true;
    }
}
