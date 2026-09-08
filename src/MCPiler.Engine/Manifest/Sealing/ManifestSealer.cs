using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Sealing;

/// <summary>The outcome of a seal attempt.</summary>
/// <param name="Root">
/// The sealed root document bytes, or <c>null</c> when sealing was refused.
/// </param>
/// <param name="Diagnostics">Everything the sealer found.</param>
/// <param name="Changed">
/// True when the sealed bytes differ from the input bytes. A manifest that is already sealed
/// and already canonical seals to itself.
/// </param>
/// <param name="Completeness">The computed completeness value, when one was produced.</param>
public sealed record ManifestSealResult(
    byte[]? Root,
    IReadOnlyList<ManifestDiagnostic> Diagnostics,
    bool Changed,
    string? Completeness)
{
    /// <summary>True when a sealed document was produced.</summary>
    public bool Succeeded => Root is not null;

    /// <summary>The refusals.</summary>
    public IReadOnlyList<ManifestDiagnostic> Errors
        => [.. Diagnostics.Where(diagnostic => diagnostic.IsError)];
}

/// <summary>
/// Recomputes a manifest's section digests and completeness seal.
/// </summary>
/// <remarks>
/// <para>
/// The sealer is a document rewriter, not a loader. It deliberately does not validate the
/// manifest: the whole point of sealing is to run it after editing a section, when the
/// declared digests are stale by construction, and an author must be able to seal a
/// work-in-progress bundle. <b>Sealing is not approval.</b> Only
/// <see cref="ManifestReader"/> decides whether a manifest is servable.
/// </para>
/// <para>
/// Section payload bytes are never rewritten. The digest describes the bytes as the author
/// wrote them; canonicalizing a payload during sealing would change content under the
/// author's feet and make the digest describe something they never saved.
/// </para>
/// <para>
/// The root document, by contrast, is written canonically, because a sealed root is a
/// distribution artifact. The seal <i>value</i> is independent of that formatting: the loader
/// canonicalizes the section index before hashing it, so an operator may reformat or reorder a
/// sealed root without breaking the seal. Only the index content is covered.
/// </para>
/// </remarks>
public static class ManifestSealer
{
    private const string SectionsMember = "sections";
    private const string CompletenessMember = "completeness";
    private const string InlineMember = "inline";
    private const string PathMember = "path";
    private const string Sha256Member = "sha256";
    private const string BytesMember = "bytes";

    /// <summary>Seals the manifest held by <paramref name="source"/>.</summary>
    public static ManifestSealResult Seal(IManifestSource source)
    {
        ArgumentNullException.ThrowIfNull(source);

        var diagnostics = new List<ManifestDiagnostic>();

        ReadOnlyMemory<byte> original;

        try
        {
            original = source.ReadRoot();
        }
        catch (IOException exception)
        {
            return Refused(diagnostics, ManifestDiagnosticCodes.SectionFileMissing, exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return Refused(diagnostics, ManifestDiagnosticCodes.SectionFileMissing, exception.Message);
        }

        JsonNode? parsed;

        try
        {
            parsed = CanonicalJson.Parse(original.Span);
        }
        catch (JsonException exception)
        {
            return Refused(
                diagnostics,
                ManifestDiagnosticCodes.RootNotAnObject,
                $"The manifest root is not valid JSON: {exception.Message}");
        }

        if (parsed is not JsonObject root)
        {
            return Refused(
                diagnostics,
                ManifestDiagnosticCodes.RootNotAnObject,
                "The manifest root must be a JSON object.");
        }

        if (root[SectionsMember] is not JsonObject sections)
        {
            return Refused(
                diagnostics,
                ManifestDiagnosticCodes.MemberRequired,
                $"'{SectionsMember}' must be present and an object before a manifest can be sealed.",
                "/" + SectionsMember);
        }

        foreach (var member in sections.ToList())
        {
            SealEntry(source, member.Key, member.Value, diagnostics);
        }

        if (diagnostics.Any(diagnostic => diagnostic.IsError))
        {
            return new ManifestSealResult(Root: null, diagnostics, Changed: false, Completeness: null);
        }

        var completeness = CanonicalJson.Hash(sections);

        root[CompletenessMember] = new JsonObject
        {
            ["algorithm"] = ManifestCompleteness.Sha256,
            ["value"] = completeness,
        };

        var document = CanonicalJson.Serialize(root);

        return new ManifestSealResult(
            document,
            diagnostics,
            Changed: !original.Span.SequenceEqual(document),
            completeness);
    }

    /// <summary>
    /// Seals a bundle directory and writes the sealed root back over the root document.
    /// </summary>
    /// <remarks>
    /// The root file is only written when sealing succeeded, so a refused seal leaves the
    /// bundle exactly as it was rather than half-updated.
    /// </remarks>
    public static ManifestSealResult SealDirectory(
        string bundleDirectory,
        string rootFileName = DirectoryManifestSource.RootFileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(rootFileName);

        var source = new DirectoryManifestSource(bundleDirectory, rootFileName);
        var result = Seal(source);

        if (result.Root is { } bytes && result.Changed)
        {
            File.WriteAllBytes(Path.Combine(Path.GetFullPath(bundleDirectory), rootFileName), bytes);
        }

        return result;
    }

    private static void SealEntry(
        IManifestSource source,
        string name,
        JsonNode? node,
        List<ManifestDiagnostic> diagnostics)
    {
        var pointer = "/" + SectionsMember + "/" + JsonPointer.Escape(name);

        if (node is not JsonObject entry)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.MemberTypeInvalid,
                $"Section entry '{name}' must be an object.",
                section: name,
                pointer: pointer));
            return;
        }

        var hasInline = entry[InlineMember] is not null;
        var hasPath = entry[PathMember] is not null;

        if (hasInline && hasPath)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionBothInlineAndPath,
                $"Section '{name}' declares both an inline payload and a path.",
                section: name,
                pointer: pointer));
            return;
        }

        if (!hasInline && !hasPath)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionNeitherInlineNorPath,
                $"Section '{name}' declares neither an inline payload nor a path.",
                section: name,
                pointer: pointer));
            return;
        }

        if (hasInline)
        {
            // An inline payload is already inside the document the seal covers. A digest on it
            // would be a second authority over the same bytes with no independent writer, so
            // the sealer refuses rather than quietly deleting members the author wrote.
            foreach (var member in new[] { Sha256Member, BytesMember })
            {
                if (entry[member] is not null)
                {
                    diagnostics.Add(ManifestDiagnostic.Error(
                        ManifestDiagnosticCodes.UnknownMember,
                        $"Section '{name}' is inline, so '{member}' is not permitted: the completeness seal already covers an inline payload.",
                        section: name,
                        pointer: pointer + "/" + member));
                }
            }

            return;
        }

        if (entry[PathMember] is not JsonValue value
            || !value.TryGetValue<string>(out var declaredPath))
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.MemberTypeInvalid,
                $"Section '{name}' must declare '{PathMember}' as a string.",
                section: name,
                pointer: pointer + "/" + PathMember));
            return;
        }

        if (!source.TryReadSection(declaredPath, out var payload, out var failure))
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                failure.IsPathViolation
                    ? ManifestDiagnosticCodes.SectionPathEscapesBundle
                    : ManifestDiagnosticCodes.SectionFileMissing,
                $"Section '{name}' could not be read from '{DiagnosticText.Echo(declaredPath)}': {failure.Reason}.",
                section: name,
                pointer: pointer + "/" + PathMember));
            return;
        }

        entry[Sha256Member] = CanonicalJson.ComputeHash(payload.Span);
        entry[BytesMember] = payload.Length;
    }

    private static ManifestSealResult Refused(
        List<ManifestDiagnostic> diagnostics,
        string code,
        string message,
        string pointer = "")
    {
        diagnostics.Add(ManifestDiagnostic.Error(code, message, pointer: pointer));
        return new ManifestSealResult(Root: null, diagnostics, Changed: false, Completeness: null);
    }
}
