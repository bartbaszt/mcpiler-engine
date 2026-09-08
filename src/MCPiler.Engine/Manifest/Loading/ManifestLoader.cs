using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Reads a manifest root document and resolves its section index into verified payloads.
/// </summary>
/// <remarks>
/// <para>
/// The loader answers exactly one question: which bytes belong to which section, and can they
/// be trusted as far as the manifest claims. It does not interpret a section's contents;
/// typed section reading and cross-section validation are separate steps, so a packaging
/// failure can never be misreported as a semantic one.
/// </para>
/// <para>
/// Every member is checked and every unknown member is refused. Lenient tolerance was
/// considered and rejected: a misspelled <c>policy</c> member would silently leave the
/// deployed perimeter at a default the author did not intend, which is a security failure
/// dressed as convenience.
/// </para>
/// </remarks>
public static class ManifestLoader
{
    private const string FormatVersionMember = "manifestFormatVersion";
    private const string GeneratorMember = "generator";
    private const string SectionsMember = "sections";
    private const string CompletenessMember = "completeness";
    private const string ProvenanceMember = "provenance";

    private const string InlineMember = "inline";
    private const string PathMember = "path";
    private const string Sha256Member = "sha256";
    private const string BytesMember = "bytes";
    private const string ModelMember = "model";
    private const string DimensionMember = "dimension";

    internal static readonly string[] RootMembers =
    [
        FormatVersionMember,
        GeneratorMember,
        SectionsMember,
        CompletenessMember,
        ProvenanceMember,
    ];

    internal static readonly string[] GeneratorMembers = ["name", "version", "producedAtUtc"];

    internal static readonly string[] CompletenessMembers = ["algorithm", "value"];

    internal static readonly string[] SectionEntryMembers =
        [InlineMember, PathMember, Sha256Member, BytesMember];

    /// <summary>
    /// The vector section carries the two facts a ranker needs to decide whether a query
    /// embedding is comparable, so its entry accepts two members no other section may declare.
    /// </summary>
    internal static readonly string[] VectorSectionEntryMembers =
        [InlineMember, PathMember, Sha256Member, BytesMember, ModelMember, DimensionMember];

    /// <summary>Loads a manifest from <paramref name="source"/>.</summary>
    /// <param name="source">Where the manifest bytes come from.</param>
    /// <param name="options">Loading behavior, or <c>null</c> for the defaults.</param>
    public static ManifestLoadResult Load(IManifestSource source, ManifestLoadOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(source);

        var effective = options ?? ManifestLoadOptions.Default;
        var diagnostics = new List<ManifestDiagnostic>();

        ReadOnlyMemory<byte> rootBytes;

        try
        {
            rootBytes = source.ReadRoot();
        }
        catch (IOException exception)
        {
            return ManifestLoadResult.Failed(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionFileMissing,
                $"The manifest root document could not be read: {exception.Message}"));
        }
        catch (UnauthorizedAccessException exception)
        {
            return ManifestLoadResult.Failed(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionFileMissing,
                $"The manifest root document could not be read: {exception.Message}"));
        }

        if (rootBytes.Length > effective.MaxRootBytes)
        {
            return ManifestLoadResult.Failed(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionSizeMismatch,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The manifest root document is {rootBytes.Length} bytes, which exceeds the {effective.MaxRootBytes} byte load limit.")));
        }

        JsonNode? parsed;

        try
        {
            parsed = CanonicalJson.Parse(rootBytes.Span);
        }
        catch (JsonException exception)
        {
            return ManifestLoadResult.Failed(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionUnparseable,
                $"The manifest root document is not valid JSON: {exception.Message}"));
        }

        if (parsed is not JsonObject root)
        {
            return ManifestLoadResult.Failed(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.RootNotAnObject,
                "The manifest root document must be a JSON object."));
        }

        RejectUnknownMembers(root, RootMembers, section: null, pointer: string.Empty, diagnostics);

        var evaluation = ManifestFormatSupport.Evaluate(ReadDeclaredFormatVersion(root));

        if (!evaluation.IsSupported)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                evaluation.Compatibility switch
                {
                    ManifestFormatCompatibility.Missing => ManifestDiagnosticCodes.FormatVersionMissing,
                    ManifestFormatCompatibility.Malformed => ManifestDiagnosticCodes.FormatVersionMalformed,
                    _ => ManifestDiagnosticCodes.FormatVersionUnsupported,
                },
                evaluation.Message,
                pointer: "/" + FormatVersionMember));

            // Without an agreed format version every later member check would be guesswork
            // about a grammar Engine does not know.
            return new ManifestLoadResult(
                Root: null,
                Sections: new Dictionary<string, ResolvedSection>(StringComparer.Ordinal),
                Diagnostics: diagnostics);
        }

        var generator = ReadGenerator(root, diagnostics);
        var completeness = ReadCompleteness(root, diagnostics);
        var provenance = ReadProvenance(root, diagnostics);
        var entries = ReadSectionIndex(root, diagnostics);

        VerifyCompleteness(root, completeness, effective, diagnostics);

        var sections = ResolveSections(source, entries, effective, diagnostics);

        var model = new ManifestRoot(
            evaluation.Version!.Value,
            entries,
            generator,
            completeness,
            provenance);

        return new ManifestLoadResult(model, sections, diagnostics);
    }

    private static ManifestGenerator? ReadGenerator(JsonObject root, List<ManifestDiagnostic> diagnostics)
    {
        if (root[GeneratorMember] is null)
        {
            return null;
        }

        if (root[GeneratorMember] is not JsonObject generator)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.UnknownMember,
                $"'{GeneratorMember}' must be an object.",
                pointer: "/" + GeneratorMember));
            return null;
        }

        RejectUnknownMembers(generator, GeneratorMembers, section: null, "/" + GeneratorMember, diagnostics);

        DateTime? producedAt = null;

        if (ReadString(generator, "producedAtUtc") is { } text)
        {
            if (DateTime.TryParse(
                    text,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
                    out var instant))
            {
                producedAt = instant;
            }
            else
            {
                // Generator data is diagnostic only, so a bad timestamp must not fail a
                // manifest that is otherwise executable.
                diagnostics.Add(ManifestDiagnostic.Warning(
                    ManifestDiagnosticCodes.UnknownMember,
                    $"'producedAtUtc' is not a valid UTC timestamp: '{DiagnosticText.Echo(text)}'. It is ignored.",
                    pointer: "/" + GeneratorMember + "/producedAtUtc"));
            }
        }

        return new ManifestGenerator(
            ReadString(generator, "name"),
            ReadString(generator, "version"),
            producedAt);
    }

    private static ManifestCompleteness? ReadCompleteness(JsonObject root, List<ManifestDiagnostic> diagnostics)
    {
        if (root[CompletenessMember] is null)
        {
            return null;
        }

        if (root[CompletenessMember] is not JsonObject completeness)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.UnknownMember,
                $"'{CompletenessMember}' must be an object.",
                pointer: "/" + CompletenessMember));
            return null;
        }

        RejectUnknownMembers(completeness, CompletenessMembers, section: null, "/" + CompletenessMember, diagnostics);

        var algorithm = ReadString(completeness, "algorithm");
        var value = ReadString(completeness, "value");

        if (!string.Equals(algorithm, ManifestCompleteness.Sha256, StringComparison.Ordinal))
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.CompletenessAlgorithmUnknown,
                $"The completeness algorithm must be '{ManifestCompleteness.Sha256}', but '{DiagnosticText.Echo(algorithm)}' was declared.",
                pointer: "/" + CompletenessMember + "/algorithm"));
            return null;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.CompletenessMismatch,
                "The completeness seal declares no value.",
                pointer: "/" + CompletenessMember + "/value"));
            return null;
        }

        return new ManifestCompleteness(ManifestCompleteness.Sha256, value);
    }

    private static JsonObject? ReadProvenance(JsonObject root, List<ManifestDiagnostic> diagnostics)
    {
        if (root[ProvenanceMember] is null)
        {
            return null;
        }

        if (root[ProvenanceMember] is JsonObject provenance)
        {
            // Deliberately not inspected. Provenance is where Studio-only identity lands, and
            // reading it here would let authoring state creep into runtime behavior.
            return (JsonObject)provenance.DeepClone();
        }

        diagnostics.Add(ManifestDiagnostic.Error(
            ManifestDiagnosticCodes.UnknownMember,
            $"'{ProvenanceMember}' must be an object.",
            pointer: "/" + ProvenanceMember));

        return null;
    }

    private static Dictionary<string, ManifestSectionEntry> ReadSectionIndex(
        JsonObject root,
        List<ManifestDiagnostic> diagnostics)
    {
        var entries = new Dictionary<string, ManifestSectionEntry>(StringComparer.Ordinal);

        if (root[SectionsMember] is null)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionMissing,
                $"The manifest declares no '{SectionsMember}' index.",
                pointer: "/" + SectionsMember));
            return entries;
        }

        if (root[SectionsMember] is not JsonObject sections)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.UnknownMember,
                $"'{SectionsMember}' must be an object.",
                pointer: "/" + SectionsMember));
            return entries;
        }

        foreach (var (name, value) in sections)
        {
            var pointer = "/" + SectionsMember + "/" + JsonPointer.Escape(name);

            if (!ManifestSectionName.IsKnown(name))
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SectionUnknown,
                    $"'{DiagnosticText.Echo(name)}' is not a manifest section. Expected one of: {DiagnosticText.List(ManifestSectionName.All)}.",
                    pointer: pointer));
                continue;
            }

            if (value is not JsonObject entry)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SectionNeitherInlineNorPath,
                    $"Section '{name}' must be an object declaring either '{InlineMember}' or '{PathMember}'.",
                    section: name,
                    pointer: pointer));
                continue;
            }

            if (ReadSectionEntry(name, entry, pointer, diagnostics) is { } parsed)
            {
                entries[name] = parsed;
            }
        }

        return entries;
    }

    private static ManifestSectionEntry? ReadSectionEntry(
        string name,
        JsonObject entry,
        string pointer,
        List<ManifestDiagnostic> diagnostics)
    {
        var isVectorSection = string.Equals(name, ManifestSectionName.Vectors, StringComparison.Ordinal);

        var allowed = isVectorSection ? VectorSectionEntryMembers : SectionEntryMembers;

        RejectUnknownMembers(entry, allowed, name, pointer, diagnostics);

        var hasInline = entry[InlineMember] is not null;
        var declaredPath = ReadString(entry, PathMember);
        var hasPath = declaredPath is not null;

        if (hasInline && hasPath)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionBothInlineAndPath,
                $"Section '{name}' declares both '{InlineMember}' and '{PathMember}'. Exactly one is permitted.",
                section: name,
                pointer: pointer));
            return null;
        }

        if (!hasInline && !hasPath)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SectionNeitherInlineNorPath,
                $"Section '{name}' declares neither '{InlineMember}' nor '{PathMember}'. Exactly one is required.",
                section: name,
                pointer: pointer));
            return null;
        }

        if (hasInline)
        {
            if (ManifestSectionName.ExternalOnly.Contains(name))
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SectionMustBeExternal,
                    $"Section '{name}' carries a binary payload and must be declared with '{PathMember}', never inline.",
                    section: name,
                    pointer: pointer));
                return null;
            }

            // An integrity declaration on an inline payload is meaningless: the payload is
            // already inside the document the completeness seal covers, so a digest here
            // would be a second authority over the same bytes.
            foreach (var member in new[] { Sha256Member, BytesMember })
            {
                if (entry[member] is not null)
                {
                    diagnostics.Add(ManifestDiagnostic.Error(
                        ManifestDiagnosticCodes.UnknownMember,
                        $"Section '{name}' declares '{member}' on an inline payload, where it has no meaning. Use '{PathMember}' or remove it.",
                        section: name,
                        pointer: pointer + "/" + member));
                    return null;
                }
            }

            return ManifestSectionEntry.FromInline(entry[InlineMember]!.DeepClone());
        }

        long? declaredBytes = null;

        if (entry[BytesMember] is { } bytesNode)
        {
            if (bytesNode is JsonValue bytesValue && bytesValue.TryGetValue<long>(out var byteCount) && byteCount >= 0)
            {
                declaredBytes = byteCount;
            }
            else
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SectionSizeMismatch,
                    $"Section '{name}' declares a '{BytesMember}' value that is not a non-negative integer.",
                    section: name,
                    pointer: pointer + "/" + BytesMember));
                return null;
            }
        }

        VectorSectionMetadata? vectors = null;

        if (isVectorSection)
        {
            int? dimension = null;

            if (entry[DimensionMember] is { } dimensionNode)
            {
                if (dimensionNode is JsonValue dimensionValue
                    && dimensionValue.TryGetValue<int>(out var parsedDimension)
                    && parsedDimension > 0)
                {
                    dimension = parsedDimension;
                }
                else
                {
                    // The vector section degrades rather than fails, so a malformed dimension
                    // is a warning and ranking simply loses its vector term.
                    diagnostics.Add(ManifestDiagnostic.Warning(
                        ManifestDiagnosticCodes.VectorsDimensionMismatch,
                        $"Section '{name}' declares a '{DimensionMember}' value that is not a positive integer. Vector ranking is disabled.",
                        section: name,
                        pointer: pointer + "/" + DimensionMember));
                }
            }

            vectors = new VectorSectionMetadata(ReadString(entry, ModelMember), dimension);
        }

        return ManifestSectionEntry.FromPath(
            declaredPath!,
            ReadString(entry, Sha256Member),
            declaredBytes,
            vectors);
    }

    private static void VerifyCompleteness(
        JsonObject root,
        ManifestCompleteness? completeness,
        ManifestLoadOptions options,
        List<ManifestDiagnostic> diagnostics)
    {
        if (completeness is null)
        {
            if (options.RequireSealed)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SealRequired,
                    "This Engine is configured to require a sealed manifest, but the manifest carries no completeness seal."));
            }
            else
            {
                diagnostics.Add(ManifestDiagnostic.Warning(
                    ManifestDiagnosticCodes.Unsealed,
                    "The manifest carries no completeness seal, so a removed or truncated section cannot be detected."));
            }

            return;
        }

        if (root[SectionsMember] is not JsonObject sections)
        {
            return;
        }

        // Hashing the index, not the concatenation of the payloads, is what makes a *removed*
        // section detectable instead of inferred from the parts that survived.
        var actual = CanonicalJson.Hash(sections);

        if (!string.Equals(actual, completeness.Value, StringComparison.OrdinalIgnoreCase))
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.CompletenessMismatch,
                $"The completeness seal does not match the section index. Declared '{DiagnosticText.Echo(completeness.Value)}', computed '{actual}'.",
                pointer: "/" + CompletenessMember + "/value"));
        }
    }

    private static Dictionary<string, ResolvedSection> ResolveSections(
        IManifestSource source,
        IReadOnlyDictionary<string, ManifestSectionEntry> entries,
        ManifestLoadOptions options,
        List<ManifestDiagnostic> diagnostics)
    {
        var resolved = new Dictionary<string, ResolvedSection>(StringComparer.Ordinal);

        foreach (var name in ManifestSectionName.All)
        {
            if (!entries.TryGetValue(name, out var entry))
            {
                continue;
            }

            var pointer = "/" + SectionsMember + "/" + JsonPointer.Escape(name);

            if (entry.IsInline)
            {
                resolved[name] = new ResolvedSection(
                    name,
                    CanonicalJson.Serialize(entry.Inline),
                    entry.Inline,
                    WasInline: true);
                continue;
            }

            if (!source.TryReadSection(entry.Path!, out var payload, out var failure))
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    failure.IsPathViolation
                        ? ManifestDiagnosticCodes.SectionPathEscapesBundle
                        : ManifestDiagnosticCodes.SectionFileMissing,
                    $"Section '{name}' could not be read from '{DiagnosticText.Echo(entry.Path)}': {failure.Reason}.",
                    section: name,
                    pointer: pointer + "/" + PathMember));
                continue;
            }

            if (payload.Length > options.MaxSectionBytes)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SectionSizeMismatch,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"Section '{name}' is {payload.Length} bytes, which exceeds the {options.MaxSectionBytes} byte load limit."),
                    section: name,
                    pointer: pointer));
                continue;
            }

            if (entry.Bytes is { } expectedBytes && expectedBytes != payload.Length)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SectionSizeMismatch,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"Section '{name}' declares {expectedBytes} bytes but the payload is {payload.Length} bytes."),
                    section: name,
                    pointer: pointer + "/" + BytesMember));
                continue;
            }

            var integrityVerified = false;

            if (entry.Sha256 is { } expectedHash)
            {
                var actualHash = CanonicalJson.ComputeHash(payload.Span);

                if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    diagnostics.Add(ManifestDiagnostic.Error(
                        ManifestDiagnosticCodes.SectionHashMismatch,
                        $"Section '{name}' does not match its declared digest. Declared '{DiagnosticText.Echo(expectedHash)}', computed '{actualHash}'.",
                        section: name,
                        pointer: pointer + "/" + Sha256Member));
                    continue;
                }

                integrityVerified = true;
            }

            // The vector matrix is binary and deliberately degrades: it is carried as bytes
            // and never parsed here, so an unreadable matrix cannot fail the load.
            if (string.Equals(name, ManifestSectionName.Vectors, StringComparison.Ordinal))
            {
                resolved[name] = new ResolvedSection(
                    name,
                    payload,
                    Document: null,
                    WasInline: false,
                    entry.Path,
                    integrityVerified);
                continue;
            }

            JsonNode? document;

            try
            {
                document = CanonicalJson.Parse(payload.Span);
            }
            catch (JsonException exception)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SectionUnparseable,
                    $"Section '{name}' is not valid JSON: {exception.Message}",
                    section: name,
                    pointer: pointer + "/" + PathMember));
                continue;
            }

            resolved[name] = new ResolvedSection(
                name,
                payload,
                document,
                WasInline: false,
                entry.Path,
                integrityVerified);
        }

        return resolved;
    }

    // Member checking and string reading are delegated rather than reimplemented: the section
    // readers apply the same rules, and two copies of "what counts as an unknown member" would
    // eventually disagree about the same document.
    private static void RejectUnknownMembers(
        JsonObject document,
        IReadOnlyList<string> allowed,
        string? section,
        string pointer,
        List<ManifestDiagnostic> diagnostics)
        => new SectionReadContext(section, diagnostics)
            .RejectUnknownMembers(document, allowed, pointer);

    private static string? ReadString(JsonObject document, string member)
        => SectionReadContext.TextOrNull(document, member);

    /// <summary>
    /// Renders the declared format version for evaluation.
    /// </summary>
    /// <remarks>
    /// A non-string value is rendered as JSON rather than read as absent, so
    /// <c>"manifestFormatVersion": 1</c> is reported as malformed instead of missing. Telling
    /// an author the version is missing when it is present is a diagnostic that sends them to
    /// the wrong line.
    /// </remarks>
    private static string? ReadDeclaredFormatVersion(JsonObject root)
    {
        var node = root[FormatVersionMember];

        return node switch
        {
            null => null,
            JsonValue value when value.TryGetValue<string>(out var text) => text,
            _ => node.ToJsonString(),
        };
    }
}
