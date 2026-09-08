using System.Globalization;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Reads the two optional, derivable sections: <c>tools</c> and <c>search</c>.
/// </summary>
/// <remarks>
/// Both sections exist so a Studio export can pin exactly what it compiled. Neither is
/// required: when a section is absent Engine derives it. Reading an explicit section is
/// therefore only half the contract; proving that the explicit and derived forms agree is a
/// separate obligation.
/// </remarks>
internal static class DerivedSectionReader
{
    private static readonly string[] ToolsSectionMembers = ["formatVersion", "surfaces"];

    private static readonly string[] SurfaceToolSetMembers = ["tools"];

    private static readonly string[] ToolMembers =
    [
        "name",
        "description",
        "inputSchema",
        "outputSchema",
        "operation",
        "operationKey",
        "annotations",
        "sizeBytes",
        "sizeTokens",
    ];

    private static readonly string[] AnnotationMembers =
        ["readOnly", "destructive", "idempotent", "openWorld"];

    private static readonly string[] SearchSectionMembers =
        ["formatVersion", "builderVersion", "indexedFields", "scoring", "operations"];

    private static readonly string[] ScoringMembers =
        ["quantizationStep", "metaMultiplier", "vectorScale", "fieldWeights"];

    private static readonly string[] SearchDocumentMembers = ["operation", "summary", "risk", "terms"];

    internal static ToolsSection? ReadTools(JsonNode? document, SectionReadContext context)
    {
        if (!context.TryReadSectionRoot(document, out var root))
        {
            return null;
        }

        context.RejectUnknownMembers(root, ToolsSectionMembers, string.Empty);
        context.VerifySectionFormatVersion(root, ToolsSection.FormatVersion);

        var surfaces = context.Object(root, "surfaces", string.Empty);
        var parsed = new Dictionary<string, SurfaceToolSet>(StringComparer.Ordinal);

        if (surfaces is null)
        {
            return new ToolsSection(parsed);
        }

        foreach (var (slug, value) in surfaces)
        {
            var pointer = "/surfaces/" + JsonPointer.Escape(slug);

            if (value is not JsonObject surface)
            {
                context.Error(
                    ManifestDiagnosticCodes.MemberTypeInvalid,
                    $"Tool set for surface '{DiagnosticText.Echo(slug)}' must be an object.",
                    pointer);
                continue;
            }

            context.RejectUnknownMembers(surface, SurfaceToolSetMembers, pointer);

            parsed[slug] = new SurfaceToolSet(ReadTools(surface, pointer, context));
        }

        return new ToolsSection(parsed);
    }

    private static IReadOnlyList<ManifestTool> ReadTools(
        JsonObject surface,
        string pointer,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(surface, "tools", pointer);
        var tools = new List<ManifestTool>(elements.Count);
        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (element, elementPointer) in elements)
        {
            context.RejectUnknownMembers(element, ToolMembers, elementPointer);

            var name = context.RequiredText(element, "name", elementPointer);
            var description = context.RequiredText(element, "description", elementPointer);

            if (name is null || description is null)
            {
                continue;
            }

            // The name is what a caller writes to invoke the tool. A name the protocol
            // cannot carry produces an entry that is advertised and unusable, so it is
            // refused here rather than truncated into something the author never wrote.
            if (!ToolName.IsWellFormed(name))
            {
                context.Error(
                    ManifestDiagnosticCodes.ToolNameInvalid,
                    $"Tool name '{DiagnosticText.Echo(name)}' is not a valid advertised name. A name must be "
                    + $"1 to {ManifestTool.MaxNameLength} characters from [A-Za-z0-9_.-].",
                    SectionReadContext.Child(elementPointer, "name"));
                continue;
            }

            if (!names.Add(name))
            {
                context.Error(
                    ManifestDiagnosticCodes.DuplicateToolName,
                    $"Tool name '{DiagnosticText.Echo(name)}' is advertised more than once on this surface.",
                    SectionReadContext.Child(elementPointer, "name"));
                continue;
            }

            var operation = context.Text(element, "operation", elementPointer);

            // A tool with no backing operation can only be a Navigator tool, and that is
            // recognized by name. Without the rule an arbitrary unbacked tool could be
            // advertised and would resolve to nothing at invocation time.
            if (operation is null && !name.StartsWith(ManifestTool.NavigatorPrefix, StringComparison.Ordinal))
            {
                context.Error(
                    ManifestDiagnosticCodes.NavigatorNameRequired,
                    $"Tool '{DiagnosticText.Echo(name)}' declares no backing operation, so its name must start with '{ManifestTool.NavigatorPrefix}'.",
                    SectionReadContext.Child(elementPointer, "name"));
                continue;
            }

            tools.Add(new ManifestTool(
                name,
                description,
                ManifestSchema.FromOrNull(element["inputSchema"]),
                ManifestSchema.FromOrNull(element["outputSchema"]),
                operation,
                context.Text(element, "operationKey", elementPointer),
                ReadAnnotations(element, elementPointer, context),
                context.Integer(element, "sizeBytes", elementPointer),
                context.Integer(element, "sizeTokens", elementPointer)));
        }

        return tools;
    }

    private static ToolAnnotations? ReadAnnotations(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        var annotations = context.Object(element, "annotations", pointer);

        if (annotations is null)
        {
            return null;
        }

        var annotationsPointer = SectionReadContext.Child(pointer, "annotations");

        context.RejectUnknownMembers(annotations, AnnotationMembers, annotationsPointer);

        return new ToolAnnotations(
            context.Flag(annotations, "readOnly", annotationsPointer),
            context.Flag(annotations, "destructive", annotationsPointer),
            context.Flag(annotations, "idempotent", annotationsPointer),
            context.Flag(annotations, "openWorld", annotationsPointer));
    }

    internal static SearchSection? ReadSearch(JsonNode? document, SectionReadContext context)
    {
        if (!context.TryReadSectionRoot(document, out var root))
        {
            return null;
        }

        context.RejectUnknownMembers(root, SearchSectionMembers, string.Empty);
        context.VerifySectionFormatVersion(root, SearchSection.FormatVersion);

        var builderVersion = context.Integer(root, "builderVersion", string.Empty)
            ?? SearchScoring.BuilderVersion;

        if (builderVersion != SearchScoring.BuilderVersion)
        {
            // A differently built index would rank differently, which is a silent relevance
            // change rather than a visible failure. Engine rebuilds instead.
            context.Warning(
                ManifestDiagnosticCodes.SearchDerivationMismatch,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The search index was built by builder version {builderVersion}, but this Engine implements version {SearchScoring.BuilderVersion}. The index is ignored and rebuilt."),
                "/builderVersion");

            return null;
        }

        return new SearchSection(
            ReadSearchDocuments(root, context),
            context.TextArray(root, "indexedFields", string.Empty),
            ReadScoring(root, context),
            builderVersion);
    }

    private static SearchScoring? ReadScoring(JsonObject root, SectionReadContext context)
    {
        var scoring = context.Object(root, "scoring", string.Empty);

        if (scoring is null)
        {
            return null;
        }

        const string pointer = "/scoring";
        var defaults = SearchScoring.Default;

        context.RejectUnknownMembers(scoring, ScoringMembers, pointer);

        var weights = context.Object(scoring, "fieldWeights", pointer);
        var parsedWeights = new Dictionary<string, int>(StringComparer.Ordinal);

        if (weights is not null)
        {
            var weightsPointer = SectionReadContext.Child(pointer, "fieldWeights");

            foreach (var (field, _) in weights)
            {
                if (context.Integer(weights, field, weightsPointer) is { } weight)
                {
                    parsedWeights[field] = weight;
                }
            }
        }

        return new SearchScoring(
            context.Integer(scoring, "quantizationStep", pointer) ?? defaults.QuantizationStep,
            context.Integer(scoring, "metaMultiplier", pointer) ?? defaults.MetaMultiplier,
            context.Integer(scoring, "vectorScale", pointer) ?? defaults.VectorScale,
            parsedWeights);
    }

    private static IReadOnlyList<SearchDocumentEntry> ReadSearchDocuments(
        JsonObject root,
        SectionReadContext context)
    {
        var elements = context.ObjectArray(root, "operations", string.Empty);
        var documents = new List<SearchDocumentEntry>(elements.Count);

        foreach (var (element, pointer) in elements)
        {
            context.RejectUnknownMembers(element, SearchDocumentMembers, pointer);

            var slug = context.RequiredText(element, "operation", pointer);

            if (slug is null)
            {
                continue;
            }

            documents.Add(new SearchDocumentEntry(
                slug,
                context.Text(element, "summary", pointer) ?? string.Empty,
                context.Text(element, "risk", pointer) ?? AgentOperationEntry.NoRisk,
                ReadTerms(element, pointer, context)));
        }

        return documents;
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> ReadTerms(
        JsonObject element,
        string pointer,
        SectionReadContext context)
    {
        var terms = context.Object(element, "terms", pointer);
        var parsed = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);

        if (terms is null)
        {
            return parsed;
        }

        var termsPointer = SectionReadContext.Child(pointer, "terms");

        foreach (var (field, _) in terms)
        {
            parsed[field] = context.TextArray(terms, field, termsPointer);
        }

        return parsed;
    }
}
