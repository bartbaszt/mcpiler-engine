using System.Globalization;
using System.Text.Json.Nodes;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Loading;

/// <summary>
/// Resolves manifest-local schema references: fragment-only, inside one section document,
/// bounded, and lazy.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why references exist at all.</b> The Platform schema mapper resolves every reference by
/// value into every use site, which is why a measured intermediate document is 1.4 to 4.0
/// times its source and a large API reaches tens of megabytes. Full inlining is a compiler
/// artifact, not an execution requirement. Permitting a local reference collapses the size
/// and simultaneously makes the section hand-authorable.
/// </para>
/// <para>
/// <b>Why it is bounded.</b> A reference is an amplification primitive: a small document can
/// describe an enormous expansion, and a cycle can describe an infinite one. In a
/// future-public runtime that is a denial-of-service vector rather than a curiosity, so
/// depth, node count and per-level property count are all capped and exceeding a cap is a
/// refusal.
/// </para>
/// <para>
/// <b>Why it is lazy.</b> Resolution never eagerly inlines. Request serialization walks a
/// schema only as far as the actual argument value goes, so a legitimately recursive schema
/// is terminated by the data rather than by a bound. Validation therefore visits each
/// referenced component once instead of re-descending into it, which is what lets a
/// self-referential type such as a tree node validate without tripping the depth cap.
/// </para>
/// <para>
/// There is no base URI, no document graph, no file access and no network access anywhere in
/// this type. A non-local reference has nothing to resolve against and is refused rather
/// than fetched.
/// </para>
/// </remarks>
public sealed class SchemaReferenceResolver
{
    private static readonly string[] SingleSchemaKeywords =
        ["items", "contains", "not", "additionalProperties", "contentSchema", "propertyNames"];

    private static readonly string[] SchemaListKeywords =
        ["allOf", "anyOf", "oneOf", "prefixItems"];

    private static readonly string[] SchemaMapKeywords =
        ["properties", "patternProperties", "$defs", "definitions"];

    private readonly JsonNode _document;

    /// <summary>Creates a resolver over one section document.</summary>
    /// <param name="sectionDocument">
    /// The section document references resolve inside. References never cross a section
    /// boundary.
    /// </param>
    /// <param name="bounds">The anti-amplification bounds from the policy section.</param>
    public SchemaReferenceResolver(JsonNode sectionDocument, SchemaBounds bounds)
    {
        ArgumentNullException.ThrowIfNull(sectionDocument);
        ArgumentNullException.ThrowIfNull(bounds);

        _document = sectionDocument;
        Bounds = bounds;
    }

    /// <summary>The bounds this resolver enforces.</summary>
    public SchemaBounds Bounds { get; }

    /// <summary>
    /// Follows a reference chain to the first non-reference schema.
    /// </summary>
    /// <param name="schema">The schema to resolve. A non-reference resolves to itself.</param>
    /// <param name="resolved">The resolved schema, when resolution succeeds.</param>
    /// <param name="failure">The refusal, when resolution fails.</param>
    /// <returns><see langword="true"/> when <paramref name="schema"/> resolves.</returns>
    public bool TryResolve(
        ManifestSchema schema,
        out ManifestSchema resolved,
        out ManifestDiagnostic? failure)
        => TryResolve(schema, section: null, pointer: string.Empty, out resolved, out failure);

    /// <summary>
    /// Follows a reference chain to the first non-reference schema, locating any refusal.
    /// </summary>
    /// <param name="schema">The schema to resolve. A non-reference resolves to itself.</param>
    /// <param name="section">The section a refusal is reported against.</param>
    /// <param name="pointer">The JSON Pointer a refusal is reported at.</param>
    /// <param name="resolved">The resolved schema, when resolution succeeds.</param>
    /// <param name="failure">The refusal, when resolution fails.</param>
    public bool TryResolve(
        ManifestSchema schema,
        string? section,
        string pointer,
        out ManifestSchema resolved,
        out ManifestDiagnostic? failure)
    {
        ArgumentNullException.ThrowIfNull(schema);

        resolved = schema;
        failure = null;

        var visited = new HashSet<string>(StringComparer.Ordinal);

        while (resolved.RefPointer is { } reference)
        {
            if (!JsonPointer.IsLocalFragment(reference))
            {
                failure = ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.RefNotLocal,
                    $"'{DiagnosticText.Echo(reference)}' is not a fragment-only reference into the same section. The manifest format has no base URI and never fetches a reference.",
                    section,
                    pointer);
                return false;
            }

            if (!visited.Add(reference))
            {
                failure = ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.RefUnresolvable,
                    $"'{DiagnosticText.Echo(reference)}' takes part in a reference cycle that never reaches a schema.",
                    section,
                    pointer);
                return false;
            }

            if (visited.Count > Bounds.MaxDepth)
            {
                failure = ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SchemaBoundExceeded,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The reference chain from '{DiagnosticText.Echo(reference)}' is longer than the {Bounds.MaxDepth} hop limit."),
                    section,
                    pointer);
                return false;
            }

            if (!JsonPointer.TryResolve(_document, reference, out var target) || target is null)
            {
                failure = ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.RefUnresolvable,
                    $"'{DiagnosticText.Echo(reference)}' does not resolve inside this section.",
                    section,
                    pointer);
                return false;
            }

            resolved = ManifestSchema.From(target);
        }

        return true;
    }

    /// <summary>
    /// Walks a schema eagerly, reporting every reference and bound problem it can reach.
    /// </summary>
    /// <remarks>
    /// This is the authoring check, not the execution path. Execution resolves lazily; this
    /// method exists so <c>validate</c> can tell an author about a broken reference before a
    /// caller discovers it at invocation time. Each referenced target is visited once, so a
    /// legitimately recursive schema is reported as valid rather than as a bound violation.
    /// </remarks>
    /// <param name="schema">The schema to walk.</param>
    /// <param name="section">The section findings are reported against.</param>
    /// <param name="pointer">The JSON Pointer the schema sits at.</param>
    public IReadOnlyList<ManifestDiagnostic> Validate(ManifestSchema schema, string? section, string pointer)
    {
        ArgumentNullException.ThrowIfNull(schema);

        var diagnostics = new List<ManifestDiagnostic>();
        var visitedReferences = new HashSet<string>(StringComparer.Ordinal);
        var budget = new NodeBudget(Bounds.MaxNodes);

        Walk(schema, section, pointer, depth: 0, visitedReferences, budget, diagnostics);

        return diagnostics;
    }

    private void Walk(
        ManifestSchema schema,
        string? section,
        string pointer,
        int depth,
        HashSet<string> visitedReferences,
        NodeBudget budget,
        List<ManifestDiagnostic> diagnostics)
    {
        if (budget.Exhausted)
        {
            return;
        }

        if (depth > Bounds.MaxDepth)
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SchemaBoundExceeded,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The schema nests deeper than the {Bounds.MaxDepth} level limit."),
                section,
                pointer));
            return;
        }

        if (!budget.TryConsume())
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.SchemaBoundExceeded,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The schema reaches more than the {Bounds.MaxNodes} node limit."),
                section,
                pointer));
            return;
        }

        if (schema.RefPointer is { } reference)
        {
            if (!TryResolve(schema, section, pointer, out var resolved, out var failure))
            {
                diagnostics.Add(failure!);
                return;
            }

            // A component already walked is not walked again. Re-descending would turn a
            // legitimate recursive type into a spurious depth violation and would let one
            // shared component be charged against the node budget once per use site.
            if (!visitedReferences.Add(reference))
            {
                return;
            }

            Walk(resolved, section, pointer, depth, visitedReferences, budget, diagnostics);
            return;
        }

        if (schema.Object is not { } document)
        {
            // A boolean schema is a leaf. Anything else at a schema position is not a schema.
            if (!schema.IsBoolean)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SchemaInvalid,
                    "A schema must be an object or a boolean.",
                    section,
                    pointer));
            }

            return;
        }

        foreach (var keyword in SingleSchemaKeywords)
        {
            if (Subschema(document, keyword) is { } child)
            {
                Walk(
                    child,
                    section,
                    SectionReadContext.Child(pointer, keyword),
                    depth + 1,
                    visitedReferences,
                    budget,
                    diagnostics);
            }
        }

        foreach (var keyword in SchemaListKeywords)
        {
            if (document[keyword] is not JsonArray list)
            {
                continue;
            }

            var listPointer = SectionReadContext.Child(pointer, keyword);

            for (var index = 0; index < list.Count; index++)
            {
                if (list[index] is not { } element)
                {
                    continue;
                }

                Walk(
                    ManifestSchema.From(element),
                    section,
                    listPointer + "/" + index.ToString(CultureInfo.InvariantCulture),
                    depth + 1,
                    visitedReferences,
                    budget,
                    diagnostics);
            }
        }

        foreach (var keyword in SchemaMapKeywords)
        {
            if (document[keyword] is not JsonObject map)
            {
                continue;
            }

            var mapPointer = SectionReadContext.Child(pointer, keyword);

            if (map.Count > Bounds.MaxPropertiesPerLevel)
            {
                diagnostics.Add(ManifestDiagnostic.Error(
                    ManifestDiagnosticCodes.SchemaBoundExceeded,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"'{keyword}' declares {map.Count} members, which exceeds the {Bounds.MaxPropertiesPerLevel} per-level limit."),
                    section,
                    mapPointer));
                continue;
            }

            foreach (var (name, value) in map)
            {
                if (value is null)
                {
                    continue;
                }

                Walk(
                    ManifestSchema.From(value),
                    section,
                    SectionReadContext.Child(mapPointer, name),
                    depth + 1,
                    visitedReferences,
                    budget,
                    diagnostics);
            }
        }
    }

    private static ManifestSchema? Subschema(JsonObject document, string keyword)
    {
        var value = document[keyword];

        // 'additionalProperties: false' is a boolean schema and a legitimate leaf; the other
        // single-schema keywords accept a boolean too.
        return value is null ? null : ManifestSchema.From(value);
    }

    private sealed class NodeBudget(int maximum)
    {
        private int _remaining = maximum;

        internal bool Exhausted { get; private set; }

        internal bool TryConsume()
        {
            if (_remaining > 0)
            {
                _remaining--;
                return true;
            }

            Exhausted = true;
            return false;
        }
    }
}
