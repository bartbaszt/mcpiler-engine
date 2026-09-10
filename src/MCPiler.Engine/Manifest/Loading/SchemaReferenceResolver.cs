using System.Globalization;
using System.Text;
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
/// <b>Why it also contains.</b> A reference is legal inside a manifest and illegal on the
/// protocol wire: an advertised tool schema travels alone, so a pointer into a section
/// document a client never received resolves to nothing. <see cref="SelfContain"/> moves every
/// reachable target into the schema's own <c>$defs</c> and rewrites the pointers, which keeps
/// a recursive contract exact instead of truncating it. It is the one place that may do so,
/// for the same reason resolution is: both need the bounds.
/// </para>
/// <para>
/// There is no base URI, no document graph, no file access and no network access anywhere in
/// this type. A non-local reference has nothing to resolve against and is refused rather
/// than fetched.
/// </para>
/// </remarks>
public sealed class SchemaReferenceResolver
{
    /// <summary>The keyword a self-contained schema carries its own components under.</summary>
    public const string DefsKeyword = "$defs";

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

    /// <summary>
    /// Returns a schema that carries everything it references.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A reference is legal in a manifest and unusable on the wire: an advertised schema
    /// travels alone, so a pointer into a section document the reader never received resolves
    /// to nothing. Every reachable target is therefore registered under the returned schema's
    /// own <c>$defs</c> and every pointer is rewritten to name it there.
    /// </para>
    /// <para>
    /// A schema that references nothing is returned unchanged, the same instance, so the
    /// common case cannot be perturbed by this method existing.
    /// </para>
    /// <para>
    /// A root whose only member is a reference is inlined instead of rewritten, because a
    /// consumer expects a typed schema at that position and <c>{"$ref": ...}</c> declares no
    /// type. Its own references still land in <c>$defs</c>, so a self-referential root appears
    /// once inline and once as a component and the recursion stays exact. A reference that has
    /// siblings is rewritten rather than inlined: inlining would have to decide what happens
    /// to the sibling keywords, and silently dropping a declared one is worse than a root that
    /// states its type by reference.
    /// </para>
    /// <para>
    /// Nothing is truncated and nothing is expanded twice. A component is registered the first
    /// time a pointer reaches it and every later reference names that entry, so a cycle
    /// terminates on the registration rather than on a bound - which is what lets a legal
    /// recursive type be advertised at all instead of being reduced and disclosed.
    /// </para>
    /// <para>
    /// A reference that does not resolve is left exactly as it was. Loading already refuses a
    /// manifest whose references are broken, and refusing again here would report one fault
    /// twice and make this answer depend on whether validation had run.
    /// </para>
    /// </remarks>
    /// <param name="schema">The schema to make self-contained.</param>
    public ManifestSchema SelfContain(ManifestSchema schema)
    {
        ArgumentNullException.ThrowIfNull(schema);

        var root = schema;

        // Only a bare reference. With siblings the reference form is kept, because the
        // sibling keywords apply alongside the target and inlining would have to drop them.
        if (schema.RefPointer is not null && schema.Object is { Count: 1 })
        {
            if (!TryResolve(schema, out var resolvedRoot, out _))
            {
                return schema;
            }

            root = resolvedRoot;
        }

        if (root.Object is not { } document)
        {
            // A boolean schema references nothing and has nowhere to carry a component.
            return schema;
        }

        var containment = new Containment(document);
        var rewritten = (JsonObject)RewriteSchema(document, depth: 0, containment);

        if (containment.Components.Count == 0)
        {
            // Nothing was relocated. When the root was a reference the resolved node is
            // already the self-contained answer; otherwise the original instance is, and
            // returning it is what makes byte identity a property rather than a hope.
            return ReferenceEquals(root, schema) ? schema : ManifestSchema.From(rewritten);
        }

        if (rewritten[DefsKeyword] is JsonObject declared)
        {
            foreach (var (name, component) in containment.Components)
            {
                declared[name] = component;
            }
        }
        else
        {
            var defs = new JsonObject();

            foreach (var (name, component) in containment.Components)
            {
                defs[name] = component;
            }

            rewritten[DefsKeyword] = defs;
        }

        return ManifestSchema.From(rewritten);
    }

    /// <summary>
    /// Rebuilds one schema node with every manifest-local reference under it rewritten.
    /// </summary>
    /// <remarks>
    /// Members are copied in document order, so a node that needed no rewriting serializes to
    /// the bytes it arrived as. Only the three keyword groups above are descended into: a
    /// <c>$ref</c> sitting inside an <c>enum</c> value or a <c>const</c> is data, and
    /// rewriting it would change what the schema accepts.
    /// </remarks>
    private JsonNode RewriteSchema(JsonNode node, int depth, Containment containment)
    {
        if (node is not JsonObject document || depth > Bounds.MaxDepth)
        {
            // A boolean schema is a leaf. Past the depth bound the manifest is refused
            // anyway, and descending further would trade a diagnostic for a stack overflow.
            return node.DeepClone();
        }

        var reference = LocalReference(document);
        var registered = reference is null ? null : Register(reference, depth, containment);
        var copy = new JsonObject();

        foreach (var (keyword, value) in document)
        {
            if (registered is not null && string.Equals(keyword, ManifestSchema.RefKeyword, StringComparison.Ordinal))
            {
                copy[keyword] = JsonPointer.LocalFragmentPrefix + "/" + DefsKeyword + "/" + JsonPointer.Escape(registered);
                continue;
            }

            copy[keyword] = RewriteMember(keyword, value, depth, containment);
        }

        return copy;
    }

    private JsonNode? RewriteMember(string keyword, JsonNode? value, int depth, Containment containment)
    {
        if (value is null)
        {
            return null;
        }

        if (Array.IndexOf(SingleSchemaKeywords, keyword) >= 0)
        {
            return RewriteSchema(value, depth + 1, containment);
        }

        if (Array.IndexOf(SchemaListKeywords, keyword) >= 0 && value is JsonArray list)
        {
            var rewritten = new JsonArray();

            foreach (var element in list)
            {
                rewritten.Add(element is null ? null : RewriteSchema(element, depth + 1, containment));
            }

            return rewritten;
        }

        if (Array.IndexOf(SchemaMapKeywords, keyword) >= 0 && value is JsonObject map)
        {
            var rewritten = new JsonObject();

            foreach (var (name, member) in map)
            {
                rewritten[name] = member is null ? null : RewriteSchema(member, depth + 1, containment);
            }

            return rewritten;
        }

        return value.DeepClone();
    }

    /// <summary>
    /// Names the component a pointer refers to, registering it the first time it is reached.
    /// </summary>
    /// <remarks>
    /// The name is recorded before the target is walked. A reference leading back to this
    /// pointer therefore finds the name and stops, which is the whole mechanism by which a
    /// cycle produces a finite document.
    /// </remarks>
    private string? Register(string pointer, int depth, Containment containment)
    {
        if (!JsonPointer.IsLocalFragment(pointer))
        {
            // Non-local, so there is nothing in this section to carry. Loading refuses it.
            return null;
        }

        if (containment.Names.TryGetValue(pointer, out var known))
        {
            return known;
        }

        var probe = ManifestSchema.From(new JsonObject { [ManifestSchema.RefKeyword] = pointer });

        if (!TryResolve(probe, out var target, out _))
        {
            return null;
        }

        var name = containment.Allocate(pointer);

        containment.Components.Add(new KeyValuePair<string, JsonNode>(
            name,
            RewriteSchema(target.Node, depth, containment)));

        return name;
    }

    private static string? LocalReference(JsonObject document)
        => document[ManifestSchema.RefKeyword] is JsonValue value
            && value.TryGetValue<string>(out var pointer)
            ? pointer
            : null;

    /// <summary>The components collected while one schema is being made self-contained.</summary>
    private sealed class Containment
    {
        private readonly HashSet<string> _allocated = new(StringComparer.Ordinal);

        internal Containment(JsonObject root)
        {
            // Names the schema already uses for its own components are reserved before
            // anything is allocated, so a relocated target cannot overwrite one the manifest
            // wrote and mean something else under the same name.
            if (root[DefsKeyword] is JsonObject declared)
            {
                foreach (var (name, _) in declared)
                {
                    _allocated.Add(name);
                }
            }
        }

        /// <summary>Pointer to the component name it was given.</summary>
        internal Dictionary<string, string> Names { get; } = new(StringComparer.Ordinal);

        /// <summary>The relocated components, in the order they were registered.</summary>
        /// <remarks>
        /// A list rather than a dictionary. The serialized order is part of what a fingerprint
        /// covers, and a dictionary's enumeration order is an implementation detail that has
        /// already been mistaken for a specified one once in this codebase.
        /// </remarks>
        internal List<KeyValuePair<string, JsonNode>> Components { get; } = [];

        /// <summary>Assigns a stable, unused name to <paramref name="pointer"/>.</summary>
        /// <remarks>
        /// The pointer's last token is used because it is what an author named the component,
        /// and a reader of the advertised schema recognises it. Two pointers ending in the same
        /// token are distinguished by an ordinal rather than by a longer path, so a name never
        /// depends on how deeply a component happened to be nested.
        /// </remarks>
        internal string Allocate(string pointer)
        {
            var stem = Sanitize(LastToken(pointer));
            var name = stem;

            for (var ordinal = 2; !_allocated.Add(name); ordinal++)
            {
                name = stem + "-" + ordinal.ToString(CultureInfo.InvariantCulture);
            }

            Names[pointer] = name;
            return name;
        }

        private static string LastToken(string pointer)
        {
            var separator = pointer.LastIndexOf('/');

            return separator < 0
                ? pointer
                : JsonPointer.Unescape(pointer[(separator + 1)..]);
        }

        /// <summary>
        /// Reduces a token to characters that need no pointer escaping and read as a name.
        /// </summary>
        private static string Sanitize(string token)
        {
            var builder = new StringBuilder(token.Length);

            foreach (var character in token)
            {
                builder.Append(
                    char.IsAsciiLetterOrDigit(character) || character is '_' or '.' or '-'
                        ? character
                        : '_');
            }

            var name = builder.ToString();

            return name.Length == 0 ? "schema" : name;
        }
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
