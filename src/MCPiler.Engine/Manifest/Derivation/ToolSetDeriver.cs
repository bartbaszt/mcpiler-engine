using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;

namespace MCPiler.Engine.Manifest.Derivation;

/// <summary>
/// Derives the advertised tool set for a surface from <c>server</c>, <c>agentSurface</c> and
/// <c>operations</c>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>tools</c> section is optional precisely because it is derivable. A hand-authored
/// manifest omits it; a Studio export carries it so the advertised set is pinned. Both must
/// advertise the same thing, so <see cref="Resolve"/> compares an explicit section against
/// the derivation and reports a disagreement instead of letting one silently win.
/// </para>
/// <para>
/// Derivation deliberately reproduces the disclosures the current adapter adds to a
/// description — the file-reference sentence and the compound retry sentence — because they
/// are the difference between a caller that uses a file operation correctly and one that
/// tries to inline bytes. Dropping them would be a behaviour regression that a schema-level
/// comparison would not notice.
/// </para>
/// </remarks>
public static class ToolSetDeriver
{
    /// <summary>The file-argument disclosure appended to an operation that accepts files.</summary>
    public const string FileArgumentDisclosure =
        "File arguments are file references; obtain a valid reference through the "
        + "authenticated transfer endpoints before invoking.";

    /// <summary>The retry disclosure appended to an idempotent compound operation.</summary>
    public const string IdempotentCompoundDisclosure =
        "Idempotency: idempotent \u2014 safe to retry.";

    /// <summary>The retry disclosure appended to a non-idempotent compound operation.</summary>
    public const string NonIdempotentCompoundDisclosure =
        "Idempotency: not idempotent \u2014 do not retry automatically.";

    /// <summary>The schema keyword that marks an agent-facing file slot.</summary>
    public const string FileSlotKeyword = "x-mcp-file";

    /// <summary>
    /// Derives the advertised tool set for one surface.
    /// </summary>
    /// <param name="manifest">The loaded manifest.</param>
    /// <param name="surface">The surface to advertise.</param>
    /// <returns>The derived tool set, in advertisement order.</returns>
    public static SurfaceToolSet Derive(ManifestDocument manifest, ManifestSurface surface)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(surface);

        var names = ToolName.Allocate(manifest.AgentSurface.Operations.Select(static entry => entry.Slug));
        var resolver = SchemaResolverFor(manifest);
        var tools = new List<ManifestTool>(surface.Operations.Count + 3);

        // Advertisement order is the surface's own exposure order. The surface list is the
        // single exposure authority, so it is also the single ordering authority; nothing
        // else gets to decide what a caller sees first.
        foreach (var entry in surface.Operations)
        {
            if (entry.Exposure != OperationExposure.Direct)
            {
                continue;
            }

            if (manifest.AgentSurface.Operation(entry.Operation) is not { } operation)
            {
                // An unresolvable exposure entry is already a validation error with its own
                // diagnostic; derivation simply has nothing to advertise for it.
                continue;
            }

            tools.Add(BuildTool(manifest, surface, operation, names[operation.Slug], resolver));
        }

        var navigator = surface.EffectiveNavigator;
        if (navigator.Enabled)
        {
            tools.AddRange(NavigatorToolDefinitions.Build(
                Math.Clamp(navigator.PageSize, 1, NavigatorToolDefinitions.MaxPageSize)));
        }

        return new SurfaceToolSet(tools);
    }

    /// <summary>
    /// Derives the tool sets for every enabled surface.
    /// </summary>
    /// <param name="manifest">The loaded manifest.</param>
    public static ToolsSection Derive(ManifestDocument manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        var surfaces = new Dictionary<string, SurfaceToolSet>(StringComparer.Ordinal);
        foreach (var surface in manifest.Server.Surfaces.Where(static surface => surface.Enabled))
        {
            surfaces[surface.Slug] = Derive(manifest, surface);
        }

        return new ToolsSection(surfaces);
    }

    /// <summary>
    /// Returns the tool set actually advertised for a surface, reconciling an explicit
    /// section with the derivation.
    /// </summary>
    /// <remarks>
    /// The explicit section wins, because a producer that pinned an advertised set meant it.
    /// A disagreement is still reported: silently preferring either side would hide the fact
    /// that a manifest advertises something its own operations no longer describe.
    /// </remarks>
    /// <param name="manifest">The loaded manifest.</param>
    /// <param name="surface">The surface to advertise.</param>
    /// <param name="diagnostics">Receives any disagreement.</param>
    public static SurfaceToolSet Resolve(
        ManifestDocument manifest,
        ManifestSurface surface,
        ICollection<ManifestDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(surface);
        ArgumentNullException.ThrowIfNull(diagnostics);

        var derived = Derive(manifest, surface);
        if (manifest.Tools is not { } section || !section.Surfaces.TryGetValue(surface.Slug, out var declared))
        {
            return derived;
        }

        var declaredFingerprint = Fingerprint(declared);
        if (!string.Equals(declaredFingerprint, Fingerprint(derived), StringComparison.Ordinal))
        {
            diagnostics.Add(ManifestDiagnostic.Error(
                ManifestDiagnosticCodes.ToolDerivationMismatch,
                $"The declared tool set for surface '{DiagnosticText.Echo(surface.Slug)}' does not match the "
                + "set derived from the server, agentSurface and operations sections. The declared set is "
                + "advertised; re-export the manifest or remove the tools section so the two cannot diverge.",
                ManifestSectionName.Tools,
                JsonPointer.Build("surfaces", surface.Slug)));
        }

        return declared;
    }

    /// <summary>
    /// Produces a canonical fingerprint of everything a surface advertises.
    /// </summary>
    /// <remarks>
    /// The fingerprint covers the advertised facts and their order: name, description, input
    /// schema, candidate output schema, annotations, and the backing operation. A protocol
    /// listing is a deterministic rendering of exactly these facts, so equal fingerprints
    /// mean equal listings for any given negotiated protocol revision. Budget accounting is
    /// excluded because it is producer bookkeeping that is never advertised.
    /// </remarks>
    /// <param name="tools">The tool set to fingerprint.</param>
    public static string Fingerprint(SurfaceToolSet tools)
    {
        ArgumentNullException.ThrowIfNull(tools);

        var array = new JsonArray();
        foreach (var tool in tools.Tools)
        {
            var annotations = tool.EffectiveAnnotations;
            array.Add(new JsonObject
            {
                ["name"] = tool.Name,
                ["description"] = tool.Description,
                ["inputSchema"] = tool.InputSchema?.Node.DeepClone(),
                ["outputSchema"] = tool.OutputSchema?.Node.DeepClone(),
                ["operation"] = tool.Operation,
                ["annotations"] = new JsonObject
                {
                    ["readOnly"] = annotations.ReadOnly,
                    ["destructive"] = annotations.Destructive,
                    ["idempotent"] = annotations.Idempotent,
                    ["openWorld"] = annotations.OpenWorld,
                },
            });
        }

        return CanonicalJson.Hash(array);
    }

    private static ManifestTool BuildTool(
        ManifestDocument manifest,
        ManifestSurface surface,
        AgentOperationEntry operation,
        string name,
        SchemaReferenceResolver? resolver)
    {
        var operationKey = ManifestBindingDispatcher.TryResolveOperationKey(operation.Binding);
        var method = operationKey is not null
            ? manifest.Operations.Operation(operationKey)?.Method
            : null;

        return new ManifestTool(
            Name: name,
            Description: BuildDescription(manifest, operation, operationKey, resolver),
            InputSchema: operation.InputSchema,
            OutputSchema: CandidateOutputSchema(surface, operation),
            Operation: operation.Slug,
            OperationKey: operationKey,
            Annotations: operation.EffectiveAnnotations(method));
    }

    /// <summary>
    /// Builds the advertised description.
    /// </summary>
    /// <remarks>
    /// The composition mirrors the current adapter exactly: the long description leads, a
    /// distinct summary is prepended, and the operation key is the last resort so a tool is
    /// never advertised with an empty description.
    /// </remarks>
    private static string BuildDescription(
        ManifestDocument manifest,
        AgentOperationEntry operation,
        string? operationKey,
        SchemaReferenceResolver? resolver)
    {
        var text = operation.Description ?? operation.Summary ?? $"Invokes {operationKey ?? operation.Slug}.";
        if (operation.Summary is { } summary
            && operation.Description is { } description
            && !string.Equals(description, summary, StringComparison.Ordinal))
        {
            text = summary + " " + text;
        }

        if (AcceptsFiles(operation.InputSchema, resolver))
        {
            text += " " + FileArgumentDisclosure;
        }

        if (operation.EffectiveKind == AgentOperationKind.Compound)
        {
            text += " " + (CompoundIsIdempotent(manifest, operation)
                ? IdempotentCompoundDisclosure
                : NonIdempotentCompoundDisclosure);
        }

        return text.Trim();
    }

    /// <summary>
    /// Decides whether a compound operation may be advertised as safe to retry.
    /// </summary>
    /// <remarks>
    /// A declared classification wins, because a producer that resolved the workflow's risk
    /// knows more than this fallback does. Otherwise the steps decide, and a workflow counts
    /// as idempotent only when every step is: one step that is not safe to repeat makes the
    /// whole workflow unsafe to repeat, and advertising otherwise invites a caller to retry a
    /// half-applied workflow.
    /// </remarks>
    private static bool CompoundIsIdempotent(ManifestDocument manifest, AgentOperationEntry compound)
    {
        if (compound.Annotations is { } declared)
        {
            return declared.Idempotent;
        }

        if (compound.Risk is { } risk)
        {
            return ToolAnnotations.FromRisk(risk).Idempotent;
        }

        var steps = ManifestBindingDispatcher.TryResolveCompoundSteps(compound.Binding);
        if (steps is null || steps.Count == 0)
        {
            return false;
        }

        foreach (var step in steps)
        {
            if (manifest.AgentSurface.Operation(step.Operation) is not { } referenced)
            {
                return false;
            }

            var key = ManifestBindingDispatcher.TryResolveOperationKey(referenced.Binding);
            var method = key is not null ? manifest.Operations.Operation(key)?.Method : null;
            if (!referenced.EffectiveAnnotations(method).Idempotent)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Returns the output schema a surface may advertise for an operation, or <c>null</c>.
    /// </summary>
    /// <remarks>
    /// This is the candidate, not the decision. Whether the schema actually appears in a
    /// listing also depends on the protocol revision the session negotiated, which is not a
    /// manifest fact and stays in the protocol adapter where the revision is known.
    /// </remarks>
    private static ManifestSchema? CandidateOutputSchema(ManifestSurface surface, AgentOperationEntry operation)
    {
        if (!surface.OutputSchemas || operation.OutputSchema is null)
        {
            return null;
        }

        var policy = operation.EffectiveOutputSchemaPolicy;
        return policy.Generate && policy.Advertise != OutputSchemaAdvertisement.No
            ? operation.OutputSchema
            : null;
    }

    /// <summary>
    /// True when the agent-facing input schema declares at least one file slot.
    /// </summary>
    /// <remarks>
    /// Presentation only. File capability itself is derived from the wire contract through
    /// the binding seam; a caller that removes this keyword changes what the description says
    /// and nothing about what the operation is permitted to do.
    /// </remarks>
    private static bool AcceptsFiles(ManifestSchema? inputSchema, SchemaReferenceResolver? resolver)
    {
        if (inputSchema is null)
        {
            return false;
        }

        var schema = inputSchema;
        if (schema.IsReference && resolver is not null && resolver.TryResolve(schema, out var target, out _))
        {
            schema = target;
        }

        if (schema.Object?["properties"] is not JsonObject properties)
        {
            return false;
        }

        foreach (var (_, value) in properties)
        {
            var property = ManifestSchema.FromOrNull(value);
            if (property is null)
            {
                continue;
            }

            if (property.IsReference && resolver is not null && resolver.TryResolve(property, out var resolved, out _))
            {
                property = resolved;
            }

            if (property.Object?[FileSlotKeyword] is not null)
            {
                return true;
            }
        }

        return false;
    }

    private static SchemaReferenceResolver? SchemaResolverFor(ManifestDocument manifest)
        => manifest.AgentSurfaceDocument is { } document
            ? new SchemaReferenceResolver(document, manifest.Policy.EffectiveSchemaBounds)
            : null;
}
