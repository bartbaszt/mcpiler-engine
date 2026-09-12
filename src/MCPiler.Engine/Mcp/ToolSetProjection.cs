using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Mcp;

/// <summary>
/// Renders a derived tool set as the protocol-neutral catalogue a transport advertises.
/// </summary>
/// <remarks>
/// <para>
/// This projects; it never derives. <c>ToolSetDeriver</c> already answers which tools a
/// surface advertises, in which order, with which descriptions and schemas, and it is the
/// component an inspection verb and a serving process both read. A second derivation here
/// would be a second answer to the same question, and the two would disagree about a manifest
/// somebody edited.
/// </para>
/// <para>
/// Order is carried through unchanged. The surface's exposure list is the single ordering
/// authority, so nothing here sorts, groups or stabilizes anything: an advertisement order
/// this file chose would be an order the fingerprint does not describe.
/// </para>
/// </remarks>
public static class ToolSetProjection
{
    /// <summary>
    /// The schema advertised for a tool whose Manifest declares none.
    /// </summary>
    /// <remarks>
    /// The protocol requires an object schema, so an absent one has to become something. It
    /// becomes the schema that constrains nothing, which is what "the Manifest declares no
    /// arguments" means. The alternative — an empty property set with additional properties
    /// refused — would advertise a prohibition the Manifest never stated.
    /// </remarks>
    public const string UnconstrainedInputSchema = """{"type":"object"}""";

    /// <summary>Projects one derived tool set into its advertised form.</summary>
    /// <remarks>
    /// The advertised title is the tool name, because a Manifest carries no separate
    /// advertised title. It is a field here rather than something a transport substitutes so
    /// that the day a Manifest does carry one, exactly one place changes.
    /// </remarks>
    /// <param name="tools">The tool set a surface derived.</param>
    /// <param name="agentSurface">The operation policies carried by the Manifest.</param>
    /// <param name="outputSchemasAllowed">The surface capability ceiling.</param>
    public static IReadOnlyList<CatalogueTool> Project(
        SurfaceToolSet tools,
        AgentSurfaceSection agentSurface,
        bool outputSchemasAllowed)
    {
        ArgumentNullException.ThrowIfNull(tools);
        ArgumentNullException.ThrowIfNull(agentSurface);

        List<CatalogueTool> projected = new(tools.Tools.Count);

        foreach (ManifestTool tool in tools.Tools)
        {
            ToolAnnotations annotations = tool.EffectiveAnnotations;
            AgentOperationEntry? operation = tool.Operation is null
                ? null
                : agentSurface.Operation(tool.Operation);
            (System.Text.Json.Nodes.JsonObject Schema, bool Wrapped)? output = tool.OutputSchema is null
                ? null
                : OutputSchemaEnvelope.Shape(tool.OutputSchema.Node);

            projected.Add(new CatalogueTool(
                tool.Name,
                tool.Name,
                tool.Description,
                tool.InputSchema?.Node.ToJsonString() ?? UnconstrainedInputSchema,
                annotations.ReadOnly,
                annotations.Destructive,
                annotations.Idempotent,
                annotations.OpenWorld)
            {
                Operation = tool.Operation,
                OutputSchemaCandidateJson = output?.Schema.ToJsonString(),
                OutputSchemaWrapped = output?.Wrapped ?? false,
                OutputSchemaAdvertisement = operation?.EffectiveOutputSchemaPolicy.Advertise
                    ?? OutputSchemaAdvertisement.No,
                OutputSchemasAllowed = outputSchemasAllowed,
            });
        }

        return projected;
    }
}
