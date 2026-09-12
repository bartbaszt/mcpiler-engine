using System.Collections.Generic;
using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Mcp;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>
/// What a derived tool set becomes before any transport sees it.
/// </summary>
public sealed class ToolSetProjectionTests
{
    /// <summary>Advertisement order is carried through, not chosen here.</summary>
    /// <remarks>
    /// The surface's exposure list is the single ordering authority. A projection that sorted —
    /// even stably — would substitute an order no Manifest describes and no fingerprint covers,
    /// and the substitution would be invisible because the result would still look tidy.
    /// </remarks>
    [Fact]
    public void Order_is_the_derived_order()
    {
        IReadOnlyList<CatalogueTool> projected = Project(new SurfaceToolSet(
        [
            new ManifestTool("zebra", "Last alphabetically, first in exposure order."),
            new ManifestTool("alpha", "First alphabetically, second in exposure order."),
        ]));

        Assert.Equal(["zebra", "alpha"], [.. Names(projected)]);
    }

    /// <summary>A declared schema is advertised verbatim.</summary>
    /// <remarks>
    /// Verbatim matters more than it looks. The surface fingerprint is taken over the
    /// advertised facts, so a projection that resolved, flattened or tidied a schema would
    /// advertise something the fingerprint does not describe, and equal fingerprints would
    /// stop meaning equal listings.
    /// </remarks>
    [Fact]
    public void A_declared_schema_is_advertised_as_the_manifest_carries_it()
    {
        JsonNode schema = JsonNode.Parse("""{"type":"object","properties":{"b":{"type":"string"},"a":{"type":"integer"}}}""")!;

        CatalogueTool projected = Assert.Single(Project(new SurfaceToolSet(
        [
            new ManifestTool("tool", "A tool.", ManifestSchema.From(schema)),
        ])));

        Assert.Equal(schema.ToJsonString(), projected.InputSchemaJson);

        // Member order included: the Manifest's own bytes, not a re-serialization that
        // happened to be equivalent.
        Assert.Contains("\"b\"", projected.InputSchemaJson[..40], System.StringComparison.Ordinal);
    }

    /// <summary>An absent schema becomes the one that constrains nothing.</summary>
    /// <remarks>
    /// The protocol requires an object schema, so an absent one has to become something. An
    /// empty property set with additional properties refused would advertise a prohibition the
    /// Manifest never stated, and a caller would be told its arguments are invalid by a rule
    /// nobody wrote.
    /// </remarks>
    [Fact]
    public void An_absent_schema_constrains_nothing()
    {
        CatalogueTool projected = Assert.Single(Project(new SurfaceToolSet(
        [
            new ManifestTool("tool", "A tool."),
        ])));

        Assert.Equal(ToolSetProjection.UnconstrainedInputSchema, projected.InputSchemaJson);
    }

    /// <summary>Annotations are carried, including the values that default to false.</summary>
    [Fact]
    public void Annotations_are_carried_including_the_absent_ones()
    {
        IReadOnlyList<CatalogueTool> projected = Project(new SurfaceToolSet(
        [
            new ManifestTool(
                "declared",
                "Every hint declared.",
                Annotations: new ToolAnnotations(ReadOnly: true, Destructive: true, Idempotent: true, OpenWorld: true)),
            new ManifestTool("undeclared", "No hint declared."),
        ]));

        Assert.True(projected[0].ReadOnly);
        Assert.True(projected[0].Destructive);
        Assert.True(projected[0].Idempotent);
        Assert.True(projected[0].OpenWorld);

        ToolAnnotations fallback = new ManifestTool("undeclared", "No hint declared.").EffectiveAnnotations;

        Assert.Equal(fallback.ReadOnly, projected[1].ReadOnly);
        Assert.Equal(fallback.Destructive, projected[1].Destructive);
        Assert.Equal(fallback.Idempotent, projected[1].Idempotent);
        Assert.Equal(fallback.OpenWorld, projected[1].OpenWorld);
    }

    /// <summary>The advertised title is the tool name, decided once and in the library.</summary>
    [Fact]
    public void The_title_is_the_name()
    {
        CatalogueTool projected = Assert.Single(Project(new SurfaceToolSet(
        [
            new ManifestTool("list-pets", "Lists pets."),
        ])));

        Assert.Equal(projected.Name, projected.Title);
    }

    private static IEnumerable<string> Names(IEnumerable<CatalogueTool> tools)
    {
        foreach (CatalogueTool tool in tools)
        {
            yield return tool.Name;
        }
    }

    private static IReadOnlyList<CatalogueTool> Project(SurfaceToolSet tools)
        => ToolSetProjection.Project(tools, new AgentSurfaceSection(), outputSchemasAllowed: false);
}
