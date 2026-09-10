using System.Text.Json;

using MCPiler.Engine.Runtime;

using ModelContextProtocol.Protocol;

namespace MCPiler.Engine.Host.Mcp;

/// <summary>
/// The only place a catalogue value becomes a protocol type.
/// </summary>
/// <remarks>
/// <para>
/// Everything below is a mapping. No field is computed, no default is supplied that the
/// catalogue did not already carry, and nothing branches on what a Manifest said. That is the
/// property the deployable's boundary guard asserts, and it is also why this file is worth
/// isolating: a translation that started deciding would be the one piece of product behaviour
/// living where no library guard looks.
/// </para>
/// <para>
/// The input schema arrives as text and is parsed, not rebuilt. Parsing bytes the library
/// produced keeps the advertised schema the Manifest's own; re-serializing a node here would
/// make the advertised bytes a property of this writer's options.
/// </para>
/// <para>
/// Order is the catalogue's order, carried by a list. The SDK's own tool collection is keyed
/// by name and enumerates in dictionary order, which is stable and is not the surface's
/// exposure order — so the definitions are held in a list and served from it.
/// </para>
/// </remarks>
internal static class SdkTranslation
{
    /// <summary>Maps one catalogue tool onto its protocol definition.</summary>
    public static Tool Define(CatalogueTool tool)
    {
        ArgumentNullException.ThrowIfNull(tool);

        return new Tool
        {
            Name = tool.Name,
            Description = tool.Description,
            InputSchema = JsonDocument.Parse(tool.InputSchemaJson).RootElement.Clone(),
            Annotations = new ToolAnnotations
            {
                Title = tool.Title,
                ReadOnlyHint = tool.ReadOnly,
                DestructiveHint = tool.Destructive,
                IdempotentHint = tool.Idempotent,
                OpenWorldHint = tool.OpenWorld,
            },
        };
    }

    /// <summary>Maps every tool of one surface, preserving advertisement order.</summary>
    public static IReadOnlyList<Tool> Define(MountedSurface surface)
    {
        ArgumentNullException.ThrowIfNull(surface);

        List<Tool> definitions = new(surface.Tools.Count);

        foreach (CatalogueTool tool in surface.Tools)
        {
            definitions.Add(Define(tool));
        }

        return definitions;
    }
}
