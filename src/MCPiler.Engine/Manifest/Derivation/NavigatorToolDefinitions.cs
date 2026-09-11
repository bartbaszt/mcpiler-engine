using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Manifest.Derivation;

/// <summary>
/// The fixed Navigator tool trio advertised by a surface with Navigator enabled.
/// </summary>
/// <remarks>
/// <para>
/// These three tools are protocol furniture rather than manifest content: they exist so a
/// caller can search, inspect, and invoke operations that are not advertised individually.
/// Their names, descriptions, and argument contracts are therefore defined here and are not
/// authorable, which is what makes a Navigator surface behave identically no matter who
/// produced the manifest.
/// </para>
/// <para>
/// None of the three declares tool annotations. That is deliberately the behaviour the
/// current adapter already produces, and changing it here would alter how a client treats
/// these tools under the banner of a format change. Whether discovery should advertise
/// itself as read-only is a real question, but it is a protocol decision to take on its own
/// evidence rather than a side effect of manifest derivation.
/// </remarks>
public static class NavigatorToolDefinitions
{
    /// <summary>The largest page a caller may request from discovery.</summary>
    public const int MaxPageSize = 100;

    private const string DiscoverDescription =
        "Discovers catalogue operations through hybrid retrieval over curated names, summaries, "
        + "descriptions, tags, groups, HTTP paths, parameters, schemas, and search metadata. "
        + "Returns a bounded, deterministically ordered ranked page and a continuation token "
        + "when more results exist.";

    private const string DescribeDescription =
        "Returns the exact argument contract for one catalogue operation, including parameter "
        + "locations, required arguments, and file semantics.";

    private const string InvokeDescription =
        "Invokes a named catalogue operation with the supplied arguments. Unknown identifiers "
        + "or invalid arguments produce a tool error and perform no upstream request.";

    /// <summary>
    /// How the operation identifier is described to a caller.
    /// </summary>
    /// <remarks>
    /// One constant for both tools, because a caller that reads two descriptions of the same
    /// identifier and finds two shapes has to guess which one is true. The identifier is the
    /// manifest slug: it is what discovery returns, what the exposure table addresses, and
    /// what execution resolves. A binding key such as <c>GET /pets</c> is none of those, and
    /// two agent operations may bind one key, so accepting it would make resolution a choice
    /// between them.
    /// </remarks>
    private const string OperationDescription =
        "The operation identifier returned by catalogue.discover, e.g. 'list-pets'.";

    private const string QueryVectorDescription =
        "Optional embedding of the query, computed by the caller with the model the catalogue "
        + "declares. Used only when the catalogue carries a usable vector matrix; a vector "
        + "whose length differs from the catalogue's dimension is a tool error.";

    /// <summary>
    /// Builds the Navigator tools for one surface.
    /// </summary>
    /// <param name="pageSize">
    /// The surface's discovery page size, advertised as the <c>pageSize</c> default so a
    /// caller that omits the argument gets the size the surface actually declares.
    /// </param>
    public static IReadOnlyList<ManifestTool> Build(int pageSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(pageSize, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(pageSize, MaxPageSize);

        return
        [
            new ManifestTool(
                Name: ManifestTool.NavigatorDiscover,
                Description: DiscoverDescription,
                InputSchema: ManifestSchema.From(new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["query"] = new JsonObject
                        {
                            ["type"] = "string",
                            ["description"] = "Optional natural-language query; matching is hybrid retrieval, not an identifier substring filter.",
                        },
                        ["pageSize"] = new JsonObject
                        {
                            ["type"] = "integer",
                            ["minimum"] = 1,
                            ["maximum"] = MaxPageSize,
                            ["default"] = pageSize,
                        },
                        ["continuation"] = new JsonObject
                        {
                            ["type"] = "string",
                            ["description"] = "Opaque continuation token from a previous page.",
                        },
                        ["queryVector"] = new JsonObject
                        {
                            ["type"] = "array",
                            ["items"] = new JsonObject { ["type"] = "number" },
                            ["description"] = QueryVectorDescription,
                        },
                    },
                })),

            new ManifestTool(
                Name: ManifestTool.NavigatorDescribe,
                Description: DescribeDescription,
                InputSchema: ManifestSchema.From(new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["operationKey"] = new JsonObject
                        {
                            ["type"] = "string",
                            ["description"] = OperationDescription,
                        },
                    },
                    ["required"] = new JsonArray("operationKey"),
                })),

            new ManifestTool(
                Name: ManifestTool.NavigatorInvoke,
                Description: InvokeDescription,
                InputSchema: ManifestSchema.From(new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["operationKey"] = new JsonObject
                        {
                            ["type"] = "string",
                            ["description"] = OperationDescription,
                        },
                        ["arguments"] = new JsonObject
                        {
                            ["type"] = "object",
                            ["description"] = "Arguments for the operation; consult catalogue.describe for the exact contract.",
                        },
                    },
                    ["required"] = new JsonArray("operationKey", "arguments"),
                })),
        ];
    }
}
