using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Transform;

/// <summary>
/// The part-scoped documents a transformation program addresses, and the way back.
/// </summary>
/// <remarks>
/// <para>
/// A program does not see arguments or a response object; it sees a document whose members are
/// the seven part selectors. This type is the only place that translation happens, in both
/// directions, so the pointer roots a program is validated against and the buckets it actually
/// reads are the same set by construction.
/// </para>
/// <para>
/// The round trip is the contract: a passthrough base with no steps has to rebuild exactly the
/// arguments it was given, or a transform declared and left empty would change a request. That
/// is why absence is preserved rather than normalized to null, and why the reserved
/// serialization members are carried across untouched instead of being rebuilt from the parts.
/// </para>
/// </remarks>
internal static class PartsDocument
{
    /// <summary>
    /// Argument members the request compiler reserves, which no program may address.
    /// </summary>
    /// <remarks>
    /// <c>partHeaders</c> is a control surface over the multipart writer, not a request part:
    /// it has no pointer root, and the seven roots are the whole of what a program may reach.
    /// It is carried across the transformation unchanged, because dropping it would make an
    /// empty passthrough program silently discard declared part headers.
    /// </remarks>
    internal static IReadOnlySet<string> Reserved { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        RequestCompiler.PartHeadersArgument,
    };

    /// <summary>Builds the input-direction document from the arguments as supplied.</summary>
    internal static JsonObject Request(
        ManifestOperation operation,
        JsonObject arguments,
        IReadOnlySet<string> fileSlots)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(fileSlots);

        var path = new JsonObject();
        var query = new JsonObject();
        var headers = new JsonObject();
        var cookies = new JsonObject();
        var parts = new JsonObject();

        foreach (ManifestParameter parameter in operation.Parameters)
        {
            if (!arguments.TryGetPropertyValue(parameter.Name, out JsonNode? value))
            {
                continue;
            }

            JsonObject bucket = fileSlots.Contains(parameter.Name)
                ? parts
                : parameter.In switch
                {
                    ParameterLocation.Path => path,
                    ParameterLocation.Query => query,
                    ParameterLocation.Header => headers,
                    _ => cookies,
                };

            bucket[parameter.Name] = value?.DeepClone();
        }

        foreach (string slot in fileSlots)
        {
            if (!parts.ContainsKey(slot) && arguments.TryGetPropertyValue(slot, out JsonNode? handle))
            {
                parts[slot] = handle?.DeepClone();
            }
        }

        // The agent document is the root, with the part selectors overlaid on it. That is what
        // the pointer rule already says: an input-direction source is anything that is not a
        // part selector, which is only addressable if the agent's own members are here. An
        // operation whose agent surface takes an argument the upstream never declared — the
        // reason a transformation exists at all — would otherwise have nothing to read.
        var document = new JsonObject();

        foreach ((string name, JsonNode? value) in arguments)
        {
            if (!Reserved.Contains(name))
            {
                document[name] = value?.DeepClone();
            }
        }

        document[Member(ManifestPointerRoots.Path)] = path;
        document[Member(ManifestPointerRoots.Query)] = query;
        document[Member(ManifestPointerRoots.Headers)] = headers;
        document[Member(ManifestPointerRoots.Cookies)] = cookies;
        document[Member(ManifestPointerRoots.Parts)] = parts;

        if (arguments.TryGetPropertyValue(BodyArgument, out JsonNode? body))
        {
            document[Member(ManifestPointerRoots.Body)] = body?.DeepClone();
        }

        return document;
    }

    /// <summary>Rebuilds compiler arguments from a transformed input-direction document.</summary>
    /// <param name="operation">The operation whose parameters name the buckets.</param>
    /// <param name="parts">The transformed document.</param>
    /// <param name="fileSlots">Members the agent schema marks as file-carrying.</param>
    /// <param name="original">
    /// The arguments the caller supplied, read only for the reserved members a program cannot
    /// address and therefore cannot have rewritten.
    /// </param>
    internal static JsonObject Arguments(
        ManifestOperation operation,
        JsonObject parts,
        IReadOnlySet<string> fileSlots,
        JsonObject original)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(parts);
        ArgumentNullException.ThrowIfNull(fileSlots);
        ArgumentNullException.ThrowIfNull(original);

        var mapped = new JsonObject();

        foreach (ManifestParameter parameter in operation.Parameters)
        {
            string bucket = fileSlots.Contains(parameter.Name)
                ? ManifestPointerRoots.Parts
                : parameter.In switch
                {
                    ParameterLocation.Path => ManifestPointerRoots.Path,
                    ParameterLocation.Query => ManifestPointerRoots.Query,
                    ParameterLocation.Header => ManifestPointerRoots.Headers,
                    _ => ManifestPointerRoots.Cookies,
                };

            if (Member(parts, bucket, parameter.Name) is { Found: true } found)
            {
                mapped[parameter.Name] = found.Value?.DeepClone();
            }
        }

        foreach (string slot in fileSlots)
        {
            if (!mapped.ContainsKey(slot)
                && Member(parts, ManifestPointerRoots.Parts, slot) is { Found: true } found)
            {
                mapped[slot] = found.Value?.DeepClone();
            }
        }

        if (parts.TryGetPropertyValue(Member(ManifestPointerRoots.Body), out JsonNode? body))
        {
            mapped[BodyArgument] = body?.DeepClone();
        }

        foreach (string reserved in Reserved)
        {
            if (original.TryGetPropertyValue(reserved, out JsonNode? carried))
            {
                mapped[reserved] = carried?.DeepClone();
            }
        }

        return mapped;
    }

    /// <summary>Builds the output-direction document from what the exchange observed.</summary>
    /// <remarks>
    /// One value per header, because a program addresses <c>/headers/name</c> and a list there
    /// would make every such pointer mean something different depending on the response. The
    /// body is parsed when it parses and carried as text when it does not, so a program over a
    /// non-JSON body still sees the payload rather than nothing.
    /// </remarks>
    internal static JsonObject Response(EngineExecutionResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var headers = new JsonObject();

        if (result.ResponseHeaders is not null)
        {
            foreach ((string name, string[] values) in result.ResponseHeaders)
            {
                if (values.Length > 0)
                {
                    headers[name] = values[0];
                }
            }
        }

        JsonNode? body = null;

        if (result.ResponseBody is { Length: > 0 } bytes)
        {
            string text = Encoding.UTF8.GetString(bytes);

            try
            {
                body = JsonNode.Parse(text);
            }
            catch (JsonException)
            {
                body = text;
            }
        }

        return new JsonObject
        {
            [Member(ManifestPointerRoots.Status)] = result.StatusCode ?? 0,
            [Member(ManifestPointerRoots.Headers)] = headers,
            [Member(ManifestPointerRoots.Body)] = body,
        };
    }

    /// <summary>The argument member carrying the request body.</summary>
    private const string BodyArgument = "body";

    /// <summary>
    /// A root as a member name: the pointer separator introduces the first segment, so the
    /// member behind <c>/query</c> is named <c>query</c>.
    /// </summary>
    private static string Member(string root) => root[1..];

    private static (bool Found, JsonNode? Value) Member(JsonObject parts, string root, string name)
        => parts.TryGetPropertyValue(Member(root), out JsonNode? bucket)
            && bucket is JsonObject members
            && members.TryGetPropertyValue(name, out JsonNode? value)
                ? (true, value)
                : (false, null);
}
