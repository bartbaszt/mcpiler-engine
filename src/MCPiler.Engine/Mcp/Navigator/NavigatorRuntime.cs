using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Derivation;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Search;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Search.Hybrid;

namespace MCPiler.Engine.Mcp.Navigator;

/// <summary>
/// The three tools that let a caller reach a catalogue larger than a listing.
/// </summary>
/// <remarks>
/// <para>
/// Discovery ranks, description states a contract, and invocation runs one operation. The
/// three exist so a surface can expose hundreds of operations without advertising hundreds of
/// tools, which is the only way a large API fits inside a client's tool budget at all.
/// </para>
/// <para>
/// Every identifier here is the Manifest slug — the same identifier the exposure table
/// addresses, the index documents, and the executor resolves. Discovery hands one back and
/// description and invocation take one, so a caller that follows the three tools in order
/// never has to translate between two spellings of the same operation.
/// </para>
/// <para>
/// Nothing here is a second way in. Invocation walks the same exposure gate, the same
/// validation and the same shaping a direct call walks, differing only in which arm of the
/// gate it presents. An operation that cannot be reached directly is not reachable here
/// either unless its exposure says so, and one that cannot be reached at all answers exactly
/// as a name that was never authored.
/// </para>
/// </remarks>
internal static class NavigatorRuntime
{
    /// <summary>The argument carrying the operation a caller names.</summary>
    /// <remarks>
    /// The spelling is fixed by <c>NavigatorToolDefinitions</c>, which advertises it. Reading
    /// a different member here would accept nothing a caller could have sent.
    /// </remarks>
    internal const string OperationArgument = "operationKey";

    internal const string QueryArgument = "query";
    internal const string PageSizeArgument = "pageSize";
    internal const string ContinuationArgument = "continuation";
    internal const string ArgumentsArgument = "arguments";
    internal const string QueryVectorArgument = "queryVector";

    /// <summary>The answer for a query vector that is not a list of numbers.</summary>
    /// <remarks>
    /// Unreachable through the advertised schema, which already constrains the argument, and
    /// stated anyway: the check that runs is the one that decides, and a malformed vector read
    /// as an absent one would silently downgrade the ranking the caller asked for.
    /// </remarks>
    internal const string MalformedVector = "The query vector must be a list of numbers.";

    /// <summary>
    /// The answer for an operation this surface cannot reach.
    /// </summary>
    /// <remarks>
    /// One message for three situations: an operation that was never authored, one the
    /// surface does not list, and one it lists as hidden. They are the same answer because
    /// any difference between them tells a caller which of the three it found, and the third
    /// is a fact about a catalogue it was not given.
    /// </remarks>
    internal static string UnknownOperation(string operation)
        => string.Create(CultureInfo.InvariantCulture, $"No operation named '{operation}' is available here.");

    /// <summary>The answer for a continuation token that does not belong to this query.</summary>
    /// <remarks>
    /// Refused rather than ignored. Resuming at a position computed for a different list
    /// would skip operations and repeat others, and the caller would have no way to notice.
    /// </remarks>
    internal const string StaleContinuation =
        "The continuation token was issued for a different query, surface or catalogue and cannot "
        + "be used here. Start again without a continuation.";

    /// <summary>Dispatches one Navigator tool.</summary>
    internal static Task<ToolOutcome> InvokeAsync(
        ExecutionService executions,
        MountedManifest mount,
        MountedSurface surface,
        string tool,
        JsonObject arguments,
        CancellationToken cancellationToken)
        => tool switch
        {
            ManifestTool.NavigatorDiscover => Task.FromResult(Discover(mount, surface, arguments)),
            ManifestTool.NavigatorDescribe => Task.FromResult(Describe(mount, surface, arguments)),
            ManifestTool.NavigatorInvoke => InvokeOperationAsync(executions, mount, surface, arguments, cancellationToken),

            // The trio is closed and every member is handled above. A fourth name reaching
            // here would have had to be advertised by something, so it is answered the way an
            // unadvertised name is rather than by a failure that would say more.
            _ => Task.FromResult(new ToolOutcome(ToolInvocation.UnknownTool(tool), IsError: true)),
        };

    /// <summary>
    /// Ranks the catalogue and returns one bounded page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The ranking is filtered by the surface's own exposure table on every query, so an
    /// index entry for an operation the surface does not expose contributes to no item, no
    /// position and no continuation. The index is never trusted to have been built from the
    /// state being served.
    /// </para>
    /// <para>
    /// How many entries that filter removed is deliberately not in the page. It is an
    /// operator diagnostic, and handed to a caller it would be a count of the operations
    /// hidden from it — the one number a hidden operation exists not to contribute.
    /// </para>
    /// </remarks>
    internal static ToolOutcome Discover(MountedManifest mount, MountedSurface surface, JsonObject arguments)
    {
        if (mount.Document.Server.Surface(surface.Slug) is not { } declared)
        {
            // Unreachable on a started mount, where every mounted surface was built from a
            // declaration. Failing closed rather than ranking an unfiltered index, because
            // the filter is the only thing keeping a hidden operation out of the results.
            return Page([], continuation: null);
        }

        if (!TryVector(arguments, out IReadOnlyList<double>? supplied))
        {
            return new ToolOutcome(MalformedVector, IsError: true);
        }

        if (!HybridRanker.TryResolve(
                mount.Index.Vectors,
                mount.Index.Section,
                supplied,
                out SemanticTerm? semantic,
                out string? unusable))
        {
            return new ToolOutcome(unusable, IsError: true);
        }

        string? query = Text(arguments, QueryArgument);
        int pageSize = Integer(arguments, PageSizeArgument)
            ?? Math.Clamp(declared.EffectiveNavigator.PageSize, 1, NavigatorToolDefinitions.MaxPageSize);

        string identity = ContinuationToken.Identify(
            query,
            surface.Slug,
            mount.Index.Fingerprint,
            semantic?.Identity);

        int offset = 0;

        if (Text(arguments, ContinuationArgument) is { Length: > 0 } token
            && !ContinuationToken.TryRedeem(token, identity, out offset))
        {
            return new ToolOutcome(StaleContinuation, IsError: true);
        }

        IReadOnlyList<LexicalSearchResult> ranked = new LexicalRanker(mount.Index.Section, declared)
            .Rank(query, semantic?.Contributions)
            .Results;

        List<LexicalSearchResult> items = [.. ranked.Skip(offset).Take(pageSize)];
        int next = offset + items.Count;

        return Page(items, next < ranked.Count ? ContinuationToken.Issue(next, identity) : null);
    }

    /// <summary>
    /// States the argument contract for one operation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The advertised input schema decides which arguments exist and which are required,
    /// because that is the schema a call is measured against. Taking the list from the wire
    /// parameters instead would describe a contract nothing enforces, and the two are allowed
    /// to differ: a Manifest may narrow what it accepts without changing the upstream.
    /// </para>
    /// <para>
    /// Where an argument is transmitted comes from the binding, and is omitted when no
    /// binding resolves it. An operation composed of steps has no single wire location for
    /// its arguments, and inventing a token to fill the field would claim knowledge this
    /// build does not have.
    /// </para>
    /// </remarks>
    internal static ToolOutcome Describe(MountedManifest mount, MountedSurface surface, JsonObject arguments)
    {
        string named = Text(arguments, OperationArgument) ?? string.Empty;

        if (Reach(mount, surface, named) is not { } operation)
        {
            return new ToolOutcome(UnknownOperation(named), IsError: true);
        }

        ManifestOperation? bound = Bound(mount, named);

        JsonObject contract = new()
        {
            ["operation"] = named,
            ["description"] = operation.Description,
            [ArgumentsArgument] = Arguments(operation, bound),
        };

        return new ToolOutcome(Render(contract), IsError: false);
    }

    /// <summary>Runs one named operation through the ordinary invocation pipeline.</summary>
    private static Task<ToolOutcome> InvokeOperationAsync(
        ExecutionService executions,
        MountedManifest mount,
        MountedSurface surface,
        JsonObject arguments,
        CancellationToken cancellationToken)
    {
        string named = Text(arguments, OperationArgument) ?? string.Empty;

        if (Reach(mount, surface, named) is not { } operation)
        {
            return Task.FromResult(new ToolOutcome(UnknownOperation(named), IsError: true));
        }

        JsonObject supplied = arguments[ArgumentsArgument] is JsonObject declared
            ? (JsonObject)declared.DeepClone()
            : [];

        return ToolInvocation.RunAsync(executions, mount, operation, supplied, cancellationToken);
    }

    /// <summary>
    /// Resolves a named operation, or nothing at all.
    /// </summary>
    /// <remarks>
    /// Two checks over the same fact, in the order the direct path uses them. The reachable
    /// set is derived from the exposure table, so on a started mount they agree; the table is
    /// asked anyway because it is the authored one and the set is the derived one, and when
    /// they disagree the authored one decides.
    /// </remarks>
    private static CatalogueTool? Reach(MountedManifest mount, MountedSurface surface, string named)
    {
        if (named.Length == 0 || surface.FindNavigable(named) is not { } operation)
        {
            return null;
        }

        return ExposureGate.Permits(mount, surface, named, InvocationPath.Navigator) ? operation : null;
    }

    private static ManifestOperation? Bound(MountedManifest mount, string named)
    {
        if (mount.Document.AgentSurface.Operation(named) is not { } entry)
        {
            return null;
        }

        return ManifestBindingDispatcher.TryResolveOperationKey(entry.Binding) is { } key
            ? mount.Document.Operations.Operation(key)
            : null;
    }

    /// <summary>Projects the advertised schema's properties onto the argument contract.</summary>
    private static JsonArray Arguments(CatalogueTool operation, ManifestOperation? bound)
    {
        JsonArray contract = [];

        if (JsonNode.Parse(operation.InputSchemaJson) is not JsonObject schema
            || schema["properties"] is not JsonObject properties)
        {
            return contract;
        }

        HashSet<string> required = new(StringComparer.Ordinal);

        if (schema["required"] is JsonArray declared)
        {
            foreach (JsonNode? name in declared)
            {
                if (name is JsonValue value && value.TryGetValue(out string? text))
                {
                    required.Add(text);
                }
            }
        }

        foreach ((string name, JsonNode? property) in properties)
        {
            JsonObject argument = new()
            {
                ["name"] = name,
                ["required"] = required.Contains(name),
                ["file"] = property is JsonObject slot && slot[ToolSetDeriver.FileSlotKeyword] is not null,
            };

            if (Location(name, bound) is { } location)
            {
                argument["in"] = location;
            }

            contract.Add(argument);
        }

        return contract;
    }

    private static string? Location(string name, ManifestOperation? bound)
    {
        if (bound is null)
        {
            return null;
        }

        foreach (ManifestParameter parameter in bound.Parameters)
        {
            if (string.Equals(parameter.Name, name, StringComparison.Ordinal))
            {
                return Vocabulary.Write(parameter.In);
            }
        }

        return string.Equals(name, BodyArgument, StringComparison.Ordinal) && bound.RequestBody is not null
            ? BodyArgument
            : null;
    }

    /// <summary>The argument name the executor reads a whole request body from.</summary>
    private const string BodyArgument = "body";

    private static ToolOutcome Page(IReadOnlyList<LexicalSearchResult> results, string? continuation)
    {
        JsonArray items = [];

        foreach (LexicalSearchResult result in results)
        {
            JsonArray matched = [];

            foreach (string field in result.MatchedBy)
            {
                matched.Add(field);
            }

            // Exactly the bounded explainability fields. No per-signal breakdown, no vector
            // pointer, and no matched value: the metadata fields a query can match hold
            // curated text the format keeps out of every client-visible payload.
            items.Add(new JsonObject
            {
                ["operation"] = result.Operation,
                ["score"] = result.Score,
                ["matchedBy"] = matched,
                ["summary"] = result.Summary,
                ["risk"] = result.Risk,
            });
        }

        JsonObject page = new() { ["items"] = items };

        // Present only when there is a next page. A token that is sometimes null is one fact
        // rendered two ways; its presence is already the answer to whether more exist, and a
        // separate flag beside it would be a second fact that can disagree with the first.
        if (continuation is not null)
        {
            page[ContinuationArgument] = continuation;
        }

        return new ToolOutcome(Render(page), IsError: false);
    }

    /// <summary>
    /// Renders a payload as the bytes a caller receives.
    /// </summary>
    /// <remarks>
    /// Canonical rather than default serialization, so member order and escaping are fixed by
    /// the format instead of by whichever writer ran. Two Engines answering the same query
    /// against the same Manifest produce the same bytes, and so does the same Engine after a
    /// restart.
    /// </remarks>
    private static string Render(JsonNode payload) => Encoding.UTF8.GetString(CanonicalJson.Serialize(payload));

    /// <summary>Reads the caller's query vector, if it sent one.</summary>
    /// <remarks>
    /// Absent and malformed are kept apart. An unreadable vector read as an absent one would
    /// answer a semantic query with a lexical ranking and say nothing, which is the failure
    /// this whole argument exists to avoid.
    /// </remarks>
    private static bool TryVector(JsonObject arguments, out IReadOnlyList<double>? vector)
    {
        vector = null;

        if (arguments[QueryVectorArgument] is not { } sent)
        {
            return true;
        }

        if (sent is not JsonArray declared)
        {
            return false;
        }

        List<double> values = new(declared.Count);

        foreach (JsonNode? element in declared)
        {
            if (element is not JsonValue value)
            {
                return false;
            }

            try
            {
                if (!value.TryGetValue(out double number))
                {
                    return false;
                }

                values.Add(number);
            }
            catch (FormatException)
            {
                return false;
            }
        }

        vector = values;
        return true;
    }

    private static string? Text(JsonObject arguments, string name)
        => arguments[name] is JsonValue value && value.TryGetValue(out string? text) ? text : null;

    private static int? Integer(JsonObject arguments, string name)
    {
        if (arguments[name] is not JsonValue value)
        {
            return null;
        }

        try
        {
            return value.TryGetValue(out int number) ? number : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
