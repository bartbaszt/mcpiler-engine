using System.Text.Json.Nodes;

using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Manifest.Validation;
using MCPiler.Engine.Mcp;
using MCPiler.Engine.Mcp.Navigator;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.UnitTests.Mcp;

/// <summary>
/// Discovery and description: what a caller is shown, and what it is never shown.
/// </summary>
public sealed class NavigatorRuntimeTests
{
    [Fact]
    public void Discovery_with_no_query_lists_every_reachable_operation()
    {
        // Direct and Navigator-exposed alike: exposure decides whether an identifier resolves,
        // and both of those say it does. The hidden one is the whole point of the assertion.
        Assert.Equal(
            ["add-pet", "list-pets", "quiet-pet"],
            Operations(Discover(new JsonObject())));
    }

    [Fact]
    public void A_hidden_operation_is_absent_from_every_page()
    {
        List<string> seen = [];
        string? continuation = null;

        do
        {
            JsonObject page = Discover(Arguments(pageSize: 1, continuation: continuation));
            seen.AddRange(Operations(page));
            continuation = (page["continuation"] as JsonValue)?.GetValue<string>();
        }
        while (continuation is not null);

        // Not in the items, and not in the accounting either: three positions for three
        // reachable operations, so the hidden one occupied none of them.
        Assert.Equal(["add-pet", "list-pets", "quiet-pet"], seen);
    }

    [Fact]
    public void A_page_carries_exactly_the_bounded_explainability_fields()
    {
        JsonObject item = (JsonObject)Discover(new JsonObject())["items"]!.AsArray()[0]!;

        // Closed on purpose. A field added here reaches every caller of every Manifest, and
        // the ones that would be tempting — a score breakdown, a matched value, an index
        // pointer — are each a disclosure the format spent effort preventing.
        Assert.Equal(
            ["matchedBy", "operation", "risk", "score", "summary"],
            Members(item));
    }

    [Fact]
    public void A_page_carries_a_continuation_only_when_one_is_owed()
    {
        Assert.Equal(["items"], Members(Discover(new JsonObject())));
        Assert.Equal(["continuation", "items"], Members(Discover(Arguments(pageSize: 1))));
    }

    [Fact]
    public void The_count_of_operations_a_surface_filtered_out_never_reaches_a_caller()
    {
        // The ranker counts them for an operator. Handed to a caller it would be a tally of
        // exactly the operations hidden from it, which is the fact hiding them removed.
        MountedManifest mount = Mount();
        string rendered = NavigatorRuntime.Discover(mount, Surface(mount, "full"), new JsonObject()).Text;

        Assert.DoesNotContain("filtered", rendered, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(["items"], Members(Parse(rendered)));
    }

    [Fact]
    public void Paging_visits_every_operation_once()
    {
        List<string> byOnes = [];
        string? continuation = null;

        do
        {
            JsonObject page = Discover(Arguments(pageSize: 1, continuation: continuation));
            byOnes.AddRange(Operations(page));
            continuation = (page["continuation"] as JsonValue)?.GetValue<string>();
        }
        while (continuation is not null);

        Assert.Equal(Operations(Discover(new JsonObject())), byOnes);
        Assert.Equal(byOnes.Distinct(StringComparer.Ordinal).Count(), byOnes.Count);
    }

    [Fact]
    public void The_same_query_renders_the_same_bytes()
    {
        MountedManifest first = Mount();
        MountedManifest second = Mount();

        Assert.Equal(
            NavigatorRuntime.Discover(first, Surface(first, "full"), Arguments(query: "pets")).Text,
            NavigatorRuntime.Discover(second, Surface(second, "full"), Arguments(query: "pets")).Text);
    }

    [Fact]
    public void A_continuation_issued_for_another_query_is_refused()
    {
        string token = (Discover(Arguments(pageSize: 1))["continuation"] as JsonValue)!.GetValue<string>();

        MountedManifest mount = Mount();
        ToolOutcome outcome = NavigatorRuntime.Discover(
            mount,
            Surface(mount, "full"),
            Arguments(query: "pets", pageSize: 1, continuation: token));

        Assert.True(outcome.IsError);
        Assert.Equal(NavigatorRuntime.StaleContinuation, outcome.Text);
    }

    [Fact]
    public void A_continuation_issued_for_another_surface_is_refused()
    {
        string token = (Discover(Arguments(pageSize: 1))["continuation"] as JsonValue)!.GetValue<string>();

        MountedManifest mount = Mount();
        ToolOutcome outcome = NavigatorRuntime.Discover(
            mount,
            Surface(mount, "read"),
            Arguments(pageSize: 1, continuation: token));

        // Two surfaces rank two different lists. A position in one is not a position in the
        // other, and resuming there would silently skip whatever the offsets disagree about.
        Assert.True(outcome.IsError);
    }

    [Fact]
    public void A_query_matching_nothing_returns_an_empty_page()
    {
        JsonObject page = Discover(Arguments(query: "zzzznothingmatchesthis"));

        Assert.Empty(page["items"]!.AsArray());
        Assert.Equal(["items"], Members(page));
    }

    [Fact]
    public void A_query_narrows_the_page_to_what_it_matched()
    {
        IReadOnlyList<string> matched = Operations(Discover(Arguments(query: "quiet")));

        Assert.Equal(["quiet-pet"], matched);
    }

    [Fact]
    public void Description_states_the_contract_and_nothing_beyond_it()
    {
        JsonObject described = Describe("list-pets");

        Assert.Equal(["arguments", "description", "operation"], Members(described));
        Assert.Equal("list-pets", described["operation"]!.GetValue<string>());

        JsonObject argument = (JsonObject)described["arguments"]!.AsArray()[0]!;

        Assert.Equal(["file", "in", "name", "required"], Members(argument));
        Assert.Equal("status", argument["name"]!.GetValue<string>());
        Assert.Equal("query", argument["in"]!.GetValue<string>());
        Assert.True(argument["required"]!.GetValue<bool>());
        Assert.False(argument["file"]!.GetValue<bool>());
    }

    [Fact]
    public void Description_reports_where_a_body_argument_is_transmitted_and_which_argument_carries_a_file()
    {
        JsonArray arguments = Describe("add-pet")["arguments"]!.AsArray();

        JsonObject body = arguments.OfType<JsonObject>().Single(a => a["name"]!.GetValue<string>() == "body");
        JsonObject photo = arguments.OfType<JsonObject>().Single(a => a["name"]!.GetValue<string>() == "photo");

        Assert.Equal("body", body["in"]!.GetValue<string>());
        Assert.False(body["file"]!.GetValue<bool>());
        Assert.True(photo["file"]!.GetValue<bool>());
    }

    [Fact]
    public void Description_omits_a_location_it_cannot_resolve()
    {
        // The photo slot is an argument of the tool, not a declared wire parameter. Naming a
        // location for it would claim a placement the binding does not state.
        JsonObject photo = Describe("add-pet")["arguments"]!
            .AsArray()
            .OfType<JsonObject>()
            .Single(a => a["name"]!.GetValue<string>() == "photo");

        Assert.Equal(["file", "name", "required"], Members(photo));
    }

    [Fact]
    public void Description_reaches_an_operation_the_surface_never_advertises()
    {
        MountedManifest mount = Mount();

        Assert.DoesNotContain("quiet-pet", Surface(mount, "full").ToolNames);
        Assert.Equal("quiet-pet", Describe("quiet-pet")["operation"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("secret-pet")]
    [InlineData("list-pets")]
    public void An_operation_the_surface_cannot_reach_answers_exactly_as_an_invented_one(string named)
    {
        MountedManifest mount = Mount();

        // On the read surface neither exists: one is not listed there at all, the other is
        // hidden. Byte-identical, because any difference tells the caller which it found.
        ToolOutcome refused = NavigatorRuntime.Describe(
            mount,
            Surface(mount, "read"),
            new JsonObject { ["operationKey"] = named });

        ToolOutcome invented = NavigatorRuntime.Describe(
            mount,
            Surface(mount, "read"),
            new JsonObject { ["operationKey"] = "no-such-operation" });

        Assert.True(refused.IsError);
        Assert.Equal(NavigatorRuntime.UnknownOperation(named), refused.Text);
        Assert.Equal(refused.Text.Replace(named, "no-such-operation", StringComparison.Ordinal), invented.Text);
    }

    [Fact]
    public void An_unnamed_operation_is_refused_rather_than_resolved()
    {
        MountedManifest mount = Mount();
        ToolOutcome outcome = NavigatorRuntime.Describe(mount, Surface(mount, "full"), new JsonObject());

        Assert.True(outcome.IsError);
    }

    [Fact]
    public void A_caller_that_asks_for_no_page_size_gets_the_one_the_surface_declares()
    {
        MountedManifest mount = Mount(SmallPages);
        ToolOutcome outcome = NavigatorRuntime.Discover(mount, Surface(mount, "full"), new JsonObject());

        JsonObject page = Parse(outcome.Text);

        // Two of three, and a token for the rest. The default is the surface's own declaration
        // rather than a constant here, which is what the advertised schema promised when it
        // published that number as the argument's default.
        Assert.Equal(["add-pet", "list-pets"], Operations(page));
        Assert.Contains("continuation", Members(page), StringComparer.Ordinal);
    }

    private static JsonObject Discover(JsonObject arguments)
    {
        MountedManifest mount = Mount();
        ToolOutcome outcome = NavigatorRuntime.Discover(mount, Surface(mount, "full"), arguments);

        Assert.False(outcome.IsError);

        return Parse(outcome.Text);
    }

    private static JsonObject Describe(string operation)
    {
        MountedManifest mount = Mount();
        ToolOutcome outcome = NavigatorRuntime.Describe(
            mount,
            Surface(mount, "full"),
            new JsonObject { ["operationKey"] = operation });

        Assert.False(outcome.IsError);

        return Parse(outcome.Text);
    }

    private static JsonObject Arguments(string? query = null, int? pageSize = null, string? continuation = null)
    {
        JsonObject arguments = [];

        if (query is not null)
        {
            arguments["query"] = query;
        }

        if (pageSize is { } size)
        {
            arguments["pageSize"] = size;
        }

        if (continuation is not null)
        {
            arguments["continuation"] = continuation;
        }

        return arguments;
    }

    private static IReadOnlyList<string> Operations(JsonObject page)
        => [.. page["items"]!.AsArray().Select(item => item!["operation"]!.GetValue<string>())];

    private static IReadOnlyList<string> Members(JsonObject value)
        => [.. value.Select(static member => member.Key).Order(StringComparer.Ordinal)];

    private static JsonObject Parse(string text) => (JsonObject)JsonNode.Parse(text)!;

    private static MountedSurface Surface(MountedManifest mount, string slug)
        => mount.Surfaces.Single(surface => string.Equals(surface.Slug, slug, StringComparison.Ordinal));

    private static MountedManifest Mount() => Mount(Catalogue);

    private static MountedManifest Mount(string manifestText)
    {
        ManifestDocument manifest = Load(manifestText);
        List<ManifestDiagnostic> diagnostics = [];

        List<MountedSurface> surfaces =
            [.. manifest.Server.Surfaces.Select(surface => SurfaceCatalogue.Build(manifest, surface, diagnostics))];

        NavigatorIndex index = NavigatorIndex.Resolve(manifest, diagnostics);

        Assert.DoesNotContain(diagnostics, static diagnostic => diagnostic.IsError);

        return new MountedManifest("/api", "bundle", manifest, manifest.Policy, surfaces, index);
    }

    private static ManifestDocument Load(string manifestText)
    {
        var result = ManifestReader.Read(InMemoryManifestSource.FromText(manifestText));
        Assert.True(result.Succeeded);
        return result.Manifest!;
    }

    /// <summary>A surface that declares a page size smaller than its catalogue.</summary>
    private const string SmallPages = """
        {
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "surfaces": [
                  {
                    "slug": "full",
                    "isDefault": true,
                    "navigator": { "enabled": true, "pageSize": 2 },
                    "operations": [
                      { "operation": "list-pets" },
                      { "operation": "add-pet" },
                      { "operation": "quiet-pet" }
                    ]
                  }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": {
                "operations": [
                  { "key": "GET /pets", "method": "GET", "path": "/pets" },
                  { "key": "POST /pets", "method": "POST", "path": "/pets" },
                  { "key": "GET /pets/quiet", "method": "GET", "path": "/pets/quiet" }
                ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  { "slug": "list-pets", "name": "List pets", "binding": { "type": "http", "operation": "GET /pets" } },
                  { "slug": "add-pet", "name": "Add pet", "binding": { "type": "http", "operation": "POST /pets" } },
                  { "slug": "quiet-pet", "name": "Quiet pet", "binding": { "type": "http", "operation": "GET /pets/quiet" } }
                ]
              }
            }
          }
        }
        """;

    private const string Catalogue = """
        {
          "manifestFormatVersion": "0.2",
          "sections": {
            "server": {
              "inline": {
                "name": "Pet API",
                "surfaces": [
                  {
                    "slug": "full",
                    "isDefault": true,
                    "navigator": { "enabled": true },
                    "operations": [
                      { "operation": "list-pets" },
                      { "operation": "add-pet" },
                      { "operation": "quiet-pet", "exposure": "navigator" },
                      { "operation": "secret-pet", "exposure": "hidden" }
                    ]
                  },
                  {
                    "slug": "read",
                    "navigator": { "enabled": true },
                    "operations": [
                      { "operation": "list-pets", "exposure": "hidden" }
                    ]
                  }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "https://api.example.com" } },
            "operations": {
              "inline": {
                "operations": [
                  {
                    "key": "GET /pets",
                    "method": "GET",
                    "path": "/pets",
                    "parameters": [
                      { "name": "status", "in": "query", "required": true, "schema": { "type": "string" } }
                    ]
                  },
                  {
                    "key": "POST /pets",
                    "method": "POST",
                    "path": "/pets",
                    "requestBody": {
                      "required": true,
                      "content": { "application/json": { "schema": { "type": "object" } } }
                    }
                  },
                  { "key": "GET /pets/quiet", "method": "GET", "path": "/pets/quiet" },
                  { "key": "DELETE /pets", "method": "DELETE", "path": "/pets" }
                ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  {
                    "slug": "list-pets",
                    "name": "List pets",
                    "summary": "Lists pets by status.",
                    "inputSchema": {
                      "type": "object",
                      "properties": { "status": { "type": "string" } },
                      "required": ["status"]
                    },
                    "binding": { "type": "http", "operation": "GET /pets" }
                  },
                  {
                    "slug": "add-pet",
                    "name": "Add pet",
                    "summary": "Adds a pet.",
                    "inputSchema": {
                      "type": "object",
                      "properties": {
                        "body": { "type": "object" },
                        "photo": { "type": "string", "x-mcp-file": true }
                      }
                    },
                    "binding": { "type": "http", "operation": "POST /pets" }
                  },
                  {
                    "slug": "quiet-pet",
                    "name": "Quiet pet",
                    "summary": "A quiet operation reached only through the catalogue.",
                    "binding": { "type": "http", "operation": "GET /pets/quiet" }
                  },
                  {
                    "slug": "secret-pet",
                    "name": "Secret pet",
                    "summary": "Never reachable.",
                    "binding": { "type": "http", "operation": "DELETE /pets" }
                  }
                ]
              }
            }
          }
        }
        """;
}
