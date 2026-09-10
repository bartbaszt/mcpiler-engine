using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// What a client is served over Streamable HTTP: the catalogue, the addresses, and what an
/// address that names nothing discloses.
/// </summary>
public sealed class ToolsListTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-wire-" + Guid.NewGuid().ToString("N"));

    public ToolsListTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    /// <summary>
    /// A listing is the surface startup derived, not a second answer to the same question.
    /// </summary>
    /// <remarks>
    /// Asserted against the value the runtime produced rather than against a literal list.
    /// A literal would be satisfied by a serving path that derived its own set and happened to
    /// agree with the Manifest; this is only satisfied by the two reading one value.
    /// </remarks>
    [Fact]
    public async Task A_surface_advertises_exactly_what_startup_derived()
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            Options("/api", ServedManifests.OneSurface),
            TestContext.Current.CancellationToken);

        MountedSurface surface = Assert.Single(Assert.Single(engine.Started.Mounts).Surfaces);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            TestContext.Current.CancellationToken);

        McpExchange listed = await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, listed.Status);
        Assert.Equal(surface.ToolNames, Names(listed));
        Assert.NotEmpty(surface.ToolNames);
    }

    /// <summary>The advertised schema is the Manifest's own, and an absent one is unconstrained.</summary>
    [Fact]
    public async Task The_advertised_schema_is_the_declared_one_and_an_absent_one_constrains_nothing()
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            Options("/api", ServedManifests.OneSurface),
            TestContext.Current.CancellationToken);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            TestContext.Current.CancellationToken);

        McpExchange listed = await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken);

        JsonArray tools = Tools(listed);

        JsonNode declared = Assert.Single(
            tools,
            tool => string.Equals(tool!["name"]!.GetValue<string>(), "list-pets", StringComparison.Ordinal))!;
        JsonNode absent = Assert.Single(
            tools,
            tool => string.Equals(tool!["name"]!.GetValue<string>(), "add-pet", StringComparison.Ordinal))!;

        Assert.Equal("integer", declared["inputSchema"]!["properties"]!["limit"]!["type"]!.GetValue<string>());
        Assert.Equal("object", absent["inputSchema"]!["type"]!.GetValue<string>());
        Assert.Null(absent["inputSchema"]!["properties"]);
    }

    /// <summary>Enumerating twice serves the same bytes.</summary>
    [Fact]
    public async Task Repeated_enumeration_is_byte_identical()
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            Options("/api", ServedManifests.OneSurface),
            TestContext.Current.CancellationToken);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            TestContext.Current.CancellationToken);

        McpExchange first = await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken);
        McpExchange second = await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken);

        Assert.Equal(first.Payload, second.Payload);
        Assert.NotEmpty(first.Payload);
    }

    /// <summary>
    /// A restarted process serves the same bytes for the same Manifest.
    /// </summary>
    /// <remarks>
    /// The two hosts bind different ports, so anything address-dependent in a listing would
    /// show up here. Nothing about a tool set is a fact about where it was served from.
    /// </remarks>
    [Fact]
    public async Task A_restart_serves_the_same_bytes()
    {
        RuntimeOptions options = Options("/api", ServedManifests.OneSurface);

        string first = await ListAsync(options, "/api/full", TestContext.Current.CancellationToken);
        string second = await ListAsync(options, "/api/full", TestContext.Current.CancellationToken);

        Assert.Equal(first, second);
        Assert.NotEmpty(first);
    }

    /// <summary>
    /// The bare mount serves the default surface itself rather than pointing at it.
    /// </summary>
    /// <remarks>
    /// The two addresses are two protected resources. A redirect would move a client from the
    /// address its token names to one it does not, and the failure would arrive later as an
    /// audience mismatch nobody could trace to a route.
    /// </remarks>
    [Fact]
    public async Task The_default_route_serves_the_default_surface_and_is_not_a_redirect()
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            Options("/api", ServedManifests.ThreeSurfaces),
            TestContext.Current.CancellationToken);

        using McpHttpSession bare = await McpHttpSession.OpenAsync(
            engine.At("/api"),
            TestContext.Current.CancellationToken);
        using McpHttpSession qualified = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            TestContext.Current.CancellationToken);

        McpExchange atBare = await bare.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken);
        McpExchange atSlug = await qualified.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, atBare.Status);
        Assert.Equal(atSlug.Payload, atBare.Payload);
    }

    /// <summary>Each surface of one Manifest advertises its own compiled set.</summary>
    [Fact]
    public async Task Every_surface_advertises_its_own_set()
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            Options("/api", ServedManifests.ThreeSurfaces),
            TestContext.Current.CancellationToken);

        Dictionary<string, IReadOnlyList<string>> served = new(StringComparer.Ordinal);

        foreach (string slug in new[] { "read", "full", "write" })
        {
            using McpHttpSession session = await McpHttpSession.OpenAsync(
                engine.At("/api/" + slug),
                TestContext.Current.CancellationToken);

            served[slug] = Names(await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken));
        }

        Assert.Equal(["list-pets"], served["read"]);
        Assert.Equal(["add-pet"], served["write"]);
        Assert.Equal(["list-pets", "add-pet"], served["full"]);
    }

    /// <summary>
    /// Two Manifests in one process share no tool namespace, even when the names collide.
    /// </summary>
    [Fact]
    public async Task Two_mounts_advertise_only_their_own_tools()
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            new RuntimeOptions(
                [
                    new MountRequest("/pets", ServedManifests.Write(_root, "pets", ServedManifests.OneSurface)),
                    new MountRequest("/weather", ServedManifests.Write(_root, "weather", ServedManifests.CollidingNames)),
                ],
                Store()),
            TestContext.Current.CancellationToken);

        using McpHttpSession pets = await McpHttpSession.OpenAsync(
            engine.At("/pets"),
            TestContext.Current.CancellationToken);
        using McpHttpSession weather = await McpHttpSession.OpenAsync(
            engine.At("/weather"),
            TestContext.Current.CancellationToken);

        McpExchange atPets = await pets.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken);
        McpExchange atWeather = await weather.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken);

        Assert.Equal(["list-pets", "add-pet"], Names(atPets));
        Assert.Equal(["list-pets"], Names(atWeather));

        // The colliding name resolves to a different tool on each mount, which is the whole
        // claim: one name, two servers, nothing shared.
        Assert.Contains("Lists every pet.", atPets.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("Lists every pet.", atWeather.Payload, StringComparison.Ordinal);
    }

    /// <summary>
    /// An address that names no mount and one that names no surface both disclose nothing.
    /// </summary>
    /// <remarks>
    /// Mapping every address explicitly is what makes this hold without a refusal of its own:
    /// neither request reaches a handler, so neither can answer with a mount name, a surface
    /// list or a tool. The assertion is about the bytes, because a refusal that differed would
    /// be an oracle for which mounts and slugs exist.
    /// </remarks>
    [Theory]
    [InlineData("/nope")]
    [InlineData("/api/nosuch")]
    [InlineData("/api/full/deeper")]
    [InlineData("/")]
    public async Task An_address_that_names_nothing_discloses_nothing(string route)
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            Options("/api", ServedManifests.ThreeSurfaces),
            TestContext.Current.CancellationToken);

        McpExchange refused = await McpHttpSession.SendAsync(
            engine.At(route),
            "tools/list",
            1,
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, refused.Status);

        // Nothing at all, which is the strongest form of disclosing nothing. If a body ever
        // appears here it is a new disclosure surface and deserves to be reviewed rather than
        // to slip past a check that only looked for today's identifiers.
        Assert.Empty(refused.Body);
    }

    /// <summary>
    /// A Manifest no address could resolve is refused before anything listens.
    /// </summary>
    /// <remarks>
    /// Both halves are load failures rather than routing failures. With no default the bare
    /// mount has nothing to serve; with two, which one it serves would depend on iteration
    /// order, and an operator cannot see iteration order.
    /// </remarks>
    [Theory]
    [InlineData("no-default", "surface/no-default")]
    [InlineData("two-defaults", "surface/multiple-defaults")]
    public void A_manifest_that_cannot_address_its_default_is_refused_at_load(string name, string code)
    {
        string manifest = string.Equals(name, "no-default", StringComparison.Ordinal)
            ? ServedManifests.NoDefaultSurface
            : ServedManifests.TwoDefaultSurfaces;

        string path = ServedManifests.Write(_root, name, manifest);

        RuntimeStartResult result = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", path)], Store()));

        Assert.False(result.Started);
        Assert.Empty(result.Mounts);

        StartupRefusal refusal = Assert.Single(result.Refusals, candidate => string.Equals(candidate.Code, code, StringComparison.Ordinal));
        Assert.Equal(path, refusal.Manifest);
    }

    /// <summary>
    /// The server offers tools, and of the product's capabilities nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Absence is the assertion. A capability advertised but unimplemented invites a client to
    /// call it, and the failure then looks like a fault rather than a boundary.
    /// </para>
    /// <para>
    /// <c>logging</c> is the exception and is expected. The SDK implements the level request
    /// itself, so advertising it is honest rather than a promise about a Manifest; it is not a
    /// surface this product decides anything about, and the Studio advertises it for the same
    /// reason. What must stay absent is every capability that would imply the product serves
    /// something a Manifest describes.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Only_the_tool_capability_is_offered()
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            Options("/api", ServedManifests.OneSurface),
            TestContext.Current.CancellationToken);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            TestContext.Current.CancellationToken);

        JsonNode capabilities = JsonNode.Parse(session.Handshake)!["result"]!["capabilities"]!;

        Assert.NotNull(capabilities["tools"]);

        foreach (string absent in new[] { "resources", "prompts", "completions" })
        {
            Assert.Null(capabilities[absent]);
        }

        // Asked for as well as read off the handshake, because a capability a server does not
        // advertise and still answers is the same surface with worse documentation.
        foreach (string method in new[] { "resources/list", "prompts/list", "completion/complete" })
        {
            McpExchange refused = await session.RequestAsync(method, 3, TestContext.Current.CancellationToken);

            Assert.Contains("\"error\"", refused.Payload, StringComparison.Ordinal);
        }
    }

    private async Task<string> ListAsync(RuntimeOptions options, string route, CancellationToken cancellationToken)
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(options, cancellationToken);
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At(route), cancellationToken);

        return (await session.RequestAsync("tools/list", 2, cancellationToken)).Payload;
    }

    private RuntimeOptions Options(string prefix, string manifest)
        => new(
            [new MountRequest(prefix, ServedManifests.Write(_root, prefix.Trim('/'), manifest))],
            Store());

    private string Store()
    {
        string store = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(store);
        return store;
    }

    private static JsonArray Tools(McpExchange exchange)
        => JsonNode.Parse(exchange.Payload)?["result"]?["tools"] as JsonArray
            ?? throw new JsonException("The payload carried no tool list: " + exchange.Body);

    private static IReadOnlyList<string> Names(McpExchange exchange)
        => [.. Tools(exchange).Select(tool => tool!["name"]!.GetValue<string>())];
}
