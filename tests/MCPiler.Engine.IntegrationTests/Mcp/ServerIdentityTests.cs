using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// What a server says it is when a client finishes the handshake.
/// </summary>
/// <remarks>
/// A deployable serves several Manifests, so this is the field that tells a client which of
/// them it reached. Every assertion here reads the wire rather than the seam: the seam can
/// carry a correct identity and the transport can still send its own.
/// </remarks>
public sealed class ServerIdentityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-identity-" + Guid.NewGuid().ToString("N"));

    public ServerIdentityTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    /// <summary>A surface introduces itself with what its Manifest declared.</summary>
    [Fact]
    public async Task A_surface_is_introduced_by_its_Manifest()
    {
        JsonNode identity = await IdentifyAsync(
            Options("/api", ServedManifests.Identified),
            "/api/read",
            TestContext.Current.CancellationToken);

        Assert.Equal("Pet API", Text(identity, "name"));
        Assert.Equal("3.1.4", Text(identity, "version"));
        Assert.Equal("Everything about pets.", Text(identity, "description"));
    }

    /// <summary>The executable's own name and version never reach a client.</summary>
    /// <remarks>
    /// The defect this replaces was not a missing field but a present and wrong one, so the
    /// assertion is about absence from the whole handshake rather than about the value of one
    /// member. A transport that set the identity correctly and also mentioned itself elsewhere
    /// would still be telling a client about the wrong thing.
    /// </remarks>
    [Fact]
    public async Task The_handshake_never_names_the_executable()
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            Options("/api", ServedManifests.Identified),
            TestContext.Current.CancellationToken);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/read"),
            TestContext.Current.CancellationToken);

        foreach (string leaked in new[] { "MCPiler.Engine.Host", "mcpiler-engine", "0.0.1-alpha" })
        {
            Assert.DoesNotContain(leaked, session.Handshake, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Two Manifests on one process are two identities, not one.
    /// </summary>
    [Fact]
    public async Task Two_mounts_introduce_themselves_differently()
    {
        RuntimeOptions options = new(
            [
                new MountRequest("/api", ServedManifests.Write(_root, "api", ServedManifests.Identified)),
                new MountRequest("/weather", ServedManifests.Write(_root, "weather", ServedManifests.CollidingNames)),
            ],
            Store());

        await using ServedEngine engine = await ServedEngine.StartAsync(options, TestContext.Current.CancellationToken);

        Assert.Equal("Pet API", Text(await IdentifyAsync(engine, "/api"), "name"));
        Assert.Equal("Weather API", Text(await IdentifyAsync(engine, "/weather"), "name"));
    }

    /// <summary>
    /// A surface the Manifest named carries that name; one it did not carries no title.
    /// </summary>
    /// <remarks>
    /// Both halves against one document, because the interesting case is the pair: a title
    /// that merely repeated the slug would pass an assertion about the named surface and tell
    /// a client nothing it did not already read out of the address it used.
    /// </remarks>
    [Fact]
    public async Task A_title_is_sent_only_where_the_Manifest_authored_one()
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(
            Options("/api", ServedManifests.Identified),
            TestContext.Current.CancellationToken);

        Assert.Equal("Read only", Text(await IdentifyAsync(engine, "/api/read"), "title"));
        Assert.Null((await IdentifyAsync(engine, "/api/full"))["title"]);
    }

    /// <summary>
    /// A Manifest that declares no version states none rather than borrowing one.
    /// </summary>
    [Fact]
    public async Task An_undeclared_version_is_stated_as_unknown()
    {
        JsonNode identity = await IdentifyAsync(
            Options("/api", ServedManifests.OneSurface),
            "/api/full",
            TestContext.Current.CancellationToken);

        Assert.Equal("Pet API", Text(identity, "name"));
        Assert.Equal(string.Empty, Text(identity, "version"));
        Assert.Null(identity["description"]);
    }

    private async Task<JsonNode> IdentifyAsync(
        RuntimeOptions options,
        string route,
        CancellationToken cancellationToken)
    {
        await using ServedEngine engine = await ServedEngine.StartAsync(options, cancellationToken);

        return await IdentifyAsync(engine, route);
    }

    private static async Task<JsonNode> IdentifyAsync(ServedEngine engine, string route)
    {
        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At(route),
            TestContext.Current.CancellationToken);

        return JsonNode.Parse(session.Handshake)?["result"]?["serverInfo"]
            ?? throw new InvalidOperationException("The handshake carried no server identity: " + session.Handshake);
    }

    private static string? Text(JsonNode identity, string member)
        => identity[member]?.GetValue<string>();

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
}
