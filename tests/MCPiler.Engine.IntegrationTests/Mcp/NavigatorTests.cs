using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// The Navigator over Streamable HTTP: discovering an operation, reading its contract, and
/// running it without it ever having been advertised.
/// </summary>
/// <remarks>
/// The journey is the test. Each of the three tools is verifiable alone, but the property
/// that matters is that the identifier discovery returns is the identifier description accepts
/// and invocation runs — a caller that has to translate between two spellings of an operation
/// has not been given a catalogue, it has been given a puzzle.
/// </remarks>
public sealed class NavigatorTests : IDisposable
{
    private readonly List<string> _roots = [];

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Discovery_describes_and_invokes_an_operation_the_listing_never_showed()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", """{"quiet":true}""");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var discovered = await session.CallAsync(
            "catalogue.discover",
            """{"query":"quiet"}""",
            2,
            Token);

        JsonElement page = Payload(discovered);
        string operation = page.GetProperty("items")[0].GetProperty("operation").GetString()!;

        Assert.Equal("quiet-pet", operation);

        var described = await session.CallAsync(
            "catalogue.describe",
            $$"""{"operationKey":"{{operation}}"}""",
            3,
            Token);

        Assert.Equal(operation, Payload(described).GetProperty("operation").GetString());

        var invoked = await session.CallAsync(
            "catalogue.invoke",
            "{\"operationKey\":\"" + operation + "\",\"arguments\":{}}",
            4,
            Token);

        Assert.Equal("""{"quiet":true}""", Text(invoked));

        // One request, for the invocation. Discovery and description read the Manifest.
        Assert.Equal(["GET /pets/quiet"], received);
    }

    [Fact]
    public async Task A_navigator_exposed_operation_is_absent_from_the_listing_it_is_reachable_behind()
    {
        await using var upstream = await Recording([], 200, "application/json", "{}");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var listed = await session.RequestAsync("tools/list", 2, Token);

        Assert.DoesNotContain("quiet-pet", listed.Payload, StringComparison.Ordinal);
        Assert.Contains("catalogue.discover", listed.Payload, StringComparison.Ordinal);

        var named = await session.CallAsync("quiet-pet", "{}", 3, Token);

        // Directly it is simply not there; through the Navigator it runs. That is the whole
        // difference navigator exposure buys, and it has to hold on both paths at once.
        Assert.Contains("\"isError\":true", named.Payload, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_hidden_operation_is_refused_by_the_navigator_exactly_as_an_invented_one()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "{}");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var hidden = await session.CallAsync(
            "catalogue.invoke",
            """{"operationKey":"hidden-pet","arguments":{}}""",
            2,
            Token);

        var invented = await session.CallAsync(
            "catalogue.invoke",
            """{"operationKey":"no-such-pet","arguments":{}}""",
            3,
            Token);

        // The Navigator is the escape from a listing, so it is also the place an existence
        // oracle would be most useful to an attacker: every identifier can be tried here.
        Assert.Equal(
            Text(hidden).Replace("hidden-pet", "no-such-pet", StringComparison.Ordinal),
            Text(invented));

        Assert.Empty(received);
    }

    [Fact]
    public async Task A_hidden_operation_occupies_no_position_in_any_page()
    {
        await using var upstream = await Recording([], 200, "application/json", "{}");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        List<string> seen = [];
        string? continuation = null;
        int id = 2;

        do
        {
            string arguments = continuation is null
                ? """{"pageSize":1}"""
                : $$"""{"pageSize":1,"continuation":"{{continuation}}"}""";

            JsonElement page = Payload(await session.CallAsync("catalogue.discover", arguments, id++, Token));

            seen.AddRange(page.GetProperty("items").EnumerateArray()
                .Select(item => item.GetProperty("operation").GetString()!));

            continuation = page.TryGetProperty("continuation", out JsonElement token)
                ? token.GetString()
                : null;
        }
        while (continuation is not null);

        Assert.Equal(["get-pet", "list-pets", "quiet-pet"], seen);
    }

    [Fact]
    public async Task A_page_size_beyond_the_advertised_maximum_is_refused_by_the_contract_that_advertised_it()
    {
        await using var upstream = await Recording([], 200, "application/json", "{}");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync("catalogue.discover", """{"pageSize":500}""", 2, Token);

        // The Navigator's own arguments go through the same validation every other tool's do.
        // A bound published in a listing that nothing enforced would be decoration.
        Assert.Contains("\"isError\":true", call.Payload, StringComparison.Ordinal);
        Assert.Contains("advertised input schema", Text(call), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_same_query_answers_identically_across_restarts()
    {
        await using var upstream = await Recording([], 200, "application/json", "{}");

        string first = await PageAsync(upstream.Address);
        string second = await PageAsync(upstream.Address);

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task A_continuation_from_one_surface_does_not_page_another()
    {
        await using var upstream = await Recording([], 200, "application/json", "{}");
        await using var engine = await ServeAsync(upstream.Address);

        using var full = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);
        JsonElement page = Payload(await full.CallAsync("catalogue.discover", """{"pageSize":1}""", 2, Token));
        string token = page.GetProperty("continuation").GetString()!;

        using var read = await McpHttpSession.OpenAsync(engine.At("api/read"), Token);
        var resumed = await read.CallAsync(
            "catalogue.discover",
            $$"""{"pageSize":1,"continuation":"{{token}}"}""",
            2,
            Token);

        Assert.Contains("\"isError\":true", resumed.Payload, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_invocation_the_target_schema_refuses_costs_no_upstream_request()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "[]");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync(
            "catalogue.invoke",
            """{"operationKey":"list-pets","arguments":{"status":7}}""",
            2,
            Token);

        // The Navigator validates against the operation's contract, not against its own. A
        // second entrance that skipped it would be a way around every advertised schema.
        Assert.Contains("\"isError\":true", call.Payload, StringComparison.Ordinal);
        Assert.Empty(received);
    }

    [Fact]
    public async Task Description_names_where_each_argument_is_transmitted()
    {
        await using var upstream = await Recording([], 200, "application/json", "{}");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        JsonElement described = Payload(
            await session.CallAsync("catalogue.describe", """{"operationKey":"get-pet"}""", 2, Token));

        JsonElement argument = described.GetProperty("arguments")[0];

        Assert.Equal("petId", argument.GetProperty("name").GetString());
        Assert.Equal("path", argument.GetProperty("in").GetString());
        Assert.True(argument.GetProperty("required").GetBoolean());
    }

    public void Dispose()
    {
        foreach (string root in _roots)
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private async Task<string> PageAsync(Uri upstream)
    {
        await using var engine = await ServeAsync(upstream);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        return Text(await session.CallAsync("catalogue.discover", """{"query":"pets"}""", 2, Token));
    }

    /// <summary>The text block of a call result, parsed as the JSON payload it carries.</summary>
    private static JsonElement Payload(McpExchange exchange)
        => JsonDocument.Parse(Text(exchange)).RootElement.Clone();

    private static string Text(McpExchange exchange)
    {
        using var document = JsonDocument.Parse(exchange.Payload);

        return document.RootElement
            .GetProperty("result")
            .GetProperty("content")[0]
            .GetProperty("text")
            .GetString()!;
    }

    private static Task<LoopbackHost> Recording(
        List<string> received,
        int statusCode,
        string mediaType,
        string body)
        => LoopbackHost.StartAsync(
            async context =>
            {
                lock (received)
                {
                    received.Add(context.Request.Method + " " + context.Request.Path + context.Request.QueryString);
                }

                byte[] bytes = Encoding.UTF8.GetBytes(body);

                context.Response.StatusCode = statusCode;
                context.Response.ContentType = mediaType;
                context.Response.ContentLength = bytes.Length;

                await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
            },
            Token);

    private async Task<ServedEngine> ServeAsync(Uri upstream)
    {
        string root = Path.Combine(Path.GetTempPath(), "mcpiler-nav-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);

        string bundle = ServedManifests.Write(root, "pets", ServedManifests.Upstream(upstream));
        string files = Directory.CreateDirectory(Path.Combine(root, "files")).FullName;

        return await ServedEngine.StartAsync(new RuntimeOptions([new MountRequest("/api", bundle)], files), Token);
    }
}
