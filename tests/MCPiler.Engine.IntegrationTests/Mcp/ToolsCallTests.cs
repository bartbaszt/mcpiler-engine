using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// <c>tools/call</c> over Streamable HTTP, from the name a client sends to the request an
/// upstream receives.
/// </summary>
/// <remarks>
/// The upstream is a real listener rather than a substituted message handler, because the
/// claims under test are about what did and did not leave the process. "No request was sent"
/// is asserted against a server that counted its requests, not inferred from a return value.
/// </remarks>
public sealed class ToolsCallTests : IDisposable
{
    private readonly List<string> _roots = [];

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_call_reaches_the_upstream_and_the_answer_comes_back()
    {
        List<string> received = [];

        await using var upstream = await Recording(
            received,
            200,
            "application/json",
            """[{"id":1,"name":"Rex"}]""");

        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync("list-pets", """{"status":"available"}""", 2, Token);

        Assert.Equal(HttpStatusCode.OK, call.Status);
        Assert.Equal("""[{"id":1,"name":"Rex"}]""", Text(call));
        Assert.DoesNotContain("\"isError\"", call.Payload, StringComparison.Ordinal);
        Assert.Equal(["GET /pets?status=available"], received);
    }

    [Fact]
    public async Task A_path_argument_is_compiled_into_the_upstream_path()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", """{"id":"p-7"}""");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        _ = await session.CallAsync("get-pet", """{"petId":"p-7"}""", 2, Token);

        Assert.Equal(["GET /pets/p-7"], received);
    }

    [Fact]
    public async Task An_argument_the_advertised_schema_refuses_costs_no_upstream_request()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "[]");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync("list-pets", """{"status":7}""", 2, Token);

        Assert.Contains("\"isError\":true", call.Payload, StringComparison.Ordinal);
        Assert.Contains("advertised input schema", Text(call), StringComparison.Ordinal);

        // The claim this test exists for. A refusal that still opened a connection would have
        // spent a credential and an upstream rate budget to reject an argument.
        Assert.Empty(received);
    }

    [Fact]
    public async Task A_missing_required_argument_costs_no_upstream_request()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "[]");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync("list-pets", "{}", 2, Token);

        Assert.Contains("\"isError\":true", call.Payload, StringComparison.Ordinal);
        Assert.Empty(received);
    }

    [Fact]
    public async Task A_name_the_surface_does_not_advertise_is_refused_without_reaching_anything()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "[]");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync("no-such-tool", "{}", 2, Token);

        Assert.Contains("\"isError\":true", call.Payload, StringComparison.Ordinal);
        Assert.Equal("No tool named 'no-such-tool' is available here.", Text(call));
        Assert.Empty(received);
    }

    [Fact]
    public async Task A_hidden_operation_is_refused_exactly_as_a_name_that_never_existed_is()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "[]");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        // 'hidden-pet' is a real operation the Manifest excludes from advertisement. The tool
        // name derived from it is 'hidden-pet', and a caller who guessed it must learn nothing
        // from the answer. Group F states this as its own requirement; asserting it here keeps
        // the property from being introduced later against code that already violated it.
        var hidden = await session.CallAsync("hidden-pet", "{}", 2, Token);
        var absent = await session.CallAsync("hidden-pet-x", "{}", 3, Token);

        Assert.Equal(
            hidden.Payload.Replace("\"id\":2", "\"id\":ID", StringComparison.Ordinal),
            absent.Payload
                .Replace("\"id\":3", "\"id\":ID", StringComparison.Ordinal)
                .Replace("hidden-pet-x", "hidden-pet", StringComparison.Ordinal));

        Assert.Empty(received);
    }

    [Fact]
    public async Task An_unsuccessful_upstream_status_is_not_a_tool_error()
    {
        List<string> received = [];

        await using var upstream = await Recording(
            received,
            404,
            "application/json",
            """{"code":"not_found"}""");

        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync("get-pet", """{"petId":"gone"}""", 2, Token);

        // The upstream answered. Calling that a tool error would tell a caller its request was
        // malformed when the request was fine and the resource was not there.
        Assert.DoesNotContain("\"isError\"", call.Payload, StringComparison.Ordinal);
        Assert.Equal("""{"code":"not_found"}""", Text(call));
        Assert.Equal(["GET /pets/gone"], received);
    }

    [Fact]
    public async Task The_shipped_address_policy_is_in_the_invocation_path()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "[]");

        // The real outbound policy this time. Loopback is a denied range, and a served engine
        // that reached it anyway would mean the address boundary is not on this path at all.
        await using var engine = await ServeAsync(upstream.Address, new OutboundConnectionPolicy());
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync("list-pets", """{"status":"available"}""", 2, Token);

        Assert.Contains("\"isError\":true", call.Payload, StringComparison.Ordinal);
        Assert.Empty(received);
    }

    [Fact]
    public async Task The_bare_mount_address_invokes_the_default_surface()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "[]");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api"), Token);

        var call = await session.CallAsync("list-pets", """{"status":"available"}""", 2, Token);

        Assert.DoesNotContain("\"isError\"", call.Payload, StringComparison.Ordinal);
        Assert.Equal(["GET /pets?status=available"], received);
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

    /// <summary>
    /// The text block of a call result.
    /// </summary>
    /// <remarks>
    /// Read out of the payload rather than matched as a substring of it. The protocol
    /// serializer escapes a quote as <c>\u0022</c>, so a substring assertion over the raw body
    /// would be asserting the serializer's escaping rules alongside the product's answer.
    /// </remarks>
    private static string Text(McpExchange exchange)
    {
        using var document = JsonDocument.Parse(exchange.Payload);

        return document.RootElement
            .GetProperty("result")
            .GetProperty("content")[0]
            .GetProperty("text")
            .GetString()!;
    }

    /// <summary>An upstream that records the request line of everything it is sent.</summary>
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

    private async Task<ServedEngine> ServeAsync(Uri upstream, OutboundConnectionPolicy? connections = null)
    {
        string root = Path.Combine(Path.GetTempPath(), "mcpiler-call-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);

        string bundle = ServedManifests.Write(root, "pets", ServedManifests.Upstream(upstream));
        string files = Directory.CreateDirectory(Path.Combine(root, "files")).FullName;

        return await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", bundle)], files),
            Token,
            connections);
    }
}
