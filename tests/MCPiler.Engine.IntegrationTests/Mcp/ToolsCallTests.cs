using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
    public async Task An_operation_excluded_from_one_surface_still_runs_on_another()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", """{"id":"p-7"}""");
        await using var engine = await ServeAsync(upstream.Address);

        using var excluded = await McpHttpSession.OpenAsync(engine.At("api/read"), Token);
        var refused = await excluded.CallAsync("get-pet", """{"petId":"p-7"}""", 2, Token);

        Assert.Contains("\"isError\":true", refused.Payload, StringComparison.Ordinal);
        Assert.Equal("No tool named 'get-pet' is available here.", Text(refused));
        Assert.Empty(received);

        // The same operation, the same Manifest, the same process. Exclusion is a property of
        // the surface a call was addressed to, not of the operation.
        using var serving = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);
        var served = await serving.CallAsync("get-pet", """{"petId":"p-7"}""", 2, Token);

        Assert.DoesNotContain("\"isError\"", served.Payload, StringComparison.Ordinal);
        Assert.Equal(["GET /pets/p-7"], received);
    }

    [Fact]
    public async Task An_operation_exposed_only_to_the_navigator_is_unlisted_and_refused_directly()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "[]");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var listed = await session.RequestAsync("tools/list", 2, Token);

        // Both halves, because "absent from the listing" is worth nothing as an assertion
        // against a listing that failed or came back empty.
        Assert.Contains("list-pets", listed.Payload, StringComparison.Ordinal);
        Assert.DoesNotContain("quiet-pet", listed.Payload, StringComparison.Ordinal);

        // Named anyway, which is the whole point: a caller can send a name it never read.
        var call = await session.CallAsync("quiet-pet", "{}", 3, Token);

        Assert.Contains("\"isError\":true", call.Payload, StringComparison.Ordinal);
        Assert.Equal("No tool named 'quiet-pet' is available here.", Text(call));
        Assert.Empty(received);
    }

    [Fact]
    public async Task An_excluded_operation_and_an_invented_one_are_refused_identically()
    {
        List<string> received = [];

        await using var upstream = await Recording(received, 200, "application/json", "[]");
        await using var engine = await ServeAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/read"), Token);

        // 'get-pet' exists, is bound, and runs on the neighbouring surface. 'get-pet-x' is
        // nothing at all. A caller able to tell the two answers apart has an oracle for the
        // catalogue the surface is hiding.
        var excluded = await session.CallAsync("get-pet", "{}", 2, Token);
        var invented = await session.CallAsync("get-pet-x", "{}", 3, Token);

        Assert.Equal(
            excluded.Payload.Replace("\"id\":2", "\"id\":ID", StringComparison.Ordinal),
            invented.Payload
                .Replace("\"id\":3", "\"id\":ID", StringComparison.Ordinal)
                .Replace("get-pet-x", "get-pet", StringComparison.Ordinal));

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

    [Fact]
    public async Task Saturating_one_mounts_concurrency_does_not_delay_another_mount()
    {
        var firstArrived = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int arrivals = 0;

        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                int arrival = Interlocked.Increment(ref arrivals);

                if (arrival == 1)
                {
                    firstArrived.TrySetResult(true);
                    await releaseFirst.Task.WaitAsync(context.RequestAborted);
                }

                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.Body.WriteAsync("[]"u8.ToArray(), context.RequestAborted);
            },
            Token);

        await using ServedEngine engine = await ServeTwoAsync(upstream.Address, concurrency: 1);
        using McpHttpSession first = await McpHttpSession.OpenAsync(engine.At("first/full"), Token);
        using McpHttpSession second = await McpHttpSession.OpenAsync(engine.At("second/full"), Token);

        Task<McpExchange> firstCall = first.CallAsync(
            "list-pets",
            """{"status":"available"}""",
            2,
            Token);

        await firstArrived.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);

        Task<McpExchange> secondCall = second.CallAsync(
            "list-pets",
            """{"status":"available"}""",
            2,
            Token);

        try
        {
            Task completed = await Task.WhenAny(secondCall, Task.Delay(TimeSpan.FromSeconds(5), Token));
            Assert.Same(secondCall, completed);

            McpExchange secondResult = await secondCall;
            Assert.DoesNotContain("\"isError\"", secondResult.Payload, StringComparison.Ordinal);
        }
        finally
        {
            // Always let the first connection drain, including when the assertion above proves
            // the old shared-pool defect by timing out.
            releaseFirst.TrySetResult(true);
        }

        McpExchange firstResult = await firstCall;
        Assert.DoesNotContain("\"isError\"", firstResult.Payload, StringComparison.Ordinal);
        Assert.Equal(2, Volatile.Read(ref arrivals));
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

    [Fact]
    public async Task A_projected_continuation_names_the_direct_tool_and_exact_arguments()
    {
        List<string> received = [];

        await using var upstream = await Recording(
            received,
            200,
            "application/json",
            """{"id":"p-7"}""",
            extraHeaders: [("Link", "</pets/p-7>; rel=\"next\"")]);

        await using var engine = await ServePaginatingAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync("list-pets", """{"status":"available"}""", 2, Token);

        var pagination = Pagination(call);

        Assert.Equal("next", pagination["state"]!.GetValue<string>());
        Assert.True(pagination["hasNext"]!.GetValue<bool>());

        var next = Assert.IsType<JsonObject>(pagination["next"]);

        Assert.Equal("get-pet", next["operation"]!.GetValue<string>());
        Assert.Equal("get-pet", next["tool"]!.GetValue<string>());
        Assert.Equal("p-7", Assert.IsType<JsonObject>(next["arguments"])["petId"]!.GetValue<string>());

        // One request: the page itself. A continuation is data, never a second exchange.
        Assert.Equal(["GET /pets?status=available"], received);
    }

    [Fact]
    public async Task A_navigator_only_target_is_named_by_the_advertised_wrapper()
    {
        List<string> received = [];

        await using var upstream = await Recording(
            received,
            200,
            "application/json",
            """{"id":"p-7"}""",
            extraHeaders: [("Link", "</pets/p-7>; rel=\"next\"")]);

        await using var engine = await ServePaginatingAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/nav"), Token);

        var call = await session.CallAsync("list-pets", """{"status":"available"}""", 2, Token);

        var next = Assert.IsType<JsonObject>(Pagination(call)["next"]);
        var payload = Assert.IsType<JsonObject>(next["arguments"]);

        Assert.Equal("catalogue.invoke", next["tool"]!.GetValue<string>());
        Assert.Equal("get-pet", payload["operationKey"]!.GetValue<string>());
        Assert.Equal("p-7", Assert.IsType<JsonObject>(payload["arguments"])["petId"]!.GetValue<string>());
        Assert.Equal(["GET /pets?status=available"], received);
    }

    [Fact]
    public async Task A_target_the_surface_cannot_call_is_unavailable_rather_than_emitted()
    {
        List<string> received = [];

        await using var upstream = await Recording(
            received,
            200,
            "application/json",
            """{"id":"p-7"}""",
            extraHeaders: [("Link", "</pets/p-7>; rel=\"next\"")]);

        await using var engine = await ServePaginatingAsync(upstream.Address);

        // 'nodirect' exposes 'get-pet' only through the Navigator and leaves the Navigator off,
        // so the static reachability table is satisfied while no callable name exists.
        using var session = await McpHttpSession.OpenAsync(engine.At("api/nodirect"), Token);

        var call = await session.CallAsync("list-pets", """{"status":"available"}""", 2, Token);

        Assert.Equal("unavailable", Pagination(call)["state"]!.GetValue<string>());
        Assert.Equal(["GET /pets?status=available"], received);
    }

    [Fact]
    public async Task Arguments_the_target_schema_refuses_are_unavailable_rather_than_emitted()
    {
        List<string> received = [];

        // The target declares 'petId' with maxLength 3, so the mapped value is one the target's
        // own advertised schema refuses even though every static mapping check passes.
        await using var upstream = await Recording(
            received,
            200,
            "application/json",
            """{"id":"p-12345"}""",
            extraHeaders: [("Link", "</pets/p-12345>; rel=\"next\"")]);

        await using var engine = await ServePaginatingAsync(upstream.Address);
        using var session = await McpHttpSession.OpenAsync(engine.At("api/full"), Token);

        var call = await session.CallAsync("list-pets", """{"status":"available"}""", 2, Token);

        Assert.Equal("unavailable", Pagination(call)["state"]!.GetValue<string>());

        // Only the page. A continuation the target would refuse never becomes a second request.
        Assert.Equal(["GET /pets?status=available"], received);
    }

    /// <summary>The normalized pagination object of a call result.</summary>
    private static JsonObject Pagination(McpExchange exchange)
    {
        using var document = JsonDocument.Parse(Text(exchange));

        return JsonNode.Parse(document.RootElement.GetProperty("pagination").GetRawText())!.AsObject();
    }

    /// <summary>An upstream that records the request line of everything it is sent.</summary>
    private static Task<LoopbackHost> Recording(
        List<string> received,
        int statusCode,
        string mediaType,
        string body,
        IReadOnlyList<(string Name, string Value)>? extraHeaders = null)
        => LoopbackHost.StartAsync(
            async context =>
            {
                lock (received)
                {
                    received.Add(context.Request.Method + " " + context.Request.Path + context.Request.QueryString);
                }

                foreach ((string name, string value) in extraHeaders ?? [])
                {
                    context.Response.Headers[name] = value;
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

    private async Task<ServedEngine> ServePaginatingAsync(Uri upstream)
    {
        string root = Path.Combine(Path.GetTempPath(), "mcpiler-call-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);

        string bundle = ServedManifests.Write(root, "pets", ServedManifests.Paginating(upstream));
        string files = Directory.CreateDirectory(Path.Combine(root, "files")).FullName;

        return await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", bundle)], files),
            Token);
    }

    private async Task<ServedEngine> ServeTwoAsync(Uri upstream, int concurrency)
    {
        string root = Path.Combine(Path.GetTempPath(), "mcpiler-call-" + Guid.NewGuid().ToString("N"));
        _roots.Add(root);

        string manifest = ServedManifests.Upstream(upstream, concurrency);
        string first = ServedManifests.Write(root, "first", manifest);
        string second = ServedManifests.Write(root, "second", manifest);
        string files = Directory.CreateDirectory(Path.Combine(root, "files")).FullName;

        return await ServedEngine.StartAsync(
            new RuntimeOptions(
                [
                    new MountRequest("/first", first),
                    new MountRequest("/second", second),
                ],
                files),
            Token);
    }
}
