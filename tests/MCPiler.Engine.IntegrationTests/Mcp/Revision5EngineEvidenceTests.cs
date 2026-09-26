using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Runtime;
using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

public sealed class Revision5EngineEvidenceTests : IAsyncDisposable
{
    private readonly List<string> _roots = [];

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Legacy_context_capture_keeps_exact_text_structured_bytes_and_schema()
    {
        List<string> received = [];
        await using var upstream = await Recording(
            received,
            "[\"a\",\"b\"]",
            [("X-Context", "captured")]);
        string manifest = LegacyStructuredManifest(upstream.Address);

        await using ServedEngine engine = await ServeAsync(manifest);
        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            Token,
            "2026-07-28");

        McpExchange listed = await session.RequestAsync("tools/list", 2, Token);
        McpExchange called = await session.CallAsync("list-pets", "{}", 3, Token);
        JsonElement tool = Tool(listed, "list-pets");
        JsonElement result = Result(called);

        Assert.Equal(
            "{\"type\":\"object\",\"properties\":{\"result\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}},\"required\":[\"result\"]}",
            tool.GetProperty("outputSchema").GetRawText());
        Assert.Equal("[\"a\",\"b\"]", Text(called));
        Assert.Equal("{\"result\":[\"a\",\"b\"]}", result.GetProperty("structuredContent").GetRawText());
        Assert.False(result.TryGetProperty("isError", out _));
        Assert.DoesNotContain("captured", called.Payload, StringComparison.Ordinal);
        Assert.Equal(["GET /pets"], received);
    }

    [Theory]
    [InlineData("Authorization")]
    [InlineData("WWW-Authenticate")]
    [InlineData("Proxy-Authenticate")]
    public async Task Hand_authored_hard_denied_headers_are_refused_before_serving(string header)
    {
        List<string> received = [];
        await using var upstream = await Recording(received, "{}");
        JsonObject root = JsonNode.Parse(ServedManifests.Paginating(upstream.Address))!.AsObject();
        JsonObject operation = root["sections"]!["agentSurface"]!["inline"]!["operations"]![0]!.AsObject();
        operation["outputProjection"]!["metadata"] = new JsonArray(
            new JsonObject
            {
                ["source"] = new JsonObject
                {
                    ["kind"] = "responseHeader",
                    ["name"] = header,
                    ["valueMode"] = "first",
                },
                ["target"] = "/metadata/challenge",
            });

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ServeAsync(root.ToJsonString()));

        Assert.Contains("agent/projection-header-sensitive", error.Message, StringComparison.Ordinal);
        Assert.Empty(received);
    }

    [Theory]
    [InlineData("other-mount/get-pet")]
    [InlineData("other-mount:get-pet")]
    public async Task Qualified_unknown_targets_are_refused_before_serving(string target)
    {
        List<string> received = [];
        await using var upstream = await Recording(received, "{}");
        JsonObject root = JsonNode.Parse(ServedManifests.Paginating(upstream.Address))!.AsObject();
        root["sections"]!["agentSurface"]!["inline"]!["operations"]![0]!["outputProjection"]!["pagination"]!["nextOperation"] = target;

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ServeAsync(root.ToJsonString()));

        Assert.Contains("agent/projection-target-unknown", error.Message, StringComparison.Ordinal);
        Assert.Empty(received);
    }

    [Fact]
    public async Task Protected_surface_a_continuation_grants_no_surface_b_authority()
    {
        List<string> received = [];
        await using var upstream = await Recording(
            received,
            "{\"id\":\"p-7\"}",
            [("Link", "</pets/p-7>; rel=\"next\"")]);
        await using FakeAuthorizationServer authorization = await FakeAuthorizationServer.StartAsync(
            active: true,
            Token);
        string manifest = ProtectedPaginating(upstream.Address);

        await using ServedEngine engine = await ServeAsync(
            manifest,
            authorization: new HostAuthorizationOptions(
                authorization.Address.AbsoluteUri,
                HostTokenValidation.Introspection));
        string resourceA = engine.At("/api/a").AbsoluteUri.TrimEnd('/');
        string tokenA = authorization.Mint(resourceA, "tools.read");

        using McpHttpSession surfaceA = await McpHttpSession.OpenAsync(
            engine.At("/api/a"),
            Token,
            bearerToken: tokenA);
        McpExchange page = await surfaceA.CallAsync("list-pets", "{\"status\":\"available\"}", 2, Token);
        JsonObject next = JsonNode.Parse(Text(page))!["pagination"]!["next"]!.AsObject();

        Assert.Equal("get-pet", next["operation"]!.GetValue<string>());
        Assert.Equal("get-pet", next["tool"]!.GetValue<string>());

        McpExchange refused = await ReplayAsync(
            engine.At("/api/b"),
            surfaceA.SessionId!,
            tokenA,
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":"
                + JsonSerializer.Serialize(next["tool"]!.GetValue<string>())
                + ",\"arguments\":"
                + next["arguments"]!.ToJsonString()
                + "}}",
            Token);

        Assert.Equal(HttpStatusCode.NotFound, refused.Status);
        Assert.Empty(refused.Body);
        Assert.Equal(["GET /pets?status=available"], received);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Successful_continuation_calls_use_the_ordinary_compiler_and_outbound_path(bool navigator)
    {
        List<string> received = [];
        await using var upstream = await Recording(
            received,
            "{\"id\":\"p-7\"}",
            [("Link", "</pets/p-7>; rel=\"next\"")]);
        int policyChecks = 0;
        var connections = new OutboundConnectionPolicy(address =>
        {
            Interlocked.Increment(ref policyChecks);
            return !IPAddress.IsLoopback(address);
        });

        await using ServedEngine engine = await ServeAsync(
            ServedManifests.Paginating(upstream.Address),
            connections);
        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At(navigator ? "/api/nav" : "/api/full"),
            Token);
        McpExchange page = await session.CallAsync("list-pets", "{\"status\":\"available\"}", 2, Token);
        JsonObject next = JsonNode.Parse(Text(page))!["pagination"]!["next"]!.AsObject();
        McpExchange followed = await session.CallAsync(
            next["tool"]!.GetValue<string>(),
            next["arguments"]!.ToJsonString(),
            3,
            Token);

        Assert.Equal(HttpStatusCode.OK, followed.Status);
        Assert.DoesNotContain("\"isError\":true", followed.Payload, StringComparison.Ordinal);
        Assert.Equal("{\"id\":\"p-7\"}", Text(followed));
        Assert.Equal(
            ["GET /pets?status=available", "GET /pets/p-7"],
            received);
        Assert.True(policyChecks >= 1);
    }

    [Fact]
    public async Task Malformed_link_keeps_the_body_and_mcp_success()
    {
        List<string> received = [];
        await using var upstream = await Recording(
            received,
            "{\"id\":\"p-7\"}",
            [("Link", "<broken")]);

        await using ServedEngine engine = await ServeAsync(ServedManifests.Paginating(upstream.Address));
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);
        McpExchange call = await session.CallAsync("list-pets", "{\"status\":\"available\"}", 2, Token);
        JsonElement result = Result(call);
        JsonObject value = JsonNode.Parse(Text(call))!.AsObject();

        Assert.Equal(HttpStatusCode.OK, call.Status);
        Assert.False(result.TryGetProperty("isError", out JsonElement error) && error.GetBoolean());
        Assert.Equal("p-7", value["data"]!["id"]!.GetValue<string>());
        Assert.Equal("unavailable", value["pagination"]!["state"]!.GetValue<string>());
        Assert.Equal(["GET /pets?status=available"], received);
    }

    [Fact]
    public async Task Three_independent_invalid_projection_mappings_return_stable_blockers()
    {
        List<string> received = [];
        await using var upstream = await Recording(received, "{}");
        string manifest = ThreeInvalidMappings(upstream.Address);
        string root = Root();
        string bundle = ServedManifests.Write(root, "three-invalid", manifest);
        string files = Directory.CreateDirectory(Path.Combine(root, "files")).FullName;

        RuntimeStartResult started = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", bundle)], files));

        Assert.False(started.Started);
        Assert.Equal(
            ["agent/projection-mapping-invalid", "agent/projection-mapping-invalid", "agent/projection-mapping-invalid"],
            started.Refusals.Select(refusal => refusal.Code));
        Assert.Equal(
            ["'/does-not-exist-a'", "'/does-not-exist-b'", "'/does-not-exist-c'"],
            started.Refusals.Select(refusal =>
            {
                int start = refusal.Message.IndexOf("Mapping target", StringComparison.Ordinal);
                return start < 0 ? string.Empty : refusal.Message[(start + 15)..].Split(' ', 2)[0];
            }));
        Assert.Empty(received);
    }

    [Fact]
    public async Task Projection_result_bytes_are_stable_across_repeat_restart_and_hostile_culture()
    {
        List<string> received = [];
        await using var upstream = await Recording(
            received,
            "{\"id\":\"p-7\"}",
            [("Link", "</pets/p-7>; rel=\"next\"")]);
        string manifest = ServedManifests.Paginating(upstream.Address);

        (string first, string repeated) = await CallProjectedTwiceAsync(manifest, 17);
        string restarted = await UnderAsync(HostileCulture(), () => CallProjectedAsync(manifest, 17));

        Assert.Equal(first, repeated);
        Assert.Equal(first, restarted);
        Assert.Equal(3, received.Count);
    }

    [Fact]
    public async Task Explicit_projection_serves_without_a_registered_ai_provider_or_ai_call()
    {
        List<string> received = [];
        await using var upstream = await Recording(
            received,
            "{\"id\":\"p-7\"}",
            [("Link", "</pets/p-7>; rel=\"next\"")]);
        int policyChecks = 0;
        var connections = new OutboundConnectionPolicy(address =>
        {
            Interlocked.Increment(ref policyChecks);
            return !address.Equals(IPAddress.Parse(upstream.Address.Host));
        });

        await using ServedEngine engine = await ServeAsync(
            ServedManifests.Paginating(upstream.Address),
            connections);
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);
        McpExchange call = await session.CallAsync("list-pets", "{\"status\":\"available\"}", 2, Token);
        JsonObject value = JsonNode.Parse(Text(call))!.AsObject();

        Assert.DoesNotContain("\"isError\":true", call.Payload, StringComparison.Ordinal);
        Assert.Equal("next", value["pagination"]!["state"]!.GetValue<string>());
        Assert.Equal(["GET /pets?status=available"], received);
        Assert.Equal(1, policyChecks);
    }

    private async Task<(string First, string Repeat)> CallProjectedTwiceAsync(string manifest, int id)
    {
        await using ServedEngine engine = await ServeAsync(manifest);
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);
        string first = (await session.CallAsync("list-pets", "{\"status\":\"available\"}", id, Token)).Body;
        string repeated = (await session.CallAsync("list-pets", "{\"status\":\"available\"}", id, Token)).Body;
        return (first, repeated);
    }

    private async Task<string> CallProjectedAsync(string manifest, int id)
    {
        await using ServedEngine engine = await ServeAsync(manifest);
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);
        return (await session.CallAsync("list-pets", "{\"status\":\"available\"}", id, Token)).Body;
    }

    private async Task<ServedEngine> ServeAsync(
        string manifest,
        OutboundConnectionPolicy? connections = null,
        HostAuthorizationOptions? authorization = null)
    {
        string root = Root();
        string bundle = ServedManifests.Write(root, "bundle-" + Guid.NewGuid().ToString("N"), manifest);
        string files = Directory.CreateDirectory(Path.Combine(root, "files-" + Guid.NewGuid().ToString("N"))).FullName;

        return await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", bundle)], files),
            Token,
            connections,
            authorization: authorization);
    }

    private static async Task<McpExchange> ReplayAsync(
        Uri endpoint,
        string sessionId,
        string token,
        string body,
        CancellationToken cancellationToken)
    {
        using var client = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("Mcp-Session-Id", sessionId);

        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        string text = await response.Content.ReadAsStringAsync(cancellationToken);

        return new McpExchange(
            response.StatusCode,
            response.Content.Headers.ContentType?.MediaType ?? string.Empty,
            text,
            text);
    }

    private static Task<LoopbackHost> Recording(
        List<string> received,
        string body,
        IReadOnlyList<(string Name, string Value)>? headers = null)
        => LoopbackHost.StartAsync(
            async context =>
            {
                lock (received)
                {
                    received.Add(context.Request.Method + " " + context.Request.Path + context.Request.QueryString);
                }

                foreach ((string name, string value) in headers ?? [])
                {
                    context.Response.Headers[name] = value;
                }

                byte[] bytes = Encoding.UTF8.GetBytes(body);
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                context.Response.ContentLength = bytes.Length;
                await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
            },
            Token);

    private static JsonElement Tool(McpExchange exchange, string name)
    {
        using JsonDocument document = JsonDocument.Parse(exchange.Payload);
        return document.RootElement
            .GetProperty("result")
            .GetProperty("tools")
            .EnumerateArray()
            .Single(tool => string.Equals(tool.GetProperty("name").GetString(), name, StringComparison.Ordinal))
            .Clone();
    }

    private static JsonElement Result(McpExchange exchange)
    {
        using JsonDocument document = JsonDocument.Parse(exchange.Payload);
        return document.RootElement.GetProperty("result").Clone();
    }

    private static string Text(McpExchange exchange)
        => Result(exchange).GetProperty("content")[0].GetProperty("text").GetString()!;

    private static string LegacyStructuredManifest(Uri upstream)
    {
        JsonObject root = JsonNode.Parse(ServedManifests.OneSurface)!.AsObject();
        JsonObject surface = root["sections"]!["server"]!["inline"]!["surfaces"]![0]!.AsObject();
        surface["outputSchemas"] = true;
        JsonObject operation = root["sections"]!["agentSurface"]!["inline"]!["operations"]![0]!.AsObject();
        operation["outputSchema"] = new JsonObject
        {
            ["type"] = "array",
            ["items"] = new JsonObject { ["type"] = "string" },
        };
        operation["outputSchemaPolicy"] = new JsonObject
        {
            ["generate"] = true,
            ["advertise"] = "yes",
            ["useInternally"] = true,
        };
        root["sections"]!["policy"]!["inline"]!["baseUrl"] = upstream.AbsoluteUri;
        return root.ToJsonString();
    }

    private static string ProtectedPaginating(Uri upstream)
    {
        JsonObject root = JsonNode.Parse(ServedManifests.Paginating(upstream))!.AsObject();
        JsonObject server = root["sections"]!["server"]!["inline"]!.AsObject();
        server["authenticationRequired"] = true;
        JsonArray surfaces = server["surfaces"]!.AsArray();
        JsonObject first = surfaces[0]!.AsObject();
        first["slug"] = "a";
        first["requiredScopes"] = new JsonArray("tools.read");
        JsonObject second = surfaces[1]!.AsObject();
        second["slug"] = "b";
        second["requiredScopes"] = new JsonArray("tools.write");
        foreach (JsonNode? entry in second["operations"]!.AsArray())
        {
            if (string.Equals(entry!["operation"]!.GetValue<string>(), "get-pet", StringComparison.Ordinal))
            {
                entry!["exposure"] = "direct";
            }
        }

        return root.ToJsonString();
    }

    private static string ThreeInvalidMappings(Uri upstream)
    {
        JsonObject root = JsonNode.Parse(ServedManifests.Paginating(upstream))!.AsObject();
        JsonObject sections = root["sections"]!.AsObject();
        JsonArray operations = sections["agentSurface"]!["inline"]!["operations"]!.AsArray();
        JsonObject source = operations[0]!.AsObject();
        operations[1]!["inputSchema"]!.AsObject().Remove("required");

        foreach (string slug in new[] { "invalid-a", "invalid-b", "invalid-c" })
        {
            JsonObject clone = source.DeepClone().AsObject();
            clone["slug"] = slug;
            clone["name"] = slug;
            clone["outputProjection"]!["pagination"]!["nextArguments"] = new JsonArray(
                new JsonObject
                {
                    ["target"] = $"/does-not-exist-{slug[^1]}",
                    ["from"] = new JsonObject
                    {
                        ["kind"] = "urlQuery",
                        ["name"] = "cursor",
                    },
                    ["as"] = "string",
                });
            operations.Add(clone);
        }

        JsonArray surfaces = sections["server"]!["inline"]!["surfaces"]!.AsArray();
        foreach (JsonNode? surface in surfaces)
        {
            JsonArray entries = surface!["operations"]!.AsArray();
            foreach (string slug in new[] { "invalid-a", "invalid-b", "invalid-c" })
            {
                entries.Add(new JsonObject { ["operation"] = slug });
            }
        }

        return root.ToJsonString();
    }

    private static CultureInfo HostileCulture()
    {
        var culture = (CultureInfo)CultureInfo.InvariantCulture.Clone();
        culture.NumberFormat.NumberDecimalSeparator = ",";
        culture.NumberFormat.NumberGroupSeparator = ".";
        culture.NumberFormat.NegativeSign = "!";
        return culture;
    }

    private static async Task<T> UnderAsync<T>(CultureInfo culture, Func<Task<T>> action)
    {
        CultureInfo previousCulture = CultureInfo.CurrentCulture;
        CultureInfo previousUiCulture = CultureInfo.CurrentUICulture;

        try
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = culture;
            return await action();
        }
        finally
        {
            CultureInfo.CurrentCulture = previousCulture;
            CultureInfo.CurrentUICulture = previousUiCulture;
        }
    }

    private string Root()
    {
        string root = Path.Combine(Path.GetTempPath(), "mcpiler-revision5-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        _roots.Add(root);
        return root;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (string root in _roots)
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
