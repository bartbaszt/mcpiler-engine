using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>
/// Proves that a compiled Manifest plus local runtime inputs is sufficient through the real host.
/// </summary>
public sealed class ManifestSufficiencyTests : IDisposable
{
    private static readonly byte[] BinaryPayload = [0, 1, 2, 3, 0x80, 0xFE, 0xFF, 9];
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-sufficiency-" + Guid.NewGuid().ToString("N"));

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public ManifestSufficiencyTests() => Directory.CreateDirectory(_root);

    [Fact]
    public async Task Direct_operation_executes_through_the_host_without_platform_or_database_runtime()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref arrivals);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
            },
            Token);

        await using ServedEngine engine = await ServeAsync(Manifest(upstream.Address), "direct");
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);

        McpExchange exchange = await session.CallAsync("ping", "{}", 1, Token);

        using JsonDocument document = JsonDocument.Parse(exchange.Payload);
        JsonElement result = document.RootElement.GetProperty("result");
        string text = result.GetProperty("content")[0].GetProperty("text").GetString()!;

        Assert.Equal(HttpStatusCode.OK, exchange.Status);
        Assert.False(result.TryGetProperty("isError", out JsonElement isError) && isError.GetBoolean(), text);
        Assert.Equal("{\"ok\":true}", text);
        Assert.Equal(1, Volatile.Read(ref arrivals));
        Assert.DoesNotContain(
            AppDomain.CurrentDomain.GetAssemblies(),
            assembly => string.Equals(assembly.GetName().Name, "MCPiler", StringComparison.Ordinal));
        Assert.DoesNotContain(
            AppDomain.CurrentDomain.GetAssemblies(),
            assembly => string.Equals(assembly.GetName().Name, "Microsoft.EntityFrameworkCore", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Binary_response_issues_a_reference_whose_download_is_byte_identical()
    {
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                context.Response.ContentType = "application/octet-stream";
                await context.Response.Body.WriteAsync(BinaryPayload, context.RequestAborted);
            },
            Token);

        await using ServedEngine engine = await ServeAsync(Manifest(upstream.Address, binary: true), "binary");
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);

        McpExchange exchange = await session.CallAsync("ping", "{}", 2, Token);
        string handle = HandleFromToolResult(exchange.Payload);

        using HttpClient http = new();
        using HttpResponseMessage response = await http.GetAsync(engine.At("/api/full/files/" + handle), Token);
        byte[] downloaded = await response.Content.ReadAsByteArrayAsync(Token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(BinaryPayload.LongLength, response.Content.Headers.ContentLength);
        Assert.Equal(BinaryPayload, downloaded);
        Assert.Equal(SHA256.HashData(BinaryPayload), SHA256.HashData(downloaded));
    }

    [Fact]
    public async Task Unset_environment_credential_sends_no_request_and_reports_authentication()
    {
        int arrivals = 0;
        string variable = "MCPILER_SUFFICIENCY_" + Guid.NewGuid().ToString("N").ToUpperInvariant();
        Assert.Null(Environment.GetEnvironmentVariable(variable));

        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            context =>
            {
                Interlocked.Increment(ref arrivals);
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return Task.CompletedTask;
            },
            Token);

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address, credentialVariable: variable),
            "missing-credential");
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);

        McpExchange exchange = await session.CallAsync("ping", "{}", 3, Token);

        using JsonDocument document = JsonDocument.Parse(exchange.Payload);
        JsonElement result = document.RootElement.GetProperty("result");

        Assert.True(result.GetProperty("isError").GetBoolean());
        Assert.Equal("Authentication", result.GetProperty("_meta").GetProperty("io.mcpiler/errorCode").GetString());
        Assert.Equal(0, Volatile.Read(ref arrivals));
    }

    /// <summary>
    /// The independently authored v4 fixture's enabled policy, served through the real host, must
    /// actually cache: two identical calls reach the upstream once. This is the behavioral half of
    /// the shared contract — Platform owns the bytes that carry <c>responseCache</c>, and this side
    /// proves Engine acts on the member rather than only accepting it at load time.
    /// </summary>
    [Fact]
    public async Task An_opted_in_policy_caches_two_identical_calls_into_one_upstream_request()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref arrivals);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
            },
            Token);

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address, cacheTtlSeconds: 300),
            "cached-policy");
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);

        McpExchange first = await session.CallAsync("ping", "{}", 10, Token);
        McpExchange second = await session.CallAsync("ping", "{}", 11, Token);

        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal("{\"ok\":true}", FirstText(first.Payload));
        Assert.Equal("{\"ok\":true}", FirstText(second.Payload));

        // The claim this test exists for: the second call was answered from cache, so the upstream
        // saw exactly one request. A fixture that only loaded would leave this at 2.
        Assert.Equal(1, Volatile.Read(ref arrivals));
    }

    /// <summary>
    /// The absent-policy compat case: the same fixture without a <c>responseCache</c> member is
    /// eligible by method and media type, but a missing policy means every call is a live send.
    /// Without this, the caching assertion above could pass on an implementation that cached
    /// everything regardless of the authored opt-in.
    /// </summary>
    [Fact]
    public async Task An_absent_policy_leaves_every_call_a_live_upstream_request()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref arrivals);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
            },
            Token);

        await using ServedEngine engine = await ServeAsync(Manifest(upstream.Address), "absent-policy");
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);

        _ = await session.CallAsync("ping", "{}", 12, Token);
        _ = await session.CallAsync("ping", "{}", 13, Token);

        Assert.Equal(2, Volatile.Read(ref arrivals));
    }

    /// <summary>
    /// A hosted generation exposes neither cache contents nor counters as manifest or desired
    /// state: the only way to observe them is the operator channel, and the served Manifest bytes
    /// carry the authored policy member alone.
    /// </summary>
    [Fact]
    public async Task The_served_manifest_carries_the_policy_member_and_no_cache_contents()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref arrivals);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
            },
            Token);

        string text = Manifest(upstream.Address, cacheTtlSeconds: 300);
        await using ServedEngine engine = await ServeAsync(text, "policy-member");
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);

        // Warm the cache so an implementation that leaked runtime state into the served document
        // would have something to leak.
        _ = await session.CallAsync("ping", "{}", 14, Token);
        Assert.Equal(1, Volatile.Read(ref arrivals));

        var mount = Assert.Single(engine.Started.Mounts);
        string served = mount.Document.AgentSurfaceDocument!.ToJsonString();

        Assert.Contains("\"responseCache\":{\"ttlSeconds\":300}", served, StringComparison.Ordinal);
        Assert.DoesNotContain("invocations", served, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("upstreamSends", served, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("keyFingerprint", served, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("observedAtUtc", served, StringComparison.OrdinalIgnoreCase);
    }

    private static string FirstText(string payload)
    {
        using JsonDocument document = JsonDocument.Parse(payload);
        return document.RootElement
            .GetProperty("result")
            .GetProperty("content")[0]
            .GetProperty("text")
            .GetString()!;
    }

    private async Task<ServedEngine> ServeAsync(string manifestText, string name)
    {
        string manifest = ServedManifests.Write(_root, name, manifestText);
        string files = Directory.CreateDirectory(Path.Combine(_root, name + "-files")).FullName;
        return await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", manifest)], files),
            Token);
    }

    private static string HandleFromToolResult(string payload)
    {
        using JsonDocument document = JsonDocument.Parse(payload);
        string text = document.RootElement
            .GetProperty("result")
            .GetProperty("content")[0]
            .GetProperty("text")
            .GetString()!;
        const string Prefix = "handle '";
        int start = text.IndexOf(Prefix, StringComparison.Ordinal);
        Assert.True(start >= 0, text);
        start += Prefix.Length;
        int end = text.IndexOf('\'', start);
        Assert.True(end > start, text);
        return text[start..end];
    }

    internal static string Manifest(Uri upstream, bool binary = false, string? credentialVariable = null, int? cacheTtlSeconds = null)
    {
        string credentialRef = credentialVariable is null ? string.Empty : ", \"credentialRef\": [\"api-key\"]";
        string credentials = credentialVariable is null
            ? string.Empty
            : ", \"credentials\": { \"inline\": { \"formatVersion\": 4, \"credentials\": ["
                + "{ \"id\": \"api-key\", \"scheme\": \"apiKey\", \"slot\": \"X-Api-Key\", "
                + "\"location\": \"header\", \"value\": { \"fromEnv\": "
                + JsonSerializer.Serialize(credentialVariable)
                + " } } ] } }";
        string responseCache = cacheTtlSeconds is { } ttl
            ? ", \"responseCache\": { \"ttlSeconds\": " + ttl.ToString(System.Globalization.CultureInfo.InvariantCulture) + " }"
            : string.Empty;
        string content = binary
            ? "\"application/octet-stream\": { \"schema\": { \"type\": \"string\", \"format\": \"binary\" } }"
            : "\"application/json\": { \"schema\": { \"type\": \"object\" } }";

        return $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": {
                  "name": "Sufficiency API",
                  "authenticationRequired": false,
                  "surfaces": [
                    { "slug": "full", "isDefault": true,
                      "operations": [ { "operation": "ping", "exposure": "direct" } ] }
                  ]
                } },
                "policy": { "inline": { "baseUrl": "{{upstream.AbsoluteUri}}" } },
                "operations": { "inline": { "operations": [
                  {
                    "key": "GET /ping", "method": "GET", "path": "/ping",
                    "responses": { "200": { "content": { {{content}} } } }
                  }
                ] } },
                "agentSurface": { "inline": { "operations": [
                  {
                    "slug": "ping", "name": "Ping", "summary": "Checks connectivity",
                    "binding": { "type": "http", "operation": "GET /ping"{{credentialRef}} }{{responseCache}}
                  }
                ] } }{{credentials}}
              }
            }
            """;
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}
