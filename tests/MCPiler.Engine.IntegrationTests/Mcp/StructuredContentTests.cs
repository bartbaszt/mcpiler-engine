using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Mcp;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>Output schemas and structured content as a third-party HTTP client receives them.</summary>
public sealed class StructuredContentTests : IDisposable
{
    private const string ArraySchema = "{\"type\":\"array\",\"items\":{\"type\":\"string\"}}";
    private const string ObjectSchema =
        "{\"type\":\"object\",\"properties\":{\"value\":{\"type\":\"integer\"}},\"required\":[\"value\"]}";
    private const string ScalarSchema = "{\"type\":\"string\"}";
    private const string ProjectionSchema =
        "{\"type\":\"object\",\"properties\":{\"data\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},\"pagination\":{\"type\":\"object\",\"properties\":{\"state\":{\"type\":\"string\",\"enum\":[\"next\",\"end\",\"unavailable\"]},\"hasNext\":{\"type\":\"boolean\"}}}},\"required\":[\"data\",\"pagination\"],\"additionalProperties\":false}";
    private const string ProjectionPolicy =
        "{\"bodyTarget\":\"/data\",\"pagination\":{\"target\":\"/pagination\",\"source\":{\"kind\":\"linkHeader\",\"header\":\"link\",\"relation\":\"next\"}}}";
    private const string GoldenEnvelope =
        """{"type":"object","properties":{"result":{"type":"array","items":{"type":"string"}}},"required":["result"]}""";

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "mcpiler-structured-" + Guid.NewGuid().ToString("N"));

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public StructuredContentTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task The_envelope_bytes_are_identical_across_supported_structured_revisions()
    {
        await using LoopbackHost upstream = await Respond("[\"a\",\"b\"]");
        await using ServedEngine engine = await ServeAsync(upstream.Address, "auto", capability: true);

        List<string> schemas = [];

        foreach (string revision in new[] { "2025-06-18", "2025-11-25", "2026-07-28" })
        {
            using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token, revision);

            if (string.Equals(revision, "2026-07-28", StringComparison.Ordinal))
            {
                Assert.Null(session.SessionId);
            }
            else
            {
                Assert.False(string.IsNullOrEmpty(session.SessionId));
            }

            McpExchange listed = await session.RequestAsync("tools/list", 2, Token);

            schemas.Add(OutputSchema(listed));
        }

        Assert.All(schemas, schema => Assert.Equal(GoldenEnvelope, schema));
        Assert.Single(schemas.Distinct(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Auto_changes_only_the_output_schema_between_pre_structured_and_structured_revisions()
    {
        await using LoopbackHost upstream = await Respond("[\"a\"]");
        await using ServedEngine engine = await ServeAsync(upstream.Address, "auto", capability: true);
        using McpHttpSession earlier = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            Token,
            "2025-03-26");
        using McpHttpSession structured = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            Token,
            "2025-06-18");

        JsonElement earlierTool = Tool(await earlier.RequestAsync("tools/list", 2, Token));
        JsonElement structuredTool = Tool(await structured.RequestAsync("tools/list", 2, Token));

        Assert.False(earlierTool.TryGetProperty("outputSchema", out _));
        string schema = structuredTool.GetProperty("outputSchema").GetRawText();
        string withSchema = structuredTool.GetRawText();
        string member = ",\"outputSchema\":" + schema;

        Assert.Contains(member, withSchema, StringComparison.Ordinal);
        Assert.Equal(
            earlierTool.GetRawText(),
            withSchema.Replace(member, string.Empty, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Yes_advertises_before_structured_content_exists_but_returns_text_only()
    {
        await using LoopbackHost upstream = await Respond("[\"a\"]");
        await using ServedEngine engine = await ServeAsync(upstream.Address, "yes", capability: true);
        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            Token,
            "2025-03-26");

        McpExchange listed = await session.RequestAsync("tools/list", 2, Token);
        McpExchange called = await session.CallAsync("read-value", "{}", 3, Token);

        Assert.True(Tool(listed).TryGetProperty("outputSchema", out _));
        Assert.False(Result(called).TryGetProperty("structuredContent", out _));
        Assert.Equal("[\"a\"]", Text(called));
        Assert.False(Result(called).TryGetProperty("isError", out _));
    }

    [Fact]
    public async Task Auto_is_absent_before_the_structured_revision_but_the_text_result_still_works()
    {
        await using LoopbackHost upstream = await Respond("[\"a\"]");
        await using ServedEngine engine = await ServeAsync(upstream.Address, "auto", capability: true);
        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            Token,
            "2025-03-26");

        McpExchange listed = await session.RequestAsync("tools/list", 2, Token);
        McpExchange called = await session.CallAsync("read-value", "{}", 3, Token);

        Assert.False(Tool(listed).TryGetProperty("outputSchema", out _));
        Assert.False(Result(called).TryGetProperty("structuredContent", out _));
        Assert.Equal("[\"a\"]", Text(called));
        Assert.False(Result(called).TryGetProperty("isError", out _));
    }

    [Fact]
    public async Task The_manifest_capability_is_a_hard_ceiling_even_for_yes()
    {
        await using LoopbackHost upstream = await Respond("[\"a\"]");
        await using ServedEngine engine = await ServeAsync(upstream.Address, "yes", capability: false);
        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            Token,
            "2026-07-28");

        McpExchange listed = await session.RequestAsync("tools/list", 2, Token);

        Assert.False(Tool(listed).TryGetProperty("outputSchema", out _));
    }

    [Theory]
    [InlineData("true", "42", "{\"result\":42}")]
    [InlineData(ScalarSchema, "\"ready\"", "{\"result\":\"ready\"}")]
    [InlineData(ObjectSchema, "{\"value\":1}", "{\"value\":1}")]
    [InlineData(ArraySchema, "[\"a\",\"b\"]", "{\"result\":[\"a\",\"b\"]}")]
    public async Task Every_conforming_root_shape_is_mirrored_and_the_text_carrier_remains(
        string outputSchema,
        string payload,
        string expectedStructured)
    {
        await using LoopbackHost upstream = await Respond(payload);
        await using ServedEngine engine = await ServeAsync(
            upstream.Address,
            "auto",
            capability: true,
            outputSchema);
        using McpHttpSession session = await McpHttpSession.OpenAsync(
            engine.At("/api/full"),
            Token,
            "2026-07-28");

        _ = await session.RequestAsync("tools/list", 2, Token);
        McpExchange called = await session.CallAsync("read-value", "{}", 3, Token);
        JsonElement result = Result(called);

        Assert.Equal(expectedStructured, result.GetProperty("structuredContent").GetRawText());
        Assert.Equal(payload, Text(called));
        Assert.False(result.TryGetProperty("isError", out _));
    }

    [Fact]
    public async Task A_mismatch_keeps_text_omits_structure_and_emits_one_identified_diagnostic()
    {
        List<RuntimeDiagnostic> diagnostics = [];
        await using LoopbackHost upstream = await Respond("[1]");
        (ServedEngine engine, string manifest) = await ServeWithManifestAsync(
            upstream.Address,
            "auto",
            capability: true,
            diagnostics.Add);
        await using (engine)
        {
            using McpHttpSession session = await McpHttpSession.OpenAsync(
                engine.At("/api/full"),
                Token,
                "2026-07-28");

            _ = await session.RequestAsync("tools/list", 2, Token);
            McpExchange called = await session.CallAsync("read-value", "{}", 3, Token);
            JsonElement result = Result(called);

            Assert.False(result.TryGetProperty("structuredContent", out _));
            Assert.False(result.TryGetProperty("isError", out _));
            Assert.Equal("[1]", Text(called));

            RuntimeDiagnostic diagnostic = Assert.Single(diagnostics);
            Assert.Equal("mcp/structured-content-invalid", diagnostic.Code);
            Assert.Equal(manifest, diagnostic.Manifest);
            Assert.Equal("full", diagnostic.Surface);
            Assert.Equal("read-value", diagnostic.Operation);
            Assert.Contains("items", diagnostic.SchemaLocation, StringComparison.Ordinal);
            Assert.Contains(manifest, diagnostic.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("[1]", diagnostic.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_schema_that_is_not_advertised_records_no_conformance_diagnostic()
    {
        List<RuntimeDiagnostic> diagnostics = [];
        await using LoopbackHost upstream = await Respond("[1]");
        (ServedEngine engine, _) = await ServeWithManifestAsync(
            upstream.Address,
            "yes",
            capability: false,
            diagnostics.Add);
        await using (engine)
        {
            using McpHttpSession session = await McpHttpSession.OpenAsync(
                engine.At("/api/full"),
                Token,
                "2026-07-28");

            _ = await session.RequestAsync("tools/list", 2, Token);
            McpExchange called = await session.CallAsync("read-value", "{}", 3, Token);

            Assert.False(Result(called).TryGetProperty("structuredContent", out _));
            Assert.Empty(diagnostics);
        }
    }

    [Fact]
    public async Task A_sink_that_throws_does_not_change_the_tool_outcome()
    {
        await using LoopbackHost upstream = await Respond("[1]");
        (ServedEngine engine, _) = await ServeWithManifestAsync(
            upstream.Address,
            "auto",
            capability: true,
            diagnostics: _ => throw new InvalidOperationException("A broken sink."));
        await using (engine)
        {
            using McpHttpSession session = await McpHttpSession.OpenAsync(
                engine.At("/api/full"),
                Token,
                "2026-07-28");

            _ = await session.RequestAsync("tools/list", 2, Token);
            McpExchange called = await session.CallAsync("read-value", "{}", 3, Token);
            JsonElement result = Result(called);

            Assert.False(result.TryGetProperty("structuredContent", out _));
            Assert.False(result.TryGetProperty("isError", out _));
            Assert.Equal("[1]", Text(called));
        }
    }

    [Fact]
    public async Task Structured_content_and_advertised_schema_describe_the_final_projection_envelope()
    {
        await using LoopbackHost upstream = await Respond("[\"a\"]");
        (ServedEngine engine, _) = await ServeWithManifestAsync(
            upstream.Address,
            "yes",
            capability: true,
            diagnostics: null,
            outputSchema: ProjectionSchema,
            outputProjection: ProjectionPolicy);
        await using (engine)
        {
            using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token, "2026-07-28");

            McpExchange listed = await session.RequestAsync("tools/list", 2, Token);
            McpExchange called = await session.CallAsync("read-value", "{}", 3, Token);
            JsonElement result = Result(called);
            JsonDocument text = JsonDocument.Parse(Text(called));

            Assert.Contains("data", Tool(listed).GetProperty("outputSchema").GetProperty("properties").EnumerateObject().Select(p => p.Name));
            Assert.Contains("pagination", Tool(listed).GetProperty("outputSchema").GetProperty("properties").EnumerateObject().Select(p => p.Name));
            Assert.Equal("[\"a\"]", result.GetProperty("structuredContent").GetProperty("data").GetRawText());
            Assert.Equal("end", result.GetProperty("structuredContent").GetProperty("pagination").GetProperty("state").GetString());
            Assert.Equal(result.GetProperty("structuredContent").GetRawText(), text.RootElement.GetRawText());
        }
    }

    [Fact]
    public async Task Generate_disabled_keeps_projected_json_as_text_without_advertised_schema()
    {
        await using LoopbackHost upstream = await Respond("[\"a\"]");
        string manifest = Manifest(
            upstream.Address,
            "yes",
            capability: true,
            outputSchema: ProjectionSchema,
            outputProjection: ProjectionPolicy)
            .Replace("\"generate\": true", "\"generate\": false", StringComparison.Ordinal);
        string name = "manifest-projection-text-" + Guid.NewGuid().ToString("N");
        string manifestPath = ServedManifests.Write(_root, name, manifest);
        string store = Directory.CreateDirectory(Path.Combine(_root, "files-" + name)).FullName;
        await using ServedEngine engine = await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", manifestPath)], store),
            Token);
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token, "2026-07-28");

        McpExchange listed = await session.RequestAsync("tools/list", 2, Token);
        McpExchange called = await session.CallAsync("read-value", "{}", 3, Token);

        Assert.False(Tool(listed).TryGetProperty("outputSchema", out _));
        Assert.False(Result(called).TryGetProperty("structuredContent", out _));
        using JsonDocument text = JsonDocument.Parse(Text(called));
        Assert.Equal("[\"a\"]", text.RootElement.GetProperty("data").GetRawText());
        Assert.Equal("end", text.RootElement.GetProperty("pagination").GetProperty("state").GetString());
        Assert.False(Result(called).TryGetProperty("isError", out _));
    }

    [Fact]
    public async Task Output_schema_validation_runs_again_on_a_cached_raw_response()
    {
        int upstreamSends = 0;
        await using LoopbackHost upstream = await LoopbackHost.StartAsync(
            async context =>
            {
                Interlocked.Increment(ref upstreamSends);
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"value\":\"not-an-integer\"}", context.RequestAborted);
            },
            Token);
        ConcurrentQueue<RuntimeDiagnostic> diagnostics = new();
        (ServedEngine engine, _) = await ServeWithManifestAsync(
            upstream.Address,
            "yes",
            capability: true,
            diagnostics: diagnostic => diagnostics.Enqueue(diagnostic),
            outputSchema: ObjectSchema,
            responseCacheTtlSeconds: 300);
        await using (engine)
        {
            using McpHttpSession session = await McpHttpSession.OpenAsync(
                engine.At("/api/full"),
                Token,
                "2025-06-18");

            McpExchange listed = await session.RequestAsync("tools/list", 2, Token);
            Assert.True(Tool(listed).TryGetProperty("outputSchema", out _));

            McpExchange first = await session.CallAsync("read-value", "{}", 3, Token);
            McpExchange second = await session.CallAsync("read-value", "{}", 4, Token);

            Assert.Equal("{\"value\":\"not-an-integer\"}", Text(first));
            Assert.Equal(Text(first), Text(second));
            Assert.False(Result(first).TryGetProperty("structuredContent", out _));
            Assert.False(Result(second).TryGetProperty("structuredContent", out _));
            Assert.False(Result(first).TryGetProperty("isError", out JsonElement firstError) && firstError.GetBoolean());
            Assert.False(Result(second).TryGetProperty("isError", out JsonElement secondError) && secondError.GetBoolean());
            Assert.Equal(1, upstreamSends);
            Assert.Equal(2, diagnostics.Count(diagnostic => diagnostic.Code == StructuredContentValidator.DiagnosticCode));
        }
    }

    private async Task<ServedEngine> ServeAsync(
        Uri upstream,
        string advertise,
        bool capability,
        string outputSchema = ArraySchema)
        => (await ServeWithManifestAsync(
            upstream,
            advertise,
            capability,
            diagnostics: null,
            outputSchema)).Engine;

    private async Task<(ServedEngine Engine, string Manifest)> ServeWithManifestAsync(
        Uri upstream,
        string advertise,
        bool capability,
        Action<RuntimeDiagnostic>? diagnostics,
        string outputSchema = ArraySchema,
        string? outputProjection = null,
        int? responseCacheTtlSeconds = null)
    {
        string name = "manifest-" + Guid.NewGuid().ToString("N");
        string manifest = ServedManifests.Write(
            _root,
            name,
            Manifest(upstream, advertise, capability, outputSchema, outputProjection, responseCacheTtlSeconds));
        string store = Directory.CreateDirectory(Path.Combine(_root, "files-" + name)).FullName;
        ServedEngine engine = await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", manifest)], store),
            Token,
            diagnostics: diagnostics);

        return (engine, manifest);
    }

    private static string Manifest(
        Uri upstream,
        string advertise,
        bool capability,
        string outputSchema,
        string? outputProjection = null,
        int? responseCacheTtlSeconds = null)
    {
        string cacheMember = responseCacheTtlSeconds is { } ttl
            ? $", \"responseCache\": {{\"ttlSeconds\": {ttl}}}"
            : string.Empty;

        return $$"""
        {
          "manifestFormatVersion": "0.3",
          "sections": {
            "server": {
              "inline": {
                "name": "Structured API",
                "authenticationRequired": false,
                "surfaces": [
                  {
                    "slug": "full",
                    "isDefault": true,
                    "outputSchemas": {{capability.ToString().ToLowerInvariant()}},
                    "operations": [ { "operation": "read-value" } ]
                  }
                ]
              }
            },
            "policy": { "inline": { "baseUrl": "{{upstream.AbsoluteUri}}" } },
            "operations": {
              "inline": {
                "operations": [ { "key": "GET /value", "method": "GET", "path": "/value" } ]
              }
            },
            "agentSurface": {
              "inline": {
                "operations": [
                  {
                    "slug": "read-value",
                    "name": "Read value",
                    "inputSchema": { "type": "object" },
                    "outputSchema": {{outputSchema}},
                    "outputSchemaPolicy": {
                      "generate": true,
                      "advertise": "{{advertise}}",
                      "useInternally": false
                    },
                    {{(outputProjection is null ? string.Empty : "\"outputProjection\": " + outputProjection + ",")}}
                    "binding": { "type": "http", "operation": "GET /value" }{{cacheMember}}
                  }
                ]
              }
            }
          }
        }
        """;
    }

    private static Task<LoopbackHost> Respond(string body)
        => LoopbackHost.StartAsync(
            async context =>
            {
                byte[] bytes = Encoding.UTF8.GetBytes(body);
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                context.Response.ContentLength = bytes.Length;
                await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
            },
            Token);

    private static JsonElement Tool(McpExchange exchange)
    {
        using JsonDocument document = JsonDocument.Parse(exchange.Payload);

        return document.RootElement
            .GetProperty("result")
            .GetProperty("tools")
            .EnumerateArray()
            .Single(tool => string.Equals(tool.GetProperty("name").GetString(), "read-value", StringComparison.Ordinal))
            .Clone();
    }

    private static string OutputSchema(McpExchange exchange)
        => Tool(exchange).GetProperty("outputSchema").GetRawText();

    private static JsonElement Result(McpExchange exchange)
    {
        using JsonDocument document = JsonDocument.Parse(exchange.Payload);
        return document.RootElement.GetProperty("result").Clone();
    }

    private static string Text(McpExchange exchange)
        => Result(exchange).GetProperty("content")[0].GetProperty("text").GetString()
            ?? throw new JsonException("The tool result carried no text.");
}
