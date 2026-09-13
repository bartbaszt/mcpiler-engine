using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.IO.Pipelines;

using MCPiler.Engine.Host.Cli;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

/// <summary>The local MCP transport as a third-party client observes it.</summary>
public sealed class StdioTransportTests : IDisposable
{
    private const string Identity = "mcpiler-engine test (manifest format 0.2)";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-stdio-" + Guid.NewGuid().ToString("N"));

    public StdioTransportTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task The_serialized_tool_list_is_byte_identical_to_streamable_http()
    {
        string manifest = ServedManifests.Write(_root, "parity", ServedManifests.OneSurface);

        await using ServedEngine http = await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", manifest)], Store("http")),
            TestContext.Current.CancellationToken);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            http.At("/api/full"),
            TestContext.Current.CancellationToken);

        McpExchange remote = await session.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken);
        string local = await StdioListAsync(manifest, Store("stdio"), TestContext.Current.CancellationToken);

        Assert.Equal(ToolListBytes(remote.Payload), ToolListBytes(local));
        Assert.NotEqual("[]", ToolListBytes(local));
    }

    [Fact]
    public async Task The_same_invalid_invocation_has_the_same_error_over_both_transports()
    {
        string manifest = ServedManifests.Write(_root, "call-parity", ServedManifests.OneSurface);

        await using ServedEngine http = await ServedEngine.StartAsync(
            new RuntimeOptions([new MountRequest("/api", manifest)], Store("call-http")),
            TestContext.Current.CancellationToken);

        using McpHttpSession session = await McpHttpSession.OpenAsync(
            http.At("/api/full"),
            TestContext.Current.CancellationToken);

        McpExchange remote = await session.CallAsync(
            "list-pets",
            "{\"limit\":\"not-an-integer\"}",
            2,
            TestContext.Current.CancellationToken);

        string local = await StdioRequestAsync(
            manifest,
            Store("call-stdio"),
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list-pets\",\"arguments\":{\"limit\":\"not-an-integer\"}}}",
            TestContext.Current.CancellationToken);

        Assert.Equal(remote.Payload, local);
        Assert.Contains("\"isError\":true", local, StringComparison.Ordinal);
        Assert.Contains("advertised input schema", local, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_scoped_surface_is_served_locally_without_a_token()
    {
        string scoped = ServedManifests.OneSurface.Replace(
            "\"isDefault\": true,",
            "\"isDefault\": true, \"requiredScopes\": [\"tools.invoke\"],",
            StringComparison.Ordinal);

        string manifest = ServedManifests.Write(_root, "scoped", scoped);
        string response = await StdioListAsync(manifest, Store("scoped"), TestContext.Current.CancellationToken);

        Assert.NotEqual("[]", ToolListBytes(response));
        Assert.Contains("no network listener", StdioTransport.SecurityBoundaryStatement, StringComparison.Ordinal);
        Assert.Contains("process boundary authorizes", StdioTransport.SecurityBoundaryStatement, StringComparison.Ordinal);
    }

    [Fact]
    public void More_than_one_mount_is_refused_before_stdio_starts()
    {
        string first = ServedManifests.Write(_root, "first", ServedManifests.OneSurface);
        string second = ServedManifests.Write(_root, "second", ServedManifests.OneSurface);

        RuntimeStartResult started = EngineRuntime.Start(
            new RuntimeOptions(
                [new MountRequest("/first", first), new MountRequest("/second", second)],
                Store("many-mounts")));

        Assert.True(started.Started);
        Assert.False(StdioTransport.TrySelectSurface(started, out _, out string? refusal));
        Assert.Contains("exactly one mounted Manifest", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void More_than_one_surface_is_refused_as_ambiguous()
    {
        string manifest = ServedManifests.Write(_root, "many-surfaces", ServedManifests.ThreeSurfaces);
        RuntimeStartResult started = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", manifest)], Store("many-surfaces")));

        Assert.True(started.Started);
        Assert.False(StdioTransport.TrySelectSurface(started, out _, out string? refusal));
        Assert.Contains("exactly one surface", refusal, StringComparison.Ordinal);
        Assert.Contains("exposes 3", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Require_sealed_refusal_is_identical_over_http_and_stdio()
    {
        string manifest = ServedManifests.Write(_root, "unsealed", ServedManifests.OneSurface);

        string[] common =
        [
            "serve",
            "--mount", "/api=" + manifest,
            "--file-store-root", Store("sealed"),
            "--require-sealed",
        ];

        CommandOutcome http = await HostCommands.RunAsync(
            common,
            Identity,
            TestContext.Current.CancellationToken);

        CommandOutcome stdio = await HostCommands.RunAsync(
            [.. common, "--transport", "stdio"],
            Identity,
            TestContext.Current.CancellationToken);

        Assert.Equal(http.ExitCode, stdio.ExitCode);
        Assert.Equal(http.Output, stdio.Output);
        Assert.Contains("manifest/seal-required", stdio.Output, StringComparison.Ordinal);
    }

    private async Task<string> StdioListAsync(
        string manifest,
        string store,
        CancellationToken cancellationToken)
        => await StdioRequestAsync(
            manifest,
            store,
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}",
            cancellationToken);

    private async Task<string> StdioRequestAsync(
        string manifest,
        string store,
        string request,
        CancellationToken cancellationToken)
    {
        RuntimeStartResult started = EngineRuntime.Start(
            new RuntimeOptions([new MountRequest("/api", manifest)], store));

        Assert.True(started.Started);

        using EngineExecution execution = EngineExecution.Create(started);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));

        Pipe toServer = new();
        Pipe fromServer = new();

        await using Stream serverInput = toServer.Reader.AsStream();
        await using Stream serverOutput = fromServer.Writer.AsStream();
        await using Stream clientInput = toServer.Writer.AsStream();
        await using Stream clientOutput = fromServer.Reader.AsStream();
        using StreamReader reader = new(clientOutput, Encoding.UTF8, leaveOpen: true);

        Task host = StdioTransport.RunAsync(started, execution, serverInput, serverOutput, timeout.Token);

        await SendAsync(clientInput, Initialize(), timeout.Token);
        string initialize = await ReadResponseAsync(reader, id: 1, timeout.Token);
        Assert.Contains("\"result\"", initialize, StringComparison.Ordinal);

        await SendAsync(
            clientInput,
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
            timeout.Token);
        await SendAsync(clientInput, request, timeout.Token);

        string listed = await ReadResponseAsync(reader, id: 2, timeout.Token);

        await clientInput.DisposeAsync();
        await host.WaitAsync(timeout.Token);

        return listed;
    }

    private static async Task SendAsync(Stream input, string message, CancellationToken cancellationToken)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(message + "\n");
        await input.WriteAsync(bytes, cancellationToken);
        await input.FlushAsync(cancellationToken);
    }

    private static async Task<string> ReadResponseAsync(
        StreamReader reader,
        int id,
        CancellationToken cancellationToken)
    {
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            JsonNode? message = JsonNode.Parse(line);

            if (message?["id"]?.GetValue<int>() == id)
            {
                return line;
            }
        }

        throw new JsonException($"The stdio wire ended before response {id}.");
    }

    private static string ToolListBytes(string payload)
    {
        using JsonDocument document = JsonDocument.Parse(payload);
        return document.RootElement.GetProperty("result").GetProperty("tools").GetRawText();
    }

    private static string Initialize()
        => "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\""
            + McpHttpSession.ProtocolVersion
            + "\",\"capabilities\":{},\"clientInfo\":{\"name\":\"engine-stdio-tests\",\"version\":\"1.0\"}}}";

    private string Store(string name)
    {
        string store = Path.Combine(_root, "files-" + name + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(store);
        return store;
    }
}
