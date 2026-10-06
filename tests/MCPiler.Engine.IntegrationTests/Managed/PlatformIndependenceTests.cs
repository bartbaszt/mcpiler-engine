using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Host.Managed;
using MCPiler.Engine.IntegrationTests;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Manifest.Loading;
using MCPiler.Engine.Manifest.Sealing;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Runtime.Managed;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Managed;

/// <summary>
/// Proves the property the Platform cannot observe: once a generation is loaded, the Engine keeps
/// serving it while the Platform is unavailable (<c>ENG-AC27</c>, obligation ENG-1).
/// </summary>
/// <remarks>
/// <para>
/// The criterion is deliberately asserted with the Platform <em>process gone</em>, not merely a
/// failing request: the stand-in's listener is stopped after the generation is active, so any
/// invocation that reaches the Platform would fail to connect. The MCP surface must answer from
/// the generation already loaded in memory, returning the same generation and the same tool set,
/// and an invocation must still reach the real upstream.
/// </para>
/// <para>
/// This is the Engine-repository half of <c>ENG-AC27</c>. The Platform change
/// <c>public-engine-website-and-manifest-catalogue</c> records ENG-AC27 as NOT VERIFIED precisely
/// because it is a runtime property of this process; this test converts it into a recorded Engine
/// fact. It is a characterisation test: if the runtime already behaves this way it pins the
/// behaviour against regression, and if it does not it is a real defect surfaced on its own merits.
/// </para>
/// </remarks>
public sealed class PlatformIndependenceTests : IAsyncDisposable
{
    private const string SecretCanary = "CANARY-deployment-secret-eng1";
    private const string ProviderKey = "MCPILER_OAUTH2_CLIENT_CREDENTIALS_CLIENTSECRET";

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "mcpiler-platform-independence-" + Guid.NewGuid().ToString("N"));

    private ManagedProcess? _process;

    public PlatformIndependenceTests() => Directory.CreateDirectory(_root);

    [Fact]
    public async Task An_active_generation_keeps_serving_after_the_platform_listener_is_gone()
    {
        // An upstream the serving path reaches on invocation: its request count proves the call
        // left the process rather than being answered from a stale in-memory refusal.
        List<string> upstreamRequests = [];
        await using LoopbackHost upstream = await RecordingUpstream(upstreamRequests);

        // A stand-in that speaks enough of the managed protocol for the product's own client to
        // receive one desired generation whose policy points at the loopback upstream. It is a real
        // listener, so stopping it is a genuine outage.
        var generation = Generation("g1", ServedManifests.Upstream(upstream.Address), prefix: "/mcp/connector");
        await using PlatformStandIn platform = await PlatformStandIn.StartAsync(
            Path.Combine(_root, "secret-" + Guid.NewGuid().ToString("N")),
            _ => Response.Generation(generation),
            TestContext.Current.CancellationToken);

        _process = await StartAsync(platform, upstream.Address);

        Assert.Equal("g1", _process.Worker.ActiveGenerationId);

        // While the Platform is up: the generation is the one serving.
        string[] onlineNames;
        using (McpHttpSession online = await McpHttpSession.OpenAsync(
            _process.At("/mcp/connector/full"),
            TestContext.Current.CancellationToken))
        {
            onlineNames = Names(await online.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)).ToArray();
        }

        Assert.Contains("list-pets", onlineNames);

        // The Platform becomes unavailable: its listener is gone, so any call to it cannot connect.
        await platform.StopListenerAsync();

        // The active generation is unchanged and the same surface keeps answering with the same
        // tools. Nothing on the serving path consults the Platform, so the outage is invisible.
        Assert.Equal("g1", _process.Worker.ActiveGenerationId);

        using McpHttpSession offline = await McpHttpSession.OpenAsync(
            _process.At("/mcp/connector/full"),
            TestContext.Current.CancellationToken);

        string[] offlineNames = Names(await offline.RequestAsync("tools/list", 2, TestContext.Current.CancellationToken)).ToArray();
        Assert.Equal(onlineNames, offlineNames);

        // An invocation is served end to end with the Platform gone: it reaches the real upstream.
        McpExchange call = await offline.CallAsync("list-pets", """{"status":"available"}""", 3, TestContext.Current.CancellationToken);
        Assert.True(
            upstreamRequests.Count == 1,
            $"The invocation did not reach the upstream. Status={call.Status} Body={call.Body} Diagnostics={string.Join(" | ", _process.Diagnostics)}");
        Assert.Equal(["GET /pets?status=available"], upstreamRequests);

        Assert.Equal("g1", _process.Worker.ActiveGenerationId);
    }

    private static async Task<LoopbackHost> RecordingUpstream(List<string> received)
        => await LoopbackHost.StartAsync(
            async context =>
            {
                lock (received)
                {
                    received.Add(context.Request.Method + " " + context.Request.Path + context.Request.QueryString);
                }

                byte[] bytes = Encoding.UTF8.GetBytes("""[{"id":1,"name":"Rex"}]""");

                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                context.Response.ContentLength = bytes.Length;

                await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
            },
            TestContext.Current.CancellationToken);

    private async Task<ManagedProcess> StartAsync(PlatformStandIn platform, Uri upstream)
    {
        string fileRoot = Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fileRoot);

        ManagedGenerationLoader loader = OpenLoader(fileRoot);

        var manager = new EngineGenerationManager(HostMode.Managed);
        var drain = new DrainCoordinator();

        int port = LoopbackPorts.Reserve();
        string authority = $"127.0.0.1:{port}";

        var binding = new HostBinding(
            new RuntimeOptions([], fileRoot),
            new HostListenOptions($"http://{authority}", HostTransport.Http),
            null,
            HostLifecycleOptions.Default);

        List<string> diagnostics = [];
        var worker = new ManagedSyncWorker(
            platform.Options(),
            loader,
            manager,
            binding,
            "test",
            diagnostics: message =>
            {
                lock (diagnostics)
                {
                    diagnostics.Add(message);
                }
            },
            backoff: new ManagedSyncBackoff(TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(50)));

        ManagedInitialSync initial = await worker.SynchronizeInitialAsync(TestContext.Current.CancellationToken);
        Assert.True(initial.Started, initial.Refusal?.Message);

        WebApplication app = EngineWebHost.BuildManaged(binding, drain, manager);
        await app.StartAsync(TestContext.Current.CancellationToken);
        worker.Start(TestContext.Current.CancellationToken);

        string bound = app.Urls.Count == 1
            ? app.Urls.Single()
            : throw new InvalidOperationException($"Expected one bound address, found {app.Urls.Count}.");

        return new ManagedProcess(app, new Uri(bound, UriKind.Absolute), manager, worker, loader, drain, diagnostics);
    }

    private static ManagedGenerationLoader OpenLoader(string fileRoot)
        => ManagedGenerationLoader.TryOpen(
            new RuntimeOptions([], fileRoot),
            ServedEngine.Permissive(),
            out ManagedGenerationLoader? loader,
            out IReadOnlyList<StartupRefusal> refusals)
            ? loader!
            : throw new InvalidOperationException(
                "The loader could not be opened: " + string.Join("; ", refusals.Select(item => item.Message)));

    private static IEnumerable<string> Names(McpExchange exchange)
        => Tools(exchange).Select(tool => tool!["name"]!.GetValue<string>());

    private static JsonArray Tools(McpExchange exchange)
        => JsonNode.Parse(exchange.Payload)?["result"]?["tools"] as JsonArray
            ?? throw new InvalidOperationException("The payload carried no tool list: " + exchange.Body);

    private static Dictionary<string, object?> Generation(string id, string manifest, string prefix)
    {
        var bundle = Bundle(manifest);

        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["protocolVersion"] = 2,
            ["generationId"] = id,
            ["mounts"] = new[]
            {
                new
                {
                    prefix,
                    bundle,
                    externalResources = new Dictionary<string, string>(StringComparer.Ordinal),
                },
            },
            ["secrets"] = new Dictionary<string, string>(StringComparer.Ordinal),
            ["metadata"] = new { desiredRevisionId = id, engineVersion = "fixture" },
            ["kind"] = "generation",
            ["compatibility"] = new
            {
                status = "compatible",
                reasonCode = "compatibility/compatible",
                dimension = "contract",
                descriptorSchemaVersion = 1,
                required = (string?)null,
                supported = (string?)null,
                message = "The Platform requirements and Engine support are compatible.",
            },
            ["diagnostics"] = Array.Empty<object>(),
        };
    }

    private static string Bundle(string manifest)
    {
        string directory = Path.Combine(Path.GetTempPath(), "mcpiler-eng1-bundle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        try
        {
            var document = JsonNode.Parse(manifest)!.AsObject();
            document["manifestFormatVersion"] = "0.3";
            File.WriteAllText(Path.Combine(directory, "manifest.json"), document.ToJsonString());

            using var buffer = new MemoryStream();
            ManifestArchiveResult packed = ManifestArchive.Pack(directory, buffer);
            Assert.True(
                packed.Succeeded,
                string.Join("; ", packed.Diagnostics.Select(diagnostic => diagnostic.ToString())));

            return Convert.ToBase64String(buffer.ToArray());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_process is not null)
        {
            await _process.DisposeAsync();
        }

        for (var attempt = 0; attempt < 20 && Directory.Exists(_root); attempt++)
        {
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.Current.CancellationToken);
            }
        }

        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class ManagedProcess : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly DrainCoordinator _drain;

        public ManagedProcess(
            WebApplication app,
            Uri address,
            EngineGenerationManager manager,
            ManagedSyncWorker worker,
            ManagedGenerationLoader loader,
            DrainCoordinator drain,
            List<string> diagnostics)
        {
            _app = app;
            Address = address;
            Manager = manager;
            Worker = worker;
            Loader = loader;
            _drain = drain;
            Diagnostics = diagnostics;
        }

        public Uri Address { get; }

        public EngineGenerationManager Manager { get; }

        public ManagedSyncWorker Worker { get; }

        public ManagedGenerationLoader Loader { get; }

        public List<string> Diagnostics { get; }

        public Uri At(string route) => new(Address, route);

        public async ValueTask DisposeAsync()
        {
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            Worker.Dispose();

            try
            {
                await _app.StopAsync(shutdown.Token);
            }
            finally
            {
                await _app.DisposeAsync();
            }

            Manager.Dispose();
            Loader.Dispose();
            _drain.Dispose();
        }
    }

    private sealed record Response(int StatusCode, byte[]? Body)
    {
        public static Response Generation(Dictionary<string, object?> generation)
            => new(200, JsonSerializer.SerializeToUtf8Bytes(generation));
    }

    /// <summary>
    /// A listener that speaks enough of the managed protocol for the product's client, and can be
    /// taken down to make the Platform genuinely unavailable.
    /// </summary>
    private sealed class PlatformStandIn : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly string _secretFile;

        private PlatformStandIn(WebApplication app, Uri address, string secretFile)
        {
            _app = app;
            Address = address;
            _secretFile = secretFile;
        }

        public Uri Address { get; private set; }

        public static async Task<PlatformStandIn> StartAsync(
            string secretFile,
            Func<JsonObject, Response> answer,
            CancellationToken cancellationToken)
        {
            File.WriteAllText(secretFile, SecretCanary + "\n");

            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                ContentRootPath = AppContext.BaseDirectory,
                EnvironmentName = "Testing",
            });
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");

            WebApplication app = builder.Build();
            var standIn = new PlatformStandIn(app, new Uri("http://127.0.0.1:1"), secretFile);

            app.MapPost("/internal/engine/v1/deployments/{deploymentId}/poll", async context =>
            {
                if (!Authorized(context))
                {
                    context.Response.StatusCode = 401;
                    return;
                }

                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                var body = await reader.ReadToEndAsync(context.RequestAborted);
                JsonObject request = JsonNode.Parse(body)?.AsObject() ?? [];

                Response response = answer(request);

                context.Response.StatusCode = response.StatusCode;
                if (response.StatusCode is >= 200 and < 300)
                {
                    context.Response.Headers[ManagedProtocol.SessionEpochHeader] = "1";
                }

                if (response.Body is { } payload)
                {
                    context.Response.ContentType = "application/json";
                    await context.Response.Body.WriteAsync(payload, context.RequestAborted);
                }
            });

            app.MapPost("/internal/engine/v1/deployments/{deploymentId}/runtime-secrets/reconcile", async context =>
            {
                if (!Authorized(context))
                {
                    context.Response.StatusCode = 401;
                    return;
                }

                context.Response.StatusCode = 503;
            });

            await app.StartAsync(cancellationToken);

            string bound = app.Urls.Count == 1
                ? app.Urls.Single()
                : throw new InvalidOperationException($"Expected one bound address, found {app.Urls.Count}.");

            standIn.Address = new Uri(bound, UriKind.Absolute);
            return standIn;
        }

        /// <summary>Stops the listener so any further call to the Platform cannot connect.</summary>
        public async Task StopListenerAsync()
        {
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await _app.StopAsync(shutdown.Token);
        }

        public ManagedSyncOptions Options()
            => new()
            {
                Endpoint = Address,
                DeploymentId = "connector",
                SecretFile = _secretFile,
                InitialSyncBound = TimeSpan.FromSeconds(3),
                PollBound = TimeSpan.FromSeconds(1),
            };

        public async ValueTask DisposeAsync()
        {
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await _app.DisposeAsync();

            for (var attempt = 0; attempt < 20 && File.Exists(_secretFile); attempt++)
            {
                try
                {
                    File.Delete(_secretFile);
                }
                catch (IOException)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.Current.CancellationToken);
                }
            }

            File.Delete(_secretFile);
        }

        private static bool Authorized(HttpContext context)
            => context.Request.Headers.Authorization.ToString() == $"Bearer {SecretCanary}";
    }
}
