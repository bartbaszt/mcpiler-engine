using MCPiler.Engine.Execution.ResponseCaching;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Execution;

public sealed class ResponseCacheOwnershipTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mcpiler-response-cache-" + Guid.NewGuid().ToString("N"));

    public ResponseCacheOwnershipTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task Mounts_and_replacement_generations_own_independent_cold_caches()
    {
        string firstManifest = WriteManifest("one");
        string secondManifest = WriteManifest("two");
        string fileRoot = Path.Combine(_root, "files");
        Directory.CreateDirectory(fileRoot);
        RuntimeStartResult started = EngineRuntime.Start(new RuntimeOptions(
        [
            new MountRequest("/one", firstManifest),
            new MountRequest("/two", secondManifest),
        ],
        fileRoot));

        Assert.True(started.Started, string.Join(Environment.NewLine, started.Refusals));

        EngineExecution firstExecution = EngineExecution.Create(started);
        ResponseCache first = Assert.IsType<ResponseCache>(firstExecution.ResponseCacheFor(started.Mounts[0]));
        ResponseCache second = Assert.IsType<ResponseCache>(firstExecution.ResponseCacheFor(started.Mounts[1]));
        Assert.NotSame(first, second);
        Assert.NotEqual(first.Activation, second.Activation);

        ResponseCacheLookup firstProducer = first.Acquire(Identity(), 300);
        Assert.Equal(ResponseCacheLookupKind.Miss, firstProducer.Kind);
        ResponseCacheEnvelope envelope = ResponseCacheEnvelope.Capture(
            200,
            "application/json",
            new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            "{}"u8.ToArray());
        ResponseCacheEnvelope stored = Assert.IsType<ResponseCacheEnvelope>(first.TryStore(firstProducer.Key!, envelope, 300));
        firstProducer.Flight!.Publish(stored);
        firstProducer.Flight.Dispose();

        ResponseCacheLookup secondMiss = second.Acquire(Identity(), 300);
        Assert.Equal(ResponseCacheLookupKind.Miss, secondMiss.Kind);
        secondMiss.Flight!.Abandon();
        secondMiss.Flight.Dispose();
        Assert.Equal(1, first.EntryCount);
        Assert.Equal(0, second.EntryCount);

        EngineExecution replacementExecution = EngineExecution.Create(started);
        ResponseCache replacement = Assert.IsType<ResponseCache>(replacementExecution.ResponseCacheFor(started.Mounts[0]));
        Assert.NotSame(first, replacement);
        Assert.NotEqual(first.Activation, replacement.Activation);
        Assert.Equal(0, replacement.EntryCount);
        ResponseCacheLookup replacementMiss = replacement.Acquire(Identity(), 300);
        Assert.Equal(ResponseCacheLookupKind.Miss, replacementMiss.Kind);
        replacementMiss.Flight!.Abandon();
        replacementMiss.Flight.Dispose();

        EngineGeneration generation = new(
            number: 1,
            MountSet.From(started),
            replacementExecution,
            ownsExecution: true);

        await generation.RetireAsync();

        Assert.True(replacement.IsDisposed);
        firstExecution.Dispose();
        Assert.True(first.IsDisposed);
    }

    [Fact]
    public void Zero_runtime_ceiling_creates_no_mount_cache()
    {
        string manifest = WriteManifest("disabled");
        string fileRoot = Path.Combine(_root, "files-disabled");
        Directory.CreateDirectory(fileRoot);
        RuntimeStartResult started = EngineRuntime.Start(new RuntimeOptions(
            [new MountRequest("/disabled", manifest)],
            fileRoot)
        {
            ResponseCache = ResponseCacheOptions.Default with { MaxTtlSeconds = 0 },
        });

        Assert.True(started.Started, string.Join(Environment.NewLine, started.Refusals));
        using EngineExecution execution = EngineExecution.Create(started);

        Assert.Null(execution.ResponseCacheFor(started.Mounts[0]));
    }

    private string WriteManifest(string name)
    {
        string path = Path.Combine(_root, name);
        Directory.CreateDirectory(path);
        File.WriteAllText(
            Path.Combine(path, "manifest.json"),
            """
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Cache API" } },
                "policy": { "inline": { "baseUrl": "https://api.example.test" } },
                "operations": {
                  "inline": {
                    "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      { "slug": "list-pets", "name": "List pets", "binding": { "type": "http", "operation": "GET /pets" } }
                    ]
                  }
                }
              }
            }
            """);
        return path;
    }

    private static ResponseCacheIdentity Identity()
        => new()
        {
            OperationSlug = "list-pets",
            ResolvedBindingSemantics = "http:binding-1",
            EffectiveHttpOperationKey = "GET /pets",
            Method = "GET",
            EffectiveUri = "https://api.example.test/pets",
            Headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["Accept"] = ["application/json"],
            },
            UpstreamAuthority = "authority-1",
            CallerPartition = "public",
            PolicyFingerprint = "response-cache:ttl=300",
        };
}
