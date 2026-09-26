using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Host.ProjectionWorker;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Runtime.Projection;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Mcp;

public sealed class MountedPolicyExecutionTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("mcpiler-mounted-policy-").FullName;

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Mounted_policy_governs_mcp_projection_effective_limits()
    {
        await using LoopbackHost upstream = await Json("{}");
        var worker = new RecordingWorker(Bytes("{\"value\":1}"));

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address),
            worker,
            Narrowing());

        MountedManifest mount = Assert.Single(engine.Started.Mounts);
        Assert.Equal(1024, mount.Document.Policy.EffectiveLimits.UpstreamResponseSizeLimitBytes);
        Assert.Equal(512, mount.Policy.EffectiveLimits.UpstreamResponseSizeLimitBytes);
        Assert.Equal(100, mount.Document.Policy.EffectiveJmesPathCeiling.MaxInputNodes);
        Assert.Equal(20, mount.Policy.EffectiveJmesPathCeiling.MaxInputNodes);
        Assert.Equal(10000, mount.Document.Policy.EffectiveJmesPathCeiling.MaxEvaluationMilliseconds);
        Assert.Equal(250, mount.Policy.EffectiveJmesPathCeiling.MaxEvaluationMilliseconds);

        McpExchange call = await CallAsync(engine, "read-value");

        Assert.False(IsError(call), $"{Text(call)} limits={string.Join(",", worker.EffectiveLimits)}");
        Assert.Equal("{\"value\":1}", Text(call));
        Assert.Equal(Expected(20, 20, 256, 250), Assert.Single(worker.EffectiveLimits));
    }

    [Fact]
    public async Task Mounted_policy_input_ceiling_refuses_before_worker()
    {
        await using LoopbackHost upstream = await Json("{\"a\":[1,2,3,4]}");
        var worker = new RecordingWorker();

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address),
            worker,
            Narrowing(inputNodes: 3));

        McpExchange call = await CallAsync(engine, "read-value");

        Assert.True(IsError(call));
        Assert.Contains("jmespath-input-too-many-nodes", Text(call), StringComparison.Ordinal);
        Assert.Empty(worker.EffectiveLimits);
    }

    [Fact]
    public async Task Mounted_policy_result_ceiling_refuses_after_worker()
    {
        await using LoopbackHost upstream = await Json("{}");
        var worker = new RecordingWorker(Bytes("[1,2,3,4]"));

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address),
            worker,
            Narrowing(resultNodes: 3));

        McpExchange call = await CallAsync(engine, "read-value");

        Assert.True(IsError(call), Text(call));
        Assert.Contains("jmespath-result-too-many-nodes", Text(call), StringComparison.Ordinal);
        Assert.Equal(Expected(20, 3, 256, 250), Assert.Single(worker.EffectiveLimits));
    }

    [Fact]
    public async Task Mounted_policy_output_ceiling_refuses_after_worker()
    {
        await using LoopbackHost upstream = await Json("{}");
        var worker = new RecordingWorker(Bytes("\"123456789\""));

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address),
            worker,
            Narrowing(outputBytes: 8));

        McpExchange call = await CallAsync(engine, "read-value");

        Assert.True(IsError(call));
        Assert.Contains("jmespath-output-too-many-bytes", Text(call), StringComparison.Ordinal);
        Assert.Equal(Expected(20, 20, 8, 250), Assert.Single(worker.EffectiveLimits));
    }

    [Fact]
    public async Task Mounted_policy_response_ceiling_refuses_before_projection()
    {
        await using LoopbackHost upstream = await Json("{\"value\":\"012345678901234567890123456789\"}");
        var worker = new RecordingWorker();

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address),
            worker,
            Narrowing(responseBytes: 8));

        McpExchange call = await CallAsync(engine, "read-value");

        Assert.True(IsError(call));
        Assert.Equal("ResponseSize", ErrorCode(call));
        Assert.Empty(worker.EffectiveLimits);
    }

    [Fact]
    public async Task Mounted_deadline_is_enforced_by_real_worker_and_pool_recovers()
    {
        int requests = 0;
        byte[] slow = Bytes(Sequence(20_000));
        byte[] quick = Bytes("[1,2,3]");
        await using LoopbackHost upstream = await JsonNext(
            () => Interlocked.Increment(ref requests) == 1 ? slow : quick);

        WorkerPoolOptions options = WorkerOptions();
        using var validator = new WorkerExpressionValidator(options);
        using var worker = new ProjectionWorkerHost(options);
        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address, expression: "sort(@)", largeLimits: true),
            validator,
            worker,
            Narrowing(
                responseBytes: 1_000_000,
                inputNodes: 100_000,
                resultNodes: 100_000,
                outputBytes: 1_000_000,
                deadlineMilliseconds: 500));

        MountedManifest mount = Assert.Single(engine.Started.Mounts);
        Assert.Equal(10_000, mount.Document.Policy.EffectiveJmesPathCeiling.MaxEvaluationMilliseconds);
        Assert.Equal(500, mount.Policy.EffectiveJmesPathCeiling.MaxEvaluationMilliseconds);

        McpExchange timedOut = await CallAsync(engine, "read-value");
        Assert.True(IsError(timedOut), Text(timedOut));
        Assert.Contains("jmespath-operational-timeout", Text(timedOut), StringComparison.Ordinal);

        McpExchange recovered = await CallAsync(engine, "read-value");
        Assert.False(IsError(recovered), Text(recovered));
        Assert.Equal("[1,2,3]", Text(recovered));
        Assert.Equal(2, Volatile.Read(ref requests));
    }

    [Fact]
    public async Task Mounted_transform_ceiling_refuses_direct_output_program()
    {
        await using LoopbackHost upstream = await Json("{}");
        var worker = new RecordingWorker();

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address, outputProjection: TransformProjection()),
            worker,
            Narrowing(transformOutputBytes: 8));

        McpExchange call = await CallAsync(engine, "read-value");

        Assert.True(IsError(call), Text(call));
        Assert.Contains("E_LIMIT_OUTPUT_BYTES", Text(call), StringComparison.Ordinal);
        Assert.Empty(worker.EffectiveLimits);
    }

    [Fact]
    public async Task Mounted_transform_ceiling_refuses_compound_output_program()
    {
        List<string> arrivals = [];
        await using LoopbackHost upstream = await Json(arrivals, "{}");
        var worker = new RecordingWorker(Bytes("{}"));

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address, compound: true, compoundOutputProgram: TransformProgram()),
            worker,
            Narrowing(transformOutputBytes: 8));

        McpExchange call = await CallAsync(engine, "flow");

        Assert.True(IsError(call), Text(call));
        Assert.Equal("Transformation", ErrorCode(call));
        using (JsonDocument detail = JsonDocument.Parse(Text(call)))
        {
            Assert.Equal("selection", detail.RootElement.GetProperty("stage").GetString());
        }
        Assert.Equal(["/child-0"], arrivals);
    }

    [Fact]
    public async Task Mounted_compound_child_propagates_the_mounted_policy()
    {
        List<string> arrivals = [];
        await using LoopbackHost upstream = await Json(arrivals, "{\"value\":1}");
        var worker = new RecordingWorker(Bytes("{\"value\":1}"));

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address, compound: true),
            worker,
            Narrowing(inputNodes: 50, resultNodes: 50, outputBytes: 256, deadlineMilliseconds: 125));

        McpExchange call = await CallAsync(engine, "flow");

        Assert.False(IsError(call), $"{Text(call)} limits={string.Join(",", worker.EffectiveLimits)}");
        Assert.Equal("{}", Text(call));
        Assert.Equal(["/child-0"], arrivals);
        Assert.Equal(Expected(50, 50, 256, 125), Assert.Single(worker.EffectiveLimits));
    }

    [Fact]
    public async Task Mounted_response_ceiling_reaches_compound_child()
    {
        List<string> arrivals = [];
        await using LoopbackHost upstream = await Json(arrivals, "{}");
        var worker = new RecordingWorker(Bytes("{}"));

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address, compound: true),
            worker,
            Narrowing(responseBytes: 1));

        McpExchange call = await CallAsync(engine, "flow");

        Assert.True(IsError(call), Text(call));
        Assert.Equal("ResponseSize", ErrorCode(call));
        Assert.Equal(["/child-0"], arrivals);
        Assert.Empty(worker.EffectiveLimits);
    }

    [Fact]
    public async Task Mounted_compound_response_budget_bounds_all_steps()
    {
        List<string> arrivals = [];
        await using LoopbackHost upstream = await Json(arrivals, "{}");
        var worker = new RecordingWorker(Bytes("{}"));

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address, compound: true, compoundSteps: 2),
            worker,
            Narrowing(compoundResponseBytes: 2));

        McpExchange call = await CallAsync(engine, "flow");

        Assert.True(IsError(call), Text(call));
        Assert.Equal("ResponseSize", ErrorCode(call));
        Assert.Equal(["/child-0"], arrivals);
        Assert.Single(worker.EffectiveLimits);
    }

    [Fact]
    public async Task Mounted_compound_timeout_bounds_workflow()
    {
        int arrivals = 0;
        await using LoopbackHost upstream = await DelayedJson(() => Interlocked.Increment(ref arrivals), 250);
        var worker = new RecordingWorker(Bytes("{}"));

        await using ServedEngine engine = await ServeAsync(
            Manifest(upstream.Address, compound: true, compoundTimeoutSeconds: 2),
            worker,
            Narrowing(compoundTimeout: TimeSpan.FromMilliseconds(50)));

        McpExchange call = await CallAsync(engine, "flow");

        Assert.True(IsError(call), Text(call));
        Assert.Equal("Timeout", ErrorCode(call));
        Assert.Equal(1, Volatile.Read(ref arrivals));
        Assert.Empty(worker.EffectiveLimits);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private Task<ServedEngine> ServeAsync(
        string manifestText,
        RecordingWorker worker,
        IReadOnlyDictionary<string, string>? narrowing)
        => ServeAsync(manifestText, worker, worker, narrowing);

    private async Task<ServedEngine> ServeAsync(
        string manifestText,
        IProjectionExpressionValidator expressionValidator,
        IProjectionWorker projectionWorker,
        IReadOnlyDictionary<string, string>? narrowing)
    {
        string name = "manifest-" + Guid.NewGuid().ToString("N");
        string manifest = ServedManifests.Write(_root, name, manifestText);
        string files = Directory.CreateDirectory(Path.Combine(_root, name + "-files")).FullName;
        MountRequest mount = new("/api", manifest)
        {
            Narrowing = narrowing ?? new Dictionary<string, string>(StringComparer.Ordinal),
        };
        RuntimeOptions options = new([mount], files)
        {
            ExpressionValidator = expressionValidator,
            ProjectionWorker = projectionWorker,
        };

        return await ServedEngine.StartAsync(options, Token);
    }

    private static async Task<McpExchange> CallAsync(ServedEngine engine, string tool)
    {
        using McpHttpSession session = await McpHttpSession.OpenAsync(engine.At("/api/full"), Token);
        return await session.CallAsync(tool, "{}", 2, Token);
    }

    private static Dictionary<string, string> Narrowing(
        long responseBytes = 512,
        long inputNodes = 20,
        long resultNodes = 20,
        long outputBytes = 256,
        int deadlineMilliseconds = 250,
        long? transformOutputBytes = null,
        long? compoundResponseBytes = null,
        TimeSpan? compoundTimeout = null)
    {
        var narrowing = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["UpstreamResponseSizeLimitBytes"] = responseBytes.ToString(CultureInfo.InvariantCulture),
            ["JmesPathMaxExpressionBytes"] = "32",
            ["JmesPathMaxInputNodes"] = inputNodes.ToString(CultureInfo.InvariantCulture),
            ["JmesPathMaxInputDepth"] = "4",
            ["JmesPathMaxResultNodes"] = resultNodes.ToString(CultureInfo.InvariantCulture),
            ["JmesPathMaxResultDepth"] = "4",
            ["JmesPathMaxOutputBytes"] = outputBytes.ToString(CultureInfo.InvariantCulture),
            ["JmesPathMaxEvaluationMilliseconds"] = TimeSpan.FromMilliseconds(deadlineMilliseconds).ToString("c", CultureInfo.InvariantCulture),
        };

        if (transformOutputBytes is { } transformOutput)
        {
            narrowing["TransformMaxOutputBytes"] = transformOutput.ToString(CultureInfo.InvariantCulture);
        }

        if (compoundResponseBytes is { } compoundResponse)
        {
            narrowing["CompoundMaxTotalResponseBytes"] = compoundResponse.ToString(CultureInfo.InvariantCulture);
        }

        if (compoundTimeout is { } timeout)
        {
            narrowing["CompoundWorkflowTimeout"] = timeout.ToString("c", CultureInfo.InvariantCulture);
        }

        return narrowing;
    }

    private static JmesPathLimits Expected(long inputNodes, long resultNodes, long outputBytes, int deadlineMilliseconds)
        => new(32, inputNodes, 4, resultNodes, 4, outputBytes, deadlineMilliseconds);

    private static Task<LoopbackHost> Json(string body)
        => LoopbackHost.StartAsync(200, "application/json", Bytes(body), Token);

    private static Task<LoopbackHost> Json(List<string> arrivals, string body)
        => LoopbackHost.StartAsync(
            async context =>
            {
                arrivals.Add(context.Request.Path.Value ?? "/");
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                context.Response.ContentLength = Bytes(body).Length;
                await context.Response.Body.WriteAsync(Bytes(body), context.RequestAborted);
            },
            Token);

    private static Task<LoopbackHost> JsonNext(Func<byte[]> next)
        => LoopbackHost.StartAsync(
            async context =>
            {
                byte[] body = next();
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                context.Response.ContentLength = body.Length;
                await context.Response.Body.WriteAsync(body, context.RequestAborted);
            },
            Token);

    private static Task<LoopbackHost> DelayedJson(Action arrived, int milliseconds)
        => LoopbackHost.StartAsync(
            async context =>
            {
                arrived();
                await Task.Delay(milliseconds, context.RequestAborted);
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.Body.WriteAsync(Bytes("{}"), context.RequestAborted);
            },
            Token);

    private static WorkerPoolOptions WorkerOptions()
    {
        string directory = AppContext.BaseDirectory;
        string apphost = Path.Combine(directory, OperatingSystem.IsWindows() ? "mcpiler-engine.exe" : "mcpiler-engine");
        Assert.True(File.Exists(apphost), $"The Engine apphost is missing from {directory}.");

        return WorkerPoolOptions.Default with
        {
            TotalDeadline = TimeSpan.FromSeconds(30),
            Launch = new WorkerLaunch(apphost, null),
        };
    }

    private static string Sequence(int count)
    {
        var value = new StringBuilder("[");
        for (int item = count; item > 0; item--)
        {
            if (item != count)
            {
                value.Append(',');
            }

            value.Append(item);
        }

        return value.Append(']').ToString();
    }

    private static byte[] Bytes(string value) => Encoding.UTF8.GetBytes(value);

    private static bool IsError(McpExchange exchange)
    {
        JsonElement result = Result(exchange);
        return result.TryGetProperty("isError", out JsonElement error) && error.GetBoolean();
    }

    private static string Text(McpExchange exchange)
        => Result(exchange).GetProperty("content")[0].GetProperty("text").GetString()!;

    private static string? ErrorCode(McpExchange exchange)
    {
        JsonElement result = Result(exchange);
        return result.TryGetProperty("_meta", out JsonElement meta)
            && meta.TryGetProperty("io.mcpiler/errorCode", out JsonElement code)
            ? code.GetString()
            : null;
    }

    private static JsonElement Result(McpExchange exchange)
    {
        using JsonDocument document = JsonDocument.Parse(exchange.Payload);
        return document.RootElement.GetProperty("result").Clone();
    }

    private static string Manifest(
        Uri upstream,
        bool compound = false,
        int compoundSteps = 1,
        string expression = "@",
        bool largeLimits = false,
        JsonObject? outputProjection = null,
        JsonObject? compoundOutputProgram = null,
        int? compoundTimeoutSeconds = null)
    {
        JsonArray operations = [];
        JsonArray surfaceOperations = [];
        JsonArray agentOperations = [];

        if (compound)
        {
            JsonArray steps = [];

            for (int index = 0; index < compoundSteps; index++)
            {
                string slug = $"child-{index}";
                string path = $"/{slug}";
                operations.Add(Operation($"GET {path}", path));
                surfaceOperations.Add(new JsonObject { ["operation"] = slug });
                agentOperations.Add(Agent(
                    slug,
                    slug,
                    OperationBinding($"GET {path}", expression, largeLimits)));
                steps.Add(new JsonObject
                {
                    ["stepId"] = $"step-{index}",
                    ["operation"] = slug,
                    ["inputMappings"] = new JsonArray(),
                });
            }

            surfaceOperations.Add(new JsonObject { ["operation"] = "flow" });

            JsonObject compoundBinding = new()
            {
                ["type"] = "compound",
                ["bindingVersion"] = 1,
                ["failurePolicy"] = "failFast",
                ["steps"] = steps,
            };

            if (compoundOutputProgram is not null)
            {
                compoundBinding["outputSelection"] = new JsonObject
                {
                    ["entries"] = new JsonArray(),
                    ["outputProgram"] = compoundOutputProgram,
                };
            }

            if (compoundTimeoutSeconds is { } timeoutSeconds)
            {
                compoundBinding["workflowTimeoutSeconds"] = timeoutSeconds;
            }

            agentOperations.Add(new JsonObject
            {
                ["slug"] = "flow",
                ["kind"] = "compound",
                ["name"] = "Flow",
                ["inputSchema"] = new JsonObject { ["type"] = "object" },
                ["binding"] = compoundBinding,
            });
        }
        else
        {
            operations.Add(Operation("GET /value", "/value"));
            surfaceOperations.Add(new JsonObject { ["operation"] = "read-value" });
            agentOperations.Add(Agent(
                "read-value",
                "Read value",
                OperationBinding("GET /value", expression, largeLimits, outputProjection)));
        }

        long responseLimit = largeLimits ? 2_000_000 : 1024;
        long nodeLimit = largeLimits ? 1_000_000 : 100;
        long outputLimit = largeLimits ? 1_000_000 : 512;

        return new JsonObject
        {
            ["manifestFormatVersion"] = "0.3",
            ["sections"] = new JsonObject
            {
                ["server"] = new JsonObject
                {
                    ["inline"] = new JsonObject
                    {
                        ["formatVersion"] = 2,
                        ["name"] = "Mounted Policy API",
                        ["authenticationRequired"] = false,
                        ["surfaces"] = new JsonArray
                        {
                            new JsonObject
                            {
                                ["slug"] = "full",
                                ["isDefault"] = true,
                                ["operations"] = surfaceOperations,
                            },
                        },
                    },
                },
                ["policy"] = new JsonObject
                {
                    ["inline"] = new JsonObject
                    {
                        ["formatVersion"] = 2,
                        ["baseUrl"] = upstream.AbsoluteUri,
                        ["limits"] = new JsonObject
                        {
                            ["upstreamResponseSizeLimitBytes"] = responseLimit,
                        },
                        ["jmesPathCeiling"] = new JsonObject
                        {
                            ["maxExpressionBytes"] = 256,
                            ["maxInputNodes"] = nodeLimit,
                            ["maxInputDepth"] = 16,
                            ["maxResultNodes"] = nodeLimit,
                            ["maxResultDepth"] = 8,
                            ["maxOutputBytes"] = outputLimit,
                            ["maxEvaluationMilliseconds"] = 10000,
                        },
                    },
                },
                ["operations"] = new JsonObject
                {
                    ["inline"] = new JsonObject
                    {
                        ["formatVersion"] = 1,
                        ["operations"] = operations,
                    },
                },
                ["agentSurface"] = new JsonObject
                {
                    ["inline"] = new JsonObject
                    {
                        ["formatVersion"] = 4,
                        ["operations"] = agentOperations,
                    },
                },
            },
        }.ToJsonString();
    }

    private static JsonObject Operation(string key, string path)
        => new()
        {
            ["key"] = key,
            ["method"] = "GET",
            ["path"] = path,
            ["responses"] = new JsonObject
            {
                ["200"] = new JsonObject
                {
                    ["content"] = new JsonObject
                    {
                        ["application/json"] = new JsonObject
                        {
                            ["schema"] = new JsonObject { ["type"] = "object" },
                        },
                    },
                },
            },
        };

    private static JsonObject Agent(string slug, string name, JsonObject binding)
        => new()
        {
            ["slug"] = slug,
            ["name"] = name,
            ["inputSchema"] = new JsonObject { ["type"] = "object" },
            ["binding"] = binding,
        };

    private static JsonObject OperationBinding(
        string operation,
        string expression = "@",
        bool largeLimits = false,
        JsonObject? outputProjection = null)
    {
        long nodeLimit = largeLimits ? 1_000_000 : 100;
        long outputLimit = largeLimits ? 1_000_000 : 512;

        return new JsonObject
        {
            ["type"] = "transformedHttp",
            ["base"] = new JsonObject { ["operation"] = operation },
            ["outputProjection"] = outputProjection ?? new JsonObject
            {
                ["kind"] = "jmespath",
                ["languageVersion"] = 1,
                ["expression"] = expression,
                ["limits"] = new JsonObject
                {
                    ["maxExpressionBytes"] = 256,
                    ["maxInputNodes"] = nodeLimit,
                    ["maxInputDepth"] = 16,
                    ["maxResultNodes"] = nodeLimit,
                    ["maxResultDepth"] = 8,
                    ["maxOutputBytes"] = outputLimit,
                    ["maxEvaluationMilliseconds"] = 10000,
                },
            },
        };
    }

    private static JsonObject TransformProjection()
        => new()
        {
            ["kind"] = "transformProgram",
            ["program"] = TransformProgram(),
        };

    private static JsonObject TransformProgram()
        => new()
        {
            ["transformVersion"] = 1,
            ["direction"] = "output",
            ["base"] = "passthrough",
            ["limits"] = new JsonObject
            {
                ["maxSteps"] = 64,
                ["maxDepth"] = 32,
                ["maxNodes"] = 8192,
                ["maxOutputBytes"] = 512,
                ["maxArrayFanout"] = 1024,
            },
            ["steps"] = new JsonArray
            {
                new JsonObject
                {
                    ["op"] = "setConstant",
                    ["target"] = "/padding",
                    ["value"] = new string('x', 32),
                },
            },
        };

    private sealed class RecordingWorker : IProjectionExpressionValidator, IProjectionWorker
    {
        private readonly Queue<byte[]> _outputs;
        private readonly List<JmesPathLimits> _effectiveLimits = [];

        internal RecordingWorker(params byte[][] outputs) => _outputs = new Queue<byte[]>(outputs);

        internal IReadOnlyList<JmesPathLimits> EffectiveLimits => _effectiveLimits;

        public ProjectionExpressionValidity Validate(string expression, JmesPathLimits limits)
            => ProjectionExpressionValidity.Valid;

        public ValueTask<JmesPathEvaluationResult> EvaluateAsync(
            string expression,
            ReadOnlyMemory<byte> normalizedJson,
            JmesPathLimits limits,
            CancellationToken cancellationToken)
        {
            _effectiveLimits.Add(limits);
            byte[] output = _outputs.Count == 0 ? Bytes("{}") : _outputs.Dequeue();
            return ValueTask.FromResult(JmesPathEvaluationResult.Produced(output));
        }
    }
}
