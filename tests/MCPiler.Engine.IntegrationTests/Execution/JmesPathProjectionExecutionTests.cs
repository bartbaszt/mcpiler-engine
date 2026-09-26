using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Host.ProjectionWorker;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Mcp;
using MCPiler.Engine.Runtime;
using MCPiler.Engine.Runtime.Projection;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Execution;

/// <summary>
/// A JMESPath output projection inside one real execution, through a real confined worker.
/// </summary>
/// <remarks>
/// <para>
/// The claims here are about ordering and about what reaches a caller, and neither is visible
/// from the library alone: the projection runs after the bounded read, the body it evaluates is
/// the body the upstream sent, the result is what the MCP surface would carry, and a failure is
/// a projection failure rather than an upstream one. The worker is the real host over the real
/// child executable, because an in-process substitute would prove the opposite of the property
/// this stage exists for.
/// </para>
/// <para>
/// The pool is supplied through the execution service directly rather than through a started
/// runtime: these cases are about the projection stage, and starting a runtime would add mount
/// loading to every one of them.
/// </para>
/// </remarks>
public sealed class JmesPathProjectionExecutionTests : IDisposable
{
    private readonly List<string> _roots = [];

    [Fact]
    public async Task An_expression_replaces_the_agent_facing_body()
    {
        await using var host = await StartJsonAsync("""{"data":{"id":7},"noise":1}""");

        var result = await Execute(host.Address, "data", worker: Worker());

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        // The whole projected value is what the caller receives, and the exchange's status and
        // headers survive it.
        Assert.Equal(200, result.StatusCode);
        Assert.Equal("""{"id":7}""", Encoding.UTF8.GetString(result.ResponseBody!));
    }

    [Fact]
    public async Task The_expression_sees_the_body_itself_not_an_envelope()
    {
        await using var host = await StartJsonAsync("""{"a":1}""");

        // An expression addressing the root directly. Under an envelope it would have to name
        // /body first, so the equality below is what pins the root to the parsed body.
        var result = await Execute(host.Address, "a", worker: Worker());

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal("1", Encoding.UTF8.GetString(result.ResponseBody!));
    }

    [Fact]
    public async Task An_expression_that_selects_nothing_yields_a_legal_null()
    {
        await using var host = await StartJsonAsync("""{"a":1}""");

        var result = await Execute(host.Address, "absent", worker: Worker());

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal("null", Encoding.UTF8.GetString(result.ResponseBody!));
    }

    [Fact]
    public async Task A_runtime_type_failure_is_a_projection_failure_with_its_own_code()
    {
        await using var host = await StartJsonAsync("""{"a":1}""");

        // A standard function applied to the wrong kind. The expression compiled, so this is the
        // runtime family and must be distinguishable from an upstream failure and from a compile
        // family.
        var result = await Execute(host.Address, "sort(@)", worker: Worker());

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Contains("jmespath-runtime-invalid-type", result.FailureReason, StringComparison.Ordinal);

        // The exchange itself succeeded, and that evidence survives the refusal.
        Assert.Equal(200, result.StatusCode);

        JsonNode detail = result.FailureDetail!;
        Assert.Equal("jmespath", detail["kind"]!.GetValue<string>());
        Assert.Equal("jmespath-runtime-invalid-type", detail["code"]!.GetValue<string>());
        Assert.False(detail["operational"]!.GetValue<bool>());
    }

    [Fact]
    public async Task A_compile_failure_is_reported_with_its_family_and_no_raw_body()
    {
        await using var host = await StartJsonAsync("""{"a":"canary"}""");

        var result = await Execute(host.Address, "foo(", worker: Worker());

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Contains("jmespath-compile-syntax", result.FailureReason, StringComparison.Ordinal);

        // The Engine result retains exchange evidence just as TransformProgram does; the
        // protocol-facing result is the error document, never the raw body.
        ToolOutcome shaped = ToolInvocation.Shape(result);
        Assert.True(shaped.IsError);
        Assert.DoesNotContain("canary", shaped.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("canary", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_non_json_inline_body_is_refused_before_the_worker()
    {
        const string canary = "private-body-canary-72";
        await using var host = await StartJsonAsync(canary);
        var worker = new RecordingProjectionWorker();

        var result = await Execute(host.Address, "@", worker: worker);

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Equal("jmespath-input-not-json", result.FailureDetail!["code"]!.GetValue<string>());
        Assert.Equal(0, worker.Calls);

        ToolOutcome shaped = ToolInvocation.Shape(result);
        Assert.True(shaped.IsError);
        Assert.DoesNotContain(canary, shaped.Text, StringComparison.Ordinal);
        Assert.DoesNotContain(canary, result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_input_node_breach_is_refused_before_the_worker_runs()
    {
        await using var host = await StartJsonAsync("""{"a":[1,2,3,4,5]}""");

        var worker = new RecordingProjectionWorker();
        var result = await Execute(
            host.Address, "@", worker: worker, limits: JmesPathLimits.AuthoringDefault with { MaxInputNodes = 3 });

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);

        JsonNode detail = result.FailureDetail!;
        Assert.Equal("jmespath-input-too-many-nodes", detail["code"]!.GetValue<string>());
        Assert.Equal(0, worker.Calls);
    }

    [Fact]
    public async Task An_input_depth_breach_is_refused_before_the_worker_runs()
    {
        const string body = "[[[[0]]]]";
        await using var host = await StartJsonAsync(body);
        var worker = new RecordingProjectionWorker();

        var result = await Execute(
            host.Address,
            "@",
            worker: worker,
            limits: JmesPathLimits.AuthoringDefault with { MaxInputDepth = 2 });

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Equal("jmespath-input-too-deep", result.FailureDetail!["code"]!.GetValue<string>());
        Assert.Equal(0, worker.Calls);
    }

    [Fact]
    public async Task An_expression_over_the_utf8_byte_limit_is_refused_before_the_worker_runs()
    {
        await using var host = await StartJsonAsync("null");
        var worker = new RecordingProjectionWorker();
        JmesPathLimits limits = JmesPathLimits.AuthoringDefault with { MaxExpressionBytes = 4 };

        var result = await Execute(host.Address, "abcdef", worker: worker, limits: limits);

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Equal("jmespath-expression-too-many-bytes", result.FailureDetail!["code"]!.GetValue<string>());
        Assert.Equal(0, worker.Calls);
    }

    [Fact]
    public async Task A_result_over_the_completed_result_bound_is_refused_without_a_partial_value()
    {
        await using var host = await StartJsonAsync("""{"a":[1,2,3,4,5]}""");

        var result = await Execute(
            host.Address, "a", worker: Worker(), limits: JmesPathLimits.AuthoringDefault with { MaxResultNodes = 3 });

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);

        JsonNode detail = result.FailureDetail!;
        Assert.Equal("jmespath-result-too-many-nodes", detail["code"]!.GetValue<string>());

        // Nothing partial or truncated reaches the caller.
        ToolOutcome shaped = ToolInvocation.Shape(result);
        Assert.True(shaped.IsError);
        Assert.DoesNotContain("[1,2,3", shaped.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_projection_does_not_run_when_the_response_ceiling_was_already_crossed()
    {
        await using var host = await StartJsonAsync("""{"data":"0123456789012345678901234567890123456789"}""");

        var worker = new RecordingProjectionWorker();
        var result = await Execute(
            host.Address,
            "data",
            worker: worker,
            policyLimits: ExecutionLimits.Default with { UpstreamResponseSizeLimitBytes = 16 });

        // The bounded read refused the body before a projection could materialize it. A selector
        // making an oversized response legal is exactly what the ordering forbids.
        Assert.Equal(ExecutionFailureKind.ResponseSize, result.Failure);
        Assert.Null(result.ResponseBody);
        Assert.Equal(0, worker.Calls);
    }

    [Fact]
    public async Task A_stored_binary_response_is_refused_before_the_worker_and_not_returned_as_a_file()
    {
        await using var host = await StartBinaryAsync(new byte[64]);

        var worker = new RecordingProjectionWorker();
        var result = await Execute(host.Address, "data", worker: worker, store: NewStore());

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Equal("jmespath-input-file-or-binary", result.FailureDetail!["code"]!.GetValue<string>());
        Assert.Equal(0, worker.Calls);

        // The raw handle is not returned as a fallback after the projection refuses it.
        ToolOutcome shaped = ToolInvocation.Shape(result);
        Assert.True(shaped.IsError);
        Assert.DoesNotContain(result.ResponseFileHandle ?? string.Empty, shaped.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_projected_string_that_looks_like_a_file_handle_remains_an_ordinary_string()
    {
        FileHandleStore store = NewStore();
        using var content = new MemoryStream(Encoding.UTF8.GetBytes("stored bytes"));
        FileHandleReference reference = await store.IssueAsync(
            content,
            "sample.txt",
            "text/plain",
            ExecutionManifests.Slug,
            TestContext.Current.CancellationToken);
        string validHandle = store.WireFormFor(reference.Id);
        Assert.NotEmpty(validHandle);

        string encoded = JsonSerializer.Serialize(validHandle);
        await using var host = await StartJsonAsync(encoded);
        using var worker = Worker();

        EngineExecutionResult result = await Execute(host.Address, "@", worker: worker, store: store);

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Null(result.ResponseFile);
        Assert.Null(result.ResponseFileHandle);
        Assert.Equal(encoded, Encoding.UTF8.GetString(result.ResponseBody!));

        ToolOutcome shaped = ToolInvocation.Shape(result);
        Assert.False(shaped.IsError);
        Assert.Equal(encoded, shaped.Text);
    }

    [Fact]
    public async Task A_process_without_a_worker_refuses_a_jmespath_projection_rather_than_evaluating_in_place()
    {
        await using var host = await StartJsonAsync("""{"a":1}""");

        var result = await Execute(host.Address, "a", worker: null);

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);

        JsonNode detail = result.FailureDetail!;
        Assert.Equal("jmespath-operational-confinement-unavailable", detail["code"]!.GetValue<string>());
        Assert.True(detail["operational"]!.GetValue<bool>());
    }

    [Fact]
    public async Task A_worker_that_hits_the_deadline_reports_an_operational_outcome_and_the_service_survives()
    {
        // A legitimate expression over a body large enough that the unchanged evaluator's
        // quadratic sort cannot finish inside the deadline.
        string items = "[" + string.Join(",", CountDown(20_000)) + "]";
        await using var host = await StartJsonAsync(items);

        using var pool = Worker(deadline: TimeSpan.FromMilliseconds(1500));

        var result = await Execute(host.Address, "sort(@)", worker: pool);

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);

        JsonNode detail = result.FailureDetail!;
        Assert.Equal("jmespath-operational-timeout", detail["code"]!.GetValue<string>());
        Assert.True(detail["operational"]!.GetValue<bool>());

        // The serving process survived and the next evaluation succeeds; a timeout is not a
        // state the pool stays broken in. The same body is used, because the claim is about the
        // pool rather than about a smaller input.
        var next = await Execute(host.Address, "length(@)", worker: pool);

        Assert.Equal(ExecutionFailureKind.None, next.Failure);
        Assert.Equal("20000", Encoding.UTF8.GetString(next.ResponseBody!));
    }

    [Fact]
    public async Task A_declared_evaluation_deadline_narrows_the_host_worker_budget()
    {
        string items = "[" + string.Join(",", CountDown(20_000)) + "]";
        await using var host = await StartJsonAsync(items);
        using var pool = Worker(deadline: TimeSpan.FromSeconds(30));
        JmesPathLimits limits = JmesPathLimits.AuthoringDefault with
        {
            MaxResultNodes = 50_000,
            MaxEvaluationMilliseconds = 250,
        };

        var result = await Execute(host.Address, "sort(@)", worker: pool, limits: limits);

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Equal("jmespath-operational-timeout", result.FailureDetail!["code"]!.GetValue<string>());
        Assert.True(result.FailureDetail["operational"]!.GetValue<bool>());
    }

    [Fact]
    public async Task An_unsupported_language_version_is_refused_before_the_worker_runs()
    {
        await using var host = await StartJsonAsync("""{"a":1}""");

        var result = await Execute(host.Address, "a", worker: Worker(), languageVersion: 2);

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Contains("languageVersion=2", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_undeclared_projection_leaves_the_body_untouched()
    {
        await using var host = await StartJsonAsync("""{"a":1,"noise":true}""");

        // Passthrough is the absence of a projection, and the body a caller receives is the
        // body the upstream sent.
        var result = await Execute(host.Address, worker: Worker(), projection: false);

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal("""{"a":1,"noise":true}""", Encoding.UTF8.GetString(result.ResponseBody!));
    }

    public void Dispose()
    {
        foreach (var root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static IEnumerable<int> CountDown(int count)
    {
        for (var i = count; i > 0; i--)
        {
            yield return i;
        }
    }

    private static ManifestDocument Manifest(
        Uri baseUrl,
        string expression,
        int languageVersion,
        JmesPathLimits limits,
        bool projection,
        ExecutionLimits? policyLimits)
    {
        var operation = ExecutionManifests.Operation();

        ManifestBinding binding = projection
            ? new TransformedHttpBinding(
                new HttpBinding(operation.Key),
                null,
                new ManifestOutputProjection.JmesPathVariant(languageVersion, expression, limits))
            : new HttpBinding(operation.Key);

        return ExecutionManifests.For(baseUrl, policyLimits, operation: operation, binding: binding);
    }

    /// <summary>
    /// Runs one execution whose binding declares the expression, against the given server.
    /// </summary>
    /// <remarks>
    /// The server's body is whatever the case started it with; <paramref name="body"/> is not
    /// what the execution receives but what the case asserts about, so the helper deliberately
    /// does not take it. The expression and limits are the only projection inputs here.
    /// </remarks>
    private static async Task<EngineExecutionResult> Execute(
        Uri baseUrl,
        string expression = "@",
        IProjectionWorker? worker = null,
        JmesPathLimits? limits = null,
        ExecutionLimits? policyLimits = null,
        bool projection = true,
        int languageVersion = 1,
        FileHandleStore? store = null)
    {
        ManifestDocument manifest = Manifest(
            baseUrl,
            expression,
            languageVersion,
            limits ?? JmesPathLimits.AuthoringDefault,
            projection,
            policyLimits);

        using var clients = new UpstreamClientFactory(new OutboundConnectionPolicy(_ => false));
        var service = new ExecutionService(
            new UpstreamSender(clients),
            new ManifestSecretResolver(),
            store,
            authentication: null,
            projections: worker);

        return await service.ExecuteAsync(
            new ExecutionRequest(manifest, ExecutionManifests.Slug, []),
            TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Creates the real confined pool over this build's own apphost.
    /// </summary>
    /// <remarks>
    /// The pair is supplied explicitly because the process that starts a worker is normally the
    /// serving executable while the test host is the runner. The program is still the real Engine
    /// apphost and the assembly is still this build's worker entry.
    /// </remarks>
    private static ProjectionWorkerHost Worker(TimeSpan? deadline = null)
    {
        string directory = AppContext.BaseDirectory;
        string apphost = Path.Combine(directory, OperatingSystem.IsWindows() ? "mcpiler-engine.exe" : "mcpiler-engine");

        Assert.True(File.Exists(apphost), $"The Engine apphost is missing from {directory}.");

        WorkerPoolOptions options = WorkerPoolOptions.Default with
        {
            TotalDeadline = deadline ?? WorkerPoolOptions.Default.TotalDeadline,
            Launch = new WorkerLaunch(apphost, null),
        };

        return new ProjectionWorkerHost(options);
    }

    private FileHandleStore NewStore()
    {
        var root = Path.Combine(Path.GetTempPath(), "mcpiler-jmespath-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        _roots.Add(root);

        return new FileHandleStore(FileHandleStoreOptions.For(root));
    }

    /// <summary>A JSON response body, as the loopback server sends it.</summary>
    private static Task<LoopbackHost> StartJsonAsync(string json)
        => LoopbackHost.StartAsync(
            200,
            "application/json",
            Encoding.UTF8.GetBytes(json),
            TestContext.Current.CancellationToken);

    /// <summary>A binary response body, as the loopback server sends it.</summary>
    private static Task<LoopbackHost> StartBinaryAsync(byte[] content)
        => LoopbackHost.StartAsync(
            200,
            "application/octet-stream",
            content,
            TestContext.Current.CancellationToken);

    private sealed class RecordingProjectionWorker : IProjectionWorker
    {
        public int Calls { get; private set; }

        public ValueTask<JmesPathEvaluationResult> EvaluateAsync(
            string expression,
            ReadOnlyMemory<byte> normalizedJson,
            JmesPathLimits limits,
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromResult(JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.OperationalWorkerFailure,
                "The test worker should not have been called.")));
        }
    }
}
