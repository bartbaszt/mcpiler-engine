using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.Secrets;
using MCPiler.Engine.Manifest.Model;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Execution;

/// <summary>
/// A declared transformation inside one execution, against a listener that counts arrivals.
/// </summary>
/// <remarks>
/// <para>
/// The claims here are about ordering, and ordering is what a substituted evaluator cannot
/// show. "No upstream request was made" is a count on a real server rather than a mock's
/// bookkeeping; "the size failure is reported and the transform never runs" is the difference
/// between two classifications on a response that genuinely exceeded a ceiling.
/// </para>
/// <para>
/// Loopback is a denied range under the shipped outbound policy, so these tests substitute the
/// address judgement through the outbound port. The perimeter itself is asserted elsewhere.
/// </para>
/// </remarks>
public sealed class TransformExecutionTests : IDisposable
{
    private readonly List<string> _roots = [];

    [Fact]
    public async Task An_input_program_rewrites_the_request_that_reaches_the_upstream()
    {
        var arrivals = new List<string>();
        await using var host = await StartAsync(async context =>
        {
            arrivals.Add(context.Request.Path + context.Request.QueryString);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}", context.RequestAborted);
        });

        var result = await Execute(
            Transformed(host.Address, input: Program("input", Copy("/term", "/query/q"))),
            arguments: new JsonObject { ["term"] = "pico" });

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal(["/thing?q=pico"], arrivals);
    }

    [Fact]
    public async Task A_passthrough_program_with_no_steps_compiles_the_same_request()
    {
        var arrivals = new List<string>();
        await using var host = await StartAsync(async context =>
        {
            arrivals.Add(context.Request.Path + context.Request.QueryString);
            await context.Response.WriteAsync("{}", context.RequestAborted);
        });

        var arguments = new JsonObject { ["q"] = "pico" };

        var plain = await Execute(Queried(host.Address), arguments: (JsonObject)arguments.DeepClone());
        var empty = await Execute(
            Transformed(host.Address, input: Program("input"), parameters: QueryParameter),
            arguments: (JsonObject)arguments.DeepClone());

        // Byte for byte the same request, which is the only way a transformation declared and
        // left empty can be said to change nothing.
        Assert.Equal(plain.Request!.ExactUrl, empty.Request!.ExactUrl);
        Assert.Equal(plain.Request.Method, empty.Request.Method);
        Assert.Equal(plain.Request.Body, empty.Request.Body);
        Assert.Equal(["/thing?q=pico", "/thing?q=pico"], arrivals);
    }

    [Fact]
    public async Task An_input_program_that_aborts_makes_no_upstream_request()
    {
        var arrivals = 0;
        await using var host = await StartAsync(context =>
        {
            Interlocked.Increment(ref arrivals);
            return context.Response.WriteAsync("unexpected", context.RequestAborted);
        });

        var demanding = Copy("/absent", "/query/q");
        demanding["onMissing"] = "error";

        var result = await Execute(
            Transformed(host.Address, input: Program("input", demanding)),
            arguments: []);

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Equal(0, arrivals);

        // The caller is told which step and which operation, not merely that something failed.
        Assert.Contains("E_MISSING_SOURCE", result.FailureReason, StringComparison.Ordinal);
        Assert.Contains("step 0", result.FailureReason, StringComparison.Ordinal);
        Assert.Contains("copy", result.FailureReason, StringComparison.Ordinal);

        // Nothing was compiled either: a refused program has no request to show.
        Assert.Null(result.Request);
    }

    [Fact]
    public async Task An_invalid_input_program_is_refused_at_the_invocation_that_would_run_it()
    {
        var arrivals = 0;
        await using var host = await StartAsync(context =>
        {
            Interlocked.Increment(ref arrivals);
            return context.Response.WriteAsync("unexpected", context.RequestAborted);
        });

        // A program nothing validated must not run because something else is believed to have
        // checked it. This manifest was assembled in code and never passed the load gate.
        var result = await Execute(
            Transformed(host.Address, input: Program("input", new JsonObject { ["op"] = "eval" })),
            arguments: []);

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Contains("E_UNKNOWN_OPERATION", result.FailureReason, StringComparison.Ordinal);
        Assert.Equal(0, arrivals);
    }

    [Fact]
    public async Task A_program_in_the_member_for_the_other_direction_is_refused()
    {
        var arrivals = 0;
        await using var host = await StartAsync(context =>
        {
            Interlocked.Increment(ref arrivals);
            return context.Response.WriteAsync("unexpected", context.RequestAborted);
        });

        var result = await Execute(
            Transformed(host.Address, input: Program("output", Copy("/body/name", "/name"))),
            arguments: []);

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Contains("E_DIRECTION_MISMATCH", result.FailureReason, StringComparison.Ordinal);
        Assert.Equal(0, arrivals);
    }

    [Fact]
    public async Task An_output_program_replaces_the_agent_facing_body()
    {
        await using var host = await StartAsync(async context =>
        {
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"data\":{\"id\":7},\"noise\":1}", context.RequestAborted);
        });

        var result = await Execute(
            Transformed(host.Address, output: Program("output", Copy("/body/data", "/result"))),
            arguments: []);

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        // The whole transformed document is what the caller is handed, and the observed status
        // and headers stay what the exchange observed.
        Assert.Equal(200, result.StatusCode);
        Assert.Contains(
            "\"result\":{\"id\":7}",
            Encoding.UTF8.GetString(result.ResponseBody!),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_output_program_that_aborts_is_not_reported_as_an_upstream_failure()
    {
        await using var host = await StartAsync(async context =>
        {
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"data\":1}", context.RequestAborted);
        });

        var demanding = Copy("/body/absent", "/result");
        demanding["onMissing"] = "error";

        var result = await Execute(Transformed(host.Address, output: Program("output", demanding)));

        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Contains("E_MISSING_SOURCE", result.FailureReason, StringComparison.Ordinal);

        // The exchange itself succeeded, and the evidence about it survives the abort.
        Assert.Equal(200, result.StatusCode);
    }

    [Fact]
    public async Task A_response_over_the_ceiling_is_a_size_failure_and_the_program_never_runs()
    {
        await using var host = await StartAsync(
            200,
            "application/json",
            Encoding.UTF8.GetBytes("{\"data\":\"" + new string('x', 4096) + "\"}"));

        var result = await Execute(
            Transformed(
                host.Address,
                output: Program("output", Copy("/body/data", "/result")),
                limits: ExecutionLimits.Default with { UpstreamResponseSizeLimitBytes = 128 }));

        // Reported as the size failure it is. A transformation running first would already have
        // materialized the bytes the ceiling exists to refuse.
        Assert.Equal(ExecutionFailureKind.ResponseSize, result.Failure);
        Assert.Null(result.ResponseBody);
    }

    [Fact]
    public async Task An_output_program_may_not_produce_more_than_the_response_ceiling_allows()
    {
        await using var host = await StartAsync(async context =>
        {
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"data\":1}", context.RequestAborted);
        });

        var inflate = new JsonObject
        {
            ["op"] = "setConstant",
            ["target"] = "/padding",
            ["value"] = new string('x', 512),
        };

        var result = await Execute(
            Transformed(
                host.Address,
                output: Program("output", inflate),
                limits: ExecutionLimits.Default with { UpstreamResponseSizeLimitBytes = 128 }));

        // The program declares the format's default maxOutputBytes, which is far above the
        // policy's ceiling. The smaller governs, or a transformation would be a way to hand back
        // a payload the policy refused to let arrive.
        Assert.Equal(ExecutionFailureKind.Transformation, result.Failure);
        Assert.Contains("E_LIMIT_OUTPUT_BYTES", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_stored_binary_response_is_never_transformed()
    {
        await using var host = await StartAsync(200, "application/octet-stream", new byte[64]);

        var demanding = Copy("/body/absent", "/result");
        demanding["onMissing"] = "error";

        var result = await Execute(
            Transformed(host.Address, output: Program("output", demanding)),
            store: NewStore());

        // The bytes were deliberately not materialized. A program that could reach them would
        // undo the only reason the handle exists, so the program does not run at all.
        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.NotNull(result.ResponseFile);
        Assert.Null(result.ResponseBody);
    }

    public void Dispose()
    {
        foreach (var root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static readonly IReadOnlyList<ManifestParameter> QueryParameter =
        [new ManifestParameter("q", ParameterLocation.Query)];

    private static ManifestDocument Queried(Uri baseUrl)
        => ExecutionManifests.For(
            baseUrl,
            operation: ExecutionManifests.Operation(parameters: QueryParameter));

    private static ManifestDocument Transformed(
        Uri baseUrl,
        JsonObject? input = null,
        JsonObject? output = null,
        IReadOnlyList<ManifestParameter>? parameters = null,
        ExecutionLimits? limits = null)
    {
        var operation = ExecutionManifests.Operation(parameters: parameters ?? QueryParameter);

        return ExecutionManifests.For(
            baseUrl,
            limits,
            operation: operation,
            binding: new TransformedHttpBinding(
                new HttpBinding(operation.Key),
                input,
                output is null ? null : new ManifestOutputProjection.TransformProgramVariant(output)));
    }

    private static JsonObject Program(string direction, params JsonObject[] steps)
        => new()
        {
            ["transformVersion"] = 1,
            ["direction"] = direction,
            ["base"] = "passthrough",
            ["limits"] = new JsonObject
            {
                ["maxSteps"] = 64,
                ["maxDepth"] = 32,
                ["maxNodes"] = 8192,
                ["maxOutputBytes"] = 262144,
                ["maxArrayFanout"] = 1024,
            },
            ["steps"] = new JsonArray([.. steps.Select(step => (JsonNode)step)]),
        };

    private static JsonObject Copy(string source, string target)
        => new()
        {
            ["op"] = "copy",
            ["source"] = source,
            ["target"] = target,
            ["onMissing"] = "skip",
        };

    private static Task<LoopbackHost> StartAsync(RequestDelegate handler)
        => LoopbackHost.StartAsync(handler, TestContext.Current.CancellationToken);

    private static Task<LoopbackHost> StartAsync(int statusCode, string mediaType, byte[] body)
        => LoopbackHost.StartAsync(statusCode, mediaType, body, TestContext.Current.CancellationToken);

    private static async Task<EngineExecutionResult> Execute(
        ManifestDocument manifest,
        FileHandleStore? store = null,
        JsonObject? arguments = null)
    {
        using var clients = new UpstreamClientFactory(new OutboundConnectionPolicy(_ => false));
        var service = new ExecutionService(new UpstreamSender(clients), new ManifestSecretResolver(), store);

        return await service.ExecuteAsync(
            new ExecutionRequest(manifest, ExecutionManifests.Slug, arguments ?? [], manifest.Policy),
            TestContext.Current.CancellationToken);
    }

    private FileHandleStore NewStore()
    {
        var root = Path.Combine(Path.GetTempPath(), "mcpiler-transform-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        _roots.Add(root);

        return new FileHandleStore(FileHandleStoreOptions.For(root));
    }
}
