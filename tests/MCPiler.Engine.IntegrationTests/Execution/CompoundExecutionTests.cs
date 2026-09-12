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
using MCPiler.Engine.Manifest;
using MCPiler.Engine.Manifest.Model;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Execution;

/// <summary>
/// A workflow against a listener that records every arrival.
/// </summary>
/// <remarks>
/// <para>
/// The claims are about what reached the network and in what order, so the evidence is a real
/// server counting real requests. "The second step never ran" and "the perimeter refused the
/// step before any socket" are both statements about arrivals, and a substituted executor could
/// satisfy neither.
/// </para>
/// <para>
/// Loopback is a denied range under the shipped outbound policy, so the address judgement is
/// substituted through the outbound port. The origin allow-list under test is the manifest's,
/// which is a different gate and is exercised here rather than mocked.
/// </para>
/// </remarks>
public sealed class CompoundExecutionTests : IDisposable
{
    private const string Flow = "flow";

    private readonly List<string> _roots = [];

    [Fact]
    public async Task Every_step_reaches_the_upstream_in_declaration_order()
    {
        var arrivals = new List<string>();
        await using var host = await StartAsync(arrivals, "{\"value\":\"from-alpha\"}");

        var result = await Execute(
            Workflow(host.Address, Steps(
                Step("one", "alpha", Map("/query/q", Argument("/term"))),
                Step("two", "beta", Map("/query/id", FromStep("one", "/body/value"))),
                Step("three", "gamma"))),
            arguments: new JsonObject { ["term"] = "pico" });

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal(["/alpha?q=pico", "/beta?id=from-alpha", "/gamma"], arrivals);
    }

    [Fact]
    public async Task The_result_is_assembled_from_the_sources_the_selection_names()
    {
        await using var host = await StartAsync([], "{\"value\":\"from-alpha\"}");

        var result = await Execute(
            Workflow(
                host.Address,
                Steps(Step("one", "alpha", Map("/query/q", Argument("/term")))),
                new CompoundOutputSelection(
                [
                    new CompoundOutputEntry("/echoed", Argument("/term")),
                    new CompoundOutputEntry("/observed", FromStep("one", "/body/value")),
                    new CompoundOutputEntry("/status", FromStep("one", "/status")),
                ])),
            arguments: new JsonObject { ["term"] = "pico" });

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal(
            "{\"echoed\":\"pico\",\"observed\":\"from-alpha\",\"status\":200}",
            Encoding.UTF8.GetString(result.ResponseBody!));
    }

    [Fact]
    public async Task A_workflow_that_declares_no_selection_returns_an_empty_object()
    {
        await using var host = await StartAsync([], "{}");

        var result = await Execute(Workflow(host.Address, Steps(Step("one", "gamma"))));

        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal("{}", Encoding.UTF8.GetString(result.ResponseBody!));
    }

    [Fact]
    public async Task A_step_cannot_reach_an_origin_the_direct_path_would_refuse()
    {
        var arrivals = new List<string>();
        await using var host = await StartAsync(arrivals, "{}");

        // The second step's own binding addresses somewhere the manifest's allowed-origin set
        // does not contain. The workflow inherits the perimeter per request rather than
        // deciding it once for the composition.
        var manifest = Workflow(
            host.Address,
            Steps(Step("one", "alpha"), Step("two", "beta"), Step("three", "gamma")),
            beta: new HttpBinding(Key("/beta"), ServerUrl: "https://elsewhere.example"));

        var workflow = await Execute(manifest);
        var direct = await Execute(manifest, slug: "beta");

        Assert.Equal(ExecutionFailureKind.OriginPolicy, workflow.Failure);
        Assert.Equal(ExecutionFailureKind.OriginPolicy, direct.Failure);

        // The refused step and the step after it both cost nothing, and the step before it
        // still happened. A workflow is several requests however it looks from the outside.
        Assert.Equal(["/alpha"], arrivals);
    }

    [Fact]
    public async Task A_failing_step_stops_the_workflow_and_the_body_says_how_far_it_got()
    {
        var arrivals = new List<string>();
        await using var host = await StartAsync(arrivals, "{}");

        var result = await Execute(Workflow(
            host.Address,
            Steps(Step("one", "alpha"), Step("two", "beta"), Step("three", "gamma")),
            beta: new HttpBinding(Key("/beta"), ServerUrl: "https://elsewhere.example")));

        JsonObject body = Body(result);

        Assert.Equal(Flow, (string?)body["tool"]);
        Assert.Equal("two", (string?)body["failedStepId"]);
        Assert.Equal("execution", (string?)body["stage"]);
        Assert.Equal("OriginPolicy", (string?)body["errorCode"]);
        Assert.Equal(["one"], Completed(body));
        Assert.Single(arrivals);
    }

    [Fact]
    public async Task An_unresolvable_step_reference_names_no_step_and_sends_nothing()
    {
        var arrivals = new List<string>();
        await using var host = await StartAsync(arrivals, "{}");

        var result = await Execute(Workflow(
            host.Address,
            Steps(Step("one", "alpha"), Step("two", "nowhere"))));

        JsonObject body = Body(result);

        Assert.Equal(ExecutionFailureKind.Compilation, result.Failure);
        Assert.Equal("plan", (string?)body["stage"]);
        Assert.Null((string?)body["failedStepId"]);
        Assert.Empty(Completed(body));

        // Resolution happens before the first step, so a workflow that cannot complete has not
        // half-completed either.
        Assert.Empty(arrivals);
    }

    [Fact]
    public async Task A_timeout_is_never_reported_as_a_partial_success()
    {
        var arrivals = new List<string>();
        await using var host = await LoopbackHost.StartAsync(
            async context =>
            {
                lock (arrivals)
                {
                    arrivals.Add(context.Request.Path);
                }

                if (context.Request.Path == "/beta")
                {
                    await Task.Delay(TimeSpan.FromSeconds(30), context.RequestAborted);
                }

                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{}", context.RequestAborted);
            },
            TestContext.Current.CancellationToken);

        var result = await Execute(Workflow(
            host.Address,
            Steps(Step("one", "alpha"), Step("two", "beta"), Step("three", "gamma")),
            compound: new CompoundBounds(100L * 1024 * 1024, TimeSpan.FromMilliseconds(400))));

        JsonObject body = Body(result);

        Assert.Equal(ExecutionFailureKind.Timeout, result.Failure);
        Assert.Null(result.ResponseBody);
        Assert.Equal("workflow", (string?)body["stage"]);
        Assert.Equal("two", (string?)body["failedStepId"]);
        Assert.Equal(["one"], Completed(body));
    }

    [Fact]
    public async Task The_aggregate_budget_bounds_the_sum_of_responses_each_of_which_is_inside_its_own_ceiling()
    {
        await using var host = await StartAsync([], new string('x', 400));

        // Every single response is well inside the per-response ceiling. The workflow's own
        // budget is what three of them exceed, which is the whole reason it exists.
        var result = await Execute(Workflow(
            host.Address,
            Steps(Step("one", "alpha"), Step("two", "beta"), Step("three", "gamma")),
            compound: new CompoundBounds(900, TimeSpan.FromSeconds(120))));

        JsonObject body = Body(result);

        Assert.Equal(ExecutionFailureKind.ResponseSize, result.Failure);
        Assert.Equal(["one", "two"], Completed(body));
    }

    [Fact]
    public async Task A_binding_may_narrow_the_policy_budget_and_may_not_raise_it()
    {
        await using var host = await StartAsync([], new string('x', 400));

        var raised = await Execute(Workflow(
            host.Address,
            Steps(Step("one", "alpha"), Step("two", "beta")),
            compound: new CompoundBounds(500, TimeSpan.FromSeconds(120)),
            declaredBytes: 100L * 1024 * 1024));

        var narrowed = await Execute(Workflow(
            host.Address,
            Steps(Step("one", "alpha"), Step("two", "beta")),
            declaredBytes: 500));

        Assert.Equal(ExecutionFailureKind.ResponseSize, raised.Failure);
        Assert.Equal(ExecutionFailureKind.ResponseSize, narrowed.Failure);
    }

    [Fact]
    public async Task A_handle_crosses_between_steps_and_its_bytes_never_reach_the_caller()
    {
        var payload = Encoding.UTF8.GetBytes("a stored payload nobody may read back");
        var uploaded = new List<byte[]>();

        await using var host = await LoopbackHost.StartAsync(
            async context =>
            {
                if (context.Request.Path == "/alpha")
                {
                    context.Response.ContentType = "application/octet-stream";
                    await context.Response.Body.WriteAsync(payload, context.RequestAborted);
                    return;
                }

                using var buffer = new MemoryStream();
                await context.Request.Body.CopyToAsync(buffer, context.RequestAborted);
                uploaded.Add(buffer.ToArray());

                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"stored\":true}", context.RequestAborted);
            },
            TestContext.Current.CancellationToken);

        var result = await Execute(
            Workflow(
                host.Address,
                Steps(
                    Step("one", "alpha"),
                    Step("two", "upload", Map("/body/document", FromStep("one", "/body")))),
                new CompoundOutputSelection([new CompoundOutputEntry("/file", FromStep("one", "/body"))]),
                binary: true),
            store: NewStore());

        Assert.Equal(ExecutionFailureKind.None, result.Failure);

        // The upstream received the bytes.
        byte[] sent = Assert.Single(uploaded);
        Assert.Contains(Encoding.UTF8.GetString(payload), Encoding.UTF8.GetString(sent), StringComparison.Ordinal);

        // The caller received the handle, and the payload appears nowhere in what it can read.
        string agentVisible = Encoding.UTF8.GetString(result.ResponseBody!);
        Assert.DoesNotContain("a stored payload", agentVisible, StringComparison.Ordinal);
        Assert.True(FileHandleStore.IsWellFormedId((string?)Body(agentVisible)["file"]));
    }

    [Fact]
    public async Task A_sixty_four_character_argument_the_workflow_did_not_issue_stays_text()
    {
        var arrivals = new List<string>();
        await using var host = await StartAsync(arrivals, "{}");

        string digest = new('a', 64);

        var result = await Execute(
            Workflow(host.Address, Steps(Step("one", "alpha", Map("/query/q", Argument("/digest"))))),
            arguments: new JsonObject { ["digest"] = digest },
            store: NewStore());

        // A well-formed identifier is not a reference. Guessing otherwise would turn a caller's
        // digest into a missing file and fail a step the argument described perfectly.
        Assert.Equal(ExecutionFailureKind.None, result.Failure);
        Assert.Equal(["/alpha?q=" + digest], arrivals);
    }

    public void Dispose()
    {
        foreach (var root in _roots.Where(Directory.Exists))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    // ---- the manifest under test ---------------------------------------------------------

    private static string Key(string path) => ManifestOperation.BuildKey("GET", path);

    private static ManifestDocument Workflow(
        Uri baseUrl,
        IReadOnlyList<CompoundStepEntry> steps,
        CompoundOutputSelection? selection = null,
        ManifestBinding? beta = null,
        CompoundBounds? compound = null,
        long? declaredBytes = null,
        bool binary = false)
    {
        ManifestOperation alpha = binary
            ? new(Key("/alpha"), "GET", "/alpha", UpstreamId: "alpha", Responses: ExecutionManifests.Declares("200", "application/octet-stream"))
            : new(Key("/alpha"), "GET", "/alpha", UpstreamId: "alpha", Parameters: [new ManifestParameter("q", ParameterLocation.Query)]);

        ManifestOperation betaOperation = new(
            Key("/beta"),
            "GET",
            "/beta",
            UpstreamId: "beta",
            Parameters: [new ManifestParameter("id", ParameterLocation.Query)]);

        ManifestOperation gamma = new(Key("/gamma"), "GET", "/gamma", UpstreamId: "gamma");

        ManifestOperation upload = new(
            ManifestOperation.BuildKey("POST", "/upload"),
            "POST",
            "/upload",
            UpstreamId: "upload",
            RequestBody: new ManifestRequestBody(new Dictionary<string, ManifestMediaType>(StringComparer.Ordinal)
            {
                ["multipart/form-data"] = new("multipart/form-data"),
            }));

        return new ManifestDocument(
            ManifestFormatSupport.Maximum,
            new ServerSection("test-server", Version: "1.0.0"),
            new PolicySection(baseUrl, Compound: compound),
            new OperationsSection([alpha, betaOperation, gamma, upload]),
            new AgentSurfaceSection(
            [
                new AgentOperationEntry("alpha", "Alpha", new HttpBinding(alpha.Key)),
                new AgentOperationEntry("beta", "Beta", beta ?? new HttpBinding(betaOperation.Key)),
                new AgentOperationEntry("gamma", "Gamma", new HttpBinding(gamma.Key)),
                new AgentOperationEntry("upload", "Upload", new HttpBinding(upload.Key)),
                new AgentOperationEntry(
                    Flow,
                    "Flow",
                    new CompoundBinding(steps, MaxTotalResponseBytes: declaredBytes, OutputSelection: selection),
                    Kind: AgentOperationKind.Compound),
            ]));
    }

    private static IReadOnlyList<CompoundStepEntry> Steps(params CompoundStepEntry[] steps) => steps;

    private static CompoundStepEntry Step(string id, string operation, params StepInputMapping[] mappings)
        => new(id, operation, mappings);

    private static StepInputMapping Map(string target, MappingSource source) => new(target, source);

    private static MappingSource Argument(string pointer) => MappingSource.FromArgument(pointer);

    private static MappingSource FromStep(string step, string pointer)
        => MappingSource.FromStepResponse(step, pointer);

    // ---- harness -------------------------------------------------------------------------

    private static Task<LoopbackHost> StartAsync(List<string> arrivals, string body)
        => LoopbackHost.StartAsync(
            context =>
            {
                lock (arrivals)
                {
                    arrivals.Add(context.Request.Path + context.Request.QueryString);
                }

                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(body, context.RequestAborted);
            },
            TestContext.Current.CancellationToken);

    private static async Task<EngineExecutionResult> Execute(
        ManifestDocument manifest,
        FileHandleStore? store = null,
        JsonObject? arguments = null,
        string slug = Flow)
    {
        using var clients = new UpstreamClientFactory(new OutboundConnectionPolicy(static _ => false));
        var service = new ExecutionService(new UpstreamSender(clients), new ManifestSecretResolver(), store);

        return await service.ExecuteAsync(
            new ExecutionRequest(manifest, slug, arguments ?? []) { Scope = "mount" },
            TestContext.Current.CancellationToken);
    }

    private static JsonObject Body(EngineExecutionResult result)
        => Assert.IsType<JsonObject>(result.FailureDetail);

    private static JsonObject Body(string json) => (JsonObject)JsonNode.Parse(json)!;

    private static string[] Completed(JsonObject body)
        => [.. ((JsonArray)body["stepsCompleted"]!).Select(static step => (string)step!)];

    private FileHandleStore NewStore()
    {
        var root = Path.Combine(Path.GetTempPath(), "mcpiler-compound-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        _roots.Add(root);

        return new FileHandleStore(FileHandleStoreOptions.For(root));
    }
}
