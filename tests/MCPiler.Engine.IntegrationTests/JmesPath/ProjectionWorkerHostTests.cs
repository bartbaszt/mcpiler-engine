using System.Text;

using MCPiler.Engine.Host.ProjectionWorker;
using MCPiler.Engine.Runtime.Projection;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.JmesPath;

/// <summary>
/// The confinement is a property of two real processes, so these tests start real ones.
/// </summary>
/// <remarks>
/// <para>
/// A fake would prove that the parent calls a method; only a child proves that a fresh process
/// applies the limit, reports it, evaluates, and dies when told. Every test here can be run only
/// where the platform's mechanism exists, and it fails rather than skips on that platform,
/// because a skipped confinement test is a confinement nobody checked.
/// </para>
/// <para>
/// The host is given the worker's exact launch pair explicitly: the process that starts a worker
/// is normally the serving executable, while the test host is the test runner. The pair is still
/// the real Engine apphost and the real Engine assembly, so the code under test is the deployed
/// one.
/// </para>
/// </remarks>
public sealed class ProjectionWorkerHostTests
{
    private static readonly JmesPathLimits Limits = new(
        MaxExpressionBytes: 4096,
        MaxInputNodes: 65_536,
        MaxInputDepth: 64,
        MaxResultNodes: 65_536,
        MaxResultDepth: 64,
        MaxOutputBytes: 1024 * 1024,
        MaxEvaluationMilliseconds: 10_000);

    [Fact]
    public async Task A_confined_worker_evaluates_and_reports_the_expected_value()
    {
        using var host = CreateHost(TimeSpan.FromSeconds(30));

        JmesPathEvaluationResult result = await EvaluateAsync(host, "length(@)", "[1,2,3]");

        Assert.True(result.Succeeded, result.Failure?.Message);
        Assert.Equal("3", Encoding.UTF8.GetString(result.Output!));
    }

    [Fact]
    public async Task A_second_evaluation_after_a_successful_one_also_succeeds()
    {
        using var host = CreateHost(TimeSpan.FromSeconds(30));

        Assert.True((await EvaluateAsync(host, "a", """{"a":1}""")).Succeeded);
        Assert.True((await EvaluateAsync(host, "a", """{"a":2}""")).Succeeded);
    }

    [Fact]
    public async Task A_worker_that_times_out_is_killed_reaped_and_replaced()
    {
        // The evaluation is a legitimate expression over a body large enough that the unchanged
        // evaluator's quadratic sort cannot finish inside the deadline, so the deadline itself —
        // not a special test mode — is what stops it.
        using var host = CreateHost(TimeSpan.FromMilliseconds(1500));

        string body = "[" + string.Join(",", Enumerable.Range(1, 20_000).Reverse()) + "]";

        JmesPathEvaluationResult timedOut = await EvaluateAsync(host, "sort(@)", body);

        Assert.False(timedOut.Succeeded);
        Assert.Equal(JmesPathFailureClass.OperationalTimeout, timedOut.Failure!.FailureClass);

        // The pool survived: the next evaluation gets a fresh, healthy child.
        JmesPathEvaluationResult next = await EvaluateAsync(host, "length(@)", "[1,2,3]");

        Assert.True(next.Succeeded, next.Failure?.Message);
        Assert.Equal("3", Encoding.UTF8.GetString(next.Output!));
    }

    [Fact]
    public async Task Invalid_syntax_returns_a_classified_compile_failure_not_a_protocol_failure()
    {
        using var host = CreateHost(TimeSpan.FromSeconds(30));

        JmesPathEvaluationResult result = await EvaluateAsync(host, "foo(", "{}");

        Assert.False(result.Succeeded);
        Assert.True(
            result.Failure!.FailureClass is
                JmesPathFailureClass.CompileSyntax
                or JmesPathFailureClass.CompileUnknownFunction
                or JmesPathFailureClass.CompileInvalidArity
                or JmesPathFailureClass.CompileUnsupportedNode);
    }

    [Fact]
    public async Task A_result_over_the_output_bound_is_refused_by_the_parent()
    {
        // The worker serializes under the same bound, and the parent validates what arrived.
        using var host = CreateHost(TimeSpan.FromSeconds(30), Limits with { MaxOutputBytes = 12 });

        JmesPathEvaluationResult result = await EvaluateAsync(host, "@", """{"a":"longer than twelve bytes"}""");

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.OutputTooManyBytes, result.Failure!.FailureClass);
    }

    [Fact]
    public async Task A_body_over_the_input_node_bound_is_refused_before_evaluation()
    {
        // The parent prepared the body under its own bounds, and the worker re-measures with the
        // bounds in the request, so a body that crossed them cannot reach the evaluator.
        using var host = CreateHost(TimeSpan.FromSeconds(30));

        JmesPathEvaluationResult result = await EvaluateAsync(
            host, "@", "[1,2,3,4,5]", Limits with { MaxInputNodes = 3 });

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.InputTooManyNodes, result.Failure!.FailureClass);
    }

    [Fact]
    public async Task Cancelling_the_call_still_reaps_the_worker()
    {
        using var host = CreateHost(TimeSpan.FromSeconds(60));

        using var cancellation = new CancellationTokenSource();
        string body = "[" + string.Join(",", Enumerable.Range(1, 20_000).Reverse()) + "]";

        Task<JmesPathEvaluationResult> running = host
            .EvaluateAsync("sort(@)", Encoding.UTF8.GetBytes(body), Limits, cancellation.Token)
            .AsTask();

        await Task.Delay(200, TestContext.Current.CancellationToken);
        cancellation.Cancel();

        JmesPathEvaluationResult result = await running;

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.OperationalCancelled, result.Failure!.FailureClass);

        // A canceled call is not a leaked process: the next evaluation succeeds.
        JmesPathEvaluationResult next = await EvaluateAsync(host, "length(@)", "[1,2,3]");

        Assert.True(next.Succeeded, next.Failure?.Message);
    }

    private static ProjectionWorkerHost CreateHost(TimeSpan deadline, JmesPathLimits? limits = null)
    {
        string directory = AppContext.BaseDirectory;

        // The integration suite's output contains the Engine apphost and assembly because it
        // references the deployable directly; that is the same pair a deployment starts.
        string apphost = Path.Combine(directory, OperatingSystem.IsWindows() ? "mcpiler-engine.exe" : "mcpiler-engine");

        Assert.True(File.Exists(apphost), $"The Engine apphost is missing from {directory}.");

        WorkerPoolOptions options = WorkerPoolOptions.Default with
        {
            TotalDeadline = deadline,
            Launch = new WorkerLaunch(apphost, null),
        };

        if (limits is { } effective)
        {
            options = options with { MaxOutputBytes = effective.MaxOutputBytes };
        }

        return new ProjectionWorkerHost(options);
    }

    private static async Task<JmesPathEvaluationResult> EvaluateAsync(
        ProjectionWorkerHost host,
        string expression,
        string body,
        JmesPathLimits? limits = null)
    {
        // Preparation always uses the suite's permissive limits so a case can hand the worker a
        // body that would be refused at preparation time and observe where the refusal lands.
        if (!JmesPathProfile.TryPrepareInput(
                Encoding.UTF8.GetBytes(body), Limits, out JmesPathPreparedInput? prepared, out JmesPathFailure? failure))
        {
            throw new InvalidOperationException(failure!.Message);
        }

        return await host
            .EvaluateAsync(expression, prepared!.Json, limits ?? Limits, CancellationToken.None)
            .ConfigureAwait(false);
    }
}
