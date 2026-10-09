using System.Buffers.Binary;
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

    [Theory]
    [InlineData(10_000, 60_000, 10_000)]
    [InlineData(30_000, 60_000, 30_000)]
    [InlineData(60_000, 60_000, 60_000)]
    [InlineData(60_000, 15_000, 15_000)]
    public void Worker_budget_is_the_minimum_of_declared_and_local_host_ceilings(
        int declaredMilliseconds,
        int hostMilliseconds,
        int expectedMilliseconds)
    {
        WorkerPoolOptions options = WorkerPoolOptions.Default with
        {
            TotalDeadline = TimeSpan.FromMilliseconds(hostMilliseconds),
        };

        Assert.Equal(
            TimeSpan.FromMilliseconds(expectedMilliseconds),
            options.GetEvaluationBudget(declaredMilliseconds));
    }

    [Fact]
    public void The_default_host_deadline_is_sixty_seconds()
    {
        Assert.Equal(TimeSpan.FromMilliseconds(60_000), WorkerPoolOptions.Default.TotalDeadline);
        Assert.Equal(10_000, JmesPathLimits.AuthoringDefault.MaxEvaluationMilliseconds);
        Assert.Equal(60_000, JmesPathLimits.AdministratorCeiling.MaxEvaluationMilliseconds);
    }

    [Fact]
    public void Host_accepts_the_sixty_second_local_ceiling()
    {
        using var host = new ProjectionWorkerHost(WorkerPoolOptions.Default with
        {
            TotalDeadline = TimeSpan.FromSeconds(60),
        });

        Assert.Equal(0, host.ActiveWorkerCount);
    }

    [Fact]
    public void Host_rejects_a_deadline_above_sixty_seconds_before_admission()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProjectionWorkerHost(
            WorkerPoolOptions.Default with
            {
                TotalDeadline = TimeSpan.FromMilliseconds(60_001),
            }));
    }

    [Fact]
    public void Host_accepts_the_timer_supported_admission_wait_boundary()
    {
        using var host = new ProjectionWorkerHost(WorkerPoolOptions.Default with
        {
            AdmissionWait = WorkerPoolOptions.MaximumAdmissionWait,
        });

        Assert.Equal(0, host.ActiveWorkerCount);
    }

    [Fact]
    public void Host_rejects_an_unsupported_admission_wait_before_admission()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProjectionWorkerHost(
            WorkerPoolOptions.Default with
            {
                AdmissionWait = TimeSpan.FromMilliseconds((double)int.MaxValue + 1),
            }));
    }

    [Fact]
    public void Host_rejects_an_overflowing_committed_memory_limit_before_admission()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProjectionWorkerHost(
            WorkerPoolOptions.Default with
            {
                Limits = WorkerPoolOptions.Default.Limits with
                {
                    CommittedBytes = long.MaxValue,
                },
            }));
    }

    [Fact]
    public void Gc_region_arithmetic_is_checked_before_environment_mutation()
    {
        var environment = new Dictionary<string, string?>();

        Assert.Throws<OverflowException>(() => WorkerResourceLimits.ApplyGcHeapCap(environment, long.MaxValue));
        Assert.Empty(environment);
    }

    [Fact]
    public async Task Prepared_input_frame_header_uses_the_protocol_representable_bound()
    {
        Assert.Equal(357_913_770, WorkerPoolOptions.Default.InputBodyLimitBytes);
        Assert.Equal(2_147_483_644, WorkerPoolOptions.Default.PreparedInputFrameLimitBytes);

        int cap = WorkerProtocol.PreparedInputFrameLimitBytes(4);
        Assert.Equal(1_048, cap);

        using var exact = new MemoryStream();
        await WorkerProtocol.WriteFrameAsync(exact, new byte[cap], TestContext.Current.CancellationToken);
        exact.Position = 0;
        byte[]? accepted = await WorkerProtocol.ReadFrameAsync(exact, cap, TestContext.Current.CancellationToken);
        Assert.Equal(cap, accepted!.Length);

        byte[] requestHeader = WorkerProtocol.RequestHeader("@", Limits, 70_000_000);
        Assert.True(WorkerProtocol.TryReadRequestHeader(requestHeader, out WorkerProtocol.WorkerRequest? request, out _));
        Assert.Equal(70_000_000, request!.BodyBytes);

        byte[] responseHeader = WorkerProtocol.SuccessHeader(70_000_000);
        Assert.True(WorkerProtocol.TryReadResponseHeader(responseHeader, out WorkerProtocol.WorkerResponse? response, out _));
        Assert.Equal(70_000_000, response!.OutputBytes);

        using var oversized = new MemoryStream();
        byte[] header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, cap + 1);
        await oversized.WriteAsync(header, TestContext.Current.CancellationToken);
        oversized.Position = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => WorkerProtocol.ReadFrameAsync(
            oversized,
            cap,
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Protocol_header_uses_relaxed_escaping_for_large_ampersand_expression()
    {
        string expression = new string('&', 16_384);
        byte[] header = WorkerProtocol.RequestHeader(expression, Limits, 1);
        string json = Encoding.UTF8.GetString(header);

        Assert.True(header.Length < WorkerProtocol.MaxHeaderBytes);
        Assert.DoesNotContain("\\u0026", json, StringComparison.OrdinalIgnoreCase);
        Assert.True(WorkerProtocol.TryReadRequestHeader(header, out WorkerProtocol.WorkerRequest? request, out _));
        Assert.Equal(expression, request!.Expression);
    }

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
    public async Task A_worker_child_does_not_inherit_parent_secret_environment_variables()
    {
        const string variableName = "MCPILER_TEST_SECRET";
        const string canary = "DO_NOT_INHERIT";
        string? original = Environment.GetEnvironmentVariable(variableName);
        Environment.SetEnvironmentVariable(variableName, canary);

        try
        {
            using var host = CreateHost(
                TimeSpan.FromSeconds(30),
                launch: new WorkerLaunch("dotnet", Path.Combine(AppContext.BaseDirectory, "mcpiler-engine.dll")));

            JmesPathEvaluationResult result = await EvaluateAsync(host, "length(@)", "[1,2,3]");

            Assert.False((result.Failure?.Message ?? string.Empty).Contains(canary, StringComparison.Ordinal));
            Assert.True(result.Succeeded, result.Failure?.Message);
            Assert.Equal("3", Encoding.UTF8.GetString(result.Output!));
        }
        finally
        {
            Environment.SetEnvironmentVariable(variableName, original);
        }
    }

    [Fact]
    public async Task Admission_caps_workers_and_waiters_and_refuses_the_next_caller_immediately()
    {
        const int maxConcurrentWorkers = 2;
        const int queueCapacity = 8;
        using var firstActiveCancellation = new CancellationTokenSource();
        using var secondActiveCancellation = new CancellationTokenSource();
        using var queuedCancellation = new CancellationTokenSource();
        using var host = CreateHost(
            TimeSpan.FromSeconds(60),
            limits: Limits with
            {
                MaxInputNodes = 100_000,
                MaxResultNodes = 100_000,
                MaxEvaluationMilliseconds = 60_000,
            },
            launch: new WorkerLaunch("dotnet", Path.Combine(AppContext.BaseDirectory, "mcpiler-engine.dll")),
            maxConcurrentWorkers: maxConcurrentWorkers,
            queueCapacity: queueCapacity);

        string slowBody = "[" + string.Join(",", Enumerable.Range(1, 40_000).Reverse()) + "]";
        byte[] slowJson = Encoding.UTF8.GetBytes(slowBody);
        JmesPathLimits slowLimits = Limits with
        {
            MaxInputNodes = 100_000,
            MaxResultNodes = 100_000,
            MaxEvaluationMilliseconds = 60_000,
        };

        Task<JmesPathEvaluationResult>[] active =
        [
            host.EvaluateAsync("sort(@)", slowJson, slowLimits, firstActiveCancellation.Token).AsTask(),
            host.EvaluateAsync("sort(@)", slowJson, slowLimits, secondActiveCancellation.Token).AsTask(),
        ];
        await WaitForConditionAsync(
            () => host.ActiveWorkerCount == maxConcurrentWorkers,
            "The active worker slots were not acquired.");

        Task<JmesPathEvaluationResult>[] queued = Enumerable.Range(0, queueCapacity)
            .Select(_ => host.EvaluateAsync("sort(@)", slowJson, slowLimits, queuedCancellation.Token).AsTask())
            .ToArray();
        await WaitForConditionAsync(
            () => host.PendingWaiterCount == queueCapacity,
            "The bounded queue did not admit exactly its configured waiters.");

        Task<JmesPathEvaluationResult> rejectedTask = host
            .EvaluateAsync("length(@)", "[]"u8.ToArray(), Limits, queuedCancellation.Token)
            .AsTask();
        Assert.True(rejectedTask.IsCompleted, "A caller beyond active-plus-queued capacity must be refused immediately.");
        JmesPathEvaluationResult rejected = await rejectedTask;
        Assert.False(rejected.Succeeded);
        Assert.Equal(JmesPathFailureClass.OperationalBusy, rejected.Failure!.FailureClass);

        // Releasing one active slot promotes a waiter. Its queue reservation must be released
        // immediately, even while that promoted worker is still active.
        firstActiveCancellation.Cancel();
        await active[0].WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await WaitForConditionAsync(
            () => host.ActiveWorkerCount == maxConcurrentWorkers
                && host.PendingWaiterCount == queueCapacity - 1,
            "A queued caller did not transition into an active worker and free its queue slot.");

        secondActiveCancellation.Cancel();
        queuedCancellation.Cancel();
        await Task.WhenAll(active).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        try
        {
            await Task.WhenAll(queued).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Queued callers honor cancellation and release queue reservations in finally.
        }

        await WaitForConditionAsync(
            () => host.ActiveWorkerCount == 0 && host.PendingWaiterCount == 0,
            "Worker or queue capacity remained charged after cancellation and reap.");

        JmesPathEvaluationResult recovered = await EvaluateAsync(host, "length(@)", "[1,2,3]");
        Assert.True(recovered.Succeeded, recovered.Failure?.Message);
    }

    [Fact]
    public async Task A_timed_out_waiter_releases_its_queue_reservation()
    {
        using var activeCancellation = new CancellationTokenSource();
        using var host = CreateHost(
            TimeSpan.FromSeconds(60),
            limits: Limits with
            {
                MaxInputNodes = 100_000,
                MaxResultNodes = 100_000,
                MaxEvaluationMilliseconds = 60_000,
            },
            launch: new WorkerLaunch("dotnet", Path.Combine(AppContext.BaseDirectory, "mcpiler-engine.dll")),
            maxConcurrentWorkers: 2,
            queueCapacity: 1,
            admissionWait: TimeSpan.FromMilliseconds(250));

        string slowBody = "[" + string.Join(",", Enumerable.Range(1, 40_000).Reverse()) + "]";
        byte[] slowJson = Encoding.UTF8.GetBytes(slowBody);
        JmesPathLimits slowLimits = Limits with
        {
            MaxInputNodes = 100_000,
            MaxResultNodes = 100_000,
            MaxEvaluationMilliseconds = 60_000,
        };
        Task<JmesPathEvaluationResult>[] active =
        [
            host.EvaluateAsync("sort(@)", slowJson, slowLimits, activeCancellation.Token).AsTask(),
            host.EvaluateAsync("sort(@)", slowJson, slowLimits, activeCancellation.Token).AsTask(),
        ];
        await WaitForConditionAsync(() => host.ActiveWorkerCount == 2, "Active workers did not start.");

        JmesPathEvaluationResult firstWaiter = await WaitForTimedOutWaiterAsync(host);
        Assert.Equal(JmesPathFailureClass.OperationalBusy, firstWaiter.Failure!.FailureClass);
        Assert.Equal(0, host.PendingWaiterCount);

        JmesPathEvaluationResult secondWaiter = await WaitForTimedOutWaiterAsync(host);
        Assert.Equal(JmesPathFailureClass.OperationalBusy, secondWaiter.Failure!.FailureClass);
        Assert.Equal(0, host.PendingWaiterCount);

        activeCancellation.Cancel();
        await Task.WhenAll(active).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await WaitForConditionAsync(() => host.ActiveWorkerCount == 0, "Canceled workers were not reaped.");

        JmesPathEvaluationResult recovered = await EvaluateAsync(host, "length(@)", "[1,2,3]");
        Assert.True(recovered.Succeeded, recovered.Failure?.Message);
    }

    [Fact]
    public async Task A_worker_that_times_out_is_killed_reaped_and_replaced()
    {
        // The evaluation is a legitimate expression over a body large enough that the unchanged
        // evaluator's quadratic sort cannot finish inside the deadline, so the deadline itself —
        // not a special test mode — is what stops it. The host ceiling is generous and the timeout
        // comes from the per-call declared deadline, so the same host can also serve the recovery
        // call under a full budget. A single narrow host deadline would make the recovery call
        // (whose budget includes a real child-process launch) fail on a starved host, which is a
        // property of the machine rather than of the pool.
        using var host = CreateHost(TimeSpan.FromSeconds(30));

        string body = "[" + string.Join(",", Enumerable.Range(1, 20_000).Reverse()) + "]";

        JmesPathEvaluationResult timedOut = await EvaluateAsync(host, "sort(@)", body, Deadline(250));

        Assert.False(timedOut.Succeeded);
        Assert.Equal(JmesPathFailureClass.OperationalTimeout, timedOut.Failure!.FailureClass);
        Assert.Contains("worker call exceeded", timedOut.Failure!.Message, StringComparison.Ordinal);

        // The slot is released while the host is still alive, so the pool is not deadlocked on the
        // timed-out child.
        Assert.Equal(0, host.ActiveWorkerCount);

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

    [Fact]
    public async Task An_expression_over_the_byte_bound_is_refused_before_any_worker_is_launched()
    {
        // MTH-JP-1: the parent refuses an oversized expression before IPC/launch. The host has no
        // launchable worker path, so a parent that reached launch would surface an operational class
        // instead; the refusal must be the language bound and must not launch a child.
        using var host = CreateHost(
            TimeSpan.FromSeconds(30),
            launch: new WorkerLaunch("definitely-not-a-real-worker-binary", null));

        string oversized = new string('@', 64);

        JmesPathEvaluationResult result = await host
            .EvaluateAsync(oversized, "{}"u8.ToArray(), Limits with { MaxExpressionBytes = 16 }, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(JmesPathFailureClass.ExpressionTooManyBytes, result.Failure!.FailureClass);
    }

    [Fact]
    public async Task Stderr_beyond_the_retained_cap_is_drained_rather_than_left_to_block_the_child()
    {
        // MTH-JP-2: the drain must read to the end of a stream longer than the retained cap.
        const int cap = 1024;
        int total = cap * 8;
        var stream = new DrainProbeStream(total);

        await ProjectionWorkerHost.ReadBoundedAsync(stream, cap, TestContext.Current.CancellationToken);

        Assert.Equal(total, stream.BytesRead);
    }

    [Fact]
    public void The_address_space_resource_id_is_platform_specific()
    {
        // MTH-JP-3: RLIMIT_AS is resource 9 on Linux but resource 5 on macOS/BSD.
        Assert.Equal(9, WorkerResourceLimits.AddressSpaceResourceId(isMacOs: false));
        Assert.Equal(5, WorkerResourceLimits.AddressSpaceResourceId(isMacOs: true));
    }

    /// <summary>A stream that yields a fixed number of bytes, then ends, tracking how many were read.</summary>
    private sealed class DrainProbeStream(int total) : Stream
    {
        private int _remaining = total;

        public int BytesRead { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int take = Math.Min(Math.Min(count, buffer.Length - offset), _remaining);
            Array.Clear(buffer, offset, take);
            _remaining -= take;
            BytesRead += take;
            return take;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int take = Math.Min(buffer.Length, _remaining);
            buffer.Span[..take].Clear();
            _remaining -= take;
            BytesRead += take;
            return ValueTask.FromResult(take);
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static ProjectionWorkerHost CreateHost(
        TimeSpan deadline,
        JmesPathLimits? limits = null,
        WorkerLaunch? launch = null,
        int? maxConcurrentWorkers = null,
        int? queueCapacity = null,
        TimeSpan? admissionWait = null)
    {
        string directory = AppContext.BaseDirectory;

        // The integration suite's output contains the Engine apphost and assembly because it
        // references the deployable directly; that is the same pair a deployment starts.
        string apphost = Path.Combine(directory, OperatingSystem.IsWindows() ? "mcpiler-engine.exe" : "mcpiler-engine");

        Assert.True(File.Exists(apphost), $"The Engine apphost is missing from {directory}.");

        WorkerPoolOptions options = WorkerPoolOptions.Default with
        {
            TotalDeadline = deadline,
            Launch = launch ?? new WorkerLaunch(apphost, null),
            MaxConcurrentWorkers = maxConcurrentWorkers ?? WorkerPoolOptions.Default.MaxConcurrentWorkers,
            QueueCapacity = queueCapacity ?? WorkerPoolOptions.Default.QueueCapacity,
            AdmissionWait = admissionWait ?? WorkerPoolOptions.Default.AdmissionWait,
        };

        if (limits is { } effective)
        {
            options = options with { MaxOutputBytes = effective.MaxOutputBytes };
        }

        return new ProjectionWorkerHost(options);
    }

    private static async Task WaitForConditionAsync(Func<bool> condition, string failureMessage)
    {
        for (var attempt = 0; attempt < 500 && !condition(); attempt++)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(10), TestContext.Current.CancellationToken);
        }

        Assert.True(condition(), failureMessage);
    }

    private static async Task<JmesPathEvaluationResult> WaitForTimedOutWaiterAsync(ProjectionWorkerHost host)
    {
        Task<JmesPathEvaluationResult> waiting = host
            .EvaluateAsync("length(@)", Encoding.UTF8.GetBytes("[]"), Limits, CancellationToken.None)
            .AsTask();

        await WaitForConditionAsync(() => host.PendingWaiterCount == 1, "Waiter never acquired queue capacity.");

        return await waiting.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
    }

    /// <summary>The suite's permissive limits with a narrower declared evaluation deadline.</summary>
    private static JmesPathLimits Deadline(int milliseconds)
        => Limits with { MaxEvaluationMilliseconds = milliseconds };

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
