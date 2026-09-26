using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;

using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.Host.ProjectionWorker;

/// <summary>
/// Runs one evaluation in a fresh, OS-confined child of this same executable.
/// </summary>
/// <remarks>
/// <para>
/// This is the parent half of the confinement, and it is the only place in the repository that
/// starts a process. The library decides what a projection means and asks through
/// <see cref="IProjectionWorker"/>; this answers by launching the same published assembly in its
/// worker mode, chosen by <see cref="Environment.ProcessPath"/> and the entry assembly rather
/// than by a path anybody configured, so a deployment cannot point the evaluator at something
/// else.
/// </para>
/// <para>
/// The evaluation clock starts before the synchronous <see cref="Process.Start"/> call and keeps
/// running through the handshake, evaluation and reap. <see cref="Process.Start"/> itself cannot
/// be cancelled, so its call is not claimed to stop at the deadline; after it returns, the
/// deadline governs every asynchronous phase. Cleanup has a separate bounded timeout, and a
/// worker whose exit is not confirmed keeps its slot charged, because a released slot with a live
/// orphan behind it is how a bounded pool becomes an unbounded process launcher.
/// </para>
/// <para>
/// Nothing about an evaluation reaches the child except the expression and the normalized body,
/// and nothing about the child's failure is presented as a language result: a deadline, an
/// unconfined child, a busy pool and a crashed worker are all operational classes.
/// </para>
/// </remarks>
internal sealed class ProjectionWorkerHost : IProjectionWorker, IDisposable
{
    private readonly WorkerPoolOptions _options;
    private readonly SemaphoreSlim _slots;
    private readonly SemaphoreSlim _queueSlots;
    private bool _disposed;

    /// <summary>Creates a host over one pool configuration.</summary>
    internal ProjectionWorkerHost(WorkerPoolOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;

        if (options.MaxConcurrentWorkers < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "At least one worker slot is required.");
        }

        if (options.QueueCapacity < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "At least one queue slot is required.");
        }

        if (options.TotalDeadline <= TimeSpan.Zero
            || options.TotalDeadline > WorkerPoolOptions.MaximumEvaluationDeadline)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "The local evaluation deadline must be positive and no more than 60 seconds.");
        }

        if (options.AdmissionWait <= TimeSpan.Zero
            || options.AdmissionWait > WorkerPoolOptions.MaximumAdmissionWait)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "The admission wait must be positive and no greater than the timer-supported maximum.");
        }

        if (options.Limits.CommittedBytes < 1
            || options.Limits.CommittedBytes > long.MaxValue / 2)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "The committed-memory limit must be positive and no more than long.MaxValue / 2.");
        }

        if (options.InputBodyLimitBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "A positive input body bound is required.");
        }

        _ = options.PreparedInputFrameLimitBytes;

        _slots = new SemaphoreSlim(options.MaxConcurrentWorkers, options.MaxConcurrentWorkers);
        _queueSlots = new SemaphoreSlim(options.QueueCapacity, options.QueueCapacity);
    }

    /// <inheritdoc />
    public async ValueTask<JmesPathEvaluationResult> EvaluateAsync(
        string expression,
        ReadOnlyMemory<byte> normalizedJson,
        JmesPathLimits limits,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(expression);
        ArgumentNullException.ThrowIfNull(limits);

        if (!limits.IsPositive)
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.InternalEvaluatorDefect,
                "The worker received non-positive projection limits."));
        }

        if (normalizedJson.Length > _options.PreparedInputFrameLimitBytes)
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.InputNotJson,
                "The prepared input exceeds the operational transport bound."));
        }

        bool slotAcquired = _slots.Wait(0, CancellationToken.None);

        if (!slotAcquired && !_queueSlots.Wait(0, CancellationToken.None))
        {
            // A worker may have released its slot between the first probe and the full-queue
            // check. Claim that slot directly rather than refuse a request while capacity exists.
            slotAcquired = _slots.Wait(0, CancellationToken.None);

            if (!slotAcquired)
            {
                return Busy("The projection worker queue is full.");
            }
        }
        else if (!slotAcquired)
        {
            try
            {
                slotAcquired = await _slots.WaitAsync(_options.AdmissionWait, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                // Queue capacity bounds only callers waiting for a worker slot. Once a slot is
                // acquired, the caller occupies worker capacity rather than queue capacity.
                _ = _queueSlots.Release();
            }

            if (!slotAcquired)
            {
                return Busy(string.Create(
                    CultureInfo.InvariantCulture,
                    $"No projection worker slot became free within {_options.AdmissionWait.TotalMilliseconds:F0} ms."));
            }
        }

        bool reapConfirmed = false;

        try
        {
            JmesPathEvaluationResult result = await RunWorkerAsync(
                expression, normalizedJson, limits, cancellationToken).ConfigureAwait(false);

            // RunWorkerAsync returns only after the child is confirmed gone, so the slot may be
            // handed on.
            reapConfirmed = true;
            return result;
        }
        catch (WorkerReapException reapFailure)
        {
            // The slot is deliberately not released: this process has no evidence the child is
            // gone, and treating it as gone is how a pool stops bounding anything.
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.OperationalWorkerFailure,
                reapFailure.Message));
        }
        finally
        {
            if (reapConfirmed)
            {
                _ = _slots.Release();
            }
        }
    }

    internal int ActiveWorkerCount => _options.MaxConcurrentWorkers - _slots.CurrentCount;

    internal int PendingWaiterCount => _options.QueueCapacity - _queueSlots.CurrentCount;

    private static JmesPathEvaluationResult Busy(string message)
        => JmesPathEvaluationResult.Failed(new JmesPathFailure(JmesPathFailureClass.OperationalBusy, message));

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _slots.Dispose();
        _queueSlots.Dispose();
    }

    private async Task<JmesPathEvaluationResult> RunWorkerAsync(
        string expression,
        ReadOnlyMemory<byte> normalizedJson,
        JmesPathLimits limits,
        CancellationToken cancellationToken)
    {
        // Start the one-call clock before process creation. Process.Start is synchronous, so it
        // cannot be interrupted; time spent in it still consumes the same wall budget, and a
        // launch that returns after the deadline receives no request data.
        TimeSpan totalBudget = _options.GetEvaluationBudget(limits.MaxEvaluationMilliseconds);
        using var total = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        total.CancelAfter(totalBudget);

        Process? process;

        try
        {
            process = TryStart(out string? launchRefusal);

            if (process is null)
            {
                if (total.IsCancellationRequested)
                {
                    return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                        JmesPathFailureClass.OperationalTimeout,
                        $"The synchronous worker launch returned after its {totalBudget.TotalMilliseconds:F0} ms deadline; no request was sent."));
                }

                return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                    JmesPathFailureClass.OperationalWorkerFailure,
                    launchRefusal!));
            }
        }
        catch (Exception launchFailure) when (
            launchFailure is InvalidOperationException
                or System.ComponentModel.Win32Exception
                or ArgumentException
                or FileNotFoundException
                or UnauthorizedAccessException
                or IOException
                or NotSupportedException)
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.OperationalWorkerFailure,
                $"The projection worker could not be launched ({launchFailure.GetType().Name})."));
        }

        using (process)
        {
            Stream input = process.StandardInput.BaseStream;
            Stream output = process.StandardOutput.BaseStream;

            // Started before the handshake and never awaited on the happy path: the read exists so
            // a child that writes diagnostics cannot fill its stderr pipe and block, and it ends
            // when the reap closes the stream.
            _ = ReadBoundedAsync(process.StandardError.BaseStream, _options.MaxStderrBytes, total.Token);

            try
            {
                long? echoed;

                try
                {
                    echoed = await WorkerProtocol.ReadReadyAsync(output, total.Token).ConfigureAwait(false);
                }
                catch (InvalidDataException)
                {
                    echoed = null;
                }

                if (echoed is null)
                {
                    return await RefuseAsync(
                        process, input, JmesPathFailureClass.OperationalWorkerFailure,
                        "The projection worker did not report a verified memory confinement before the worker call deadline.")
                        .ConfigureAwait(false);
                }

                if (echoed != _options.Limits.CommittedBytes)
                {
                    return await RefuseAsync(
                        process, input, JmesPathFailureClass.OperationalConfinementUnavailable,
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"The projection worker reported an unexpected memory limit of {echoed} bytes."))
                        .ConfigureAwait(false);
                }

                await WorkerProtocol
                    .WriteFrameAsync(
                        input,
                        WorkerProtocol.RequestHeader(expression, limits, normalizedJson.Length),
                        total.Token)
                    .ConfigureAwait(false);

                await WorkerProtocol
                    .WriteFrameAsync(input, normalizedJson, total.Token)
                    .ConfigureAwait(false);

                byte[]? header;

                try
                {
                    header = await WorkerProtocol
                        .ReadFrameAsync(output, WorkerProtocol.MaxHeaderBytes, total.Token)
                        .ConfigureAwait(false);
                }
                catch (InvalidDataException protocolRefusal)
                {
                    return await RefuseAsync(
                        process, input, JmesPathFailureClass.OperationalWorkerFailure, protocolRefusal.Message)
                        .ConfigureAwait(false);
                }

                if (header is null)
                {
                    return await RefuseAsync(
                        process, input, JmesPathFailureClass.OperationalWorkerFailure,
                        "The projection worker produced no response header before the worker call deadline.")
                        .ConfigureAwait(false);
                }

                if (!WorkerProtocol.TryReadResponse(
                        header,
                        out WorkerProtocol.WorkerResponse? response,
                        out string? headerRefusal,
                        out bool succeeded))
                {
                    return await RefuseAsync(
                        process, input, JmesPathFailureClass.OperationalWorkerFailure,
                        headerRefusal ?? "The projection worker produced no usable response header.")
                        .ConfigureAwait(false);
                }

                if (!succeeded)
                {
                    // A classified failure is the worker's answer rather than a protocol fault, so
                    // it is reaped and reported as it stands.
                    await ReapAsync(process, input).ConfigureAwait(false);

                    return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                        JmesPathFailure.ClassFromCode(response!.Code), response.Message!));
                }

                long responseLimit = Math.Min(_options.MaxOutputBytes, limits.MaxOutputBytes);

                if (response!.OutputBytes > responseLimit)
                {
                    return await RefuseAsync(
                        process,
                        input,
                        JmesPathFailureClass.OutputTooManyBytes,
                        $"The projection worker declared {response.OutputBytes} output bytes, exceeding maxOutputBytes={responseLimit}.")
                        .ConfigureAwait(false);
                }

                byte[]? payload;

                try
                {
                    payload = await WorkerProtocol
                        .ReadFrameAsync(
                            output,
                            checked((int)Math.Min(responseLimit, int.MaxValue)),
                            total.Token)
                        .ConfigureAwait(false);
                }
                catch (InvalidDataException protocolRefusal)
                {
                    return await RefuseAsync(
                        process, input, JmesPathFailureClass.OutputTooManyBytes, protocolRefusal.Message)
                        .ConfigureAwait(false);
                }

                if (payload is null || payload.Length != response!.OutputBytes)
                {
                    return await RefuseAsync(
                        process, input, JmesPathFailureClass.OperationalWorkerFailure,
                        "The projection worker's result frame did not match its declared size.")
                        .ConfigureAwait(false);
                }

                // The parent validates the frame itself, and this call is what makes the reap
                // unconditional below: the verification may refuse, and the child still must die.
                bool verified = JmesPathProfile.TryVerifyResult(
                    payload, limits, out byte[]? canonical, out _, out JmesPathFailure? resultFailure);

                await ReapAsync(process, input).ConfigureAwait(false);

                return verified
                    ? JmesPathEvaluationResult.Produced(canonical!)
                    : JmesPathEvaluationResult.Failed(resultFailure!);
            }
            catch (OperationCanceledException)
            {
                await ReapAsync(process, input).ConfigureAwait(false);

                return JmesPathEvaluationResult.Failed(cancellationToken.IsCancellationRequested
                    ? new JmesPathFailure(
                        JmesPathFailureClass.OperationalCancelled,
                        "The projection evaluation was cancelled before it completed.")
                    : new JmesPathFailure(
                        JmesPathFailureClass.OperationalTimeout,
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"The projection worker call exceeded its {totalBudget.TotalMilliseconds:F0} ms deadline; synchronous process launch is not interruptible.")));
            }
            catch (Exception streamFailure) when (
                streamFailure is IOException or ObjectDisposedException or InvalidOperationException)
            {
                await ReapAsync(process, input).ConfigureAwait(false);

                return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                    JmesPathFailureClass.OperationalWorkerFailure,
                    $"The projection worker's stream failed: {streamFailure.GetType().Name}."));
            }
        }
    }

    /// <summary>
    /// Reports a failure after reaping the child. The reap is what makes returning safe: the slot
    /// this evaluation holds must not be handed on while the child could still be running.
    /// </summary>
    private static async Task<JmesPathEvaluationResult> RefuseAsync(
        Process process,
        Stream input,
        JmesPathFailureClass failureClass,
        string message)
    {
        await ReapAsync(process, input).ConfigureAwait(false);

        return JmesPathEvaluationResult.Failed(new JmesPathFailure(failureClass, message));
    }

    private Process? TryStart(out string? refusal)
    {
        refusal = null;

        string host;
        string? assembly;

        if (_options.Launch is { } launch)
        {
            // A test supplies the exact pair to start, because the process that starts a worker
            // is normally the serving executable while a test host is not. The pair is still a
            // program and this build's worker assembly; nothing else about the launch changes.
            host = launch.HostPath;
            assembly = launch.AssemblyPath;
        }
        else
        {
            host = Environment.ProcessPath ?? string.Empty;

            if (host.Length == 0)
            {
                refusal = "The serving process cannot name its own executable, so it cannot start a worker.";
                return null;
            }

            assembly = typeof(ProjectionWorkerHost).Assembly.Location;

            if (string.IsNullOrEmpty(assembly))
            {
                // A single-file deployment has no assembly path, and inventing another launch
                // mechanism silently would be worse than refusing: the confinement is only
                // meaningful when the parent knows exactly what it started.
                refusal = "The host's own assembly path is unavailable, so a worker cannot be started with its exact code.";
                return null;
            }
        }

        var information = new ProcessStartInfo(host)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            CreateNoWindow = true,

            // The child runs this build's code, from the directory this build was published to.
            WorkingDirectory = AppContext.BaseDirectory,
        };

        // A framework-dependent deployment is started through the shared muxer, which needs the
        // assembly as its first argument. An apphost needs only the mode. Passing the assembly to
        // an apphost would make the worker read it as its mode and refuse.
        if (assembly is not null
            && Path.GetFileNameWithoutExtension(host).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            information.ArgumentList.Add(assembly);
        }

        information.ArgumentList.Add(WorkerProtocol.ModeArgument);

        // Start from an empty environment. Only required Windows runtime values and explicit
        // worker confinement settings reach the child; application secrets never do.
        if (!WorkerResourceLimits.TryConfigureWorkerEnvironment(
                information.Environment,
                _options.Limits.CommittedBytes,
                _options.Limits.AddressSpaceBytes,
                _options.InputBodyLimitBytes,
                out refusal))
        {
            return null;
        }

        try
        {
            return Process.Start(information);
        }
        catch (Exception startFailure) when (startFailure is IOException or InvalidOperationException or Win32Exception)
        {
            refusal = $"The projection worker could not be started: {JmesPathFailure.Sanitize(startFailure.Message)}";
            return null;
        }
    }

    /// <summary>
    /// Kills the child and waits, bounded, for the operating system to confirm it is gone.
    /// </summary>
    /// <exception cref="WorkerReapException">The exit was not confirmed.</exception>
    private static async Task ReapAsync(Process process, Stream input)
    {
        try
        {
            input.Close();
        }
        catch (IOException)
        {
        }

        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception killFailure) when (
            killFailure is InvalidOperationException or NotSupportedException or Win32Exception)
        {
            // The process may have exited between the check and the kill, and the wait below is
            // the authority on whether it is gone.
        }

        using var reap = new CancellationTokenSource(WorkerPoolOptions.CleanupTimeout);

        try
        {
            await process.WaitForExitAsync(reap.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw new WorkerReapException(
                $"The projection worker did not confirm its exit within the {WorkerPoolOptions.CleanupTimeout.TotalSeconds:F0}-second cleanup bound, so its capacity remains charged.");
        }
    }

    /// <summary>Reads a diagnostic stream under a hard cap, discarding anything past it.</summary>
    private static async Task ReadBoundedAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[4096];
        var kept = new StringBuilder();
        long read = 0;

        try
        {
            while (read < maxBytes)
            {
                int count = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);

                if (count == 0)
                {
                    break;
                }

                read += count;

                if (kept.Length < 4096)
                {
                    kept.Append(Encoding.UTF8.GetString(buffer, 0, count));
                }
            }
        }
        catch
        {
            // A diagnostic read can end in any way a pipe can end. None of it changes the
            // outcome the evaluation already reached, and an unobserved failure would be noise.
        }
    }

    /// <summary>The exception an unconfirmed reap raises, which keeps a slot charged.</summary>
    private sealed class WorkerReapException : Exception
    {
        internal WorkerReapException(string message)
            : base(message)
        {
        }
    }
}

/// <summary>The operational policy one host applies to every worker it starts. The total deadline is an independent absolute local ceiling.</summary>
/// <param name="Limits">The OS-confined memory values.</param>
/// <param name="MaxConcurrentWorkers">How many workers may run at once.</param>
/// <param name="TotalDeadline">The independent absolute local launch/IPC/evaluation host ceiling; it is capped at 60 seconds.</param>
/// <param name="AdmissionWait">How long a caller waits for a slot before a busy refusal; it is capped at the timer-supported maximum.</param>
/// <param name="QueueCapacity">How many callers may wait beyond active workers.</param>
/// <param name="MaxStderrBytes">The diagnostic cap per worker.</param>
/// <param name="MaxOutputBytes">The parent's own cap on a result frame.</param>
/// <param name="Launch">
/// The exact program and assembly to start, or null to start this process's own pair. Tests set
/// it because the process that starts a worker is normally the serving executable while a test
/// host is a different one; production leaves it unset.
/// </param>
/// <param name="InputBodyLimitBytes">The accepted raw JSON input bound for this host.</param>
internal sealed record WorkerPoolOptions(
    WorkerLimits Limits,
    int MaxConcurrentWorkers,
    TimeSpan TotalDeadline,
    TimeSpan AdmissionWait,
    int MaxStderrBytes,
    long MaxOutputBytes,
    int QueueCapacity = 8,
    WorkerLaunch? Launch = null,
    long InputBodyLimitBytes = WorkerResourceLimits.DefaultInputBodyLimitBytes)
{
    internal static TimeSpan MaximumEvaluationDeadline { get; } = TimeSpan.FromSeconds(60);

    internal static TimeSpan MaximumAdmissionWait { get; } = TimeSpan.FromMilliseconds(int.MaxValue);

    internal static TimeSpan CleanupTimeout { get; } = TimeSpan.FromSeconds(5);

    internal int PreparedInputFrameLimitBytes
        => WorkerProtocol.PreparedInputFrameLimitBytes(InputBodyLimitBytes);

    internal TimeSpan GetEvaluationBudget(int declaredMilliseconds)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(declaredMilliseconds);

        if (TotalDeadline <= TimeSpan.Zero || TotalDeadline > MaximumEvaluationDeadline)
        {
            throw new InvalidOperationException(
                "The local evaluation deadline must be positive and no more than 60 seconds.");
        }

        TimeSpan declared = TimeSpan.FromMilliseconds(declaredMilliseconds);
        return declared < TotalDeadline ? declared : TotalDeadline;
    }

    /// <summary>The calibrated production defaults.</summary>
    internal static WorkerPoolOptions Default { get; } = new(
        Limits: new WorkerLimits(
            CommittedBytes: WorkerResourceLimits.DefaultCommittedBytes,
            AddressSpaceBytes: WorkerResourceLimits.DefaultAddressSpaceBytes,
            InputBodyLimitBytes: WorkerResourceLimits.DefaultInputBodyLimitBytes),
        MaxConcurrentWorkers: 2,
        TotalDeadline: TimeSpan.FromMilliseconds(60_000),
        AdmissionWait: TimeSpan.FromMilliseconds(5_000),
        MaxStderrBytes: 64 * 1024,
        MaxOutputBytes: 1024L * 1024,
        QueueCapacity: 8,
        InputBodyLimitBytes: WorkerResourceLimits.DefaultInputBodyLimitBytes);
}

/// <summary>The exact program and worker assembly a host starts.</summary>
/// <param name="HostPath">The program to start, such as the shared muxer or an apphost.</param>
/// <param name="AssemblyPath">
/// The worker assembly the program runs, or null when the program is an apphost that already
/// names it.
/// </param>
internal sealed record WorkerLaunch(string HostPath, string? AssemblyPath);
