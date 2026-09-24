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
/// The parent's obligations are the ones a child cannot be trusted with: a total wall deadline
/// spanning launch, handshake, evaluation and reap; a cap on every frame in both directions,
/// enforced while reading; a bounded number of concurrent workers and a bounded wait for a slot;
/// and kill-and-reap on every failure path before a slot is released. A worker whose exit was
/// not confirmed keeps its slot charged, because a released slot with a live orphan behind it is
/// how a bounded pool becomes an unbounded process launcher.
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

        _slots = new SemaphoreSlim(options.MaxConcurrentWorkers, options.MaxConcurrentWorkers);
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

        if (!_slots.Wait(0, CancellationToken.None)
            && !await _slots.WaitAsync(_options.AdmissionWait, cancellationToken).ConfigureAwait(false))
        {
            return JmesPathEvaluationResult.Failed(new JmesPathFailure(
                JmesPathFailureClass.OperationalBusy,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"No projection worker slot became free within {_options.AdmissionWait.TotalMilliseconds:F0} ms.")));
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

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _slots.Dispose();
    }

    private async Task<JmesPathEvaluationResult> RunWorkerAsync(
        string expression,
        ReadOnlyMemory<byte> normalizedJson,
        JmesPathLimits limits,
        CancellationToken cancellationToken)
    {
        // Start the one-call clock before process creation. Process.Start is synchronous, so it
        // cannot be interrupted, but time spent in it still consumes the same wall budget: a
        // launch that returns after its deadline is killed before it receives any request data.
        TimeSpan requestedDeadline = TimeSpan.FromMilliseconds(limits.MaxEvaluationMilliseconds);
        TimeSpan totalBudget = requestedDeadline < _options.TotalDeadline
            ? requestedDeadline
            : _options.TotalDeadline;
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
                        $"The projection worker did not launch within its {totalBudget.TotalMilliseconds:F0} ms deadline."));
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
                        "The projection worker did not report a verified memory confinement before its deadline.")
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
                        "The projection worker produced no response header before its deadline.")
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

                if (response!.OutputBytes > limits.MaxOutputBytes)
                {
                    return await RefuseAsync(
                        process,
                        input,
                        JmesPathFailureClass.OutputTooManyBytes,
                        $"The projection worker declared {response.OutputBytes} output bytes, exceeding maxOutputBytes={limits.MaxOutputBytes}.")
                        .ConfigureAwait(false);
                }

                byte[]? payload;

                try
                {
                    payload = await WorkerProtocol
                        .ReadFrameAsync(
                            output,
                            (int)Math.Min(
                                Math.Min(_options.MaxOutputBytes, limits.MaxOutputBytes),
                                WorkerProtocol.MaxBodyBytes),
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
                            $"The projection evaluation exceeded its {totalBudget.TotalMilliseconds:F0} ms deadline.")));
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

        // The child caps its managed heap from the environment before the runtime initializes.
        WorkerResourceLimits.ApplyGcHeapCap(information.Environment, _options.Limits.CommittedBytes);

        // The child applies the same confinement values the parent believes it applied. Passing
        // them means a deployment that narrowed the policy narrows the worker identically, and
        // the echoed handshake is then a verification rather than a coincidence.
        information.Environment["MCPILER_PROJECTION_WORKER_COMMITTED_BYTES"] =
            _options.Limits.CommittedBytes.ToString(CultureInfo.InvariantCulture);
        information.Environment["MCPILER_PROJECTION_WORKER_ADDRESS_SPACE_BYTES"] =
            _options.Limits.AddressSpaceBytes.ToString(CultureInfo.InvariantCulture);

        // No ambient host environment travels with the evaluator.
        information.Environment.Remove("ASPNETCORE_ENVIRONMENT");
        information.Environment.Remove("DOTNET_ENVIRONMENT");

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

        using var reap = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try
        {
            await process.WaitForExitAsync(reap.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw new WorkerReapException(
                "The projection worker did not confirm its exit after a kill, so its capacity remains charged.");
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

/// <summary>The operational policy one host applies to every worker it starts.</summary>
/// <param name="Limits">The OS-confined memory values.</param>
/// <param name="MaxConcurrentWorkers">How many workers may run at once.</param>
/// <param name="TotalDeadline">The whole-call wall budget.</param>
/// <param name="AdmissionWait">How long a caller waits for a slot before a busy refusal.</param>
/// <param name="MaxStderrBytes">The diagnostic cap per worker.</param>
/// <param name="MaxOutputBytes">The parent's own cap on a result frame.</param>
/// <param name="Launch">
/// The exact program and assembly to start, or null to start this process's own pair. Tests set
/// it because the process that starts a worker is normally the serving executable while a test
/// host is a different one; production leaves it unset.
/// </param>
internal sealed record WorkerPoolOptions(
    WorkerLimits Limits,
    int MaxConcurrentWorkers,
    TimeSpan TotalDeadline,
    TimeSpan AdmissionWait,
    int MaxStderrBytes,
    long MaxOutputBytes,
    WorkerLaunch? Launch = null)
{
    /// <summary>The calibrated production defaults.</summary>
    internal static WorkerPoolOptions Default { get; } = new(
        Limits: new WorkerLimits(
            CommittedBytes: WorkerResourceLimits.DefaultCommittedBytes,
            AddressSpaceBytes: WorkerResourceLimits.DefaultAddressSpaceBytes),
        MaxConcurrentWorkers: 2,
        TotalDeadline: TimeSpan.FromMilliseconds(10_000),
        AdmissionWait: TimeSpan.FromMilliseconds(5_000),
        MaxStderrBytes: 64 * 1024,
        MaxOutputBytes: 1024L * 1024);
}

/// <summary>The exact program and worker assembly a host starts.</summary>
/// <param name="HostPath">The program to start, such as the shared muxer or an apphost.</param>
/// <param name="AssemblyPath">
/// The worker assembly the program runs, or null when the program is an apphost that already
/// names it.
/// </param>
internal sealed record WorkerLaunch(string HostPath, string? AssemblyPath);
