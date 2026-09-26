using System.Globalization;

using MCPiler.Engine.Runtime.Projection;

namespace MCPiler.Engine.Host.ProjectionWorker;

/// <summary>
/// The entry point of one short-lived projection worker.
/// </summary>
/// <remarks>
/// <para>
/// The worker's whole life is: apply and verify the memory limit, prove it can still allocate,
/// print the ready handshake, read exactly one bounded request, evaluate it, write exactly one
/// bounded response, exit. It reads no configuration, opens no socket, resolves no secret and
/// touches no Manifest, because none of those is reachable from here and the process it is
/// running in was started for this one evaluation.
/// </para>
/// <para>
/// Standard output belongs to the protocol and only to the protocol. Every diagnostic goes to
/// standard error, where the parent reads it under its own cap. A worker that wrote a stray line
/// to stdout would corrupt the frame stream, and the parent would classify that as a protocol
/// failure rather than guess what the line meant.
/// </para>
/// <para>
/// One request per process, deliberately. A worker that stayed alive for a second evaluation
/// would carry the previous evaluation's allocator state into it, and the confinement would then
/// be a claim about a process rather than about an evaluation.
/// </para>
/// </remarks>
internal static class ProjectionWorkerEntry
{
    /// <summary>The process exit code of a worker that could not establish confinement.</summary>
    internal const int ConfinementRefusedExitCode = 10;

    /// <summary>The process exit code of a worker whose request could not be read.</summary>
    internal const int ProtocolRefusedExitCode = 11;

    /// <summary>Runs one worker over the protocol streams and returns its exit code.</summary>
    internal static async Task<int> RunAsync(
        Stream input,
        Stream output,
        Stream diagnostics,
        WorkerLimits options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(diagnostics);
        ArgumentNullException.ThrowIfNull(options);

        int bodyFrameLimit;
        try
        {
            bodyFrameLimit = WorkerProtocol.PreparedInputFrameLimitBytes(options.InputBodyLimitBytes);
        }
        catch (Exception exception) when (exception is ArgumentOutOfRangeException or OverflowException)
        {
            await WriteDiagnosticAsync(
                diagnostics,
                "The worker input bound cannot be represented by the frame protocol.",
                cancellationToken).ConfigureAwait(false);

            return ProtocolRefusedExitCode;
        }

        if (!WorkerResourceLimits.TryValidateWorkerEnvironment(out string? environmentRefusal))
        {
            await WriteDiagnosticAsync(diagnostics, environmentRefusal!, cancellationToken).ConfigureAwait(false);

            return ConfinementRefusedExitCode;
        }

        if (!WorkerResourceLimits.TryApply(
                options.CommittedBytes,
                options.AddressSpaceBytes,
                out string applied,
                out string? confinementRefusal))
        {
            await WriteDiagnosticAsync(diagnostics, confinementRefusal!, cancellationToken).ConfigureAwait(false);

            return ConfinementRefusedExitCode;
        }

        // After the limit, before readiness: this is what turns a limit the runtime cannot live
        // under into a refusal instead of a child that dies before its first frame.
        if (!WorkerResourceLimits.TryProveAllocatable(options.CommittedBytes, out string? witnessRefusal))
        {
            await WriteDiagnosticAsync(diagnostics, witnessRefusal!, cancellationToken).ConfigureAwait(false);

            return ConfinementRefusedExitCode;
        }

        // The witness proves a managed allocation fits; this proves the loader can still map the
        // assemblies an evaluation needs, which is the failure an address-space limit that is too
        // tight actually produces on Linux.
        if (!WorkerResourceLimits.TryWarmUp(out string? warmUpRefusal))
        {
            await WriteDiagnosticAsync(diagnostics, warmUpRefusal!, cancellationToken).ConfigureAwait(false);

            return ConfinementRefusedExitCode;
        }

        await output
            .WriteAsync(System.Text.Encoding.UTF8.GetBytes($"READY {options.CommittedBytes}\n"), cancellationToken)
            .ConfigureAwait(false);

        await output.FlushAsync(cancellationToken).ConfigureAwait(false);

        WorkerProtocol.WorkerRequest? request = null;
        string? refusal = null;

        try
        {
            byte[]? header = await WorkerProtocol
                .ReadFrameAsync(input, WorkerProtocol.MaxHeaderBytes, cancellationToken)
                .ConfigureAwait(false);

            if (header is null
                || !WorkerProtocol.TryReadRequestHeader(header, out request, out refusal))
            {
                await WriteDiagnosticAsync(
                    diagnostics,
                    refusal ?? "The worker received no request.",
                    cancellationToken).ConfigureAwait(false);

                return ProtocolRefusedExitCode;
            }

            byte[]? body = await WorkerProtocol
                .ReadFrameAsync(input, bodyFrameLimit, cancellationToken)
                .ConfigureAwait(false);

            if (body is null || body.Length != request!.BodyBytes)
            {
                await WriteDiagnosticAsync(
                    diagnostics,
                    "The worker received no body matching the request's declared size.",
                    cancellationToken).ConfigureAwait(false);

                return ProtocolRefusedExitCode;
            }

            await EvaluateAsync(body, request, output, cancellationToken).ConfigureAwait(false);
            return 0;
        }
        catch (InvalidDataException malformedFrame)
        {
            await WriteDiagnosticAsync(diagnostics, malformedFrame.Message, cancellationToken).ConfigureAwait(false);

            return ProtocolRefusedExitCode;
        }
    }

    private static async Task EvaluateAsync(
        byte[] body,
        WorkerProtocol.WorkerRequest request,
        Stream output,
        CancellationToken cancellationToken)
    {
        JmesPathEvaluationResult result = JmesPathProfile.EvaluatePrepared(
            body, request.Expression, request.Limits);

        if (!result.Succeeded)
        {
            await WorkerProtocol
                .WriteFrameAsync(
                    output,
                    WorkerProtocol.FailureHeader(result.Failure!),
                    cancellationToken)
                .ConfigureAwait(false);

            return;
        }

        await WorkerProtocol
            .WriteFrameAsync(
                output,
                WorkerProtocol.SuccessHeader(result.Output!.Length),
                cancellationToken)
            .ConfigureAwait(false);

        await WorkerProtocol
            .WriteFrameAsync(output, result.Output, cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task WriteDiagnosticAsync(
        Stream diagnostics,
        string message,
        CancellationToken cancellationToken)
    {
        string flattened = message.Replace('\r', ' ').Replace('\n', ' ').Trim();

        if (flattened.Length > 512)
        {
            flattened = flattened[..512];
        }

        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(
            string.Create(CultureInfo.InvariantCulture, $"worker: {flattened}\n"));

        try
        {
            await diagnostics.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await diagnostics.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (IOException)
        {
            // The parent closed the pipe; the exit code is the outcome either way.
        }
    }
}

/// <summary>What one worker process is allowed to use.</summary>
/// <param name="CommittedBytes">The Windows committed-memory limit, and the GC heap cap.</param>
/// <param name="AddressSpaceBytes">The Linux address-space limit.</param>
/// <param name="InputBodyLimitBytes">The accepted raw JSON input bound.</param>
internal sealed record WorkerLimits(
    long CommittedBytes,
    long AddressSpaceBytes,
    long InputBodyLimitBytes = WorkerResourceLimits.DefaultInputBodyLimitBytes);
