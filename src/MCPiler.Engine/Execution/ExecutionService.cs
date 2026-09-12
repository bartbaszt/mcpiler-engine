using System.Text.Json.Nodes;

using MCPiler.Engine.Compound;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Transform;

namespace MCPiler.Engine.Execution;

/// <summary>One execution as a caller describes it.</summary>
/// <param name="Manifest">The compiled manifest that governs the execution.</param>
/// <param name="Slug">The agent operation to execute.</param>
/// <param name="Arguments">The arguments as the caller supplied them.</param>
public sealed record ExecutionRequest(ManifestDocument Manifest, string Slug, JsonObject Arguments)
{
    /// <summary>File payloads by parameter name.</summary>
    public IReadOnlyDictionary<string, byte[]>? Files { get; init; }

    /// <summary>Declared filenames for those payloads.</summary>
    public IReadOnlyDictionary<string, string>? FileNames { get; init; }

    /// <summary>Declared media types for those payloads.</summary>
    public IReadOnlyDictionary<string, string>? FileMediaTypes { get; init; }

    /// <summary>
    /// The scope an issued file handle belongs to, defaulting to the manifest's server name.
    /// </summary>
    /// <remarks>
    /// Recorded now although nothing authorizes against it yet. A handle issued without a scope
    /// could not be retrofitted with one later without invalidating every handle already
    /// outstanding.
    /// </remarks>
    public string? Scope { get; init; }

    /// <summary>
    /// A response ceiling for this one execution, which may only narrow the policy's.
    /// </summary>
    /// <remarks>
    /// A workflow's aggregate budget is spent by its steps, and a step told only the policy's
    /// per-response ceiling would let the sum overrun by a whole response before anyone noticed.
    /// Stating what is left makes the aggregate a bound on what arrives rather than a total
    /// checked after it already did. It never widens: the effective limit is the smaller of the
    /// two, so a caller cannot raise a ceiling the policy compiled.
    /// </remarks>
    public long? ResponseSizeLimitBytes { get; init; }
}

/// <summary>
/// Runs one operation: which destination, which credentials, which limits, and what the answer
/// means.
/// </summary>
/// <remarks>
/// <para>
/// Everything that decides something lives here, and everything that touches the host is behind
/// a port. The consequence worth stating is that the whole order of operations — perimeter
/// before credentials, credentials before compilation, compilation before any socket — is
/// exercisable against a transport that opens nothing, so "no request was sent" is an assertion
/// rather than an inference.
/// </para>
/// <para>
/// The exchange has exactly one deadline, and it spans the chain rather than a request. A
/// redirect chain whose hops are each individually fast can take arbitrarily long, and a
/// per-request timeout bounds none of it. The budget also covers reading the body, because an
/// upstream that answers immediately and then trickles bytes has not been bounded by anything
/// that stops at the response headers.
/// </para>
/// </remarks>
public sealed class ExecutionService
{
    private readonly IUpstreamTransport _transport;
    private readonly IManifestSecretResolver _secrets;
    private readonly FileHandleStore? _files;

    /// <summary>Creates a service over the supplied ports.</summary>
    /// <param name="transport">How an exchange reaches an upstream.</param>
    /// <param name="secrets">How credential references become values.</param>
    /// <param name="files">
    /// Where a binary response is stored. With none configured, a binary body is returned as
    /// bytes rather than as a handle.
    /// </param>
    public ExecutionService(
        IUpstreamTransport transport,
        IManifestSecretResolver secrets,
        FileHandleStore? files = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(secrets);

        _transport = transport;
        _secrets = secrets;
        _files = files;
    }

    /// <summary>Executes <paramref name="request"/> and returns what happened.</summary>
    public async Task<EngineExecutionResult> ExecuteAsync(
        ExecutionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var manifest = request.Manifest;
        var entry = manifest.AgentSurface.Operation(request.Slug);

        if (entry is null)
        {
            return Failed(ExecutionFailureKind.Compilation, $"No operation is exposed as '{request.Slug}'.");
        }

        // Before anything single-exchange is resolved. A workflow has no one destination, no
        // one credential scope and no one response, so every question below is the wrong
        // question to ask about it — and it is asked of the dispatcher, not of the binding's
        // type, so this stays the only place that knows a workflow is a possibility.
        if (ManifestBindingDispatcher.TryResolveCompound(entry.Binding) is { } workflow)
        {
            return await CompoundExecutor
                .ExecuteAsync(this, _files, request, workflow, cancellationToken)
                .ConfigureAwait(false);
        }

        var operationKey = ManifestBindingDispatcher.TryResolveOperationKey(entry.Binding);
        var operation = operationKey is null ? null : manifest.Operations.Operation(operationKey);

        if (operation is null)
        {
            return Failed(
                ExecutionFailureKind.Compilation,
                $"Operation '{request.Slug}' has no HTTP binding this runtime can execute.");
        }

        var policy = manifest.Policy;
        var limits = policy.EffectiveLimits;

        OriginAllowList origins;
        try
        {
            origins = new OriginAllowList(policy.AllowedOrigins);
        }
        catch (ArgumentException ex)
        {
            return Failed(ExecutionFailureKind.OriginPolicy, ex.Message);
        }

        var serverUrl = ManifestBindingDispatcher.TryResolveServerUrl(entry.Binding);
        if (!TryResolveBaseUri(serverUrl, policy.BaseUrl, out var baseUri, out var baseFailure))
        {
            return Failed(ExecutionFailureKind.Compilation, baseFailure!);
        }

        // Before anything is resolved, compiled or opened. A binding override outside the
        // governing perimeter is a configuration mistake, and discovering it after a credential
        // has been read would mean a secret was fetched to serve a request that could never be
        // sent.
        if (!origins.IsAllowed(baseUri))
        {
            return Failed(
                ExecutionFailureKind.OriginPolicy,
                $"The destination '{baseUri}' is not inside the governing allowed-origin set.");
        }

        // Before a credential is read and before anything is compiled. A program that aborts
        // must cost nothing observable, and a secret fetched to serve a request that could
        // never be sent is exactly the cost the origin check above already refuses to pay.
        if (!TransformStage.TryInput(
                manifest,
                entry,
                operation,
                request.Arguments,
                out JsonObject arguments,
                out string? transformFailure))
        {
            return Failed(ExecutionFailureKind.Transformation, transformFailure);
        }

        IReadOnlyList<ResolvedCredential> credentials;
        try
        {
            credentials = await _secrets.ResolveAsync(
                manifest.EffectiveCredentials,
                ManifestBindingDispatcher.CredentialRefsOf(entry.Binding),
                cancellationToken).ConfigureAwait(false);
        }
        catch (CredentialUnavailableException ex)
        {
            return Failed(ExecutionFailureKind.Authentication, ex.Message);
        }

        CompiledRequest compiled;
        UpstreamRequest upstream;
        try
        {
            compiled = RequestCompiler.Compile(
                operation,
                baseUri,
                arguments,
                request.Files,
                request.FileNames,
                request.FileMediaTypes);

            upstream = CredentialApplier.Apply(compiled, credentials);
        }
        catch (CredentialUnavailableException ex)
        {
            return Failed(ExecutionFailureKind.Authentication, ex.Message);
        }
        catch (Exception ex) when (ex is ArgumentValidationException
            or InvalidBaseUrlException
            or UnsupportedSerializationException
            or UnsupportedBodyMediaTypeException)
        {
            return Failed(ExecutionFailureKind.Compilation, ex.Message);
        }

        EngineExecutionResult outcome = await SendAsync(
                request, operation, compiled, upstream, origins, limits, cancellationToken)
            .ConfigureAwait(false);

        // After the exchange, and only for a response that arrived whole and inside the
        // ceiling. A failed exchange has no body to map, and a body that breached the response
        // limit was refused before it was ever materialized — transforming it here would hand
        // back the bytes the ceiling exists to stop.
        if (!outcome.Succeeded)
        {
            return outcome;
        }

        if (!TransformStage.TryOutput(manifest, entry, outcome, out byte[]? body, out transformFailure))
        {
            return outcome with
            {
                Failure = ExecutionFailureKind.Transformation,
                FailureReason = transformFailure,
            };
        }

        return ReferenceEquals(body, outcome.ResponseBody) ? outcome : outcome with { ResponseBody = body };
    }

    private async Task<EngineExecutionResult> SendAsync(
        ExecutionRequest request,
        ManifestOperation operation,
        CompiledRequest compiled,
        UpstreamRequest upstream,
        OriginAllowList origins,
        ExecutionLimits limits,
        CancellationToken cancellationToken)
    {
        using var exchange = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        if (limits.UpstreamRequestTimeout > TimeSpan.Zero)
        {
            exchange.CancelAfter(limits.UpstreamRequestTimeout);
        }

        UpstreamResponse response;
        try
        {
            response = await _transport.SendAsync(upstream, new UpstreamSendPolicy(origins, OutboundLimits.From(limits)), exchange.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (BudgetExpired(exchange, cancellationToken))
        {
            return TimedOut(compiled, limits.UpstreamRequestTimeout);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Failed(Classify(ex), ex.Message) with { Request = compiled };
        }

        await using (response.ConfigureAwait(false))
        {
            // Captured while the response is open. Reading status or headers from a released
            // transport object happens to work today and is not a contract.
            var partial = new EngineExecutionResult
            {
                Request = compiled,
                StatusCode = response.StatusCode,
                ResponseHeaders = response.Headers,
                ResponseMediaType = response.MediaType,
            };

            try
            {
                return await ReadBodyAsync(request, operation, response, limits, partial, exchange.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (BudgetExpired(exchange, cancellationToken))
            {
                // The status and headers observed before the body ran out of time are still
                // true, and a diagnosis that lost them would be missing the only evidence about
                // what the upstream was doing.
                return partial with
                {
                    Failure = ExecutionFailureKind.Timeout,
                    FailureReason = TimeoutReason(limits.UpstreamRequestTimeout),
                };
            }
            catch (ResponseSizeLimitException ex)
            {
                return partial with
                {
                    Failure = ExecutionFailureKind.ResponseSize,
                    FailureReason = ex.Message,
                };
            }
            catch (FileRuntimeException ex)
            {
                // A store refusal is a classified result carrying the response that was
                // observed, not an exception escaping the execution path.
                return partial with
                {
                    Failure = ExecutionFailureKind.FileRuntime,
                    FailureReason = ex.Message,
                };
            }
        }
    }

    private async Task<EngineExecutionResult> ReadBodyAsync(
        ExecutionRequest request,
        ManifestOperation operation,
        UpstreamResponse response,
        ExecutionLimits limits,
        EngineExecutionResult partial,
        CancellationToken cancellationToken)
    {
        // The smaller of the two. A caller may narrow this for its own accounting — a workflow
        // spending an aggregate budget does — and may never raise what the policy compiled.
        var limit = request.ResponseSizeLimitBytes is { } requested
            ? Math.Min(limits.UpstreamResponseSizeLimitBytes, requested)
            : limits.UpstreamResponseSizeLimitBytes;

        var binary = ResponseClassification.IsBinaryResponse(operation, response.StatusCode, response.MediaType);

        if (binary && _files is not null)
        {
            // Bounded before the store sees it. The store enforces its own ceiling on what it
            // will keep, which is a different question from how much this response was allowed
            // to be, and only the outer one classifies as a response-size failure.
            await using var bounded = new BoundedStream(response.Body, limit);

            var reference = await _files.IssueAsync(
                bounded,
                FileNameFor(operation, response.MediaType),
                response.MediaType,
                request.Scope ?? request.Manifest.Server.Name,
                cancellationToken).ConfigureAwait(false);

            return partial with { ResponseFile = reference };
        }

        var body = await BoundedResponseReader
            .ReadAllWithLimitAsync(response.Body, limit, cancellationToken)
            .ConfigureAwait(false);

        return partial with { ResponseBody = body };
    }

    /// <summary>
    /// Maps a send failure onto the closed classification.
    /// </summary>
    /// <remarks>
    /// Every arm names an Engine type. The transport wraps whatever a framework raised, so the
    /// set is closed and the fallback is a floor rather than the usual answer — which is what
    /// makes it possible to assert that each classification is reachable from a producing site.
    /// </remarks>
    internal static ExecutionFailureKind Classify(Exception exception) => exception switch
    {
        CredentialUnavailableException => ExecutionFailureKind.Authentication,
        OriginPolicyViolationException => ExecutionFailureKind.OriginPolicy,
        AddressPolicyViolationException or HostResolutionException => ExecutionFailureKind.AddressPolicy,
        RedirectLimitException => ExecutionFailureKind.RedirectLimit,
        ResponseSizeLimitException => ExecutionFailureKind.ResponseSize,
        FileRuntimeException => ExecutionFailureKind.FileRuntime,

        // A redirect status with no destination is a malformed answer, not a refused one.
        // Reporting it as a policy failure would send an operator to inspect an allow-list that
        // was never consulted.
        MalformedRedirectException => ExecutionFailureKind.Transport,
        UpstreamTransportException => ExecutionFailureKind.Transport,
        _ => ExecutionFailureKind.Transport,
    };

    /// <summary>
    /// A filename for a stored response body.
    /// </summary>
    /// <remarks>
    /// Derived from the operation and the observed media type rather than from anything the
    /// upstream supplied. A name is a label for a human; taking it from a remote header would
    /// let an upstream choose what a downstream consumer saves the payload as.
    /// </remarks>
    private static string FileNameFor(ManifestOperation operation, string? mediaType)
    {
        var extension = ContentSignature.Essence(mediaType) switch
        {
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/gif" => "gif",
            "application/pdf" => "pdf",
            "application/zip" => "zip",
            "application/gzip" => "gz",
            "application/x-tar" => "tar",
            _ => "bin",
        };

        var stem = FileHandleStore.SanitizeFileName(operation.UpstreamId ?? operation.Key);

        return $"{stem}.{extension}";
    }

    private static bool TryResolveBaseUri(
        string? serverUrl,
        Uri policyBaseUrl,
        out Uri baseUri,
        out string? failure)
    {
        if (serverUrl is null)
        {
            baseUri = policyBaseUrl;
            failure = null;
            return true;
        }

        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out var parsed))
        {
            baseUri = policyBaseUrl;
            failure = $"The binding server URL '{serverUrl}' is not an absolute URI.";
            return false;
        }

        baseUri = parsed;
        failure = null;
        return true;
    }

    /// <summary>
    /// True when the exchange's own deadline fired rather than the caller abandoning the call.
    /// </summary>
    /// <remarks>
    /// Both surface as the same exception type. Without this distinction a caller cancelling a
    /// request would be told the upstream was slow, and a genuinely slow upstream would look
    /// like a caller changing its mind.
    /// </remarks>
    private static bool BudgetExpired(CancellationTokenSource exchange, CancellationToken caller)
        => exchange.IsCancellationRequested && !caller.IsCancellationRequested;

    private static EngineExecutionResult TimedOut(CompiledRequest compiled, TimeSpan budget)
        => new()
        {
            Request = compiled,
            Failure = ExecutionFailureKind.Timeout,
            FailureReason = TimeoutReason(budget),
        };

    private static string TimeoutReason(TimeSpan budget)
        => $"The exchange exceeded its total time budget of {budget}.";

    private static EngineExecutionResult Failed(ExecutionFailureKind kind, string reason)
        => new() { Failure = kind, FailureReason = reason };

    /// <summary>
    /// A read-only view over a stream that refuses to yield more than a stated number of bytes.
    /// </summary>
    /// <remarks>
    /// Exists so that a consumer which does its own reading — the file store — is still bounded
    /// by the response ceiling. Handing the raw stream over and trusting the consumer's own
    /// limit would make the response ceiling depend on which consumer happened to be
    /// configured.
    /// </remarks>
    private sealed class BoundedStream(Stream inner, long limit) : Stream
    {
        private long _read;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => _read;
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Count(read);
            return read;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = inner.Read(buffer, offset, count);
            Count(read);
            return read;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private void Count(int read)
        {
            _read += read;

            if (_read > limit)
            {
                throw new ResponseSizeLimitException(_read, limit);
            }
        }
    }
}
