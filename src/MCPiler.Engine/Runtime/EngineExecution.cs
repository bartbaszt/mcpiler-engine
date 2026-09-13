using System.Text.Json.Nodes;

using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Files;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Files;
using MCPiler.Engine.Mcp;

namespace MCPiler.Engine.Runtime;

/// <summary>
/// The process-wide machinery a mounted Manifest is invoked through.
/// </summary>
/// <remarks>
/// <para>
/// The second half of the seam. <see cref="EngineRuntime"/> answers what a process serves;
/// this answers what happens when a client calls one of it. A deployable holds both and names
/// nothing else, which is why an outbound client, a credential resolver and a handle store are
/// assembled here rather than wired up by whatever is hosting.
/// </para>
/// <para>
/// The caller owns the lifetime, deliberately. An outbound client pool is the one thing in the
/// process whose disposal has to happen at a point somebody chose: a pool disposed by a
/// container's teardown ordering would close connections at a moment no drain accounted for.
/// </para>
/// <para>
/// Created from a started runtime, so the store this executes against is the store startup
/// proved usable, and the credential rules are the ones loading was told about. Passing those
/// separately would let a process resolve secrets under a switch the Manifests were not read
/// under.
/// </para>
/// </remarks>
public sealed class EngineExecution : IDisposable
{
    private readonly UpstreamClientFactory _clients;
    private readonly ExecutionService _executions;
    private readonly FileHandleStore _files;
    private readonly Action<RuntimeDiagnostic>? _diagnostics;

    private EngineExecution(
        UpstreamClientFactory clients,
        ExecutionService executions,
        FileHandleStore files,
        Action<RuntimeDiagnostic>? diagnostics)
    {
        _clients = clients;
        _executions = executions;
        _files = files;
        _diagnostics = diagnostics;
    }

    /// <summary>Assembles the execution machinery for a started runtime.</summary>
    /// <param name="started">A runtime whose every mount is ready.</param>
    /// <param name="diagnostics">
    /// Receives operational diagnostics the engine emits instead of failing a call, such as a
    /// structured-content payload that did not conform to its advertised schema. A sink must
    /// not throw; a sink that throws is ignored after the outcome was already decided. Sinks
    /// may be called concurrently and must be thread-safe.
    /// </param>
    public static EngineExecution Create(
        RuntimeStartResult started,
        Action<RuntimeDiagnostic>? diagnostics = null)
        => Create(started, new OutboundConnectionPolicy(), diagnostics);

    /// <summary>
    /// Assembles the execution machinery over a stated outbound connection policy.
    /// </summary>
    /// <remarks>
    /// The policy is a parameter for the same reason it is a seam one layer down: the shipped
    /// one refuses loopback, and every in-process server a test can reach lives there. A test
    /// supplies a permissive judgement instead of the real policy being weakened to
    /// accommodate it.
    /// </remarks>
    /// <param name="started">A runtime whose every mount is ready.</param>
    /// <param name="connections">Which addresses a connection may be opened to.</param>
    /// <param name="diagnostics">
    /// Receives operational diagnostics the engine emits instead of failing a call. A sink
    /// must not throw; a sink that throws is ignored after the outcome was already decided.
    /// Sinks may be called concurrently and must be thread-safe.
    /// </param>
    public static EngineExecution Create(
        RuntimeStartResult started,
        OutboundConnectionPolicy connections,
        Action<RuntimeDiagnostic>? diagnostics = null)
    {
        ArgumentNullException.ThrowIfNull(started);
        ArgumentNullException.ThrowIfNull(connections);

        if (!started.Started || started.Files is null)
        {
            throw new InvalidOperationException(
                "A refused runtime executes nothing. Nothing partially mounts, so a caller that "
                + "reached here has already ignored a refusal.");
        }

        UpstreamClientFactory clients = new(connections);

        return new EngineExecution(
            clients,
            new ExecutionService(
                new UpstreamSender(clients),
                new ManifestSecretResolver(new SecretResolutionOptions(started.AllowInlineSecrets)),
                started.Files),
            started.Files,
            diagnostics);
    }

    /// <summary>
    /// Streams one HTTP-transfer payload into the runtime's file store and issues its opaque
    /// process-local capability in the exact protected-resource scope supplied by the host.
    /// </summary>
    public async Task<RuntimeFileUploadResult> UploadFileAsync(
        Stream content,
        string? fileName,
        string? mediaType,
        string resourceIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentException.ThrowIfNullOrEmpty(resourceIdentity);

        try
        {
            FileHandleReference reference = await _files
                .IssueAsync(content, fileName, mediaType, resourceIdentity, cancellationToken)
                .ConfigureAwait(false);

            string capability = _files.WireFormFor(reference.Id);

            if (capability.Length == 0)
            {
                return RuntimeFileUploadResult.Refused(
                    "The file was stored but no transfer capability could be issued.");
            }

            return RuntimeFileUploadResult.Issued(
                capability,
                reference.FileName,
                reference.MediaType,
                reference.Length);
        }
        catch (FileRuntimeException refusal)
        {
            return RuntimeFileUploadResult.Refused(refusal.Message);
        }
    }

    /// <summary>
    /// Authorizes and opens one wire capability for a transfer download. Unknown and
    /// cross-resource values share one result; expiry remains distinct for the owning resource.
    /// </summary>
    public async Task<RuntimeFileDownload> OpenFileAsync(
        string capability,
        string resourceIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentException.ThrowIfNullOrEmpty(resourceIdentity);

        FileRedemption redemption = await RedemptionAuthorization
            .RedeemAsync(_files, capability, resourceIdentity, cancellationToken)
            .ConfigureAwait(false);

        if (!redemption.Succeeded || redemption.Reference is not { } reference)
        {
            return redemption.Refusal == FileRedemptionRefusalKind.Expired
                ? RuntimeFileDownload.Expired()
                : RuntimeFileDownload.Unknown();
        }

        if (redemption.File is { } descriptor)
        {
            await descriptor.Content.DisposeAsync().ConfigureAwait(false);
        }

        FileHandleLookup opened = await _files
            .OpenAsync(reference.Id, cancellationToken)
            .ConfigureAwait(false);

        if (opened.Status == FileHandleStatus.Expired)
        {
            return RuntimeFileDownload.Expired();
        }

        if (opened.Status != FileHandleStatus.Available || opened.Content is not { } content)
        {
            return RuntimeFileDownload.Unknown();
        }

        return RuntimeFileDownload.Available(
            reference.FileName,
            reference.MediaType,
            reference.Length,
            content);
    }

    /// <summary>Runs one tool call against one surface of one mount.</summary>
    /// <remarks>
    /// The mount and the surface are passed as the values a caller already resolved by
    /// routing, rather than as names to be resolved again. A second resolution would be a
    /// second answer to which Manifest a request addressed, and the one that disagreed would
    /// be the one that accepted an address the first had already rejected.
    /// </remarks>
    /// <param name="mount">The Manifest the request addressed.</param>
    /// <param name="surface">The surface the request addressed.</param>
    /// <param name="tool">The tool name the caller sent, exactly as sent.</param>
    /// <param name="arguments">The arguments the caller sent.</param>
    /// <param name="cancellationToken">The caller's deadline.</param>
    public async Task<ToolOutcome> InvokeAsync(
        MountedManifest mount,
        MountedSurface surface,
        string invocationScope,
        string tool,
        JsonObject arguments,
        string? negotiatedProtocolRevision,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mount);
        ArgumentNullException.ThrowIfNull(surface);
        ArgumentException.ThrowIfNullOrEmpty(invocationScope);
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(arguments);

        ToolOutcome outcome = await ToolInvocation
            .InvokeAsync(
                _executions,
                mount,
                surface,
                invocationScope,
                tool,
                arguments,
                negotiatedProtocolRevision,
                cancellationToken)
            .ConfigureAwait(false);

        if (outcome.Diagnostic is { } diagnostic)
        {
            // The tool outcome is already decided; a sink that throws must not convert
            // a finished call into an unexplained failure. Sinks are non-throwing by
            // contract and may be called concurrently, so they must be thread-safe.
            try
            {
                _diagnostics?.Invoke(diagnostic);
            }
            catch
            {
            }
        }

        return outcome;
    }

    /// <inheritdoc />
    public void Dispose() => _clients.Dispose();
}
