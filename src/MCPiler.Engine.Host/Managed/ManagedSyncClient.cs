using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using MCPiler.Engine.Runtime;
using MCPiler.Engine.Runtime.Managed;

namespace MCPiler.Engine.Host.Managed;

/// <summary>What one poll produced.</summary>
/// <remarks>
/// Three outcomes rather than two, because "the Platform had nothing new" and "the Platform
/// could not be reached" call for different worker behaviour: the first resets backoff and
/// continues, the second advances it.
/// </remarks>
internal enum ManagedPollOutcome
{
    /// <summary>The Platform answered that the active generation is still desired.</summary>
    Unchanged,

    /// <summary>The Platform delivered a generation this process does not have active.</summary>
    Delivered,

    /// <summary>The Platform answered, but the candidate it delivered could not be loaded.</summary>
    CandidateRefused,

    /// <summary>The Platform could not be reached, or answered with a retryable failure.</summary>
    Unreachable,
}

/// <summary>The result of one poll: what happened, and the generation when one arrived.</summary>
/// <param name="Outcome">Which of the three cases the Platform's answer fell into.</param>
/// <param name="Delivery">The delivered generation, when one arrived.</param>
/// <param name="Diagnostics">Sanitized diagnostics the Platform reported, if any.</param>
/// <param name="SessionEpoch">Platform-issued fencing epoch returned by an accepted poll.</param>
internal sealed record ManagedPollResult(
    ManagedPollOutcome Outcome,
    ManagedGenerationDelivery? Delivery,
    IReadOnlyList<ManagedDiagnosticMessage> Diagnostics,
    long? SessionEpoch)
{
    /// <summary>A result that carried no generation and no diagnostics.</summary>
    public static ManagedPollResult Unchanged(long sessionEpoch)
        => new(ManagedPollOutcome.Unchanged, null, [], sessionEpoch);

    /// <summary>A result for an exchange that could not complete.</summary>
    public static ManagedPollResult Unreachable { get; } = new(ManagedPollOutcome.Unreachable, null, [], null);
}

/// <summary>
/// Speaks the managed synchronization protocol to one Platform deployment.
/// </summary>
/// <remarks>
/// <para>
/// The client owns exactly the transport concerns: authenticating with the deployment secret,
/// bounding the request and the response, and translating the Platform's answer into the three
/// cases the worker acts on. It never decides what a generation means; that is the loader's job
/// on the library side of the seam.
/// </para>
/// <para>
/// The secret is re-read from its file on every poll. A deployment that rotates the secret can
/// then take effect without restarting the Engine, and a file that has been removed fails the
/// poll rather than continuing to present a secret the operator believes is gone.
/// </para>
/// </remarks>
internal sealed class ManagedSyncClient : IDisposable
{
    private readonly HttpClient _client;
    private readonly ManagedSyncOptions _options;
    private readonly string _pollPath;
    private bool _disposed;

    private static readonly JsonSerializerOptions ProtocolJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
    };

    /// <summary>Creates a client for one deployment.</summary>
    public ManagedSyncClient(ManagedSyncOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _pollPath = $"/internal/engine/v1/deployments/{Uri.EscapeDataString(options.DeploymentId)}/poll";

        SocketsHttpHandler handler = new()
        {
            ConnectTimeout = options.ConnectBound,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };

        _client = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = new Uri(options.Endpoint, "/"),
            Timeout = Timeout.InfiniteTimeSpan,
        };

        _client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    /// <summary>The endpoint this client polls, rendered without query or user information.</summary>
    public string DescribeEndpoint() => _options.Describe();

    /// <summary>
    /// Runs one long poll and reports what came back.
    /// </summary>
    /// <param name="request">What this Engine currently serves, so the Platform can decide.</param>
    /// <param name="sessionEpoch">The Platform-issued epoch from the preceding accepted poll, when assigned.</param>
    /// <param name="cancellationToken">Cancels the poll, including the Platform's bounded wait.</param>
    public async Task<ManagedPollResult> PollAsync(
        ManagedPollRequestMessage request,
        long? sessionEpoch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);

        string secret;

        try
        {
            secret = await ReadSecretAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A secret that cannot be read is an authentication fault, not a network one. The
            // worker should back off and retry after the operator restores the file.
            return ManagedPollResult.Unreachable;
        }

        byte[] body;

        try
        {
            body = JsonSerializer.SerializeToUtf8Bytes(request, ProtocolJson);
        }
        catch (JsonException)
        {
            return ManagedPollResult.Unreachable;
        }

        if (body.LongLength > _options.MaximumRequestBytes)
        {
            return ManagedPollResult.Unreachable;
        }

        using HttpRequestMessage message = new(HttpMethod.Post, _pollPath)
        {
            Content = new ByteArrayContent(body),
        };

        message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
        {
            CharSet = "utf-8",
        };

        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        if (sessionEpoch is { } epoch)
        {
            message.Headers.TryAddWithoutValidation(
                ManagedProtocol.SessionEpochHeader,
                epoch.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        using HttpResponseMessage response = await SendAsync(message, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NoContent)
        {
            return TryReadSessionEpoch(response, out var acceptedEpoch)
                ? ManagedPollResult.Unchanged(acceptedEpoch)
                : ManagedPollResult.Unreachable;
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            // Distinguished from an unreachable Platform so the operator sees it as the credential
            // fault it is, but still retried: a rotated secret takes effect without a restart.
            return ManagedPollResult.Unreachable;
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests
            || (int)response.StatusCode >= 500)
        {
            return ManagedPollResult.Unreachable;
        }

        if (!response.IsSuccessStatusCode)
        {
            return ManagedPollResult.Unreachable;
        }

        if (!TryReadSessionEpoch(response, out var responseEpoch))
        {
            return ManagedPollResult.Unreachable;
        }

        var result = await ReadDeliveryAsync(response, cancellationToken).ConfigureAwait(false);
        return result with { SessionEpoch = responseEpoch };
    }

    private static bool TryReadSessionEpoch(HttpResponseMessage response, out long sessionEpoch)
    {
        sessionEpoch = 0;
        if (!response.Headers.TryGetValues(ManagedProtocol.SessionEpochHeader, out var values))
        {
            return false;
        }

        var raw = values.SingleOrDefault();
        return raw is not null
            && long.TryParse(
                raw,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out sessionEpoch)
            && sessionEpoch > 0;
    }

    /// <summary>
    /// Sends one conditional rotation report and reports what the Platform did with it.
    /// </summary>
    /// <remarks>
    /// The report names a committed revision and the value behind it. A refused report is not an
    /// error to retry: it means the Platform holds a different operator decision, so the worker
    /// drops it. An undeliverable report stays queued and is regenerated from the local record on
    /// the next attempt, so an outage never loses the fact that the credential rotated.
    /// </remarks>
    /// <param name="report">The committed rotation, already read back from the local store.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<ReconciliationOutcome> ReconcileAsync(
        RuntimeSecretReconciliationMessage report,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        ObjectDisposedException.ThrowIf(_disposed, this);

        string secret;

        try
        {
            secret = await ReadSecretAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return ReconciliationOutcome.Unreachable;
        }

        byte[] body;

        try
        {
            body = JsonSerializer.SerializeToUtf8Bytes(report, ProtocolJson);
        }
        catch (JsonException)
        {
            return ReconciliationOutcome.Unreachable;
        }

        if (body.LongLength > _options.MaximumRequestBytes)
        {
            return ReconciliationOutcome.Unreachable;
        }

        var path = $"/internal/engine/v1/deployments/{Uri.EscapeDataString(_options.DeploymentId)}"
            + "/runtime-secrets/reconcile";

        using HttpRequestMessage message = new(HttpMethod.Post, path)
        {
            Content = new ByteArrayContent(body),
        };

        message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
        {
            CharSet = "utf-8",
        };

        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

        using HttpResponseMessage response = await SendAsync(message, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            return ReconciliationOutcome.Unreachable;
        }

        try
        {
            var payload = await ReadBoundedAsync(response, _options.MaximumRequestBytes, cancellationToken)
                .ConfigureAwait(false);
            using var document = JsonDocument.Parse(payload);

            var outcome = document.RootElement.TryGetProperty("outcome", out var value)
                ? value.GetString()
                : null;

            // 'recorded' is the only outcome that means the Platform now holds the replacement.
            // Every other spelling describes a Platform state the report no longer matches, which
            // retrying cannot fix.
            return string.Equals(outcome, "recorded", StringComparison.Ordinal)
                ? ReconciliationOutcome.Recorded
                : ReconciliationOutcome.Refused;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            return ReconciliationOutcome.Unreachable;
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage message,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _client
                .SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException)
        {
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new HttpResponseMessage(HttpStatusCode.GatewayTimeout);
        }
    }

    private async Task<ManagedPollResult> ReadDeliveryAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is { } declared
            && declared > _options.MaximumResponseBytes)
        {
            return ManagedPollResult.Unreachable;
        }

        byte[] payload;

        try
        {
            payload = await ReadBoundedAsync(response, _options.MaximumResponseBytes, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            return ManagedPollResult.Unreachable;
        }

        ManagedGenerationMessage? parsed;

        try
        {
            parsed = JsonSerializer.Deserialize<ManagedGenerationMessage>(payload, ProtocolJson);
        }
        catch (JsonException)
        {
            return Refused(
                "managed/response-json-invalid",
                "The Platform returned malformed managed JSON.");
        }

        if (parsed is null)
        {
            return Refused(
                "managed/response-shape-invalid",
                "The Platform returned an empty managed response.");
        }

        if (parsed.ProtocolVersion != ManagedProtocol.Version)
        {
            return Refused(
                "managed/protocol-version-unsupported",
                $"The Platform answered managed protocol {parsed.ProtocolVersion}; this Engine speaks {ManagedProtocol.Version}.");
        }

        if (!HasValidShape(parsed))
        {
            return Refused(
                "managed/response-shape-invalid",
                "The Platform returned a managed response with an invalid shape.");
        }

        if (string.Equals(parsed.Kind, "refusal", StringComparison.Ordinal))
        {
            ManagedDiagnosticMessage diagnostic = parsed.Diagnostics.Count > 0
                ? parsed.Diagnostics[0]
                : new ManagedDiagnosticMessage
                {
                    Code = parsed.Compatibility?.ReasonCode ?? "managed/refused",
                    Message = parsed.Compatibility?.Message ?? "The Platform refused the generation.",
                };
            return Refused(diagnostic.Code, diagnostic.Message);
        }

        if (!string.Equals(parsed.Kind, "generation", StringComparison.Ordinal))
        {
            return Refused("managed/response-kind-invalid", "The Platform returned an unknown managed response kind.");
        }

        if (parsed.Compatibility is null
            || !string.Equals(parsed.Compatibility.Status, "compatible", StringComparison.Ordinal)
            || parsed.Compatibility.DescriptorSchemaVersion != CompatibilitySchema.Version)
        {
            return Refused(
                parsed.Compatibility?.ReasonCode ?? "managed/compatibility-invalid",
                parsed.Compatibility?.Message ?? "The Platform did not provide a compatible contract result.");
        }

        if (string.IsNullOrWhiteSpace(parsed.GenerationId) || parsed.Mounts.Count == 0)
        {
            return ManagedPollResult.Unreachable;
        }

        List<ManagedMountDelivery> mounts = new(parsed.Mounts.Count);

        foreach (ManagedMountMessage mount in parsed.Mounts)
        {
            if (string.IsNullOrWhiteSpace(mount.Prefix)
                || string.IsNullOrEmpty(mount.Bundle)
                || mount.ExternalResources is null)
            {
                return ManagedPollResult.Unreachable;
            }

            byte[] bundle;

            try
            {
                bundle = Convert.FromBase64String(mount.Bundle);
            }
            catch (FormatException)
            {
                return ManagedPollResult.Unreachable;
            }

            mounts.Add(new ManagedMountDelivery(
                mount.Prefix,
                bundle,
                new SortedDictionary<string, string>(mount.ExternalResources, StringComparer.Ordinal)));
        }

        return new ManagedPollResult(
            ManagedPollOutcome.Delivered,
            new ManagedGenerationDelivery(
                parsed.GenerationId,
                parsed.Metadata.EngineVersion,
                mounts,
                parsed.Secrets),
            [],
            null);
    }

    private static bool HasValidShape(ManagedGenerationMessage message)
    {
        if (message.Mounts is null
            || message.Secrets is null
            || message.Metadata is null
            || message.Diagnostics is null
            || message.Kind is not ("generation" or "refusal"))
        {
            return false;
        }

        if (message.Compatibility is { } compatibility
            && (string.IsNullOrWhiteSpace(compatibility.Status)
                || compatibility.Status.Length > 32
                || string.IsNullOrWhiteSpace(compatibility.ReasonCode)
                || compatibility.ReasonCode.Length > 200
                || string.IsNullOrWhiteSpace(compatibility.Dimension)
                || compatibility.Dimension.Length > 200
                || string.IsNullOrWhiteSpace(compatibility.Message)
                || compatibility.Message.Length > 500
                || compatibility.DescriptorSchemaVersion != CompatibilitySchema.Version))
        {
            return false;
        }

        foreach (ManagedDiagnosticMessage diagnostic in message.Diagnostics)
        {
            if (diagnostic is null
                || string.IsNullOrWhiteSpace(diagnostic.Code)
                || diagnostic.Code.Length > 200
                || string.IsNullOrWhiteSpace(diagnostic.Message)
                || diagnostic.Message.Length > 500)
            {
                return false;
            }
        }

        foreach (ManagedMountMessage mount in message.Mounts)
        {
            if (mount is null
                || string.IsNullOrWhiteSpace(mount.Prefix)
                || mount.Prefix.Length > 256
                || string.IsNullOrEmpty(mount.Bundle)
                || mount.ExternalResources is null
                || mount.ExternalResources.Any(pair =>
                    string.IsNullOrWhiteSpace(pair.Key)
                    || pair.Key.Length > 256
                    || pair.Value is null
                    || pair.Value.Length > 2048))
            {
                return false;
            }
        }

        return message.Secrets.All(pair => pair.Key is not null && pair.Value is not null);
    }

    private static ManagedPollResult Refused(string code, string message)
        => new(
            ManagedPollOutcome.CandidateRefused,
            null,
            [new ManagedDiagnosticMessage { Code = code, Message = message }],
            null);


    private static async Task<byte[]> ReadBoundedAsync(
        HttpResponseMessage response,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

        using MemoryStream buffer = new();
        byte[] chunk = new byte[8192];

        while (true)
        {
            int read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                return buffer.ToArray();
            }

            if (buffer.Length + read > maximumBytes)
            {
                throw new InvalidOperationException("The response exceeded the accepted bound.");
            }

            buffer.Write(chunk, 0, read);
        }
    }

    private async Task<string> ReadSecretAsync(CancellationToken cancellationToken)
    {
        string text = await File.ReadAllTextAsync(_options.SecretFile, Encoding.UTF8, cancellationToken)
            .ConfigureAwait(false);

        // A secret file written by an editor or a secret manager commonly ends in one newline.
        // Trailing whitespace is not part of the secret and would otherwise authenticate as a
        // different value than the operator believes they deployed.
        return text.TrimEnd('\r', '\n');
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _client.Dispose();
    }
}
