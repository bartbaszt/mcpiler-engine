using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.Runtime;

namespace MCPiler.Engine.Host.Cli;

/// <summary>
/// Runs <c>auth authorize</c> as a relay against a serving Engine's operator channel.
/// </summary>
/// <remarks>
/// <para>
/// A serving process already holds the store-root lease, so this process cannot commit anything
/// itself: it opens an attempt on the serving process over the authenticated operator channel, binds
/// its own loopback listener to the callback it registered with the provider, and hands back only the
/// values the exchange needs. The verifier, the protocol state and the commit stay on the serving
/// process.
/// </para>
/// <para>
/// This process therefore holds no lease, opens no runtime-state store, and never writes a token: the
/// only durable effect of the whole operation is the commit the serving process performs. The raw
/// callback query is parsed and discarded here — it is never logged, stored or echoed, and neither
/// are the values taken from it.
/// </para>
/// <para>
/// The relay talks to whatever the operator names on <c>--oauth-operator-endpoint</c>. It is the
/// operator's own statement of which deployment this invocation drives; the credential it presents is
/// the same dedicated operator secret the serving process was configured with, read from the same
/// file.
/// </para>
/// </remarks>
internal static class OAuthOperatorRelayCommands
{
    /// <summary>How long the operator channel is given to answer, per request.</summary>
    private static readonly TimeSpan RequestDeadline = TimeSpan.FromSeconds(30);

    /// <summary>How long the operator channel is given to answer the exchange that reaches the provider.</summary>
    private static readonly TimeSpan ExchangeDeadline = TimeSpan.FromMinutes(2);

    /// <summary>Largest response body read from the operator channel, in characters.</summary>
    private const int MaximumResponseCharacters = 8192;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>Runs <c>auth authorize &lt;mount&gt; &lt;profile&gt; --oauth-operator-endpoint &lt;url&gt;</c>.</summary>
    internal static async Task<CommandOutcome> AuthorizeAsync(
        CommandLineResult parsed,
        string identity,
        TextWriter? progress,
        AuthorizationOutcomeLog outcomes,
        CancellationToken cancellationToken)
    {
        if (parsed.Targets.Count < 2)
        {
            return Refuse(identity, ExitCodes.Usage, "This command needs a mount prefix and a profile id.");
        }

        string mount = parsed.Targets[0];
        string profileId = parsed.Targets[1];

        if (parsed.OAuthRedirectUri is not { Length: > 0 } redirectText)
        {
            return Refuse(
                identity,
                ExitCodes.Configuration,
                "'auth authorize' needs '--oauth-redirect-uri <uri>' naming the exact loopback callback URI the provider has registered.");
        }

        if (!Uri.TryCreate(redirectText, UriKind.Absolute, out Uri? redirect))
        {
            return Refuse(
                identity,
                ExitCodes.Configuration,
                $"'--oauth-redirect-uri' was given '{redirectText}', which is not an absolute URI.");
        }

        if (!Uri.TryCreate(parsed.OAuthOperatorEndpoint, UriKind.Absolute, out Uri? endpoint)
            || endpoint.Scheme is not ("http" or "https")
            || endpoint.AbsolutePath is not ("" or "/")
            || endpoint.Query.Length != 0
            || endpoint.Fragment.Length != 0)
        {
            return Refuse(
                identity,
                ExitCodes.Configuration,
                $"'--oauth-operator-endpoint' was given '{parsed.OAuthOperatorEndpoint}', which is not the absolute base address of a serving Engine (scheme, host and optional port only).");
        }

        if (!OperatorChannel.IsEndpointTransportAcceptable(endpoint))
        {
            // Refused before the operator secret file is even read: the credential exists to
            // authenticate this client to the serving Engine, and it must not leave this machine in
            // cleartext for a remote endpoint the serving channel would refuse only after receiving it.
            return Refuse(
                identity,
                ExitCodes.Configuration,
                $"'--oauth-operator-endpoint' was given '{parsed.OAuthOperatorEndpoint}', which is not a loopback address. The operator credential must not travel in cleartext: use an https endpoint, or a loopback address that keeps it on this machine.");
        }

        string? secretFile = parsed.Settings
            .FirstOrDefault(setting => setting.Key == HostConfiguration.OAuthOperatorSecretFileKey)
            .Value;

        if (string.IsNullOrWhiteSpace(secretFile))
        {
            return Refuse(
                identity,
                ExitCodes.Configuration,
                $"'auth authorize' against a serving Engine needs '--{HostConfiguration.OAuthOperatorSecretFileKey} <file>' holding that deployment's authorization operator secret.");
        }

        if (!OAuthOperatorSecret.TryRead(secretFile, out string secret, out string? secretRefusal))
        {
            return Refuse(identity, ExitCodes.Configuration, secretRefusal!);
        }

        await using var listener = OAuthLoopbackCallbackListener.For(redirect);

        try
        {
            await listener.StartAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception bindFailure) when (bindFailure is IOException or InvalidOperationException)
        {
            return Refuse(
                identity,
                ExitCodes.Configuration,
                $"The loopback callback listener could not bind {redirect.GetLeftPart(UriPartial.Authority)}. Another process may hold the port; choose a free loopback URI and register it with the provider. ({bindFailure.Message})");
        }

        using HttpClient client = Client(secret);

        Uri authorizeUri = new(endpoint, OAuthOperatorEndpoints.AuthorizePath);
        (int Status, RelayStart? Value) opened;

        try
        {
            opened = await PostAsync<RelayStart>(
                    client,
                    authorizeUri,
                    JsonSerializer.Serialize(new { mount, profile = profileId, redirectUri = redirect.AbsoluteUri }, Json),
                    RequestDeadline,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception transportFailure) when (transportFailure is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            return Refuse(
                identity,
                ExitCodes.Failure,
                $"The authorization operator channel at {endpoint.GetLeftPart(UriPartial.Authority)} could not be reached. ({transportFailure.Message})");
        }

        if (opened.Value is not { Relay: { Length: > 0 } handle, AuthorizationUrl: { Length: > 0 } authorizationUrl })
        {
            return Refuse(identity, OpenExitCode(opened.Status), Describe(opened.Value, mount, profileId));
        }

        if (progress is not null)
        {
            progress.WriteLine("Open this URL in a browser to authorize:");
            progress.WriteLine(authorizationUrl);
            progress.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"Waiting for the provider to redirect to {redirect.AbsoluteUri} ..."));
            progress.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"If the callback is not reachable from the browser, forward the callback port to this machine, for example: ssh -L {redirect.Port.ToString(CultureInfo.InvariantCulture)}:127.0.0.1:{redirect.Port.ToString(CultureInfo.InvariantCulture)} <host>"));
            progress.Flush();
        }

        string? callbackQuery;

        try
        {
            callbackQuery = await listener
                .WaitAsync(opened.Value.ExpiresAtUtc, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await AbandonAsync(client, endpoint, handle, CancellationToken.None).ConfigureAwait(false);

            return Record(
                outcomes,
                identity,
                mount,
                profileId,
                "oauth/attempt-cancelled",
                "The authorization attempt was cancelled before a callback arrived, so the profile is not authorized.");
        }

        if (callbackQuery is null)
        {
            await AbandonAsync(client, endpoint, handle, CancellationToken.None).ConfigureAwait(false);

            return Record(
                outcomes,
                identity,
                mount,
                profileId,
                "oauth/attempt-expired",
                "No callback arrived before the attempt expired, so the profile is not authorized.");
        }

        if (!StandaloneAuthorizationCallback.TryRead(callbackQuery, out string? state, out string? code, out string? error))
        {
            // The query is malformed or repeats a name, so nothing from it is forwarded: a repeated
            // parameter means two readers could disagree about which value they saw.
            await AbandonAsync(client, endpoint, handle, CancellationToken.None).ConfigureAwait(false);

            return Record(
                outcomes,
                identity,
                mount,
                profileId,
                "oauth/malformed-callback",
                "The authorization callback was malformed or repeated a parameter, so nothing was exchanged.");
        }

        RelayOutcome? outcome;

        try
        {
            (_, outcome) = await PostAsync<RelayOutcome>(
                    client,
                    new Uri(endpoint, OAuthOperatorEndpoints.AuthorizeCompletePath),
                    JsonSerializer.Serialize(new { relay = handle, state, code, error }, Json),
                    ExchangeDeadline,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception transportFailure) when (transportFailure is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            return Record(
                outcomes,
                identity,
                mount,
                profileId,
                "oauth/relay-unreachable",
                "The authorization operator channel did not answer the completion, so the local listener stopped waiting and nothing was reported as authorized.");
        }

        if (outcome?.Authorized is not true)
        {
            string refusalCode = outcome?.Code ?? "oauth/relay-failed";
            string refusalMessage = outcome?.Message
                ?? "The serving Engine refused the completion, so nothing was reported as authorized.";

            return Record(outcomes, identity, mount, profileId, refusalCode, refusalMessage);
        }

        StringBuilder text = new(identity);
        text.AppendLine();
        text.AppendLine(string.Create(
            CultureInfo.InvariantCulture,
            $"authorized {mount} {profileId} {outcome.Code}"));
        text.AppendLine(outcome.Message ?? string.Empty);
        text.AppendLine(string.Create(
            CultureInfo.InvariantCulture,
            $"authority epoch {outcome.AuthorityEpoch.ToString(CultureInfo.InvariantCulture)}, revision {outcome.RuntimeRevision.ToString(CultureInfo.InvariantCulture)}. The serving Engine already holds this credential; its next call uses it."));

        outcomes.Record(new AuthorizationOutcome(
            TimeProvider.System.GetUtcNow(),
            "authorize",
            mount,
            profileId,
            "local",
            outcome.Code ?? "oauth/authorized",
            outcome.Message ?? string.Empty));

        return new CommandOutcome(ExitCodes.Success, text.ToString());
    }

    private static HttpClient Client(string secret)
    {
        var client = new HttpClient(new HttpClientHandler
        {
            // The credential is bound to the endpoint the operator named. A redirect would move the
            // destination after the operator chose it, so it is answered as a refusal instead of
            // followed; the request either goes to the configured endpoint or nowhere.
            AllowAutoRedirect = false,
        })
        {
            // Every request carries its own deadline, so a shared default would only ever fire first.
            Timeout = Timeout.InfiniteTimeSpan,
        };

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            OperatorChannelCredential.Scheme, secret);
        client.DefaultRequestHeaders.Add(
            CompatibilitySchema.ContractGenerationHeader,
            CompatibilitySchema.OAuthOperatorGeneration);

        return client;
    }

    /// <summary>
    /// Posts one JSON body and reads a bounded JSON answer.
    /// </summary>
    /// <remarks>
    /// A refusal is answered as a body rather than as an exception, because the code and the message
    /// in it are what an operator acts on. Only a transport failure, an unreadable answer or an
    /// answer with no usable body is raised.
    /// </remarks>
    /// <returns>The status the channel answered with and the value it carried, when it carried one.</returns>
    private static async Task<(int Status, T? Value)> PostAsync<T>(
        HttpClient client,
        Uri uri,
        string body,
        TimeSpan deadline,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(deadline);

        using HttpResponseMessage response = await client
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, budget.Token)
            .ConfigureAwait(false);

        int status = (int)response.StatusCode;
        string payload = await ReadBoundedAsync(response, budget.Token).ConfigureAwait(false);

        if (payload.Length == 0)
        {
            if (response.IsSuccessStatusCode)
            {
                return (status, default);
            }

            throw new HttpRequestException($"The operator channel answered {status} with no description.");
        }

        try
        {
            return (status, JsonSerializer.Deserialize<T>(payload, Json));
        }
        catch (JsonException)
        {
            throw new HttpRequestException($"The operator channel answered {status} with a body this command could not read.");
        }
    }

    private static async Task<string> ReadBoundedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

        byte[] buffer = new byte[MaximumResponseCharacters];
        int read = 0;

        while (read < buffer.Length)
        {
            int chunk = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken).ConfigureAwait(false);

            if (chunk == 0)
            {
                break;
            }

            read += chunk;
        }

        return read == 0 ? string.Empty : Encoding.UTF8.GetString(buffer, 0, read);
    }

    private static async Task AbandonAsync(HttpClient client, Uri endpoint, string handle, CancellationToken cancellationToken)
    {
        try
        {
            await PostAsync<RelayAbandoned>(
                    client,
                    new Uri(endpoint, OAuthOperatorEndpoints.AuthorizeAbortPath),
                    JsonSerializer.Serialize(new { relay = handle }, Json),
                    RequestDeadline,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception abandonmentFailure) when (abandonmentFailure is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            // Abandoning is best effort: the serving process drops the session when its bounded
            // lifetime elapses, so a failure here changes nothing about the outcome being reported.
        }
    }

    /// <summary>The exit an operator gets for a refusal to open an attempt.</summary>
    private static int OpenExitCode(int status) => status switch
    {
        503 => ExitCodes.Failure,
        500 => ExitCodes.Failure,
        _ => ExitCodes.Configuration,
    };

    private static string Describe(RelayStart? refused, string mount, string profileId)
    {
        if (refused?.Refusals is { Count: > 0 } refusals)
        {
            StringBuilder text = new();

            foreach (RelayRefusal refusal in refusals)
            {
                text.AppendLine($"{refusal.Mount ?? mount} {refusal.Code ?? "standalone/refused"} {refusal.Message}");
            }

            return text.ToString();
        }

        return refused?.Error
            ?? $"The serving Engine did not open an authorization attempt for {mount} {profileId}.";
    }

    private static CommandOutcome Record(
        AuthorizationOutcomeLog outcomes,
        string identity,
        string mount,
        string profileId,
        string code,
        string message)
    {
        outcomes.Record(new AuthorizationOutcome(
            TimeProvider.System.GetUtcNow(), "authorize", mount, profileId, "local", code, message));

        StringBuilder text = new(identity);
        text.AppendLine();
        text.AppendLine(string.Create(CultureInfo.InvariantCulture, $"refused {mount} {profileId} {code}"));
        text.AppendLine(message);
        text.AppendLine("Nothing was changed. Fix the cause and run 'auth authorize' again.");

        return new CommandOutcome(ExitCodes.Failure, text.ToString());
    }

    private static CommandOutcome Refuse(string identity, int exitCode, string message)
        => new(exitCode, identity + Environment.NewLine + message + Environment.NewLine);

    private sealed record RelayRefusal(string? Mount, string? Code, string? Message);

    private sealed record RelayStart(
        string? Relay,
        string? AuthorizationUrl,
        DateTimeOffset ExpiresAtUtc,
        string? Error,
        IReadOnlyList<RelayRefusal>? Refusals);

    private sealed record RelayOutcome(
        bool Authorized,
        string? Code,
        string? Message,
        string? MountPrefix,
        string? ProfileId,
        long AuthorityEpoch,
        long RuntimeRevision);

    private sealed record RelayAbandoned(bool Abandoned);
}
