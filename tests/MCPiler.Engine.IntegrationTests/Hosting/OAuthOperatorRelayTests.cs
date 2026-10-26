using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Host.Cli;
using MCPiler.Engine.Host.Configuration;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.IntegrationTests.Authorization;
using MCPiler.Engine.IntegrationTests.Cli;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Hosting;

/// <summary>
/// The host-owned authorization relay: an operator authorizes a profile against a serving Engine
/// without stopping it.
/// </summary>
/// <remarks>
/// <para>
/// The serving process owns the attempt, the PKCE verifier, the protocol state and the commit; the
/// operator's own listener owns the callback. These tests drive both sides over real HTTP: a real
/// <see cref="ServedEngine"/>, a real loopback provider and the real operator channel, so the route
/// mapping, the credential guard, the single-use handle and the compare-and-commit are the ones a
/// deployment runs.
/// </para>
/// <para>
/// Sessions are process-local and hold a live verifier, so the bounds and the credential binding are
/// asserted against the set itself, where a second credential and an elapsed clock can be staged at
/// all: no portable test can change the serving process's configured secret mid-flight.
/// </para>
/// </remarks>
public sealed class OAuthOperatorRelayTests : IDisposable
{
    private const string OperatorSecret = "oauth-operator-secret-for-tests";
    private const string ProfileId = "oauth";
    private const string MountPrefix = "/api";
    private const string Tool = "list-things";

    private const string UnusedTokenAuthority = "https://auth.example.test:443";
    private const string UnusedDestinationAuthority = "https://api.example.test:443";

    private const string ManifestScopeFingerprint =
        "0000000000000000000000000000000000000000000000000000000000000007";

    private static readonly string[] RelayCapabilities = ["authorize", "complete", "abort"];

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "mcpiler-oauth-relay-" + Guid.NewGuid().ToString("N"));

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public OAuthOperatorRelayTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public async Task A_relayed_authorization_commits_and_the_served_call_uses_the_committed_authority()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        using HttpClient client = Authorized(OperatorSecret);
        RelayOpened opened = await OpenAsync(client, fixture.Engine.Address, fixture.Redirect, MountPrefix, ProfileId);
        Assert.Equal((int)HttpStatusCode.OK, opened.StatusCode);

        // The serving process must never expose the verifier or the state it keeps: the URL carries the
        // attempt's own state, and the challenge is derived from a verifier this process never sees.
        Assert.Contains("code_challenge_method=S256", opened.AuthorizationUrl, StringComparison.Ordinal);
        Assert.DoesNotContain("code_verifier", opened.AuthorizationUrl, StringComparison.Ordinal);

        Callback callback = await fixture.DriveProviderAsync(opened.AuthorizationUrl);
        Assert.Equal(
            fixture.Redirect.GetLeftPart(UriPartial.Path),
            callback.Redirect.GetLeftPart(UriPartial.Path));
        Assert.Equal(1, fixture.Provider.AuthorizationRequests);

        RelayCompleted completed = await CompleteAsync(client, fixture.Engine.Address, opened.Relay, callback);
        Assert.Equal((int)HttpStatusCode.OK, completed.StatusCode);
        Assert.True(completed.Authorized, completed.Message);
        Assert.Equal(2, completed.AuthorityEpoch);
        Assert.Equal(0, completed.RuntimeRevision);

        // The commit is durable and holds the provider's own credential.
        MutableSlotDecision? decision = await fixture.ReadDecisionAsync();
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Authorized, decision!.Kind);
        Assert.Equal(2, decision.AuthorityEpoch);
        Assert.Equal(fixture.Provider.RefreshToken, decision.RefreshToken);

        // The next ordinary call uses the authority the relay just committed, and the access token the
        // attempt already obtained is reused rather than asked for a second time.
        ToolOutcome served = await InvokeAsync(fixture.Engine);
        Assert.False(served.IsError, served.Text);
        Assert.Equal(0, fixture.Provider.RefreshRequests);

        // Nothing in the answers an operator reads carries the credential.
        Assert.DoesNotContain(fixture.Provider.RefreshToken, completed.Body, StringComparison.Ordinal);
        Assert.DoesNotContain(fixture.Provider.AccessToken, completed.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_replayed_completion_handle_is_refused_without_a_second_exchange()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        using HttpClient client = Authorized(OperatorSecret);
        RelayOpened opened = await OpenAsync(client, fixture.Engine.Address, fixture.Redirect, MountPrefix, ProfileId);
        Callback callback = await fixture.DriveProviderAsync(opened.AuthorizationUrl);

        RelayCompleted first = await CompleteAsync(client, fixture.Engine.Address, opened.Relay, callback);
        Assert.True(first.Authorized, first.Message);
        Assert.Equal(1, fixture.Provider.TokenRequests);

        RelayCompleted second = await CompleteAsync(client, fixture.Engine.Address, opened.Relay, callback);
        Assert.Equal((int)HttpStatusCode.NotFound, second.StatusCode);
        Assert.False(second.Authorized);
        Assert.Equal("standalone/relay-unknown", second.Code);

        // A replayed handle cannot reach the provider, and the committed authority is unchanged.
        Assert.Equal(1, fixture.Provider.TokenRequests);
        Assert.Equal(2, (await fixture.ReadDecisionAsync())!.AuthorityEpoch);
    }

    [Fact]
    public async Task A_callback_that_does_not_match_the_attempt_state_is_refused_before_any_exchange()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        using HttpClient client = Authorized(OperatorSecret);
        RelayOpened opened = await OpenAsync(client, fixture.Engine.Address, fixture.Redirect, MountPrefix, ProfileId);
        Callback callback = await fixture.DriveProviderAsync(opened.AuthorizationUrl);

        // A callback minted for another attempt carries another state. It is refused, and refusal
        // happens before the code is presented anywhere.
        RelayCompleted mismatched = await CompleteAsync(
            client,
            fixture.Engine.Address,
            opened.Relay,
            new Callback(callback.Redirect, "not-the-state", callback.Code, null));

        Assert.Equal((int)HttpStatusCode.BadRequest, mismatched.StatusCode);
        Assert.False(mismatched.Authorized);
        Assert.Equal("oauth/state-mismatch", mismatched.Code);
        Assert.Equal(0, fixture.Provider.TokenRequests);
        Assert.Null(await fixture.ReadDecisionAsync());
    }

    [Fact]
    public async Task A_relay_session_is_bound_to_the_credential_that_opened_it()
    {
        var sessions = new StandaloneAuthorizationRelaySessions();
        OAuthAuthorizationAttempt attempt = Attempt(TimeProvider.System);

        StandaloneAuthorizationRelay? relay = sessions.Open(
            MountPrefix, ProfileId, attempt, credentialFingerprint: "AAAA");

        Assert.NotNull(relay);
        Assert.Equal(1, sessions.Count);

        // A different credential cannot take the session, and taking it is what it would have to do to
        // complete or abandon the attempt.
        Assert.False(sessions.TryTake(relay!.Handle, "BBBB", out _, out StandaloneAuthorizationRelayRefusal refusal));
        Assert.Equal(StandaloneAuthorizationRelayRefusal.CredentialMismatch, refusal);
        Assert.Equal(1, sessions.Count);

        (bool mismatchedRemoved, bool mismatchedMatched) = sessions.Abandon(relay.Handle, "BBBB");
        Assert.False(mismatchedRemoved);
        Assert.False(mismatchedMatched);
        Assert.Equal(1, sessions.Count);

        // The credential that opened it still can.
        Assert.True(sessions.TryTake(relay.Handle, "AAAA", out OAuthAuthorizationAttempt taken, out _));
        Assert.Same(attempt, taken);
        Assert.Equal(0, sessions.Count);
    }

    [Fact]
    public async Task A_relay_session_past_its_bounded_lifetime_is_refused()
    {
        // The attempt's lifetime is measured from the clock it was built with, so the clock is the
        // only way to reach the deadline without waiting ten minutes for it.
        var clock = new AdvanceableClock(DateTimeOffset.UtcNow);
        var sessions = new StandaloneAuthorizationRelaySessions(clock);
        OAuthAuthorizationAttempt attempt = Attempt(clock);

        StandaloneAuthorizationRelay? relay = sessions.Open(
            MountPrefix, ProfileId, attempt, credentialFingerprint: "AAAA");

        Assert.NotNull(relay);
        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.True(attempt.ExpiresAtUtc <= clock.GetUtcNow());

        Assert.False(sessions.TryTake(relay!.Handle, "AAAA", out _, out StandaloneAuthorizationRelayRefusal refusal));
        Assert.Equal(StandaloneAuthorizationRelayRefusal.Expired, refusal);
        Assert.Equal(0, sessions.Count);

        // An expired attempt cannot be completed either, which is what makes the expiry a refusal
        // rather than a longer wait.
        attempt.Begin();

        OAuthAuthorizationAttemptException expired = await Assert.ThrowsAsync<OAuthAuthorizationAttemptException>(
            async () => await attempt.CompleteAsync("state", "code", null, Token));
        Assert.Equal(OAuthAuthorizationAttemptError.AttemptExpired, expired.Error);
    }

    [Fact]
    public void The_relay_capacity_refuses_an_attempt_beyond_it()
    {
        var sessions = new StandaloneAuthorizationRelaySessions();
        List<StandaloneAuthorizationRelay> opened = [];

        for (int index = 0; index < StandaloneAuthorizationRelaySessions.MaximumSessions; index++)
        {
            StandaloneAuthorizationRelay? relay = sessions.Open(
                MountPrefix, ProfileId, Attempt(TimeProvider.System), credentialFingerprint: "AAAA");

            Assert.NotNull(relay);
            opened.Add(relay!);
        }

        Assert.Equal(StandaloneAuthorizationRelaySessions.MaximumSessions, sessions.Count);

        // Each session holds a live verifier, so the set is bounded rather than grown on demand.
        Assert.Null(sessions.Open(MountPrefix, ProfileId, Attempt(TimeProvider.System), credentialFingerprint: "AAAA"));

        // Completing one frees a slot for another.
        Assert.True(sessions.TryTake(opened[0].Handle, "AAAA", out _, out _));
        Assert.NotNull(sessions.Open(MountPrefix, ProfileId, Attempt(TimeProvider.System), credentialFingerprint: "AAAA"));
    }

    [Fact]
    public async Task An_abandoned_session_cannot_be_completed_afterwards()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        using HttpClient client = Authorized(OperatorSecret);
        RelayOpened opened = await OpenAsync(client, fixture.Engine.Address, fixture.Redirect, MountPrefix, ProfileId);
        Callback callback = await fixture.DriveProviderAsync(opened.AuthorizationUrl);

        using HttpResponseMessage abandoned = await client.PostAsync(
            new Uri(fixture.Engine.Address, OAuthOperatorEndpoints.AuthorizeAbortPath),
            JsonContent(new { relay = opened.Relay }),
            Token);

        Assert.Equal(HttpStatusCode.OK, abandoned.StatusCode);

        using JsonDocument body = JsonDocument.Parse(await abandoned.Content.ReadAsStringAsync(Token));
        Assert.True(body.RootElement.GetProperty("abandoned").GetBoolean());

        // The handle is gone, so the callback the provider already issued cannot be exchanged.
        RelayCompleted afterAbort = await CompleteAsync(client, fixture.Engine.Address, opened.Relay, callback);
        Assert.Equal((int)HttpStatusCode.NotFound, afterAbort.StatusCode);
        Assert.Equal("standalone/relay-unknown", afterAbort.Code);
        Assert.Equal(0, fixture.Provider.TokenRequests);

        // Abandoning twice is idempotent rather than an error: the operator's intent already holds.
        using HttpResponseMessage again = await client.PostAsync(
            new Uri(fixture.Engine.Address, OAuthOperatorEndpoints.AuthorizeAbortPath),
            JsonContent(new { relay = opened.Relay }),
            Token);

        Assert.Equal(HttpStatusCode.OK, again.StatusCode);

        using JsonDocument againBody = JsonDocument.Parse(await again.Content.ReadAsStringAsync(Token));
        Assert.False(againBody.RootElement.GetProperty("abandoned").GetBoolean());
    }

    [Fact]
    public async Task The_serving_process_exposes_no_callback_endpoint()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        using HttpClient client = new();

        // The callback belongs to the operator's listener, in the operator's process. The serving
        // Engine must not answer it: an Engine-held callback endpoint would be a public endpoint that
        // completes an authorization.
        using HttpResponseMessage callback = await client.GetAsync(
            new Uri(fixture.Engine.Address, fixture.Redirect.AbsolutePath),
            Token);

        Assert.Equal(HttpStatusCode.NotFound, callback.StatusCode);
    }

    [Fact]
    public async Task A_relay_driven_from_the_command_line_commits_and_leaks_nothing()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        string secretFile = Path.Combine(_root, "operator-" + Guid.NewGuid().ToString("N") + ".secret");
        File.WriteAllText(secretFile, OperatorSecret);

        using var progress = new AuthorizationProgress();
        var outcomes = new AuthorizationOutcomeLog();

        Task<CommandOutcome> relay = HostCommands.RunAsync(
            [
                "auth", "authorize", MountPrefix, ProfileId,
                "--oauth-redirect-uri", fixture.Redirect.AbsoluteUri,
                "--oauth-operator-endpoint", fixture.Engine.Address.GetLeftPart(UriPartial.Authority),
                "--oauth-operator-secret-file", secretFile,
            ],
            "mcpiler-engine test (relay)",
            Token,
            progress,
            outcomes);

        string authorizationUrl = await progress.AuthorizationUrl;

        // The command line prints the URL the serving process built and never the verifier.
        Assert.Contains("code_challenge_method=S256", authorizationUrl, StringComparison.Ordinal);
        Assert.DoesNotContain("code_verifier", authorizationUrl, StringComparison.Ordinal);

        Callback callback = await fixture.DriveProviderAsync(authorizationUrl, deliver: true);
        _ = callback;

        CommandOutcome outcome = await relay;

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("authorized " + MountPrefix + " " + ProfileId, outcome.Output, StringComparison.Ordinal);
        Assert.Contains("authority epoch 2", outcome.Output, StringComparison.Ordinal);

        MutableSlotDecision? decision = await fixture.ReadDecisionAsync();
        Assert.Equal(fixture.Provider.RefreshToken, decision!.RefreshToken);

        // Neither the credential nor the callback is echoed, and the in-memory outcome buffer is
        // sanitized the same way.
        Assert.DoesNotContain(fixture.Provider.RefreshToken, outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(fixture.Provider.AccessToken, outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(callback.Code!, outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(callback.Code!, progress.Text, StringComparison.Ordinal);

        foreach (AuthorizationOutcome recorded in outcomes.Recent(DateTimeOffset.UtcNow))
        {
            Assert.DoesNotContain(fixture.Provider.RefreshToken, recorded.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(callback.Code!, recorded.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_relay_whose_endpoint_does_not_answer_changes_nothing()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        string secretFile = Path.Combine(_root, "operator-" + Guid.NewGuid().ToString("N") + ".secret");
        File.WriteAllText(secretFile, OperatorSecret);

        int port = LoopbackPorts.Reserve();
        var outcomes = new AuthorizationOutcomeLog();

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "auth", "authorize", MountPrefix, ProfileId,
                "--oauth-redirect-uri", fixture.Redirect.AbsoluteUri,
                "--oauth-operator-endpoint", "http://127.0.0.1:" + port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--oauth-operator-secret-file", secretFile,
            ],
            "mcpiler-engine test (relay)",
            Token,
            progress: null,
            outcomes);

        Assert.Equal(ExitCodes.Failure, outcome.ExitCode);
        Assert.Contains("could not be reached", outcome.Output, StringComparison.Ordinal);

        // The serving process's authority is untouched: a relay that never reached it committed
        // nothing, and no attempt was opened.
        Assert.Null(await fixture.ReadDecisionAsync());
        Assert.Equal(0, fixture.Provider.AuthorizationRequests);
    }

    /// <summary>
    /// A remote plaintext endpoint is refused before the operator secret is even read: the credential
    /// authenticates this client to the serving Engine, and sending it in cleartext to a remote
    /// address the serving channel would only refuse on arrival is the leak the client must prevent.
    /// </summary>
    [Fact]
    public async Task A_remote_plaintext_operator_endpoint_is_refused_before_the_secret_is_read()
    {
        var outcomes = new AuthorizationOutcomeLog();

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "auth", "authorize", MountPrefix, ProfileId,
                "--oauth-redirect-uri",
                    "http://127.0.0.1:"
                        + LoopbackPorts.Reserve().ToString(System.Globalization.CultureInfo.InvariantCulture)
                        + "/callback",
                "--oauth-operator-endpoint", "http://192.0.2.10:8443",

                // Deliberately absent: the endpoint refusal must come first, so the secret file is
                // never opened. If the check moved after the read, this path would report the missing
                // secret file instead and this test would observe a different message.
                "--oauth-operator-secret-file", Path.Combine(_root, "never-read.secret"),
            ],
            "mcpiler-engine test (relay)",
            Token,
            progress: null,
            outcomes);

        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Contains("must not travel in cleartext", outcome.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(HostConfiguration.OAuthOperatorSecretFileKey, outcome.Output, StringComparison.Ordinal);
    }

    /// <summary>
    /// A redirect answer is refused instead of followed, so the operator's credential never reaches a
    /// destination the operator did not name.
    /// </summary>
    [Fact]
    public async Task A_redirected_operator_endpoint_is_refused_without_reaching_the_redirect_target()
    {
        await using AuthorizationTransportServer target = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                await context.Response.WriteAsync("{}", TestContext.Current.CancellationToken);
            });

        await using AuthorizationTransportServer redirecting = await AuthorizationTransportServer.StartAsync(
            async context =>
            {
                context.Response.StatusCode = StatusCodes.Status302Found;
                context.Response.Headers.Location =
                    new Uri(target.Address, OAuthOperatorEndpoints.AuthorizePath).AbsoluteUri;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"error\":\"redirected\"}", TestContext.Current.CancellationToken);
            });

        string secretFile = Path.Combine(_root, "operator-" + Guid.NewGuid().ToString("N") + ".secret");
        File.WriteAllText(secretFile, OperatorSecret);

        var outcomes = new AuthorizationOutcomeLog();

        CommandOutcome outcome = await HostCommands.RunAsync(
            [
                "auth", "authorize", MountPrefix, ProfileId,
                "--oauth-redirect-uri",
                    "http://127.0.0.1:"
                        + LoopbackPorts.Reserve().ToString(System.Globalization.CultureInfo.InvariantCulture)
                        + "/callback",
                "--oauth-operator-endpoint", redirecting.Address.GetLeftPart(UriPartial.Authority),
                "--oauth-operator-secret-file", secretFile,
            ],
            "mcpiler-engine test (relay)",
            Token,
            progress: null,
            outcomes);

        // The answer the stub gave was a redirect, so the channel was never legitimately opened; the
        // proof is that the configured endpoint was asked exactly once, with the credential, and the
        // redirect target was never asked at all.
        Assert.Equal(ExitCodes.Configuration, outcome.ExitCode);
        Assert.Equal(1, redirecting.RequestCount);
        Assert.Equal(0, target.RequestCount);
        Assert.NotNull(redirecting.LastAuthorization);
        Assert.Null(target.LastAuthorization);
    }

    [Fact]
    public async Task A_relay_authorization_supersedes_a_cleared_floor()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        using HttpClient client = Authorized(OperatorSecret);

        // A cleared floor first: the ordinary served call refuses rather than resurrecting a source.
        using HttpResponseMessage cleared = await client.PostAsync(
            new Uri(fixture.Engine.Address, OAuthOperatorEndpoints.ClearPath + "?mount=" + MountPrefix + "&profile=" + ProfileId),
            null,
            Token);
        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);
        Assert.True((await fixture.ReadDecisionAsync())!.Kind is MutableSlotDecisionKind.Cleared);

        // An explicit re-authorization is the documented way back, and it opens a newer epoch.
        RelayOpened opened = await OpenAsync(client, fixture.Engine.Address, fixture.Redirect, MountPrefix, ProfileId);
        Callback callback = await fixture.DriveProviderAsync(opened.AuthorizationUrl);
        RelayCompleted completed = await CompleteAsync(client, fixture.Engine.Address, opened.Relay, callback);

        Assert.True(completed.Authorized, completed.Message);
        Assert.Equal(3, completed.AuthorityEpoch);

        MutableSlotDecision? decision = await fixture.ReadDecisionAsync();
        Assert.Equal(MutableSlotDecisionKind.Authorized, decision!.Kind);
        Assert.Equal(3, decision.AuthorityEpoch);

        ToolOutcome served = await InvokeAsync(fixture.Engine);
        Assert.False(served.IsError, served.Text);
    }

    [Fact]
    public async Task A_managed_deployment_maps_no_relay_route()
    {
        string manifestDirectory = Directory.CreateDirectory(Path.Combine(_root, "manifest-" + Guid.NewGuid().ToString("N"))).FullName;
        File.WriteAllText(
            Path.Combine(manifestDirectory, "manifest.json"),
            ManifestOf(UnusedTokenAuthority, UnusedDestinationAuthority, UnusedDestinationAuthority));

        string storeRoot = Directory.CreateDirectory(Path.Combine(_root, "files-" + Guid.NewGuid().ToString("N"))).FullName;

        // A mount that declares runtime-owned mutable state needs a durable store even in managed
        // mode: the process refuses to start rather than hold a rotated credential it cannot keep.
        string stateRoot = Directory.CreateDirectory(Path.Combine(_root, "state-" + Guid.NewGuid().ToString("N"))).FullName;
        string keyFile = Path.Combine(_root, "key-" + Guid.NewGuid().ToString("N"));
        File.WriteAllBytes(keyFile, [.. Enumerable.Range(0, 32).Select(index => (byte)index)]);

        WebApplication managed = await ManagedAsync(manifestDirectory, storeRoot, stateRoot, keyFile);

        try
        {
            Uri address = new(managed.Urls.Single(), UriKind.Absolute);

            using HttpClient client = Authorized(OperatorSecret);

            using HttpResponseMessage capability = await client.GetAsync(
                new Uri(address, OAuthOperatorEndpoints.CapabilityPath),
                Token);
            Assert.Equal(HttpStatusCode.OK, capability.StatusCode);

            using JsonDocument document = JsonDocument.Parse(await capability.Content.ReadAsStringAsync(Token));
            string[] capabilities =
                [.. document.RootElement.GetProperty("capabilities").EnumerateArray().Select(entry => entry.GetString()!)];

            foreach (string relayCapability in RelayCapabilities)
            {
                Assert.DoesNotContain(relayCapability, capabilities);
            }

            // Local authorization is Platform-owned in a managed deployment, so the relay routes are
            // not mapped at all rather than mapped and refused.
            using HttpResponseMessage authorize = await client.PostAsync(
                new Uri(address, OAuthOperatorEndpoints.AuthorizePath),
                JsonContent(new { mount = MountPrefix, profile = ProfileId, redirectUri = "http://127.0.0.1:1/oauth/callback" }),
                Token);
            Assert.Equal(HttpStatusCode.NotFound, authorize.StatusCode);
        }
        finally
        {
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await managed.StopAsync(shutdown.Token);
            await managed.DisposeAsync();
        }
    }

    /// <summary>A file-mode deployment that advertises the relay capabilities.</summary>
    [Fact]
    public async Task A_file_mode_deployment_advertises_the_relay_capabilities()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        using HttpClient client = Authorized(OperatorSecret);
        using HttpResponseMessage capability = await client.GetAsync(
            new Uri(fixture.Engine.Address, OAuthOperatorEndpoints.CapabilityPath),
            Token);

        Assert.Equal(HttpStatusCode.OK, capability.StatusCode);

        using JsonDocument document = JsonDocument.Parse(await capability.Content.ReadAsStringAsync(Token));
        string[] capabilities =
            [.. document.RootElement.GetProperty("capabilities").EnumerateArray().Select(entry => entry.GetString()!)];

        foreach (string relayCapability in RelayCapabilities)
        {
            Assert.Contains(relayCapability, capabilities);
        }
    }

    [Fact]
    public async Task A_relay_from_a_separate_process_commits_through_the_serving_engine()
    {
        await using RelayFixture fixture = await RelayFixture.StartAsync(_root);

        string secretFile = Path.Combine(_root, "operator-" + Guid.NewGuid().ToString("N") + ".secret");
        File.WriteAllText(secretFile, OperatorSecret);

        // The two halves of a real relay are two processes: the serving Engine holds the store-root
        // lease and owns the attempt, and the operator's own Engine process binds the callback and
        // takes no lease at all. Running the command line in-process would not show that the relay
        // works without the operator holding anything.
        await using EngineCliProcess relay = EngineCliProcess.Start(
            "auth", "authorize", MountPrefix, ProfileId,
            "--oauth-redirect-uri", fixture.Redirect.AbsoluteUri,
            "--oauth-operator-endpoint", fixture.Engine.Address.GetLeftPart(UriPartial.Authority),
            "--oauth-operator-secret-file", secretFile);

        string authorizationUrl = (await relay.WaitForStderrLineAsync("code_challenge_method=", Token)).Trim();
        Assert.StartsWith("http", authorizationUrl, StringComparison.Ordinal);
        Assert.DoesNotContain("code_verifier", authorizationUrl, StringComparison.Ordinal);

        Callback callback = await fixture.DriveProviderAsync(authorizationUrl, deliver: true);

        EngineCliOutcome outcome = await relay.CompleteAsync(Token);

        Assert.Equal(0, outcome.ExitCode);
        Assert.Contains("authorized " + MountPrefix + " " + ProfileId, outcome.Stdout, StringComparison.Ordinal);
        Assert.Contains("authority epoch 2", outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(fixture.Provider.RefreshToken, outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(fixture.Provider.AccessToken, outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(callback.Code!, outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(callback.Code!, outcome.Stderr, StringComparison.Ordinal);

        MutableSlotDecision? decision = await fixture.ReadDecisionAsync();
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Authorized, decision!.Kind);
        Assert.Equal(2, decision.AuthorityEpoch);
        Assert.Equal(fixture.Provider.RefreshToken, decision.RefreshToken);

        // The commit is the serving process's, and its next call already observes it.
        ToolOutcome served = await InvokeAsync(fixture.Engine);
        Assert.False(served.IsError, served.Text);
        Assert.Equal(0, fixture.Provider.RefreshRequests);
    }

    private static string ClearPath()
        => OAuthOperatorEndpoints.ClearPath + "?mount=" + MountPrefix + "&profile=" + ProfileId;

    private static string Origin(Uri address) => address.GetLeftPart(UriPartial.Authority);

    private static HttpClient Authorized(string secret)
    {
        HttpClient client = new();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        client.DefaultRequestHeaders.Add(
            CompatibilitySchema.ContractGenerationHeader,
            CompatibilitySchema.OAuthOperatorGeneration);
        return client;
    }

    private static StringContent JsonContent(object payload)
        => new(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static async Task<RelayOpened> OpenAsync(
        HttpClient client,
        Uri address,
        Uri redirect,
        string mount,
        string profile)
    {
        using HttpResponseMessage response = await client.PostAsync(
            new Uri(address, OAuthOperatorEndpoints.AuthorizePath),
            JsonContent(new { mount, profile, redirectUri = redirect.AbsoluteUri }),
            Token);

        string body = await response.Content.ReadAsStringAsync(Token);

        return OpenBody(response, body);
    }

    private static RelayOpened OpenBody(HttpResponseMessage response, string body)
    {
        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement root = document.RootElement;

        return new RelayOpened(
            (int)response.StatusCode,
            body,
            root.TryGetProperty("relay", out JsonElement relay) ? relay.GetString()! : string.Empty,
            root.TryGetProperty("authorizationUrl", out JsonElement url) ? url.GetString()! : string.Empty);
    }

    private static async Task<RelayCompleted> CompleteAsync(
        HttpClient client,
        Uri address,
        string handle,
        Callback callback)
    {
        using HttpResponseMessage response = await client.PostAsync(
            new Uri(address, OAuthOperatorEndpoints.AuthorizeCompletePath),
            JsonContent(new { relay = handle, state = callback.State, code = callback.Code, error = callback.Error }),
            Token);

        string body = await response.Content.ReadAsStringAsync(Token);

        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement root = document.RootElement;

        return new RelayCompleted(
            (int)response.StatusCode,
            body,
            root.TryGetProperty("authorized", out JsonElement authorized) && authorized.ValueKind is JsonValueKind.True,
            root.TryGetProperty("code", out JsonElement code) ? code.GetString() : null,
            root.TryGetProperty("message", out JsonElement message) ? message.GetString()! : string.Empty,
            root.TryGetProperty("authorityEpoch", out JsonElement epoch) ? epoch.GetInt64() : 0,
            root.TryGetProperty("runtimeRevision", out JsonElement revision) ? revision.GetInt64() : 0);
    }

    private static async Task<ToolOutcome> InvokeAsync(ServedEngine engine)
    {
        MountedManifest mount = Assert.Single(engine.Started.Mounts);
        MountedSurface surface = Assert.Single(mount.Surfaces);

        return await engine.Execution.InvokeAsync(
            mount,
            surface,
            mount.Prefix + "/" + surface.Slug,
            Tool,
            [],
            negotiatedProtocolRevision: null,
            Token,
            CallerPartition.Public);
    }

    private static OAuthAuthorizationAttempt Attempt(TimeProvider clock)
    {
        AuthenticationProfile profile = Profile(UnusedTokenAuthority, UnusedDestinationAuthority);

        return OAuthAuthorizationAttempt.Create(
            new OAuthAuthorizationAttemptRequest(
                MountPrefix,
                profile,
                new AuthenticationSlot(OAuthTokenService.RefreshTokenSlot, 1, 0),
                OAuthStrategyConfiguration.FromConfiguration(profile.Configuration, authorizationCodeRequired: true),
                new Uri("http://127.0.0.1:57431/oauth/callback")),
            new OAuthTokenEndpointClient(
                new UpstreamSender(new UpstreamClientFactory(ServedEngine.Permissive())),
                clock),
            clock);
    }

    private async Task<WebApplication> ManagedAsync(
        string manifestDirectory,
        string storeRoot,
        string stateRoot,
        string keyFile)
    {
        var options = new RuntimeOptions([new MountRequest(MountPrefix, manifestDirectory)], storeRoot)
        {
            RuntimeStateRoot = stateRoot,
            RuntimeStateKeyFile = keyFile,
        };

        RuntimeStartResult initial = EngineRuntime.Start(options);

        Assert.True(
            initial.Started,
            "The runtime refused to start: "
                + string.Join("; ", initial.Refusals.Select(refusal => refusal.Code + " " + refusal.Message)));

        var manager = new EngineGenerationManager(HostMode.Managed);
        var drain = new DrainCoordinator();
        EngineExecution execution = EngineExecution.Create(initial, ServedEngine.Permissive());

        _ = manager.Activate(new EngineGeneration(
            number: 0,
            MountSet.From(initial),
            execution,
            ownsExecution: true));

        int port = LoopbackPorts.Reserve();

        WebApplication app = EngineWebHost.BuildManaged(
            new HostBinding(
                options,
                new HostListenOptions($"http://127.0.0.1:{port}", HostTransport.Http),
                Authorization: null,
                HostLifecycleOptions.Default)
            {
                OAuthOperatorSecret = OperatorSecret,
            },
            drain,
            manager);

        await app.StartAsync(Token);
        return app;
    }

    /// <summary>The OAuth configuration both the Manifest and the in-code twin carry.</summary>
    private static string ConfigurationOf(string tokenAuthority)
        => "{\"strategyId\":\"oauth2-authorization-code-pkce-refresh\","
            + "\"inputs\":{\"clientId\":\"test-client\"},"
            + "\"clientId\":\"test-client\","
            + "\"tokenAuthMethod\":\"none\","
            + $"\"authorizationEndpoint\":\"{tokenAuthority}/authorize\","
            + $"\"tokenEndpoint\":\"{tokenAuthority}/token\"}}";

    private static AuthenticationProfile Profile(string tokenAuthority, string destinationAuthority)
        => new(
            ProfileId,
            AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
            CanonicalJson.Parse(Encoding.UTF8.GetBytes(ConfigurationOf(tokenAuthority)))!.AsObject(),
            [tokenAuthority],
            [destinationAuthority],
            ["oauth-refresh"],
            ManifestScopeFingerprint,
            [new AuthenticationSlot(OAuthTokenService.RefreshTokenSlot, 1, 0)]);

    private static string ManifestOf(
        string tokenAuthority,
        string destinationAuthority,
        string destinationBase,
        string? credential = null)
        => $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Authorization Relay Probe", "authenticationRequired": false } },
                "policy": { "inline": { "baseUrl": "{{destinationBase}}" } },
                "operations": {
                  "inline": {
                    "operations": [
                      {
                        "key": "GET /things",
                        "method": "GET",
                        "path": "/things",
                        "responses": { "200": { "content": { "application/json": { "schema": { "type": "object" } } } } }
                      }
                    ]
                  }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      {
                        "slug": "{{Tool}}",
                        "name": "List things",
                        "binding": { "type": "http", "operation": "GET /things", "authenticationRef": "{{ProfileId}}" }
                      }
                    ]
                  }
                },
                "credentials": {
                  "inline": {
                    "formatVersion": 4,
                    "credentials": [
                      {
                        "id": "oauth-refresh",
                        "scheme": "oauth2-authorization-code",
                        "slot": "refreshToken",
                        "value": {{credential ?? "{ \"fromEnv\": \"MCPILER_RELAY_UNSET_REFRESH\" }"}}
                      }
                    ]
                  }
                },
                "authentication": {
                  "inline": {
                    "formatVersion": 2,
                    "profiles": [
                      {
                        "id": "{{ProfileId}}",
                        "kind": "oauth2-authorization-code-pkce-refresh",
                        "configuration": {{ConfigurationOf(tokenAuthority)}},
                        "authenticationOrigins": ["{{tokenAuthority}}"],
                        "destinationOrigins": ["{{destinationAuthority}}"],
                        "credentialRef": ["oauth-refresh"],
                        "scopeFingerprint": "{{ManifestScopeFingerprint}}",
                        "slots": [ { "slot": "refreshToken", "authorityEpoch": 1, "runtimeRevision": 0 } ]
                      }
                    ]
                  }
                }
              }
            }
            """;

    private sealed record RelayOpened(int StatusCode, string Body, string Relay, string AuthorizationUrl);

    private sealed record RelayCompleted(
        int StatusCode,
        string Body,
        bool Authorized,
        string? Code,
        string Message,
        long AuthorityEpoch,
        long RuntimeRevision);

    private sealed record Callback(Uri Redirect, string? State, string? Code, string? Error);

    /// <summary>A clock a test can move forward, so a bounded lifetime is reachable in one run.</summary>
    private sealed class AdvanceableClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        internal void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }

    /// <summary>A serving Engine, a real loopback provider and the operator's own callback listener.</summary>
    private sealed class RelayFixture : IAsyncDisposable
    {
        private RelayFixture(
            string root,
            ServedEngine engine,
            LoopbackHost upstream,
            FakeAuthorizationServer server,
            AuthorizationCodeProviderScenario provider,
            Uri redirect)
        {
            Root = root;
            Engine = engine;
            Upstream = upstream;
            Server = server;
            Provider = provider;
            Redirect = redirect;
        }

        internal string Root { get; }

        internal ServedEngine Engine { get; }

        internal LoopbackHost Upstream { get; }

        internal FakeAuthorizationServer Server { get; }

        internal AuthorizationCodeProviderScenario Provider { get; }

        internal Uri Redirect { get; }

        internal static async Task<RelayFixture> StartAsync(string root)
        {
            int port = LoopbackPorts.Reserve();
            Uri redirect = new($"http://127.0.0.1:{port}/oauth/callback");

            LoopbackHost upstream = await LoopbackHost.StartAsync(
                async context =>
                {
                    context.Response.StatusCode = 200;
                    context.Response.ContentType = "application/json";
                    await context.Response.Body.WriteAsync("{\"ok\":true}"u8.ToArray(), context.RequestAborted);
                },
                Token);

            var provider = new AuthorizationCodeProviderScenario(redirect.AbsoluteUri);
            var server = await FakeAuthorizationServer.StartAsync(
                active: true,
                Token,
                authorizationCode: provider);

            string identity = Guid.NewGuid().ToString("N");
            string manifestDirectory = Directory.CreateDirectory(Path.Combine(root, "manifest-" + identity)).FullName;

            // The declared source must resolve, because the execution layer resolves a profile's
            // declared credentials before it consults the local authority. A file keeps that resolution
            // local to this fixture rather than mutating the process environment other suites share.
            string declared = Path.Combine(root, "declared-" + identity + ".refresh");
            File.WriteAllText(declared, "CANARY-declared-refresh-1a44");

            File.WriteAllText(
                Path.Combine(manifestDirectory, "manifest.json"),
                ManifestOf(
                    Origin(server.Address),
                    Origin(upstream.Address),
                    upstream.Address.GetLeftPart(UriPartial.Path),
                    credential: $"{{ \"fromFile\": \"{declared.Replace('\\', '/')}\" }}"));

            string stateRoot = Directory.CreateDirectory(Path.Combine(root, "state-" + identity)).FullName;
            string storeRoot = Directory.CreateDirectory(Path.Combine(root, "files-" + identity)).FullName;
            string keyFile = Path.Combine(root, "key-" + identity);
            File.WriteAllBytes(keyFile, [.. Enumerable.Range(0, 32).Select(index => (byte)index)]);

            ServedEngine engine = await ServedEngine.StartAsync(
                new RuntimeOptions([new MountRequest(MountPrefix, manifestDirectory)], storeRoot)
                {
                    RuntimeStateRoot = stateRoot,
                    RuntimeStateKeyFile = keyFile,
                },
                Token,
                oauthOperatorSecret: OperatorSecret);

            return new RelayFixture(root, engine, upstream, server, provider, redirect)
            {
                StateRoot = stateRoot,
                Key = [.. Enumerable.Range(0, 32).Select(index => (byte)index)],
            };
        }

        private string StateRoot { get; init; } = string.Empty;

        private byte[] Key { get; init; } = [];

        /// <summary>
        /// Opens the provider's authorization URL and follows its redirect to the callback.
        /// </summary>
        /// <param name="authorizationUrl">The URL the attempt is registered for.</param>
        /// <param name="deliver">
        /// Whether to also follow the redirect to the callback address. A relay test that drives the
        /// command line must deliver it, because the command line's own listener is the only thing
        /// that can complete the attempt there; a test that completes the attempt itself only needs
        /// the values the provider put in the redirect.
        /// </param>
        internal async Task<Callback> DriveProviderAsync(string authorizationUrl, bool deliver = false)
        {
            using HttpClientHandler handler = new() { AllowAutoRedirect = false };
            using var driver = new HttpClient(handler);

            using HttpResponseMessage response = await driver.GetAsync(new Uri(authorizationUrl), Token);
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);

            Uri location = response.Headers.Location!;

            Assert.True(
                StandaloneAuthorizationCallback.TryRead(location.Query, out string? state, out string? code, out string? error),
                "The provider's callback query was not readable.");

            if (deliver)
            {
                // This is the operator's browser step: the callback is handed to the listener the
                // operator bound, which is what lets the command line complete the attempt.
                using HttpResponseMessage delivered = await driver.GetAsync(location, Token);
                Assert.True(delivered.IsSuccessStatusCode, delivered.StatusCode.ToString());
            }

            return new Callback(location, state, code, error);
        }

        internal async Task<MutableSlotDecision?> ReadDecisionAsync()
            => await new FileMutableSlotStore(StateRoot, MountPrefix, Key)
                .LoadDecisionAsync(ProfileId, OAuthTokenService.RefreshTokenSlot, Token);

        public async ValueTask DisposeAsync()
        {
            await Engine.DisposeAsync();
            await Server.DisposeAsync();
            await Upstream.DisposeAsync();
        }
    }

    /// <summary>Captures the progress a command writes, and surfaces the authorization URL.</summary>
    private sealed class AuthorizationProgress : TextWriter
    {
        private readonly TaskCompletionSource<string> _authorizationUrl =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly StringBuilder _text = new();

        public override Encoding Encoding => Encoding.UTF8;

        internal string Text
        {
            get
            {
                lock (_text)
                {
                    return _text.ToString();
                }
            }
        }

        internal Task<string> AuthorizationUrl => _authorizationUrl.Task;

        public override void Write(char value)
        {
            lock (_text)
            {
                _text.Append(value);
            }
        }

        public override void Write(string? value)
        {
            if (value is null)
            {
                return;
            }

            lock (_text)
            {
                _text.Append(value);
            }

            if (value.Contains("code_challenge_method=", StringComparison.Ordinal))
            {
                _authorizationUrl.TrySetResult(value.Trim());
            }
        }

        public override void WriteLine(string? value)
        {
            Write(value);
            Write('\n');
        }
    }
}
