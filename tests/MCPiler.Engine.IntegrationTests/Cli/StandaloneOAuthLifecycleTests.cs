using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Caching;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Host.Hosting;
using MCPiler.Engine.IntegrationTests.Mcp;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;
using MCPiler.Engine.Runtime;
using Xunit;

namespace MCPiler.Engine.IntegrationTests.Cli;

/// <summary>Real HTTP OAuth provider fixtures and CLI process refusal before provider egress.</summary>
[Collection(AuthorizationCommandCollection.Name)]
public sealed class StandaloneOAuthLifecycleTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "engine-oauth-cli-" + Guid.NewGuid().ToString("N"));

    /// <summary>
    /// The scope fingerprint the seam manifest and its in-code twin share. A manifest fingerprint
    /// must be 64 lower-case hex characters, so it cannot reuse the "fixture-scope" placeholder.
    /// </summary>
    private const string ManifestScopeFingerprint =
        "0000000000000000000000000000000000000000000000000000000000000007";

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task Authorization_code_provider_enforces_PKCE_redirect_identity_and_single_use()
    {
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken,
            authorizationCode: provider);

        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        string verifier = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        string callback = "http://127.0.0.1:57431/oauth/callback";
        string state = "test-state";
        string endpoint = new Uri(server.Address, "authorize").AbsoluteUri;
        string query = "?response_type=code&code_challenge_method=S256&client_id=test-client"
            + "&state=" + Uri.EscapeDataString(state)
            + "&code_challenge=" + Uri.EscapeDataString(AuthorizationCodeProviderScenario.Challenge(verifier))
            + "&redirect_uri=" + Uri.EscapeDataString(callback);

        using HttpResponseMessage authorize = await client.GetAsync(endpoint + query, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var redirect = authorize.Headers.Location!;
        Assert.Equal(callback, redirect.GetLeftPart(UriPartial.Path));
        var returned = QueryHelpers.ParseQuery(redirect.Query);
        Assert.Equal(state, returned["state"].ToString());
        string code = returned["code"].ToString();
        Assert.NotEmpty(code);

        async Task<HttpResponseMessage> Exchange(string suppliedVerifier, string? suppliedRedirect = null)
            => await client.PostAsync(new Uri(server.Address, "token"), new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = "test-client",
                ["code"] = code,
                ["redirect_uri"] = suppliedRedirect ?? callback,
                ["code_verifier"] = suppliedVerifier,
            }), TestContext.Current.CancellationToken);

        using (HttpResponseMessage wrongRedirect = await Exchange(verifier, "http://127.0.0.1:57431/other"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, wrongRedirect.StatusCode);
        }

        using (HttpResponseMessage invalid = await Exchange("wrong-verifier"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        }

        using (HttpResponseMessage valid = await Exchange(verifier))
        {
            Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
            using JsonDocument payload = JsonDocument.Parse(await valid.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.Equal(provider.AccessToken, payload.RootElement.GetProperty("access_token").GetString());
            Assert.Equal(provider.RefreshToken, payload.RootElement.GetProperty("refresh_token").GetString());
        }

        using (HttpResponseMessage replayed = await Exchange(verifier))
        {
            Assert.Equal(HttpStatusCode.BadRequest, replayed.StatusCode);
        }

        Assert.Equal(1, provider.AuthorizationRequests);
        Assert.Equal(4, provider.TokenRequests);
    }

    [Theory]
    [InlineData("other-client", "http://127.0.0.1:57431/oauth/callback")]
    [InlineData("test-client", "http://127.0.0.1:57431/other")]
    [InlineData("test-client", "http://127.0.0.1:57432/oauth/callback")]
    [InlineData("test-client", "http://localhost:57431/oauth/callback")]
    [InlineData("test-client", "https://127.0.0.1:57431/oauth/callback")]
    public async Task OAuth_provider_rejects_unregistered_client_or_callback_before_issuing_code(
        string clientId, string redirectUri)
    {
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, TestContext.Current.CancellationToken, authorizationCode: provider);
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        string url = new Uri(server.Address, "authorize")
            + "?response_type=code&code_challenge_method=S256"
            + "&client_id=" + Uri.EscapeDataString(clientId)
            + "&state=test-state&code_challenge=" + AuthorizationCodeProviderScenario.Challenge("verifier")
            + "&redirect_uri=" + Uri.EscapeDataString(redirectUri);

        using HttpResponseMessage response = await client.GetAsync(url, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(1, provider.AuthorizationRequests);
        Assert.Equal(0, provider.TokenRequests);
    }

    [Theory]
    [InlineData("&state=duplicate")]
    [InlineData("&%73tate=duplicate")]
    [InlineData("&code_challenge_method=plain")]
    [InlineData("&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback")]
    [InlineData("&response_type=token")]
    [InlineData("&%63lient_id=other-client")]
    [InlineData("&code_challenge=another-challenge")]
    public async Task OAuth_provider_rejects_ambiguous_reserved_authorization_parameters(string suffix)
    {
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken,
            authorizationCode: provider);
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        string url = new Uri(server.Address, "authorize")
            + "?response_type=code&code_challenge_method=S256&client_id=test-client"
            + "&state=first&code_challenge=" + AuthorizationCodeProviderScenario.Challenge("verifier")
            + "&redirect_uri=http%3A%2F%2F127.0.0.1%3A57431%2Fcallback" + suffix;

        using var response = await client.GetAsync(url, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(1, provider.AuthorizationRequests);
        Assert.Equal(0, provider.TokenRequests);
    }

    [Fact]
    public async Task Missing_mount_is_refused_by_real_CLI_before_store_creation_and_provider_traffic()
    {
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken,
            authorizationCode: provider);
        string root = Path.Combine(_directory, "store-not-created");

        EngineCliOutcome result = await EngineCliProcess.RunAsync(
            TestContext.Current.CancellationToken, "serve", "--file-store-root", root);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("--mount", result.Stdout, StringComparison.Ordinal);
        Assert.False(Directory.Exists(root));
        Assert.Equal(0, provider.AuthorizationRequests);
        Assert.Equal(0, provider.TokenRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Unreadable_authority_refuses_real_provider_egress_without_mutating_disk(bool wrongKey)
    {
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true,
            TestContext.Current.CancellationToken,
            authorizationCode: provider);

        string root = Path.Combine(_directory, "encrypted-" + Guid.NewGuid().ToString("N"));
        byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        const string profileId = "oauth";
        const string slot = "refreshToken";
        var writer = new FileMutableSlotStore(root, "mount", key);
        await writer.ReplaceAsync(new MutableSlotRecord(
            profileId, slot, "fixture-scope", 1, 0, provider.RefreshToken),
            TestContext.Current.CancellationToken);

        string committedPath = Assert.Single(Directory.GetFiles(root, "*.rstate"));
        byte[] committed = File.ReadAllBytes(committedPath);
        Assert.DoesNotContain(provider.RefreshToken, Encoding.UTF8.GetString(committed), StringComparison.Ordinal);

        if (!wrongKey)
        {
            byte[] tampered = (byte[])committed.Clone();
            tampered[^1] ^= 0x01;
            File.WriteAllBytes(committedPath, tampered);
        }

        byte[] beforeDenial = File.ReadAllBytes(committedPath);
        var reader = new FileMutableSlotStore(root, "mount",
            wrongKey ? Enumerable.Repeat((byte)0xFF, 32).ToArray() : key);

        AuthenticationProfile profile = new(
            profileId,
            AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
            CanonicalJson.Parse(Encoding.UTF8.GetBytes($$"""
                {"strategyId":"oauth2-authorization-code-pkce-refresh",
                 "clientId":"test-client", "tokenAuthMethod":"none",
                 "authorizationEndpoint":"{{server.Address}}authorize",
                 "tokenEndpoint":"{{server.Address}}token"}
                """))!.AsObject(),
            [server.Address.GetLeftPart(UriPartial.Authority)],
            [server.Address.GetLeftPart(UriPartial.Authority)],
            [], "fixture-scope", [new AuthenticationSlot(slot, 1, 0)]);
        IReadOnlyList<ResolvedCredential> credentials =
        [
            new(new ManifestCredential("initial", CredentialScheme.OAuth2AuthorizationCode,
                slot, CredentialReference.Literal("fixture")), "CANARY-declared-fallback")
        ];

        static OAuthTokenService CreateService(FileMutableSlotStore store)
            => new(new OAuthTokenEndpointClient(
                    new UpstreamSender(new UpstreamClientFactory(new OutboundConnectionPolicy(_ => false))),
                    TimeProvider.System),
                new AccessTokenCache(), new AccessTokenSingleFlight(), store, TimeProvider.System);

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => CreateService(reader)
            .AcquireAsync(profile, credentials, TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(0, provider.TokenRequests);
        Assert.Equal(0, provider.RefreshRequests);
        Assert.Equal(beforeDenial, File.ReadAllBytes(committedPath));
        Assert.Single(Directory.GetFiles(root, "*.rstate"));

        // Restart-style reopening must fail identically without reading an old manifest secret.
        var fresh = new FileMutableSlotStore(root, "mount",
            wrongKey ? Enumerable.Repeat((byte)0xFF, 32).ToArray() : key);
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => CreateService(fresh)
            .AcquireAsync(profile, credentials, TestContext.Current.CancellationToken).AsTask());
        Assert.Equal(0, provider.TokenRequests);
        Assert.Equal(beforeDenial, File.ReadAllBytes(committedPath));

        // Positive control: with the original authenticated bytes/key, the *same* real HTTP
        // provider receives exactly one refresh request from the production acquisition path.
        File.WriteAllBytes(committedPath, committed);
        OAuthAcquisition acquired = await CreateService(new FileMutableSlotStore(root, "mount", key))
            .AcquireAsync(profile, credentials, TestContext.Current.CancellationToken);
        Assert.Equal(provider.AccessToken, Assert.Single(acquired.Credentials).Value);
        Assert.Equal(1, provider.TokenRequests);
        Assert.Equal(1, provider.RefreshRequests);
        Assert.Equal(committed, File.ReadAllBytes(committedPath));
    }

    [Fact]
    public async Task Served_path_refuses_a_cleared_decision_before_provider_egress()
    {
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, TestContext.Current.CancellationToken, authorizationCode: provider);

        string root = Path.Combine(_directory, "cleared-" + Guid.NewGuid().ToString("N"));
        var store = new FileMutableSlotStore(root, "mount", FixtureKey());
        AuthenticationProfile profile = FixtureProfile(server);
        await store.CompareAndCommitAsync(
            ClearedDecision(profile, epoch: 2), expectedVersion: null, declaredEpoch: 1,
            TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<CredentialUnavailableException>(() => CreateService(store)
            .AcquireAsync(profile, FixtureCredentials(), TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(0, provider.TokenRequests);
        Assert.Equal(0, provider.RefreshRequests);
    }

    [Fact]
    public async Task Served_path_uses_a_committed_local_authorized_decision()
    {
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, TestContext.Current.CancellationToken, authorizationCode: provider);

        string root = Path.Combine(_directory, "authorized-" + Guid.NewGuid().ToString("N"));
        var store = new FileMutableSlotStore(root, "mount", FixtureKey());
        AuthenticationProfile profile = FixtureProfile(server);
        await store.CompareAndCommitAsync(
            AuthorizedDecision(profile, epoch: 2, revision: 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            TestContext.Current.CancellationToken);

        OAuthAcquisition acquired = await CreateService(store)
            .AcquireAsync(profile, FixtureCredentials(), TestContext.Current.CancellationToken);

        Assert.Equal(provider.AccessToken, Assert.Single(acquired.Credentials).Value);
        Assert.Equal(1, provider.RefreshRequests);
        Assert.Equal(2, acquired.AuthorityEpoch);
        Assert.Equal(0, acquired.RuntimeRevision);

        // The committed successor is a v2 decision, advanced in the same epoch by rotation once the
        // provider returns a new refresh token. A fresh store instance is what the next process sees.
        MutableSlotDecision? decision = await new FileMutableSlotStore(root, "mount", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Authorized, decision!.Kind);
        Assert.Equal(2, decision.AuthorityEpoch);
        Assert.Single(Directory.GetFiles(root, "*.rstate"));
    }

    // ST-1/ST-2/ST-3: the whole standalone bootstrap against a real provider. The CLI seam presents a
    // URL, admits one real callback, exchanges the code with PKCE, and commits an advancing durable
    // decision. A restarted serving acquisition then reads that decision and refreshes exactly once.
    [Fact]
    public async Task Standalone_authorize_commits_a_durable_decision_the_restarted_engine_refreshes()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        int port = LoopbackPorts.Reserve();
        string redirect = $"http://127.0.0.1:{port}/oauth/callback";
        var provider = new AuthorizationCodeProviderScenario(redirect);
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        string root = Path.Combine(_directory, "seam-" + Guid.NewGuid().ToString("N"));
        string stateRoot = Path.Combine(root, "state");
        string keyFile = Path.Combine(root, "key");
        string storeRoot = Path.Combine(root, "files");
        Directory.CreateDirectory(stateRoot);
        Directory.CreateDirectory(storeRoot);
        File.WriteAllBytes(keyFile, FixtureKey());

        string mount = WriteAuthorizationManifest("authorize", server.Address);

        RuntimeStartResult start = EngineRuntime.Start(new RuntimeOptions(
            [new MountRequest("/api", mount)], storeRoot)
        {
            RuntimeStateRoot = stateRoot,
            RuntimeStateKeyFile = keyFile,
        });

        Assert.True(
            start.Started,
            "The runtime refused to start: " + string.Join("; ", start.Refusals.Select(r => r.Code + " " + r.Message)));

        StandaloneAuthorizationStart begun = await StandaloneAuthorization.BeginAsync(
            start,
            new StandaloneAuthorizationTarget("/api", "oauth", new Uri(redirect)),
            TimeProvider.System,
            allowLoopbackAuthorization: true,
            cancellationToken: cancellationToken);

        Assert.True(
            begun.Started,
            "The target was refused: " + string.Join("; ", begun.Refusals.Select(r => r.Code + " " + r.Message)));

        StandaloneAuthorizationAttempt attempt = begun.Attempt!;
        attempt.Begin();

        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        using HttpResponseMessage authorize = await client.GetAsync(attempt.AuthorizationUrl, cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        Uri callback = authorize.Headers.Location!;
        Assert.Equal(redirect, callback.GetLeftPart(UriPartial.Path));

        StandaloneAuthorizationOutcome outcome = await attempt.CompleteAsync(callback.Query, cancellationToken);

        Assert.True(outcome.Authorized, outcome.Code + " " + outcome.Message);
        Assert.Equal("oauth/authorized", outcome.Code);
        Assert.Equal(2, outcome.AuthorityEpoch);
        Assert.Equal(0, outcome.RuntimeRevision);
        Assert.Equal(1, provider.AuthorizationRequests);

        // The provider-issued refresh credential is the durable authority a fresh process reads.
        MutableSlotDecision? decision = await new FileMutableSlotStore(stateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Authorized, decision!.Kind);
        Assert.Equal(2, decision.AuthorityEpoch);
        Assert.Equal(provider.RefreshToken, decision.RefreshToken);

        // A restarted serving acquisition reads the committed decision and refreshes exactly once.
        OAuthAcquisition acquired = await CreateService(new FileMutableSlotStore(stateRoot, "/api", FixtureKey()))
            .AcquireAsync(ManifestProfile(server.Address), FixtureCredentials(), cancellationToken);

        Assert.Equal(provider.AccessToken, Assert.Single(acquired.Credentials).Value);
        Assert.Equal(1, provider.RefreshRequests);
        Assert.Equal(2, acquired.AuthorityEpoch);
        Assert.Equal(0, acquired.RuntimeRevision);
    }

    // OPS-4a/G1: the same bootstrap through the real CLI process rather than the seam, with the
    // operator's explicit loopback allowance. Nothing here runs in-process: the verb parses,
    // leases, starts a runtime, opens the one-shot callback listener, exchanges the code with
    // PKCE and commits the advancing decision.
    [Fact]
    public async Task A_cli_subprocess_authorizes_against_a_loopback_provider_when_the_operator_allows_it()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        int port = LoopbackPorts.Reserve();
        string redirect = $"http://127.0.0.1:{port}/oauth/callback";
        var provider = new AuthorizationCodeProviderScenario(redirect);
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        (string stateRoot, string keyFile, string storeRoot) = CreateDeploymentDirectories("cli-authorize");
        string mount = WriteAuthorizationManifest("cli-authorize", server.Address);

        await using EngineCliProcess child = EngineCliProcess.Start(
            AuthorizationArguments("authorize", mount, storeRoot, stateRoot, keyFile, redirect, allowLoopback: true));

        string authorizationUrl = await child.WaitForStderrLineAsync("authorize?", cancellationToken);

        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        using HttpResponseMessage authorize = await client.GetAsync(
            new Uri(authorizationUrl.Trim()), cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);

        // The provider's redirect lands on the CLI's own listener, which completes the attempt.
        using HttpResponseMessage delivered = await client.GetAsync(authorize.Headers.Location!, cancellationToken);
        Assert.True(delivered.IsSuccessStatusCode, "The registered loopback callback must be delivered.");

        EngineCliOutcome outcome = await child.CompleteAsync(cancellationToken);

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("authorized /api oauth oauth/authorized", outcome.Stdout, StringComparison.Ordinal);
        Assert.Contains("authority epoch 2", outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(provider.AccessToken, outcome.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(provider.RefreshToken, outcome.Stdout, StringComparison.Ordinal);

        MutableSlotDecision? decision = await new FileMutableSlotStore(stateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Authorized, decision!.Kind);
        Assert.Equal(2, decision.AuthorityEpoch);
        Assert.Equal(0, decision.RuntimeRevision);
        Assert.Equal(provider.RefreshToken, decision.RefreshToken);

        // The serving path, restarted against the same store, refreshes once from that decision.
        OAuthAcquisition acquired = await CreateService(new FileMutableSlotStore(stateRoot, "/api", FixtureKey()))
            .AcquireAsync(ManifestProfile(server.Address), FixtureCredentials(), cancellationToken);

        Assert.Equal(provider.AccessToken, Assert.Single(acquired.Credentials).Value);
        Assert.Equal(1, provider.RefreshRequests);
    }

    // The other side of the same bound: with no allowance the shipped table stops the exchange, the
    // process reports it, and nothing durable is written. This is what every deployment that has not
    // asked for the allowance does.
    [Fact]
    public async Task A_cli_subprocess_refuses_a_loopback_provider_without_the_allowance()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        int port = LoopbackPorts.Reserve();
        string redirect = $"http://127.0.0.1:{port}/oauth/callback";
        var provider = new AuthorizationCodeProviderScenario(redirect);
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        (string stateRoot, string keyFile, string storeRoot) = CreateDeploymentDirectories("cli-refused");
        string mount = WriteAuthorizationManifest("cli-refused", server.Address);

        await using EngineCliProcess child = EngineCliProcess.Start(
            AuthorizationArguments("authorize", mount, storeRoot, stateRoot, keyFile, redirect, allowLoopback: false));

        string authorizationUrl = await child.WaitForStderrLineAsync("authorize?", cancellationToken);

        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        using HttpResponseMessage authorize = await client.GetAsync(
            new Uri(authorizationUrl.Trim()), cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        using HttpResponseMessage delivered = await client.GetAsync(authorize.Headers.Location!, cancellationToken);
        Assert.True(delivered.IsSuccessStatusCode, "The registered loopback callback must be delivered.");

        EngineCliOutcome outcome = await child.CompleteAsync(cancellationToken);

        Assert.Equal(ExitCodes.Failure, outcome.ExitCode);
        Assert.Contains("oauth/provider-exchange-failed", outcome.Stdout, StringComparison.Ordinal);
        Assert.Contains("Nothing was changed", outcome.Stdout, StringComparison.Ordinal);
        Assert.Equal(0, provider.TokenRequests);
        Assert.Empty(Directory.GetFiles(stateRoot, "*.rstate", SearchOption.AllDirectories));
    }

    // OPS-5a/OPS-5c: a real CLI clear reports the local floor and the provider result separately, and
    // the allowance is what lets the same process reach the loopback revocation endpoint.
    [Fact]
    public async Task A_cli_subprocess_clear_revokes_at_a_loopback_endpoint_when_the_operator_allows_it()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        (string stateRoot, string keyFile, string storeRoot) = CreateDeploymentDirectories("cli-clear");
        Uri revocation = new(server.Address, "revoke");
        string mount = WriteAuthorizationManifest("cli-clear", server.Address, revocation);
        AuthenticationProfile profile = ManifestProfile(server.Address, revocation);

        await new FileMutableSlotStore(stateRoot, "/api", FixtureKey()).CompareAndCommitAsync(
            AuthorizedDecision(profile, epoch: 2, revision: 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        EngineCliOutcome outcome = await EngineCliProcess.RunAsync(
            cancellationToken,
            AuthorizationArguments("clear", mount, storeRoot, stateRoot, keyFile, redirect: null, allowLoopback: true));

        Assert.Equal(ExitCodes.Success, outcome.ExitCode);
        Assert.Contains("cleared /api oauth oauth/cleared", outcome.Stdout, StringComparison.Ordinal);
        Assert.Contains("provider revocation: revoked", outcome.Stdout, StringComparison.Ordinal);
        Assert.Equal(1, provider.RevocationRequests);
        Assert.DoesNotContain(provider.RefreshToken, outcome.Stdout, StringComparison.Ordinal);

        MutableSlotDecision? decision = await new FileMutableSlotStore(stateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Cleared, decision!.Kind);
        Assert.Equal(3, decision.AuthorityEpoch);
        Assert.Null(decision.RefreshToken);
    }

    // OPS-2/ST-3f: an operator clear commits a floor the next process and the provider both see.
    [Fact]
    public async Task Standalone_clear_commits_a_floor_a_restarted_engine_cannot_bypass()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario();
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        (string stateRoot, string keyFile, string storeRoot) = CreateDeploymentDirectories("clear");
        Uri revocation = new(server.Address, "revoke");
        string mount = WriteAuthorizationManifest("clear", server.Address, revocation);
        RuntimeStartResult start = StartRuntime(mount, storeRoot, stateRoot, keyFile);
        AuthenticationProfile profile = ManifestProfile(server.Address, revocation);

        await new FileMutableSlotStore(stateRoot, "/api", FixtureKey()).CompareAndCommitAsync(
            AuthorizedDecision(profile, epoch: 2, revision: 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        StandaloneClearOutcome cleared = await StandaloneAuthorizationOperations.ClearAsync(
            start, "/api", "oauth", TimeProvider.System,
            allowLoopbackAuthorization: true, cancellationToken: cancellationToken);

        Assert.True(cleared.Cleared, cleared.Code + " " + cleared.Message);
        Assert.Equal("oauth/cleared", cleared.Code);
        Assert.Equal("cleared", cleared.LocalOutcome);
        Assert.Equal("revoked", cleared.ProviderOutcome);
        Assert.Equal(1, provider.RevocationRequests);

        IReadOnlyList<StandaloneAuthorizationStatus> report = await StandaloneAuthorizationOperations
            .DescribeAsync(start, "/api", "oauth", cancellationToken: cancellationToken);
        Assert.Equal(StandaloneAuthorizationState.Cleared, Assert.Single(report).State);

        // A fresh process reads an advancing cleared floor, and the retired record is gone.
        MutableSlotDecision? decision = await new FileMutableSlotStore(stateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Cleared, decision!.Kind);
        Assert.Equal(3, decision.AuthorityEpoch);
        Assert.Null(decision.RefreshToken);

        // Neither the retired runtime record nor the Manifest-declared source can be used.
        Assert.Equal(0, provider.RefreshRequests);
        await Assert.ThrowsAsync<CredentialUnavailableException>(() => CreateService(new FileMutableSlotStore(stateRoot, "/api", FixtureKey()))
            .AcquireAsync(profile, FixtureCredentials(), cancellationToken).AsTask());
        Assert.Equal(0, provider.RefreshRequests);
        Assert.Equal(1, provider.RevocationRequests);
    }

    // OPS-2a: an explicit newer authorization restores operation after a clear.
    [Fact]
    public async Task Standalone_authorize_after_a_clear_restores_operation()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        int port = LoopbackPorts.Reserve();
        string redirect = $"http://127.0.0.1:{port}/oauth/callback";
        var provider = new AuthorizationCodeProviderScenario(redirect);
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        (string stateRoot, string keyFile, string storeRoot) = CreateDeploymentDirectories("reauthorize");
        string mount = WriteAuthorizationManifest("reauthorize", server.Address);
        RuntimeStartResult start = StartRuntime(mount, storeRoot, stateRoot, keyFile);
        AuthenticationProfile profile = ManifestProfile(server.Address);

        await new FileMutableSlotStore(stateRoot, "/api", FixtureKey()).CompareAndCommitAsync(
            AuthorizedDecision(profile, epoch: 2, revision: 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        StandaloneClearOutcome cleared = await StandaloneAuthorizationOperations.ClearAsync(
            start, "/api", "oauth", TimeProvider.System,
            allowLoopbackAuthorization: true, cancellationToken: cancellationToken);
        Assert.True(cleared.Cleared, cleared.Code + " " + cleared.Message);

        StandaloneAuthorizationStart begun = await StandaloneAuthorization.BeginAsync(
            start,
            new StandaloneAuthorizationTarget("/api", "oauth", new Uri(redirect)),
            TimeProvider.System,
            allowLoopbackAuthorization: true,
            cancellationToken: cancellationToken);
        Assert.True(begun.Started, string.Join("; ", begun.Refusals.Select(refusal => refusal.Code + " " + refusal.Message)));

        StandaloneAuthorizationAttempt attempt = begun.Attempt!;
        attempt.Begin();

        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        using HttpResponseMessage authorize = await client.GetAsync(attempt.AuthorizationUrl, cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);

        StandaloneAuthorizationOutcome authorized = await attempt.CompleteAsync(authorize.Headers.Location!.Query, cancellationToken);
        Assert.True(authorized.Authorized, authorized.Code + " " + authorized.Message);
        Assert.Equal(4, authorized.AuthorityEpoch);

        // The next process uses the newly committed authority and nothing older.
        OAuthAcquisition acquired = await CreateService(new FileMutableSlotStore(stateRoot, "/api", FixtureKey()))
            .AcquireAsync(profile, FixtureCredentials(), cancellationToken);
        Assert.Equal(provider.AccessToken, Assert.Single(acquired.Credentials).Value);
        Assert.Equal(1, provider.RefreshRequests);
        Assert.Equal(4, acquired.AuthorityEpoch);
    }

    // OPS-5b: a refused revocation changes the reported provider outcome and nothing else.
    [Fact]
    public async Task Standalone_clear_revocation_denial_keeps_the_local_clear()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario { Revocation = RevocationBehaviour.Reject };
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        (string stateRoot, string keyFile, string storeRoot) = CreateDeploymentDirectories("revoke-denied");
        Uri revocation = new(server.Address, "revoke");
        string mount = WriteAuthorizationManifest("revoke-denied", server.Address, revocation);
        RuntimeStartResult start = StartRuntime(mount, storeRoot, stateRoot, keyFile);
        AuthenticationProfile profile = ManifestProfile(server.Address, revocation);

        await new FileMutableSlotStore(stateRoot, "/api", FixtureKey()).CompareAndCommitAsync(
            AuthorizedDecision(profile, epoch: 2, revision: 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        StandaloneClearOutcome cleared = await StandaloneAuthorizationOperations.ClearAsync(
            start, "/api", "oauth", TimeProvider.System,
            allowLoopbackAuthorization: true, cancellationToken: cancellationToken);

        Assert.True(cleared.Cleared, cleared.Code + " " + cleared.Message);
        Assert.Equal("cleared", cleared.LocalOutcome);
        Assert.Equal("failed", cleared.ProviderOutcome);
        Assert.Equal(1, provider.RevocationRequests);
        Assert.DoesNotContain("CANARY-revocation-secret-4a1f", cleared.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-revocation-secret-4a1f", cleared.ProviderDetail, StringComparison.Ordinal);

        MutableSlotDecision? decision = await new FileMutableSlotStore(stateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.Equal(MutableSlotDecisionKind.Cleared, decision!.Kind);
        Assert.Equal(3, decision.AuthorityEpoch);
    }

    // OPS-5b: a stalling provider is bounded, and the local clear is already committed regardless.
    [Fact]
    public async Task Standalone_clear_revocation_attempt_is_bounded_when_the_provider_stalls()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var provider = new AuthorizationCodeProviderScenario { RevocationDelay = TimeSpan.FromSeconds(60) };
        await using var server = await FakeAuthorizationServer.StartAsync(
            active: true, cancellationToken, authorizationCode: provider);

        (string stateRoot, string keyFile, string storeRoot) = CreateDeploymentDirectories("revoke-stalled");
        Uri revocation = new(server.Address, "revoke");
        string mount = WriteAuthorizationManifest("revoke-stalled", server.Address, revocation);
        RuntimeStartResult start = StartRuntime(mount, storeRoot, stateRoot, keyFile);
        AuthenticationProfile profile = ManifestProfile(server.Address, revocation);

        await new FileMutableSlotStore(stateRoot, "/api", FixtureKey()).CompareAndCommitAsync(
            AuthorizedDecision(profile, epoch: 2, revision: 0, provider.RefreshToken),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));

        StandaloneClearOutcome cleared = await StandaloneAuthorizationOperations.ClearAsync(
            start, "/api", "oauth", TimeProvider.System,
            allowLoopbackAuthorization: true, cancellationToken: deadline.Token);

        Assert.True(cleared.Cleared, cleared.Code + " " + cleared.Message);
        Assert.Equal("cleared", cleared.LocalOutcome);
        Assert.Equal("failed", cleared.ProviderOutcome);
        Assert.Equal(1, provider.RevocationRequests);

        MutableSlotDecision? decision = await new FileMutableSlotStore(stateRoot, "/api", FixtureKey())
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.Equal(MutableSlotDecisionKind.Cleared, decision!.Kind);
    }

    /// <summary>
    /// The arguments a real CLI bootstrap or clear runs with, so a process-level case and a
    /// seam-level case cannot drift apart in their deployment settings.
    /// </summary>
    private static string[] AuthorizationArguments(
        string verb,
        string manifestDirectory,
        string storeRoot,
        string stateRoot,
        string keyFile,
        string? redirect,
        bool allowLoopback)
    {
        List<string> arguments =
        [
            "auth", verb, "/api", "oauth",
            "--file-store-root", storeRoot,
            "--runtime-state-root", stateRoot,
            "--runtime-state-key-file", keyFile,
            "--mount", "/api=" + manifestDirectory,
        ];

        if (redirect is not null)
        {
            arguments.Add("--oauth-redirect-uri");
            arguments.Add(redirect);
        }

        if (allowLoopback)
        {
            arguments.Add("--allow-loopback-authorization");
            arguments.Add("true");
        }

        return [.. arguments];
    }

    /// <summary>A private state/key/store triple for a deployment a test drives directly.</summary>
    private (string StateRoot, string KeyFile, string StoreRoot) CreateDeploymentDirectories(string name)
    {
        string root = Path.Combine(_directory, name + "-" + Guid.NewGuid().ToString("N"));
        string stateRoot = Path.Combine(root, "state");
        string storeRoot = Path.Combine(root, "files");
        Directory.CreateDirectory(stateRoot);
        Directory.CreateDirectory(storeRoot);
        string keyFile = Path.Combine(root, "state.key");
        File.WriteAllBytes(keyFile, FixtureKey());
        return (stateRoot, keyFile, storeRoot);
    }

    private static RuntimeStartResult StartRuntime(string mount, string storeRoot, string stateRoot, string keyFile)
    {
        RuntimeStartResult start = EngineRuntime.Start(new RuntimeOptions(
            [new MountRequest("/api", mount)], storeRoot)
        {
            RuntimeStateRoot = stateRoot,
            RuntimeStateKeyFile = keyFile,
        });

        Assert.True(
            start.Started,
            "The runtime refused to start: " + string.Join("; ", start.Refusals.Select(refusal => refusal.Code + " " + refusal.Message)));

        return start;
    }

    /// <summary>A manifest whose OAuth profile points at the live loopback provider.</summary>
    private string WriteAuthorizationManifest(string name, Uri serverAddress, Uri? revocationEndpoint = null)
    {
        string directory = Path.Combine(_directory, name + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string authority = serverAddress.GetLeftPart(UriPartial.Authority);
        string revocation = revocationEndpoint is null
            ? string.Empty
            : ",\n                          \"revocationEndpoint\": \"" + revocationEndpoint + "\"";
        File.WriteAllText(Path.Combine(directory, "manifest.json"), $$"""
            {
              "manifestFormatVersion": "0.3",
              "sections": {
                "server": { "inline": { "name": "Seam API", "authenticationRequired": false } },
                "policy": { "inline": { "baseUrl": "https://api.example.com" } },
                "operations": {
                  "inline": { "operations": [ { "key": "GET /pets", "method": "GET", "path": "/pets" } ] }
                },
                "agentSurface": {
                  "inline": {
                    "operations": [
                      {
                        "slug": "list-pets",
                        "name": "List pets",
                        "binding": { "type": "http", "operation": "GET /pets", "authenticationRef": "oauth" }
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
                        "value": { "fromEnv": "MCPILER_SEAM_UNUSED_REFRESH" }
                      }
                    ]
                  }
                },
                "authentication": {
                  "inline": {
                    "formatVersion": 2,
                    "profiles": [
                      {
                        "id": "oauth",
                        "kind": "oauth2-authorization-code-pkce-refresh",
                        "configuration": {
                          "strategyId": "oauth2-authorization-code-pkce-refresh",
                          "inputs": { "clientId": "test-client" },
                          "clientId": "test-client",
                          "tokenAuthMethod": "none",
                          "authorizationEndpoint": "{{serverAddress}}authorize",
                          "tokenEndpoint": "{{serverAddress}}token"{{revocation}}
                        },
                        "authenticationOrigins": ["{{authority}}"],
                        "destinationOrigins": ["{{authority}}"],
                        "credentialRef": ["oauth-refresh"],
                        "scopeFingerprint": "{{ManifestScopeFingerprint}}",
                        "slots": [ { "slot": "refreshToken", "authorityEpoch": 1, "runtimeRevision": 0 } ]
                      }
                    ]
                  }
                }
              }
            }
            """);
        return directory;
    }

    private static AuthenticationProfile ManifestProfile(Uri serverAddress, Uri? revocationEndpoint = null) => new(
        "oauth",
        AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
        CanonicalJson.Parse(Encoding.UTF8.GetBytes($$"""
            {"strategyId":"oauth2-authorization-code-pkce-refresh",
             "clientId":"test-client", "tokenAuthMethod":"none",
             "authorizationEndpoint":"{{serverAddress}}authorize",
             "tokenEndpoint":"{{serverAddress}}token"{{(revocationEndpoint is null ? string.Empty : ",\n \"revocationEndpoint\":\"" + revocationEndpoint + "\"")}}}
            """))!.AsObject(),
        [serverAddress.GetLeftPart(UriPartial.Authority)],
        [serverAddress.GetLeftPart(UriPartial.Authority)],
        [], ManifestScopeFingerprint, [new AuthenticationSlot("refreshToken", 1, 0)]);

    private static byte[] FixtureKey()
        => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    private static AuthenticationProfile FixtureProfile(FakeAuthorizationServer server) => new(
        "oauth",
        AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
        CanonicalJson.Parse(Encoding.UTF8.GetBytes($$"""
            {"strategyId":"oauth2-authorization-code-pkce-refresh",
             "clientId":"test-client", "tokenAuthMethod":"none",
             "authorizationEndpoint":"{{server.Address}}authorize",
             "tokenEndpoint":"{{server.Address}}token"}
            """))!.AsObject(),
        [server.Address.GetLeftPart(UriPartial.Authority)],
        [server.Address.GetLeftPart(UriPartial.Authority)],
        [], "fixture-scope", [new AuthenticationSlot("refreshToken", 1, 0)]);

    private static IReadOnlyList<ResolvedCredential> FixtureCredentials() =>
    [
        new(new ManifestCredential("initial", CredentialScheme.OAuth2AuthorizationCode,
            "refreshToken", CredentialReference.Literal("fixture")), "CANARY-declared-fallback"),
    ];

    private static OAuthTokenService CreateService(FileMutableSlotStore store)
        => new(new OAuthTokenEndpointClient(
                new UpstreamSender(new UpstreamClientFactory(new OutboundConnectionPolicy(_ => false))),
                TimeProvider.System),
            new AccessTokenCache(), new AccessTokenSingleFlight(), store, TimeProvider.System);

    private static MutableSlotDecision AuthorizedDecision(
        AuthenticationProfile profile, long epoch, long revision, string refresh)
        => new(
            profile.Id,
            "refreshToken",
            profile.ScopeFingerprint,
            AuthorityBinding.Declaration(profile),
            AuthorityBinding.Configuration(OAuthStrategyConfiguration.FromConfiguration(
                profile.Configuration, authorizationCodeRequired: true)),
            epoch,
            revision,
            MutableSlotDecisionKind.Authorized,
            refresh);

    private static MutableSlotDecision ClearedDecision(AuthenticationProfile profile, long epoch)
        => new(
            profile.Id,
            "refreshToken",
            profile.ScopeFingerprint,
            AuthorityBinding.Declaration(profile),
            AuthorityBinding.Configuration(OAuthStrategyConfiguration.FromConfiguration(
                profile.Configuration, authorizationCodeRequired: true)),
            epoch,
            0,
            MutableSlotDecisionKind.Cleared,
            null);
}
