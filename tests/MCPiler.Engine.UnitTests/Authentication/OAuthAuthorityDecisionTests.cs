using System.Text;
using System.Text.Json;
using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Caching;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;
using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// Characterizes the original v1 encrypted authority boundary via normal OAuth acquisition.
/// This fixture is reused as v2 authorized/cleared decision and binding semantics are added in T02–T04.
/// No fixture treats an unreadable record as an absent credential.
/// </summary>
public sealed class OAuthAuthorityDecisionTests : IDisposable
{
    private const string LegacyCanary = "CANARY-legacy-refresh-authority";
    private const string ManifestCanary = "CANARY-manifest-refresh-authority";
    private static readonly byte[] Key = Convert.FromHexString(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private readonly string _root = Path.Combine(Path.GetTempPath(), "oauth-authority-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Theory]
    [InlineData(false, "refresh_token=CANARY-manifest-refresh-authority")]
    [InlineData(true, "refresh_token=CANARY-legacy-refresh-authority")]
    public async Task Absent_and_legacy_authority_select_the_expected_refresh_source(
        bool hasLegacyRecord, string expectedBody)
    {
        var store = Open();
        if (hasLegacyRecord)
        {
            await SeedLegacyAsync(store);
        }

        var provider = new RecordingProvider();
        OAuthAcquisition result = await Service(store, provider).AcquireAsync(
            Profile(), ManifestCredentials(), TestContext.Current.CancellationToken);

        Assert.Equal("CANARY-access-token", Assert.Single(result.Credentials).Value);
        Assert.Contains(expectedBody, Assert.Single(provider.Requests), StringComparison.Ordinal);
        Assert.Equal(hasLegacyRecord ? 1 : 0, Directory.GetFiles(_root, "*.rstate").Length);
    }

    [Theory]
    [InlineData("changed-scope", 1, 0)]
    [InlineData("fixture-scope", 2, 0)]
    [InlineData("fixture-scope", 1, 5)]
    public async Task Legacy_record_ineligible_for_declared_binding_uses_manifest_refresh_source(
        string scopeFingerprint, long authorityEpoch, long runtimeRevision)
    {
        var store = Open();
        await SeedLegacyAsync(store);
        string recordPath = Assert.Single(Directory.GetFiles(_root, "*.rstate"));
        byte[] originalBytes = File.ReadAllBytes(recordPath);
        var provider = new RecordingProvider();

        await Service(store, provider).AcquireAsync(
            Profile(scopeFingerprint, authorityEpoch, runtimeRevision),
            ManifestCredentials(), TestContext.Current.CancellationToken);

        Assert.Contains("refresh_token=" + ManifestCanary,
            Assert.Single(provider.Requests), StringComparison.Ordinal);
        Assert.Equal(originalBytes, File.ReadAllBytes(recordPath));
        MutableSlotRecord retained = Assert.IsType<MutableSlotRecord>(
            await Open().LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
        Assert.Equal(LegacyCanary, retained.Value);
        Assert.Equal(4, retained.RuntimeRevision);
    }

    [Theory]
    [InlineData("replacement-client", "https://auth.example.test/token")]
    [InlineData("test-client", "https://auth.example.test/another-token-endpoint")]
    public async Task Legacy_v1_record_does_not_bind_client_configuration_beyond_scope_fingerprint(
        string clientId, string tokenEndpoint)
    {
        // Characterization of a v1 limitation, NOT the expected v2 contract: T02 must bind
        // an explicit authorized successor to the validated client configuration as well.
        var store = Open();
        await SeedLegacyAsync(store);
        string path = Assert.Single(Directory.GetFiles(_root, "*.rstate"));
        byte[] before = File.ReadAllBytes(path);
        var provider = new RecordingProvider();

        await Service(store, provider).AcquireAsync(
            Profile(clientId: clientId, tokenEndpoint: tokenEndpoint),
            ManifestCredentials(), TestContext.Current.CancellationToken);

        Assert.Contains("refresh_token=" + LegacyCanary,
            Assert.Single(provider.Requests), StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData(false, "changed-scope", 1, 0)]
    [InlineData(true, "fixture-scope", 2, 0)]
    [InlineData(false, "fixture-scope", 1, 5)]
    public async Task Unreadable_legacy_record_blocks_changed_declaration_before_any_provider_request(
        bool wrongKey, string scopeFingerprint, long authorityEpoch, long runtimeRevision)
    {
        var store = Open();
        await SeedLegacyAsync(store);
        string recordPath = Assert.Single(Directory.GetFiles(_root, "*.rstate"));
        FileMutableSlotStore reader;
        if (wrongKey)
        {
            reader = Open(Enumerable.Repeat((byte)0xFF, 32).ToArray());
        }
        else
        {
            byte[] corrupt = File.ReadAllBytes(recordPath);
            corrupt[^1] ^= 0x01;
            File.WriteAllBytes(recordPath, corrupt);
            reader = Open();
        }

        byte[] initialBytes = File.ReadAllBytes(recordPath);
        var provider = new RecordingProvider();
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => Service(reader, provider)
            .AcquireAsync(Profile(scopeFingerprint, authorityEpoch, runtimeRevision),
                ManifestCredentials(), TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(provider.Requests);
        Assert.Equal(initialBytes, File.ReadAllBytes(recordPath));
    }

    [Fact]
    public async Task Unreadable_legacy_record_blocks_changed_client_configuration_before_provider_egress()
    {
        var original = Open();
        await SeedLegacyAsync(original);
        string path = Assert.Single(Directory.GetFiles(_root, "*.rstate"));
        byte[] corrupt = File.ReadAllBytes(path);
        corrupt[^1] ^= 0x01;
        File.WriteAllBytes(path, corrupt);
        var provider = new RecordingProvider();

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => Service(Open(), provider)
            .AcquireAsync(Profile(clientId: "replacement-client"),
                ManifestCredentials(), TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(provider.Requests);
        Assert.Equal(corrupt, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task Committed_rotation_survives_postcommit_failure_and_fresh_acquisition_uses_new_secret()
    {
        var store = Open();
        await SeedLegacyAsync(store, revision: 0);
        store.CompactionBarrier = () => throw new IOException("injected post-commit maintenance failure");
        var rotatingProvider = new RecordingProvider(rotate: true);

        OAuthAcquisition acquired = await Service(store, rotatingProvider).AcquireAsync(
            Profile(), ManifestCredentials(), TestContext.Current.CancellationToken);

        Assert.Equal("CANARY-access-token", Assert.Single(acquired.Credentials).Value);
        Assert.Contains("refresh_token=" + LegacyCanary,
            Assert.Single(rotatingProvider.Requests), StringComparison.Ordinal);
        MutableSlotRecord committed = Assert.IsType<MutableSlotRecord>(
            await Open().LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
        Assert.Equal("CANARY-next-refresh", committed.Value);
        Assert.Equal(1, committed.RuntimeRevision);

        var subsequentProvider = new RecordingProvider();
        await Service(Open(), subsequentProvider).AcquireAsync(
            Profile(), ManifestCredentials(), TestContext.Current.CancellationToken);
        Assert.Contains("refresh_token=CANARY-next-refresh",
            Assert.Single(subsequentProvider.Requests), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_committed_v2_rotation_survives_and_advances_the_local_decision()
    {
        var store = Open();
        var profile = Profile();
        await store.CompareAndCommitAsync(
            AuthorizedDecision(profile, epoch: 2, revision: 0, "CANARY-v2-local"),
            expectedVersion: null,
            declaredEpoch: 1,
            TestContext.Current.CancellationToken);

        var provider = new RecordingProvider(rotate: true);
        OAuthAcquisition acquired = await Service(store, provider).AcquireAsync(
            profile, ManifestCredentials(), TestContext.Current.CancellationToken);

        Assert.Equal("CANARY-access-token", Assert.Single(acquired.Credentials).Value);
        Assert.Contains("refresh_token=CANARY-v2-local", Assert.Single(provider.Requests), StringComparison.Ordinal);
        Assert.Equal(2, acquired.AuthorityEpoch);
        Assert.Equal(1, acquired.RuntimeRevision);

        MutableSlotDecision? decision = await Open().LoadDecisionAsync(
            "oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.NotNull(decision);
        Assert.Equal(MutableSlotDecisionKind.Authorized, decision!.Kind);
        Assert.Equal("CANARY-next-refresh", decision.RefreshToken);
        Assert.Equal(2, decision.AuthorityEpoch);
        Assert.Equal(1, decision.RuntimeRevision);
    }

    [Fact]
    public async Task A_v2_rotation_commit_failure_retains_the_predecessor_and_publishes_nothing()
    {
        var store = Open();
        var profile = Profile();
        await store.CompareAndCommitAsync(
            AuthorizedDecision(profile, epoch: 2, revision: 0, "CANARY-v2-local"),
            expectedVersion: null,
            declaredEpoch: 1,
            TestContext.Current.CancellationToken);
        store.TempFlushedBarrier = _ => throw new IOException("injected pre-commit failure");

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => Service(store, new RecordingProvider(rotate: true))
            .AcquireAsync(profile, ManifestCredentials(), TestContext.Current.CancellationToken).AsTask());

        MutableSlotDecision? retained = await Open().LoadDecisionAsync(
            "oauth", "refreshToken", TestContext.Current.CancellationToken);
        Assert.NotNull(retained);
        Assert.Equal(MutableSlotDecisionKind.Authorized, retained!.Kind);
        Assert.Equal("CANARY-v2-local", retained.RefreshToken);
        Assert.Equal(0, retained.RuntimeRevision);
    }

    [Fact]
    public async Task A_cleared_decision_refuses_served_acquisition_over_the_file_store()
    {
        var store = Open();
        var profile = Profile();
        await store.CompareAndCommitAsync(
            ClearedDecision(profile, epoch: 2), expectedVersion: null, declaredEpoch: 1,
            TestContext.Current.CancellationToken);

        var provider = new RecordingProvider();
        await Assert.ThrowsAsync<CredentialUnavailableException>(() => Service(store, provider)
            .AcquireAsync(profile, ManifestCredentials(), TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(provider.Requests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Corrupt_or_wrong_key_authority_refuses_before_provider_egress(bool wrongKey)
    {
        var original = Open();
        await SeedLegacyAsync(original);

        FileMutableSlotStore reader;
        if (wrongKey)
        {
            reader = Open(Enumerable.Repeat((byte)0xFF, 32).ToArray());
        }
        else
        {
            string record = Assert.Single(Directory.GetFiles(_root, "*.rstate"));
            byte[] encrypted = File.ReadAllBytes(record);
            encrypted[^1] ^= 0x01;
            File.WriteAllBytes(record, encrypted);
            reader = Open();
        }

        var provider = new RecordingProvider();
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => Service(reader, provider)
            .AcquireAsync(Profile(), ManifestCredentials(), TestContext.Current.CancellationToken).AsTask());

        Assert.Empty(provider.Requests);
        Assert.Single(Directory.GetFiles(_root, "*.rstate"));
    }

    [Fact]
    public async Task Failed_rotation_commit_does_not_publish_token_and_fresh_load_retains_prior_record()
    {
        var store = Open();
        await SeedLegacyAsync(store, revision: 0);
        var provider = new RecordingProvider(rotate: true);
        OAuthTokenService service = Service(store, provider);
        store.TempFlushedBarrier = _ => throw new IOException("injected pre-commit failure");

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => service
            .AcquireAsync(Profile(), ManifestCredentials(), TestContext.Current.CancellationToken).AsTask());

        // The failed transition did not make the new access token observable. Check a fresh
        // store instance and then run ordinary acquisition through the SAME cache instance.
        var fresh = Open();
        MutableSlotRecord retained = Assert.IsType<MutableSlotRecord>(
            await fresh.LoadAsync("oauth", "refreshToken", TestContext.Current.CancellationToken));
        Assert.Equal(LegacyCanary, retained.Value);
        Assert.Equal(0, retained.RuntimeRevision);

        store.TempFlushedBarrier = null;
        await service.AcquireAsync(Profile(), ManifestCredentials(), TestContext.Current.CancellationToken);
        Assert.Equal(2, provider.Requests.Count);
        Assert.All(provider.Requests, body => Assert.Contains("refresh_token=" + LegacyCanary, body, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Two_mounts_with_same_profile_in_shared_root_keep_legacy_authorities_separate()
    {
        var mountA = Open();
        var mountB = new FileMutableSlotStore(_root, "/another-mount", Key);
        const string mountASecret = "CANARY-mount-A-refresh";
        const string mountBSecret = "CANARY-mount-B-refresh";
        var cancellationToken = TestContext.Current.CancellationToken;

        await mountA.ReplaceAsync(new MutableSlotRecord(
            "oauth", "refreshToken", "fixture-scope", 1, 0, mountASecret), cancellationToken);
        await mountB.ReplaceAsync(new MutableSlotRecord(
            "oauth", "refreshToken", "fixture-scope", 1, 0, mountBSecret), cancellationToken);

        // Distinct runtime mounts may contain identical local profile/slot identities. Reopen
        // both from disk and use the ordinary token-acquisition path, not a private decoder.
        var providerA = new RecordingProvider();
        var providerB = new RecordingProvider();
        await Service(Open(), providerA).AcquireAsync(Profile(), ManifestCredentials(), cancellationToken);
        await Service(new FileMutableSlotStore(_root, "/another-mount", Key), providerB)
            .AcquireAsync(Profile(), ManifestCredentials(), cancellationToken);

        Assert.Contains("refresh_token=" + mountASecret, Assert.Single(providerA.Requests), StringComparison.Ordinal);
        Assert.Contains("refresh_token=" + mountBSecret, Assert.Single(providerB.Requests), StringComparison.Ordinal);
        string[] records = Directory.GetFiles(_root, "*.rstate");
        Assert.Equal(2, records.Length);
        foreach (string path in records)
        {
            string ciphertext = Encoding.UTF8.GetString(File.ReadAllBytes(path));
            Assert.DoesNotContain(mountASecret, ciphertext, StringComparison.Ordinal);
            Assert.DoesNotContain(mountBSecret, ciphertext, StringComparison.Ordinal);
        }
    }

    // OPS-2g: an acknowledged reset retires unreadable authority by one atomic replacement, so the
    // slot is never observably absent and no earlier source can reappear in the gap.
    [Fact]
    public async Task An_acknowledged_baseline_retires_unreadable_authority_with_one_commit()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // A record written by a key this deployment no longer has: readable bytes it cannot authenticate.
        var stale = Open(Enumerable.Repeat((byte)0x5A, 32).ToArray());
        await SeedLegacyAsync(stale);
        var deployment = Open();

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => deployment
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken).AsTask());

        MutableSlotDecision established = await deployment.EstablishBaselineAsync(
            ClearedDecision(Profile(), epoch: 2), declaredEpoch: 1, cancellationToken);

        Assert.Equal(MutableSlotDecisionKind.Cleared, established.Kind);
        Assert.Equal(2, established.AuthorityEpoch);
        Assert.Equal(0, established.RuntimeRevision);
        Assert.Null(established.RefreshToken);
        Assert.False(established.IsLegacy);

        // A fresh process authenticates the baseline: the slot is cleared, not absent.
        MutableSlotDecision? fresh = await Open().LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.NotNull(fresh);
        Assert.Equal(MutableSlotDecisionKind.Cleared, fresh!.Kind);
        Assert.Equal(2, fresh.AuthorityEpoch);
        Assert.Single(Directory.GetFiles(_root, "*.rstate"));

        // The retired v1 record is gone, so the pre-reset declared source stays masked.
        await Assert.ThrowsAsync<CredentialUnavailableException>(() => Service(deployment, new RecordingProvider())
            .AcquireAsync(Profile(), ManifestCredentials(), cancellationToken).AsTask());
    }

    // OPS-2g: an interrupted reset must remain fail-closed for every affected slot.
    [Fact]
    public async Task An_interrupted_baseline_leaves_the_unreadable_record_and_stays_fail_closed()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await SeedLegacyAsync(Open());
        string path = Assert.Single(Directory.GetFiles(_root, "*.rstate"));
        byte[] before = File.ReadAllBytes(path);

        byte[] unreadable = Enumerable.Repeat((byte)0xFF, 32).ToArray();
        var reader = Open(unreadable);
        reader.TempFlushedBarrier = _ => throw new IOException("injected pre-commit failure");

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => reader
            .EstablishBaselineAsync(ClearedDecision(Profile(), epoch: 2), declaredEpoch: 1, cancellationToken).AsTask());

        // The predecessor is byte-for-byte intact and still unreadable: no absent window, no
        // resurrection of the Manifest-declared credential.
        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(_root, "*.rstate"));
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => Open(unreadable)
            .LoadDecisionAsync("oauth", "refreshToken", cancellationToken).AsTask());
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => Service(reader, new RecordingProvider())
            .AcquireAsync(Profile(), ManifestCredentials(), cancellationToken).AsTask());
    }

    // A reset is for authority this deployment cannot read; a readable newer decision is never regressed.
    [Fact]
    public async Task A_baseline_never_regresses_a_readable_newer_decision()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var store = Open();
        await store.CompareAndCommitAsync(
            AuthorizedDecision(Profile(), epoch: 5, revision: 0, "CANARY-newer-authority"),
            expectedVersion: null,
            declaredEpoch: 1,
            cancellationToken);

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store
            .EstablishBaselineAsync(ClearedDecision(Profile(), epoch: 2), declaredEpoch: 1, cancellationToken).AsTask());

        MutableSlotDecision? read = await Open().LoadDecisionAsync("oauth", "refreshToken", cancellationToken);
        Assert.NotNull(read);
        Assert.Equal(MutableSlotDecisionKind.Authorized, read!.Kind);
        Assert.Equal(5, read.AuthorityEpoch);
    }

    [Fact]
    public async Task An_in_memory_baseline_advances_once_and_refuses_every_regression()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var memory = new InMemoryMutableSlotStore();

        MutableSlotDecision established = await memory.EstablishBaselineAsync(
            ClearedDecision(Profile(), epoch: 2), declaredEpoch: 1, cancellationToken);

        Assert.Equal(MutableSlotDecisionKind.Cleared, established.Kind);
        Assert.False(established.IsLegacy);
        Assert.NotEmpty(established.Version);

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => memory
            .EstablishBaselineAsync(ClearedDecision(Profile(), epoch: 2), declaredEpoch: 1, cancellationToken).AsTask());

        // The legacy record port may not overwrite an established authenticated floor.
        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => memory
            .ReplaceAsync(new MutableSlotRecord("oauth", "refreshToken", "fixture-scope", 1, 0, "CANARY-legacy-overwrite"), cancellationToken)
            .AsTask());
    }

    private FileMutableSlotStore Open(byte[]? key = null)
        => new(_root, "/fixture", key ?? Key);

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

    private static Task SeedLegacyAsync(FileMutableSlotStore store, long revision = 4)
        => store.ReplaceAsync(new MutableSlotRecord("oauth", "refreshToken", "fixture-scope", 1, revision, LegacyCanary),
                TestContext.Current.CancellationToken).AsTask();

    private static AuthenticationProfile Profile(
        string scopeFingerprint = "fixture-scope", long authorityEpoch = 1, long runtimeRevision = 0,
        string clientId = "test-client", string tokenEndpoint = "https://auth.example.test/token") => new(
        "oauth",
        AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
        CanonicalJson.Parse(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            strategyId = "oauth2-authorization-code-pkce-refresh",
            clientId,
            authorizationEndpoint = "https://auth.example.test/authorize",
            tokenEndpoint,
            tokenAuthMethod = "none",
        })))!.AsObject(),
        ["https://auth.example.test:443"],
        ["https://resource.example.test:443"],
        [],
        scopeFingerprint,
        [new AuthenticationSlot("refreshToken", authorityEpoch, runtimeRevision)]);

    private static IReadOnlyList<ResolvedCredential> ManifestCredentials() =>
    [
        new(new ManifestCredential("initial", CredentialScheme.OAuth2AuthorizationCode,
            "refreshToken", CredentialReference.Literal("fixture")), ManifestCanary),
    ];

    private static OAuthTokenService Service(FileMutableSlotStore store, RecordingProvider provider)
        => new(new OAuthTokenEndpointClient(provider, TimeProvider.System),
            new AccessTokenCache(), new AccessTokenSingleFlight(), store, TimeProvider.System);

    private sealed class RecordingProvider(bool rotate = false) : IUpstreamTransport
    {
        public List<string> Requests { get; } = [];

        public Task<UpstreamResponse> SendAsync(
            UpstreamRequest request, UpstreamSendPolicy policy, CancellationToken cancellationToken)
        {
            Requests.Add(Encoding.UTF8.GetString(request.Body ?? []));
            string body = rotate
                ? """{"access_token":"CANARY-access-token","refresh_token":"CANARY-next-refresh","token_type":"Bearer","expires_in":3600}"""
                : """{"access_token":"CANARY-access-token","token_type":"Bearer","expires_in":3600}""";
            return Task.FromResult(new UpstreamResponse(200,
                new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
                "application/json", new MemoryStream(Encoding.UTF8.GetBytes(body))));
        }
    }
}
