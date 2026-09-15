using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Caching;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Execution.Outbound;
using MCPiler.Engine.Execution.Secrets.RuntimeState;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.IntegrationTests.Authentication;

/// <summary>
/// Crash-point and durability tests for the file-backed runtime-auth store.
/// </summary>
/// <remarks>
/// <para>
/// The unit suite substitutes the store and proves the port. This suite uses the real adapter
/// over a real directory, because the properties that matter here are properties of the
/// filesystem: what survives an interruption between two writes, whether a temporary sibling can
/// ever be read as a record, and whether any plaintext reaches disk. A fake filesystem would
/// assert the fake.
/// </para>
/// <para>
/// Each test owns its root and deletes it. A failure therefore cannot be caused by an earlier
/// test's leftover ciphertext, which matters because "the store is empty" is one of the
/// behaviours under test.
/// </para>
/// </remarks>
public sealed class RefreshRotationDurabilityTests : IDisposable
{
    private const string DeclaredRefreshCanary = "CANARY-declared-refresh-4c19";
    private const string RotatedRefreshCanary = "CANARY-rotated-refresh-a72e";
    private const string ClientSecretCanary = "CANARY-client-secret-e55a";
    private const string AccessTokenCanary = "CANARY-access-token-19ff";
    private const string ProfileId = "oauth2-authorization-code-pkce-refresh";
    private const string RefreshSlot = "refreshToken";

    private readonly List<string> _roots = [];

    [Fact]
    public async Task A_committed_rotation_survives_a_new_store_over_the_same_directory()
    {
        var root = NewRoot();
        var requests = new List<Recorded>();
        await using var host = await TokenHostAsync(requests);

        var first = await AcquireAsync(root, new FileMutableSlotStore(root, "mount", Key()), host);

        Assert.Equal(ExecutionFailureKind.None, first.Failure);

        var record = await first.Store.LoadAsync(ProfileId, RefreshSlot, TestContext.Current.CancellationToken);

        Assert.NotNull(record);
        Assert.Equal(RotatedRefreshCanary, record!.Value);
        Assert.Equal(1, record.AuthorityEpoch);
        Assert.Equal(1, record.RuntimeRevision);

        // A fresh store instance over the same directory is what the next process sees.
        var reloaded = new FileMutableSlotStore(root, "mount", Key());
        var persisted = await reloaded.LoadAsync(ProfileId, RefreshSlot, TestContext.Current.CancellationToken);

        Assert.Equal(RotatedRefreshCanary, persisted!.Value);

        // The replacement is used instead of the declared credential, so the provider is never
        // presented with the value it has already retired.
        requests.Clear();
        var second = await AcquireAsync(root, reloaded, host, declaredRefresh: DeclaredRefreshCanary);

        Assert.Equal(ExecutionFailureKind.None, second.Failure);

        var tokenCall = Assert.Single(requests, request => request.Path == "/token");
        Assert.Contains($"refresh_token={RotatedRefreshCanary}", tokenCall.Form, StringComparison.Ordinal);
        Assert.DoesNotContain(DeclaredRefreshCanary, tokenCall.Form, StringComparison.Ordinal);
        AssertNoPlaintext(root);
    }

    [Fact]
    public async Task A_failure_before_the_flush_leaves_the_previous_record_authoritative()
    {
        var root = NewRoot();
        var store = new FileMutableSlotStore(root, "mount", Key());

        await store.ReplaceAsync(
            Record(DeclaredRefreshCanary, runtimeRevision: 0),
            TestContext.Current.CancellationToken);

        store.TempWrittenBarrier = _ => throw new IOException("injected failure before the flush");

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            Record(RotatedRefreshCanary, runtimeRevision: 1),
            TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("could not be committed", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(RotatedRefreshCanary, failure.Message, StringComparison.Ordinal);

        // The complete predecessor is what a fresh reader sees. Nothing was half-written.
        var reloaded = new FileMutableSlotStore(root, "mount", Key());
        var record = await reloaded.LoadAsync(ProfileId, RefreshSlot, TestContext.Current.CancellationToken);

        Assert.Equal(DeclaredRefreshCanary, record!.Value);
        Assert.Equal(0, record.RuntimeRevision);
        AssertNoPlaintext(root);
    }

    [Fact]
    public async Task A_failure_after_the_flush_before_the_replace_leaves_the_previous_record_authoritative()
    {
        var root = NewRoot();
        var store = new FileMutableSlotStore(root, "mount", Key());

        await store.ReplaceAsync(
            Record(DeclaredRefreshCanary, runtimeRevision: 0),
            TestContext.Current.CancellationToken);

        store.TempFlushedBarrier = _ => throw new IOException("injected failure after the flush");

        await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.ReplaceAsync(
            Record(RotatedRefreshCanary, runtimeRevision: 1),
            TestContext.Current.CancellationToken).AsTask());

        var reloaded = new FileMutableSlotStore(root, "mount", Key());
        var record = await reloaded.LoadAsync(ProfileId, RefreshSlot, TestContext.Current.CancellationToken);

        Assert.Equal(DeclaredRefreshCanary, record!.Value);
        Assert.Equal(0, record.RuntimeRevision);

        // The abandoned temporary sibling is never the record, and it carries no plaintext.
        Assert.Single(Directory.GetFiles(root, "*" + FileMutableSlotStore.RecordExtension));
        AssertNoPlaintext(root);
    }

    [Fact]
    public async Task A_failed_commit_never_publishes_the_access_token_it_produced()
    {
        var root = NewRoot();
        var requests = new List<Recorded>();
        await using var host = await TokenHostAsync(requests);

        var store = new FileMutableSlotStore(root, "mount", Key());

        await store.ReplaceAsync(
            Record(DeclaredRefreshCanary, runtimeRevision: 0),
            TestContext.Current.CancellationToken);

        store.TempFlushedBarrier = _ => throw new IOException("injected failure after the flush");

        var cache = new AccessTokenCache();
        using var singleFlight = new AccessTokenSingleFlight();

        var service = new OAuthTokenService(
            new OAuthTokenEndpointClient(new UpstreamSender(PermissiveClients()), Clock),
            cache,
            singleFlight,
            store,
            Clock);

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(() => service.AcquireAsync(
            Profile(host),
            DeclaredCredentials(includeRefresh: true),
            TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("could not be committed", failure.Message, StringComparison.Ordinal);

        // The access token the failed transition produced must not be resolvable afterwards: a
        // caller holding it while the refresh credential was never recorded would lose the
        // connector at the next expiry.
        var key = new AccessTokenKey(ProfileId, 1, 0, ScopeKey(host));

        Assert.False(cache.TryGet(key, TimeSpan.Zero, Clock.GetUtcNow(), out _));
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public async Task Concurrent_refresh_attempts_commit_one_ordered_replacement()
    {
        var root = NewRoot();
        var requests = new List<Recorded>();
        await using var host = await TokenHostAsync(requests);

        var store = new FileMutableSlotStore(root, "mount", Key());

        await store.ReplaceAsync(
            Record(DeclaredRefreshCanary, runtimeRevision: 0),
            TestContext.Current.CancellationToken);

        var cache = new AccessTokenCache();
        using var singleFlight = new AccessTokenSingleFlight();

        var service = new OAuthTokenService(
            new OAuthTokenEndpointClient(new UpstreamSender(PermissiveClients()), Clock),
            cache,
            singleFlight,
            store,
            Clock);

        var profile = Profile(host);
        var declared = DeclaredCredentials(includeRefresh: true);

        Task<OAuthAcquisition>[] attempts =
        [
            service.AcquireAsync(profile, declared, TestContext.Current.CancellationToken).AsTask(),
            service.AcquireAsync(profile, declared, TestContext.Current.CancellationToken).AsTask(),
            service.AcquireAsync(profile, declared, TestContext.Current.CancellationToken).AsTask(),
        ];

        var results = await Task.WhenAll(attempts);

        Assert.All(results, result => Assert.NotEmpty(result.Credentials));

        // A rotating provider must be presented the refresh credential exactly once; a second
        // presentation would retire the replacement the first call stored.
        Assert.Single(requests, request => request.Path == "/token");

        var reloaded = new FileMutableSlotStore(root, "mount", Key());
        var record = await reloaded.LoadAsync(ProfileId, RefreshSlot, TestContext.Current.CancellationToken);

        Assert.NotNull(record);
        Assert.Equal(1, record!.RuntimeRevision);
        Assert.Equal(RotatedRefreshCanary, record.Value);
        AssertNoPlaintext(root);
    }

    [Fact]
    public async Task A_corrupt_record_fails_closed_and_preserves_the_evidence()
    {
        var root = NewRoot();
        var store = new FileMutableSlotStore(root, "mount", Key());

        await store.ReplaceAsync(
            Record(RotatedRefreshCanary, runtimeRevision: 1),
            TestContext.Current.CancellationToken);

        var recordFile = Assert.Single(Directory.GetFiles(root, "*" + FileMutableSlotStore.RecordExtension));
        var bytes = File.ReadAllBytes(recordFile);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(recordFile, bytes);

        // Fail-closed rather than fall-back: the caller is told the durable state is unusable,
        // and the unreadable ciphertext is left exactly where it was for an operator to inspect.
        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(() => store.LoadAsync(
            ProfileId,
            RefreshSlot,
            TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("cannot be authenticated", failure.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(recordFile));
        Assert.Equal(bytes, File.ReadAllBytes(recordFile));
        AssertNoPlaintext(root);
    }

    [Fact]
    public async Task A_record_from_an_older_authority_epoch_is_not_used()
    {
        var root = NewRoot();
        var requests = new List<Recorded>();
        await using var host = await TokenHostAsync(requests);

        // A record written under epoch 1, then a generation that declares epoch 2.
        var store = new FileMutableSlotStore(root, "mount", Key());

        await store.ReplaceAsync(
            new MutableSlotRecord(ProfileId, RefreshSlot, null, AuthorityEpoch: 1, RuntimeRevision: 5, RotatedRefreshCanary),
            TestContext.Current.CancellationToken);

        var service = new OAuthTokenService(
            new OAuthTokenEndpointClient(new UpstreamSender(PermissiveClients()), Clock),
            new AccessTokenCache(),
            new AccessTokenSingleFlight(),
            store,
            Clock);

        var acquisition = await service.AcquireAsync(
            Profile(host, authorityEpoch: 2, runtimeRevision: 0),
            DeclaredCredentials(includeRefresh: true),
            TestContext.Current.CancellationToken);

        Assert.Equal(2, acquisition.AuthorityEpoch);

        // The stale epoch's value was never presented; the declared credential was used instead.
        var tokenCall = Assert.Single(requests, request => request.Path == "/token");
        Assert.Contains($"refresh_token={DeclaredRefreshCanary}", tokenCall.Form, StringComparison.Ordinal);
        Assert.DoesNotContain(RotatedRefreshCanary, tokenCall.Form, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_rotated_record_is_not_reused_after_the_key_changes()
    {
        var root = NewRoot();
        var requests = new List<Recorded>();
        await using var host = await TokenHostAsync(requests);

        var store = new FileMutableSlotStore(root, "mount", Key());

        await store.ReplaceAsync(
            Record(RotatedRefreshCanary, runtimeRevision: 1),
            TestContext.Current.CancellationToken);

        // A deployment that reprovisions its runtime-state key while old ciphertext remains on
        // disk must fail closed rather than silently present the declared credential: the rotated
        // value is still the only valid one, and the deployment needs an operator's decision.
        var otherKey = Key();
        otherKey[0] ^= 0xFF;
        var reprovisioned = new FileMutableSlotStore(root, "mount", otherKey);

        var failure = await Assert.ThrowsAsync<RuntimeStateStoreException>(() => reprovisioned.LoadAsync(
            ProfileId,
            RefreshSlot,
            TestContext.Current.CancellationToken).AsTask());

        Assert.Contains("cannot be authenticated", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(RotatedRefreshCanary, failure.Message, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        foreach (var root in _roots)
        {
            try
            {
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    /// <summary>One arrival, as the token host observed it.</summary>
    private sealed record Recorded(string Path, string Form);

    private sealed record AcquireOutcome(ExecutionFailureKind Failure, FileMutableSlotStore Store);

    private static async Task<AcquireOutcome> AcquireAsync(
        string root,
        FileMutableSlotStore store,
        LoopbackHost host,
        string declaredRefresh = DeclaredRefreshCanary)
    {
        _ = root;

        var service = new OAuthTokenService(
            new OAuthTokenEndpointClient(new UpstreamSender(PermissiveClients()), Clock),
            new AccessTokenCache(),
            new AccessTokenSingleFlight(),
            store,
            Clock);

        try
        {
            await service.AcquireAsync(
                Profile(host),
                DeclaredCredentials(includeRefresh: true, declaredRefresh),
                TestContext.Current.CancellationToken);

            return new AcquireOutcome(ExecutionFailureKind.None, store);
        }
        catch (Exception ex) when (ex is CredentialUnavailableException
            or UnsupportedAuthenticationStrategyException
            or AuthenticationPlanException
            or RuntimeStateStoreException)
        {
            return new AcquireOutcome(ExecutionFailureKind.Authentication, store);
        }
    }

    private static async Task<LoopbackHost> TokenHostAsync(List<Recorded> requests) =>
        await LoopbackHost.StartAsync(
            async context =>
            {
                string form = await ReadBodyAsync(context);

                lock (requests)
                {
                    requests.Add(new Recorded(context.Request.Path.Value ?? "/", form));
                }

                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    $$"""{ "access_token": "{{AccessTokenCanary}}", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "{{RotatedRefreshCanary}}" }""",
                    context.RequestAborted);
            },
            TestContext.Current.CancellationToken);

    private static async Task<string> ReadBodyAsync(HttpContext context)
    {
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
        return await reader.ReadToEndAsync(context.RequestAborted);
    }

    private static byte[] Key()
    {
        var key = new byte[32];

        for (var index = 0; index < key.Length; index++)
        {
            key[index] = (byte)(index + 1);
        }

        return key;
    }

    private static TimeProvider Clock => FixedClock.Instance;

    private sealed class FixedClock : TimeProvider
    {
        public static readonly FixedClock Instance = new();

        private readonly DateTimeOffset _now = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;
    }

    private static MutableSlotRecord Record(string value, long runtimeRevision) =>
        new(ProfileId, RefreshSlot, null, AuthorityEpoch: 1, runtimeRevision, value);

    private static IReadOnlyList<ResolvedCredential> DeclaredCredentials(
        bool includeRefresh,
        string declaredRefresh = DeclaredRefreshCanary)
    {
        var credentials = new List<ResolvedCredential>
        {
            Declared("oauth2-authorization-client", CredentialScheme.OAuth2AuthorizationCode, "clientSecret", ClientSecretCanary),
        };

        if (includeRefresh)
        {
            credentials.Add(Declared("oauth2-authorization-refresh", CredentialScheme.OAuth2AuthorizationCode, RefreshSlot, declaredRefresh));
        }

        return credentials;
    }

    private static ResolvedCredential Declared(string id, CredentialScheme scheme, string slot, string value) =>
        new(new ManifestCredential(id, scheme, slot, CredentialReference.Literal("placeholder")), value);

    private static AuthenticationProfile Profile(
        LoopbackHost host,
        long authorityEpoch = 1,
        long runtimeRevision = 0)
    {
        string origin = host.Address.GetLeftPart(UriPartial.Authority);

        var configuration = CanonicalJson.Parse(Encoding.UTF8.GetBytes($$"""
            {
              "strategyId": "oauth2-authorization-code-pkce-refresh",
              "tokenEndpoint": "{{host.Address}}token",
              "authorizationEndpoint": "{{host.Address}}authorize",
              "clientId": "example-client",
              "tokenAuthMethod": "client_secret_post"
            }
            """))!.AsObject();

        return new AuthenticationProfile(
            ProfileId,
            AuthenticationKind.OAuth2AuthorizationCodePkceRefresh,
            configuration,
            [origin],
            [origin],
            ["oauth2-authorization-client", "oauth2-authorization-refresh"],
            ScopeFingerprint: null,
            Slots: [new AuthenticationSlot(RefreshSlot, authorityEpoch, runtimeRevision)]);
    }

    private static string ScopeKey(LoopbackHost host) =>
        OAuthStrategyConfiguration
            .FromConfiguration(Profile(host).Configuration, authorizationCodeRequired: true)
            .ScopeResourceKey;

    private static UpstreamClientFactory PermissiveClients() => new(new OutboundConnectionPolicy(_ => false));

    private string NewRoot()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "mcpiler-rotation-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));

        _roots.Add(root);
        return root;
    }

    private static void AssertNoPlaintext(string root)
    {
        foreach (var file in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
        {
            string text = Encoding.UTF8.GetString(File.ReadAllBytes(file));

            Assert.DoesNotContain(DeclaredRefreshCanary, text, StringComparison.Ordinal);
            Assert.DoesNotContain(RotatedRefreshCanary, text, StringComparison.Ordinal);
            Assert.DoesNotContain(ClientSecretCanary, text, StringComparison.Ordinal);
            Assert.DoesNotContain(AccessTokenCanary, text, StringComparison.Ordinal);
        }
    }
}
