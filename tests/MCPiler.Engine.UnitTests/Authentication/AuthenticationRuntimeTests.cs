using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using MCPiler.Engine.Authentication;
using MCPiler.Engine.Authentication.Caching;
using MCPiler.Engine.Authentication.OAuth1;
using MCPiler.Engine.Authentication.Signing;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Canonical;
using MCPiler.Engine.Manifest.Model;

using Xunit;

namespace MCPiler.Engine.UnitTests.Authentication;

/// <summary>
/// The authentication runtime's kind dispatch: which strategy each profile kind selects, and
/// that a kind with no runtime semantics is refused rather than approximated.
/// </summary>
/// <remarks>
/// These tests substitute the transport, because what is asserted is a decision the runtime
/// makes before any byte leaves the process: which strategy acquired the credential and which
/// failure classification a kind with no execution handler produces.
/// </remarks>
public sealed class AuthenticationRuntimeTests : IDisposable
{
    private const string SecretCanary = "CANARY-77ab01-signing-secret";

    private readonly AuthenticationRuntime _runtime = new(new RecordingTransport());

    [Fact]
    public async Task A_static_profile_passes_the_declared_credentials_through()
    {
        var declared = Declared("api", CredentialScheme.Bearer, "Authorization", "token-value");

        var resolved = await _runtime.ResolveAsync(Profile(AuthenticationKind.Static), declared, CancellationToken.None);

        Assert.Same(declared, resolved.Credentials);
        Assert.Null(resolved.DestinationAuthority);
        Assert.Null(resolved.Signing);
    }

    [Fact]
    public async Task A_reserved_composite_profile_is_refused_rather_than_executed()
    {
        // The owner decision: reviewed-composite stays vocabulary-only. A profile declaring it
        // must never reach a network call, which is what the substituted transport proves.
        var transport = new RecordingTransport();
        using var runtime = new AuthenticationRuntime(transport);

        await Assert.ThrowsAsync<UnsupportedAuthenticationStrategyException>(() => runtime.ResolveAsync(
            Profile(AuthenticationKind.ReviewedComposite),
            [],
            CancellationToken.None).AsTask());

        Assert.Equal(0, transport.Arrivals);
    }

    [Fact]
    public async Task A_request_signing_profile_resolves_a_signer_and_never_hands_back_a_plain_credential()
    {
        var declared = Declared("signing", CredentialScheme.RequestSigning, "signingSecret", SecretCanary);

        var resolved = await _runtime.ResolveAsync(
            Profile(
                AuthenticationKind.RequestSigning,
                """
                {
                  "strategyId": "request-signing-hmac",
                  "inputs": { "accessKeyId": "example-key" }
                }
                """,
                destinationOrigins: ["https://api.example.com:443"]),
            declared,
            CancellationToken.None);

        Assert.NotNull(resolved.Signing);
        Assert.Equal("request-signing-hmac", resolved.Signing!.StrategyId);

        // The signing secret itself must not be returned as an applicable credential: it is
        // material for the signature, not a value any request carries.
        Assert.DoesNotContain(
            resolved.Credentials,
            credential => string.Equals(credential.Value, SecretCanary, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_request_signing_profile_without_a_signing_secret_is_refused()
    {
        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(() => _runtime.ResolveAsync(
            Profile(
                AuthenticationKind.RequestSigning,
                """
                {
                  "strategyId": "request-signing-hmac",
                  "inputs": { "accessKeyId": "example-key" }
                }
                """),
            [],
            CancellationToken.None).AsTask());

        Assert.Contains("signing secret", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_unknown_signer_is_refused_before_any_request()
    {
        var failure = await Assert.ThrowsAsync<UnsupportedAuthenticationStrategyException>(() => _runtime.ResolveAsync(
            Profile(
                AuthenticationKind.RequestSigning,
                """
                {
                  "strategyId": "request-signing-unknown",
                  "inputs": { "accessKeyId": "example-key" }
                }
                """),
            Declared("signing", CredentialScheme.RequestSigning, "signingSecret", SecretCanary),
            CancellationToken.None).AsTask());

        Assert.Contains("request-signing-hmac", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_challenge_profile_without_a_cached_session_resolves_to_no_credential()
    {
        var resolved = await _runtime.ResolveAsync(
            Profile(AuthenticationKind.ChallengeSession),
            [],
            CancellationToken.None);

        // No session yet: the first attempt goes out unauthenticated so the upstream can issue
        // its challenge. A fabricated credential here would authenticate nothing.
        Assert.Empty(resolved.Credentials);
    }

    [Fact]
    public void Authority_epoch_and_runtime_revision_default_to_zero_without_a_declared_slot()
    {
        var profile = Profile(AuthenticationKind.OAuth2ClientCredentials);

        Assert.Equal(0, AuthenticationRuntime.AuthorityEpoch(profile));
        Assert.Equal(0, AuthenticationRuntime.RuntimeRevision(profile));
    }

    [Fact]
    public void Authority_epoch_and_runtime_revision_come_from_the_declared_slot()
    {
        var profile = Profile(
            AuthenticationKind.OAuth2ClientCredentials,
            slots: [new AuthenticationSlot("refreshToken", AuthorityEpoch: 4, RuntimeRevision: 9)]);

        Assert.Equal(4, AuthenticationRuntime.AuthorityEpoch(profile));
        Assert.Equal(9, AuthenticationRuntime.RuntimeRevision(profile));
    }

    [Fact]
    public async Task An_oauth1_hmac_profile_resolves_shared_secret_material_and_reveals_no_plain_credential()
    {
        var declared = new[]
        {
            OAuth1Declared("consumer-secret", "consumerSecret", "consumer-value"),
            OAuth1Declared("token", "oauthToken", "token-value"),
            OAuth1Declared("token-secret", "oauthTokenSecret", "token-secret-value"),
        };

        var resolved = await _runtime.ResolveAsync(
            OAuth1Profile("HMAC-SHA1"),
            declared,
            CancellationToken.None);

        Assert.Empty(resolved.Credentials);
        Assert.Null(resolved.Signing);
        var material = Assert.IsType<OAuth1SigningMaterial.SharedSecretMaterial>(resolved.OAuth1);
        Assert.Equal("example-client", material.ConsumerKey);
        Assert.Equal("token-value", material.Token);
        Assert.Equal("consumer-value", material.ConsumerSecret);
        Assert.Equal("token-secret-value", material.TokenSecret);
    }

    [Fact]
    public async Task An_oauth1_rsa_profile_resolves_private_key_material_without_a_token_secret()
    {
        var declared = new[]
        {
            OAuth1Declared("private-key", "rsaPrivateKey", SecretCanary),
            OAuth1Declared("token", "oauthToken", "token-value"),
        };

        var resolved = await _runtime.ResolveAsync(
            OAuth1Profile("RSA-SHA1"),
            declared,
            CancellationToken.None);

        var material = Assert.IsType<OAuth1SigningMaterial.RsaMaterial>(resolved.OAuth1);
        Assert.Equal("example-client", material.ConsumerKey);
        Assert.Equal("token-value", material.Token);
        Assert.Equal(SecretCanary, material.PrivateKeyPem);
        Assert.Empty(resolved.Credentials);
    }

    [Fact]
    public async Task An_oauth1_profile_without_a_required_slot_is_refused_without_values()
    {
        var declared = new[]
        {
            OAuth1Declared("consumer-secret", "consumerSecret", SecretCanary),
            OAuth1Declared("token", "oauthToken", "token-value"),
        };

        var failure = await Assert.ThrowsAsync<CredentialUnavailableException>(() => _runtime.ResolveAsync(
            OAuth1Profile("HMAC-SHA1"),
            declared,
            CancellationToken.None).AsTask());

        Assert.Contains("oauthTokenSecret", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretCanary, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_oauth1_profile_with_an_unexpected_slot_is_refused()
    {
        var declared = new[]
        {
            OAuth1Declared("private-key", "rsaPrivateKey", SecretCanary),
            OAuth1Declared("token", "oauthToken", "token-value"),
            OAuth1Declared("token-secret", "oauthTokenSecret", "another-secret"),
        };

        var failure = await Assert.ThrowsAsync<AuthenticationPlanException>(() => _runtime.ResolveAsync(
            OAuth1Profile("RSA-SHA1"),
            declared,
            CancellationToken.None).AsTask());

        Assert.Contains("oauthTokenSecret", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretCanary, failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("another-secret", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_oauth1_profile_with_an_unknown_method_is_refused_with_the_vocabulary()
    {
        var declared = new[]
        {
            OAuth1Declared("consumer-secret", "consumerSecret", SecretCanary),
        };

        var failure = await Assert.ThrowsAsync<UnsupportedAuthenticationStrategyException>(() => _runtime.ResolveAsync(
            OAuth1Profile("HMAC-SHA9"),
            declared,
            CancellationToken.None).AsTask());

        Assert.Contains("HMAC-SHA256", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretCanary, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_oauth1_profile_without_a_consumer_key_is_refused()
    {
        var declared = new[]
        {
            OAuth1Declared("consumer-secret", "consumerSecret", SecretCanary),
            OAuth1Declared("token", "oauthToken", "token-value"),
            OAuth1Declared("token-secret", "oauthTokenSecret", "token-secret-value"),
        };

        await Assert.ThrowsAsync<AuthenticationPlanException>(() => _runtime.ResolveAsync(
            OAuth1Profile("HMAC-SHA1", consumerKey: " "),
            declared,
            CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task An_oauth1_profile_resolves_per_hop_signing_and_no_plain_credential()
    {
        var declared = new[]
        {
            OAuth1Declared("consumer-secret", "consumerSecret", "consumer-value"),
            OAuth1Declared("token", "oauthToken", "token-value"),
            OAuth1Declared("token-secret", "oauthTokenSecret", "token-secret-value"),
        };

        var resolved = await _runtime.ResolveAsync(
            OAuth1Profile("HMAC-SHA1"),
            declared,
            CancellationToken.None);

        Assert.Empty(resolved.Credentials);
        Assert.Null(resolved.Signing);
        Assert.NotNull(resolved.OAuth1Signing);
        Assert.NotNull(resolved.OAuth1);
    }

    [Fact]
    public async Task An_oauth1_profile_with_an_unknown_transport_is_refused_before_any_request()
    {
        var transport = new RecordingTransport();
        using var runtime = new AuthenticationRuntime(transport);

        await Assert.ThrowsAsync<UnsupportedAuthenticationStrategyException>(() => runtime.ResolveAsync(
            OAuth1Profile("HMAC-SHA1", transport: "cookie"),
            [],
            CancellationToken.None).AsTask());

        Assert.Equal(0, transport.Arrivals);
    }

    public void Dispose() => _runtime.Dispose();

    private static AuthenticationProfile Profile(
        AuthenticationKind kind,
        string? configuration = null,
        IReadOnlyList<string>? destinationOrigins = null,
        IReadOnlyList<AuthenticationSlot>? slots = null)
        => new(
            kind switch
            {
                AuthenticationKind.RequestSigning => "request-signing",
                _ => "static",
            },
            kind,
            CanonicalJson.Parse(System.Text.Encoding.UTF8.GetBytes(configuration ?? "{}"))!.AsObject(),
            [],
            destinationOrigins ?? ["https://api.example.com:443"],
            [],
            ScopeFingerprint: null,
            Slots: slots!);

    private static IReadOnlyList<ResolvedCredential> Declared(
        string id,
        CredentialScheme scheme,
        string slot,
        string value)
        => [new ResolvedCredential(
            new ManifestCredential(id, scheme, slot, CredentialReference.Literal("placeholder")),
            value)];

    private static AuthenticationProfile OAuth1Profile(
        string method,
        string consumerKey = "example-client",
        string transport = "authorization-header")
        => Profile(
            AuthenticationKind.OAuth1Authorization,
            $$"""
            {
              "consumerKey": "{{consumerKey}}",
              "signatureMethod": "{{method}}",
              "parameterTransport": "{{transport}}"
            }
            """);

    private static ResolvedCredential OAuth1Declared(string id, string slot, string value)
        => new(
            new ManifestCredential(id, CredentialScheme.OAuth1Authorization, slot, CredentialReference.Literal("placeholder")),
            value);

    private sealed class RecordingTransport : IUpstreamTransport
    {
        public int Arrivals { get; private set; }

        public Task<UpstreamResponse> SendAsync(
            UpstreamRequest request,
            UpstreamSendPolicy policy,
            CancellationToken cancellationToken)
        {
            Arrivals++;
            throw new InvalidOperationException("The authentication runtime must not reach the network.");
        }
    }
}
