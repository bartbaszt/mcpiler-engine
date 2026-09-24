using System.Text.Json.Nodes;

using MCPiler.Engine.Authentication.Caching;
using MCPiler.Engine.Authentication.Challenge;
using MCPiler.Engine.Authentication.Exchange;
using MCPiler.Engine.Authentication.OAuth;
using MCPiler.Engine.Authentication.OAuth1;
using MCPiler.Engine.Execution.RuntimeState;
using MCPiler.Engine.Authentication.Signing;
using MCPiler.Engine.Execution;
using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication;

/// <summary>
/// The credentials, destination and signer one profiled execution must use.
/// </summary>
/// <remarks>
/// The three travel together because they are decided together: a token/session exchange can
/// redirect the request to an authority the response selected, and a signer must sign the exact
/// destination the exchange chose. Returning them separately would let a caller rebind the
/// destination and forget to re-derive what covers it.
/// </remarks>
/// <param name="Credentials">The credentials to apply, already revealed.</param>
/// <param name="DestinationAuthority">
/// An authority replacing the compiled destination, when the strategy selected one.
/// </param>
/// <param name="Signing">The signer covering this execution, when the strategy signs.</param>
/// <param name="OAuth1">
/// The method-specific OAuth 1.0a material covering this execution. It travels beside the
/// generic signer rather than through it, because no OAuth 1.0a method fits the one-key-id
/// one-secret request-signing shape.
/// </param>
/// <param name="OAuth1Signing">
/// The per-hop OAuth 1.0a signing closure state. Present exactly when <see cref="OAuth1"/>
/// is present; the execution layer signs each hop through it with fresh hop values.
/// </param>
public sealed record ResolvedAuthentication(
    IReadOnlyList<ResolvedCredential> Credentials,
    Uri? DestinationAuthority = null,
    ResolvedRequestSigning? Signing = null,
    OAuth1.OAuth1SigningMaterial? OAuth1 = null,
    OAuth1.ResolvedOAuth1Signing? OAuth1Signing = null);

/// <summary>
/// Per-kind acquisition over the ported authentication services.
/// </summary>
/// <remarks>
/// <para>
/// One place decides which service a profile kind uses and what a profile's declared credential
/// references mean to it. The execution layer above supplies the manifest credentials the profile
/// declared, because resolving a reference is the manifest's business, and this type turns them
/// into the credentials the wire request carries — an access token, a session, an injected
/// cookie, or the signing material that never becomes a header until a signer writes it.
/// </para>
/// <para>
/// The runtime owns bounded caches whose capacity is fixed at construction. There is no ambient
/// store: the mutable-slot port is supplied by the caller, so the library core holds no durable
/// state of its own.
/// </para>
/// </remarks>
public sealed class AuthenticationRuntime : IDisposable
{
    private static readonly IReadOnlyList<IRequestSigner> Signers =
    [
        new AwsSigV4RequestSigner(),
        new ExoscaleHmacRequestSigner(),
        new JwtHmacRequestSigner(),
        new SubsonicMd5RequestSigner(),
    ];

    private readonly AccessTokenCache _accessTokens;
    private readonly AccessTokenSingleFlight _singleFlight;
    private readonly IMutableSlotStore _slots;
    private readonly ChallengeSessionCache _challenges;
    private readonly TimeProvider _timeProvider;
    private readonly RequestSignerRegistry _registry;

    /// <summary>Creates a runtime over the transport and runtime-state port.</summary>
    /// <param name="transport">How an authentication endpoint is reached.</param>
    /// <param name="timeProvider">The clock; the system clock when absent.</param>
    /// <param name="slots">Where a rotated refresh token is committed; in-memory when absent.</param>
    /// <param name="rotationSink">
    /// Receives one committed refresh-token rotation so a managed host can reconcile it with the
    /// deployment that issued the profile. The callback runs after the local commit; a callback
    /// that throws fails the invocation that rotated, because reporting a rotation that could not
    /// be queued would lose the only record that the credential changed.
    /// </param>
    public AuthenticationRuntime(
        IUpstreamTransport transport,
        TimeProvider? timeProvider = null,
        IMutableSlotStore? slots = null,
        Func<RotatedRefreshToken, CancellationToken, ValueTask>? rotationSink = null)
    {
        ArgumentNullException.ThrowIfNull(transport);

        _timeProvider = timeProvider ?? TimeProvider.System;
        _slots = slots ?? new InMemoryMutableSlotStore();
        _accessTokens = new AccessTokenCache();
        _singleFlight = new AccessTokenSingleFlight();
        _challenges = new ChallengeSessionCache(_timeProvider);
        _registry = new RequestSignerRegistry(Signers);

        OAuth = new OAuthTokenService(
            new OAuthTokenEndpointClient(transport, _timeProvider),
            _accessTokens,
            _singleFlight,
            _slots,
            _timeProvider,
            rotationSink);

        Exchange = new TokenSessionExchangeService(transport, _timeProvider);
        Challenge = new ChallengeSessionService(_challenges, _timeProvider);
    }

    /// <summary>OAuth token acquisition and caching.</summary>
    public OAuthTokenService OAuth { get; }

    /// <summary>Token/session exchange acquisition.</summary>
    public TokenSessionExchangeService Exchange { get; }

    /// <summary>Challenge-session state and disposition.</summary>
    public ChallengeSessionService Challenge { get; }

    /// <summary>
    /// Resolves the credentials, destination and signer for one profile.
    /// </summary>
    /// <param name="profile">The manifest-declared profile that governs the execution.</param>
    /// <param name="declared">
    /// The credentials the profile's references resolved to, in declaration order.
    /// </param>
    /// <param name="cancellationToken">The execution's token.</param>
    public async ValueTask<ResolvedAuthentication> ResolveAsync(
        AuthenticationProfile profile,
        IReadOnlyList<ResolvedCredential> declared,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(declared);

        switch (profile.Kind)
        {
            case AuthenticationKind.Static:
                return new ResolvedAuthentication(declared);

            case AuthenticationKind.OAuth2ClientCredentials:
            case AuthenticationKind.OAuth2AuthorizationCodePkceRefresh:
                var acquisition = await OAuth
                    .AcquireAsync(profile, declared, cancellationToken)
                    .ConfigureAwait(false);

                return new ResolvedAuthentication(acquisition.Credentials);

            case AuthenticationKind.TokenSessionExchange:
                var exchange = await Exchange
                    .AcquireAsync(profile, declared, cancellationToken)
                    .ConfigureAwait(false);

                return new ResolvedAuthentication([exchange.Credential], exchange.DestinationAuthority);

            case AuthenticationKind.ChallengeSession:
                var session = Challenge.ResolveCredential(
                    profile,
                    RuntimeRevision(profile),
                    AuthorityEpoch(profile));

                return new ResolvedAuthentication(session is null ? [] : [session]);

            case AuthenticationKind.RequestSigning:
                return new ResolvedAuthentication([], Signing: ResolveSigner(profile, declared));

            case AuthenticationKind.OAuth1Authorization:
                ResolvedOAuth1Signing.ValidateConfiguration(profile);
                var material = OAuth1.OAuth1Authentication.ResolveMaterial(profile, declared);
                return new ResolvedAuthentication(
                    [],
                    OAuth1: material,
                    OAuth1Signing: OAuth1.ResolvedOAuth1Signing.Create(profile, material, _timeProvider));

            default:
                throw new UnsupportedAuthenticationStrategyException(
                    $"Authentication strategy kind '{profile.Kind}' has no credential application handler installed.");
        }
    }

    /// <summary>Drops every cached ephemeral credential for one profile.</summary>
    public void InvalidateProfile(string profileId)
    {
        ArgumentException.ThrowIfNullOrEmpty(profileId);

        _accessTokens.InvalidateProfile(profileId);
        _challenges.InvalidateProfile(profileId);
    }

    /// <inheritdoc />
    public void Dispose() => _singleFlight.Dispose();

    /// <summary>The authority epoch a profile declares, or zero when it declares no slot.</summary>
    internal static long AuthorityEpoch(AuthenticationProfile profile)
        => profile.Slots.Count > 0 ? profile.Slots[0].AuthorityEpoch : 0;

    /// <summary>The runtime revision a profile declares, or zero when it declares no slot.</summary>
    internal static long RuntimeRevision(AuthenticationProfile profile)
        => profile.Slots.Count > 0 ? profile.Slots[0].RuntimeRevision : 0;

    private ResolvedRequestSigning ResolveSigner(
        AuthenticationProfile profile,
        IReadOnlyList<ResolvedCredential> declared)
    {
        string strategyId = RequiredText(profile.Configuration, "strategyId")
            ?? throw new AuthenticationPlanException(profile.Id, "A request-signing profile requires 'strategyId'.");

        string accessKeyId = profile.Configuration["inputs"] is JsonObject inputs
            ? RequiredText(inputs, "accessKeyId")
                ?? throw new AuthenticationPlanException(profile.Id, "A request-signing profile requires 'inputs.accessKeyId'.")
            : throw new AuthenticationPlanException(profile.Id, "A request-signing profile requires 'inputs.accessKeyId'.");

        ResolvedCredential? secret = null;
        foreach (ResolvedCredential credential in declared)
        {
            if (credential.Declaration.Scheme == CredentialScheme.RequestSigning
                && string.Equals(credential.Declaration.Slot, "signingSecret", StringComparison.Ordinal))
            {
                secret = credential;
                break;
            }
        }

        if (secret is null)
        {
            throw new CredentialUnavailableException(
                "request-signing",
                "The request-signing profile does not declare exactly one signing secret.");
        }

        return _registry.Resolve(
            profile.Id,
            strategyId,
            accessKeyId,
            secret.Value,
            profile.DestinationOrigins,
            _timeProvider);
    }

    private static string? RequiredText(JsonObject source, string member)
        => source[member] is JsonValue value
            && value.TryGetValue<string>(out string? text)
            && text.Length > 0
                ? text
                : null;
}
