using System.Security.Cryptography;
using System.Text;

using MCPiler.Engine.Manifest.Model;

namespace MCPiler.Engine.Authentication.OAuth;

/// <summary>
/// The stable, non-secret identity one authorization attempt is bound to: the mount and profile
/// it authorizes, the runtime-owned slot it will write, and the declaration/configuration
/// fingerprints that make a later commit refuse a changed manifest.
/// </summary>
/// <param name="Mount">The runtime mount the profile belongs to.</param>
/// <param name="ProfileId">The manifest-local authentication profile id.</param>
/// <param name="Slot">The runtime-owned mutable slot the attempt authorizes.</param>
/// <param name="DeclarationFingerprint">The non-secret declaration fingerprint at attempt start.</param>
/// <param name="ConfigurationFingerprint">The non-secret configuration fingerprint at attempt start.</param>
public sealed record OAuthAuthorizationBinding(
    string Mount,
    string ProfileId,
    string Slot,
    string DeclarationFingerprint,
    string ConfigurationFingerprint);

/// <summary>Where one authorization attempt stands.</summary>
public enum OAuthAuthorizationAttemptStatus
{
    /// <summary>Built but not yet accepting a callback.</summary>
    Created,

    /// <summary>Accepting exactly one callback.</summary>
    Pending,

    /// <summary>Exchanging the single admitted callback at the token endpoint.</summary>
    Exchanging,

    /// <summary>A usable refresh token was obtained; the access token is ready to publish.</summary>
    Committed,

    /// <summary>The provider refused consent.</summary>
    Denied,

    /// <summary>The attempt was refused or the exchange failed.</summary>
    Failed,

    /// <summary>The attempt was cancelled.</summary>
    Cancelled,

    /// <summary>The attempt passed its bounded lifetime before completion.</summary>
    Expired,
}

/// <summary>
/// A bounded, non-secret reason an attempt did not produce a result. It is a stable category for
/// CLI and operator output, never a provider body or any secret.
/// </summary>
public enum OAuthAuthorizationAttemptError
{
    /// <summary>The profile kind or slot cannot drive an authorization-code attempt.</summary>
    UnsupportedProfile,

    /// <summary>The declared token authentication method needs a client secret that was not supplied.</summary>
    MissingClientSecret,

    /// <summary>The configured callback URI is not an exact loopback registration.</summary>
    RedirectUriInvalid,

    /// <summary>An extension parameter collides with a protocol-owned field or an endpoint parameter.</summary>
    AuthorizationParameterRefused,

    /// <summary>The bounded attempt lifetime is out of range.</summary>
    LifetimeInvalid,

    /// <summary>The attempt is not in a state that can accept or complete a callback.</summary>
    AttemptNotPending,

    /// <summary>The attempt's bounded lifetime elapsed.</summary>
    AttemptExpired,

    /// <summary>The callback query was not well formed.</summary>
    MalformedCallback,

    /// <summary>The callback carried the same decoded parameter name more than once.</summary>
    DuplicateCallbackParameter,

    /// <summary>The callback carried no <c>state</c>.</summary>
    MissingState,

    /// <summary>The callback <c>state</c> did not match this attempt.</summary>
    StateMismatch,

    /// <summary>The callback carried no usable <c>code</c>.</summary>
    MissingCode,

    /// <summary>The callback carried both a code and an error, or was otherwise ambiguous.</summary>
    AmbiguousCallback,

    /// <summary>The provider refused the request (<c>error</c> in the callback).</summary>
    ProviderDenied,

    /// <summary>The code exchange failed at the declared token endpoint.</summary>
    ProviderExchangeFailed,

    /// <summary>The exchange returned no usable refresh token for a refresh-required profile.</summary>
    RefreshTokenRequired,
}

/// <summary>
/// Raised when an attempt cannot start or cannot complete. The message names the attempt category
/// and never a state, verifier, code, token or provider body.
/// </summary>
public sealed class OAuthAuthorizationAttemptException(
    OAuthAuthorizationAttemptError error,
    string message,
    Exception? inner = null)
    : Exception(message, inner)
{
    /// <summary>The stable, non-secret refusal category.</summary>
    public OAuthAuthorizationAttemptError Error { get; } = error;
}

/// <summary>
/// What one completed attempt produced: the acquired access credential, its declared expiry, the
/// refresh token that must be committed before the access token is published, and the identity the
/// attempt was bound to.
/// </summary>
/// <param name="AccessToken">The access token the provider issued.</param>
/// <param name="ExpiresAtUtc">When the access token stops being usable.</param>
/// <param name="RefreshToken">The usable refresh token that must be committed atomically.</param>
/// <param name="Binding">The identity and fingerprints captured when the attempt started.</param>
public sealed record OAuthAuthorizationResult(
    string AccessToken,
    DateTimeOffset ExpiresAtUtc,
    string RefreshToken,
    OAuthAuthorizationBinding Binding);

/// <summary>The inputs needed to build one bounded authorization attempt.</summary>
/// <param name="Mount">The runtime mount the profile belongs to.</param>
/// <param name="Profile">The selected, already-validated authorization-code profile.</param>
/// <param name="Slot">The runtime-owned mutable slot the attempt authorizes.</param>
/// <param name="Configuration">The profile's projected configuration.</param>
/// <param name="RedirectUri">The explicitly configured loopback callback URI.</param>
/// <param name="ClientSecret">The client secret, absent for the <c>none</c> method.</param>
/// <param name="Lifetime">The bounded attempt lifetime; the documented default applies when absent.</param>
public sealed record OAuthAuthorizationAttemptRequest(
    string Mount,
    AuthenticationProfile Profile,
    AuthenticationSlot Slot,
    OAuthStrategyConfiguration Configuration,
    Uri RedirectUri,
    string? ClientSecret = null,
    TimeSpan? Lifetime = null);

/// <summary>
/// One bounded OAuth 2.0 Authorization Code + PKCE S256 attempt: it builds the authorization
/// request, admits exactly one callback, exchanges the code at the declared token endpoint, and
/// hands back a refresh token for the caller to commit. The caller owns the transport and the
/// durable commit; this type owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The attempt is host-neutral and memory-only. It never persists a state, verifier, code, token
/// or callback payload, and it never logs one. The <c>state</c> and the PKCE verifier are unique per
/// attempt; the verifier is never exposed. A callback completes an attempt only when its decoded
/// <c>state</c> matches this attempt's own value exactly, so one attempt cannot complete another.
/// </para>
/// <para>
/// The state machine is <c>created -&gt; pending -&gt; exchanging -&gt; committed | denied | failed |
/// cancelled | expired</c>. The caller calls <see cref="Begin"/> once its callback listener is
/// bound and before it presents the URL, and completes the attempt at most once. Restarting the
/// owning process discards every attempt, because they live only in memory.
/// </para>
/// </remarks>
public sealed class OAuthAuthorizationAttempt
{
    /// <summary>The bounded lifetime applied when a request declares none.</summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(10);

    /// <summary>The longest bounded lifetime an attempt may declare.</summary>
    public static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(30);

    /// <summary>The largest callback <c>code</c> this runtime will read.</summary>
    public const int MaximumCodeLength = 4096;

    private const int StateBytes = 32;
    private const int VerifierBytes = 32;

    private readonly object _gate = new();
    private readonly OAuthStrategyConfiguration _configuration;
    private readonly IReadOnlyList<string> _authenticationOrigins;
    private readonly OAuthTokenEndpointClient _tokenClient;
    private readonly TimeProvider _timeProvider;
    private readonly string? _clientSecret;
    private readonly string _verifier;
    private readonly DateTimeOffset _expiresAt;

    private OAuthAuthorizationAttemptStatus _status = OAuthAuthorizationAttemptStatus.Created;

    private OAuthAuthorizationAttempt(
        OAuthAuthorizationBinding binding,
        Uri redirectUri,
        Uri authorizationUrl,
        string state,
        string verifier,
        OAuthStrategyConfiguration configuration,
        IReadOnlyList<string> authenticationOrigins,
        string? clientSecret,
        OAuthTokenEndpointClient tokenClient,
        TimeProvider timeProvider,
        TimeSpan lifetime)
    {
        Binding = binding;
        RedirectUri = redirectUri;
        AuthorizationUrl = authorizationUrl;
        State = state;
        _verifier = verifier;
        _configuration = configuration;
        _authenticationOrigins = authenticationOrigins;
        _clientSecret = clientSecret;
        _tokenClient = tokenClient;
        _timeProvider = timeProvider;
        _expiresAt = timeProvider.GetUtcNow().Add(lifetime);
    }

    /// <summary>The identity and fingerprints this attempt is bound to.</summary>
    public OAuthAuthorizationBinding Binding { get; }

    /// <summary>The exact configured loopback callback URI the attempt is registered for.</summary>
    public Uri RedirectUri { get; }

    /// <summary>The authorization URL to present to the operator, carrying the attempt's own state.</summary>
    public Uri AuthorizationUrl { get; }

    /// <summary>
    /// The one-time, unpredictable <c>state</c> this attempt requires in its callback. It is not a
    /// secret, but it is single-use; presenting it in the URL is the point.
    /// </summary>
    public string State { get; }

    /// <summary>When the bounded attempt lifetime elapses.</summary>
    public DateTimeOffset ExpiresAtUtc => _expiresAt;

    /// <summary>The current lifecycle position.</summary>
    public OAuthAuthorizationAttemptStatus Status
    {
        get
        {
            lock (_gate)
            {
                return _status;
            }
        }
    }

    /// <summary>Whether the attempt can no longer change state.</summary>
    public bool IsTerminal
    {
        get
        {
            lock (_gate)
            {
                return IsTerminalStatus(_status);
            }
        }
    }

    /// <summary>
    /// Builds an attempt from a validated request. Every refusal here happens before any listener,
    /// provider request or durable write.
    /// </summary>
    /// <param name="request">The non-secret inputs for the attempt.</param>
    /// <param name="tokenClient">The declared token endpoint client.</param>
    /// <param name="timeProvider">The clock used for the attempt lifetime and exchange.</param>
    /// <returns>A new attempt in the <see cref="OAuthAuthorizationAttemptStatus.Created"/> state.</returns>
    public static OAuthAuthorizationAttempt Create(
        OAuthAuthorizationAttemptRequest request,
        OAuthTokenEndpointClient tokenClient,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(tokenClient);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var profile = request.Profile
            ?? throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.UnsupportedProfile,
                "An authorization attempt requires an authentication profile.");

        if (profile.Kind != AuthenticationKind.OAuth2AuthorizationCodePkceRefresh)
        {
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.UnsupportedProfile,
                $"Authentication profile '{profile.Id}' is not an authorization-code profile.");
        }

        if (request.Slot is null || string.IsNullOrEmpty(request.Slot.Slot))
        {
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.UnsupportedProfile,
                $"Authentication profile '{profile.Id}' declares no runtime-owned slot.");
        }

        var configuration = request.Configuration
            ?? throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.UnsupportedProfile,
                $"Authentication profile '{profile.Id}' has no usable configuration.");

        if (configuration.AuthorizationEndpoint is null)
        {
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.UnsupportedProfile,
                $"Authentication profile '{profile.Id}' declares no authorization endpoint.");
        }

        ValidateRedirectUri(request.RedirectUri);

        if (configuration.TokenAuthMethod is "client_secret_post" or "client_secret_basic"
            && string.IsNullOrEmpty(request.ClientSecret))
        {
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.MissingClientSecret,
                $"Authentication profile '{profile.Id}' requires a client secret for its token authentication method.");
        }

        // Both endpoints reveal credentials or receive the operator's consent, so both must sit
        // inside the reviewed authentication origins before anything is presented or contacted.
        OAuthProtocol.RequireAuthenticationOrigin(configuration.AuthorizationEndpoint, profile.AuthenticationOrigins);
        OAuthProtocol.RequireAuthenticationOrigin(configuration.TokenEndpoint, profile.AuthenticationOrigins);

        var lifetime = request.Lifetime ?? DefaultLifetime;
        if (lifetime <= TimeSpan.Zero || lifetime > MaximumLifetime)
        {
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.LifetimeInvalid,
                "The authorization attempt lifetime is outside the supported range.");
        }

        var state = OAuthProtocol.CreateRandomToken(StateBytes);
        var verifier = OAuthProtocol.CreateRandomToken(VerifierBytes);
        var challenge = OAuthProtocol.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorizationUrl = OAuthAuthorizationRequest.Build(configuration, request.RedirectUri, state, challenge);

        var binding = new OAuthAuthorizationBinding(
            request.Mount,
            profile.Id,
            request.Slot.Slot,
            AuthorityBinding.Declaration(profile),
            AuthorityBinding.Configuration(configuration));

        return new OAuthAuthorizationAttempt(
            binding,
            request.RedirectUri,
            authorizationUrl,
            state,
            verifier,
            configuration,
            profile.AuthenticationOrigins,
            request.ClientSecret,
            tokenClient,
            timeProvider,
            lifetime);
    }

    /// <summary>Moves the attempt from <c>created</c> to <c>pending</c> once a listener is bound.</summary>
    /// <remarks>An already pending attempt is left unchanged; any other state is refused.</remarks>
    public void Begin()
    {
        lock (_gate)
        {
            if (_status == OAuthAuthorizationAttemptStatus.Created)
            {
                _status = OAuthAuthorizationAttemptStatus.Pending;
                return;
            }

            if (_status == OAuthAuthorizationAttemptStatus.Pending)
            {
                return;
            }

            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.AttemptNotPending,
                "The authorization attempt is no longer awaiting admission.");
        }
    }

    /// <summary>Cancels a non-terminal attempt.</summary>
    public void Cancel()
    {
        lock (_gate)
        {
            if (!IsTerminalStatus(_status))
            {
                _status = OAuthAuthorizationAttemptStatus.Cancelled;
            }
        }
    }

    /// <summary>
    /// Admits exactly one callback and exchanges its code at the declared token endpoint. The
    /// attempt refuses a mismatched, replayed, ambiguous or expired callback before any exchange.
    /// </summary>
    /// <param name="rawCallbackQuery">
    /// The callback's raw query string, with or without a leading <c>?</c>, exactly as received.
    /// </param>
    /// <param name="cancellationToken">The completion deadline.</param>
    /// <returns>The acquired material and the attempt's binding.</returns>
    public async ValueTask<OAuthAuthorizationResult> CompleteAsync(
        string rawCallbackQuery,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rawCallbackQuery);

        Admit();

        try
        {
            return await ExchangeAsync(ReadCallback(rawCallbackQuery), cancellationToken).ConfigureAwait(false);
        }
        catch (OAuthAuthorizationAttemptException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            Transition(OAuthAuthorizationAttemptStatus.Cancelled);
            throw;
        }
        catch (Exception exception)
        {
            Transition(OAuthAuthorizationAttemptStatus.Failed);
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.ProviderExchangeFailed,
                "The authorization code exchange failed at the declared token endpoint.",
                exception);
        }
    }

    /// <summary>
    /// Admits exactly one callback whose values the caller's own listener already read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the relay path. A listener in another process receives the callback and forwards only
    /// the values the exchange needs, so the raw query string never has to leave that process and
    /// this process never has to hold one. The checks are the same ones the raw-query path makes,
    /// and the forwarded <c>state</c> is still compared with this attempt's own value before any
    /// exchange, so a callback minted for another attempt cannot complete this one.
    /// </para>
    /// <para>
    /// Passing a value the caller read from a callback it did not validate is not a way to weaken
    /// anything: an absent state is refused, a mismatched state is refused, a callback carrying both
    /// an error and a code is refused as ambiguous, and the attempt is single-use — a second call
    /// finds it no longer pending.
    /// </para>
    /// </remarks>
    /// <param name="state">The callback's decoded <c>state</c>, exactly as received.</param>
    /// <param name="code">The callback's decoded <c>code</c>, when it carried one.</param>
    /// <param name="error">The callback's decoded <c>error</c>, when the provider refused.</param>
    /// <param name="cancellationToken">The completion deadline.</param>
    /// <returns>The acquired material and the attempt's binding.</returns>
    public async ValueTask<OAuthAuthorizationResult> CompleteAsync(
        string? state,
        string? code,
        string? error,
        CancellationToken cancellationToken)
    {
        Admit();

        try
        {
            return await ExchangeAsync(ReadForwardedCallback(state, code, error), cancellationToken).ConfigureAwait(false);
        }
        catch (OAuthAuthorizationAttemptException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            Transition(OAuthAuthorizationAttemptStatus.Cancelled);
            throw;
        }
        catch (Exception exception)
        {
            Transition(OAuthAuthorizationAttemptStatus.Failed);
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.ProviderExchangeFailed,
                "The authorization code exchange failed at the declared token endpoint.",
                exception);
        }
    }

    /// <summary>A redacted description: the attempt never prints its verifier or callback values.</summary>
    public override string ToString()
        => $"OAuthAuthorizationAttempt {{ Profile = {Binding.ProfileId}, Mount = {Binding.Mount}, Status = {Status} }}";

    private Dictionary<string, string> CodeForm(string code)
        => new(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = RedirectUri.AbsoluteUri,
            ["code_verifier"] = _verifier,
        };

    private string ReadCallback(string rawQuery)
    {
        if (!OAuthAuthorizationRequest.TryParseQuery(rawQuery, out var pairs))
        {
            throw Fail(OAuthAuthorizationAttemptError.MalformedCallback, "The authorization callback query is malformed.");
        }

        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var pair in pairs)
        {
            counts[pair.Key] = counts.GetValueOrDefault(pair.Key) + 1;
        }

        if (counts.Values.Any(static count => count > 1))
        {
            throw Fail(
                OAuthAuthorizationAttemptError.DuplicateCallbackParameter,
                "The authorization callback repeated a parameter.");
        }

        if (!counts.ContainsKey("state"))
        {
            throw Fail(OAuthAuthorizationAttemptError.MissingState, "The authorization callback carried no state.");
        }

        if (!MatchesState(Value(pairs, "state")))
        {
            // A callback minted for another attempt cannot complete this one.
            throw Fail(OAuthAuthorizationAttemptError.StateMismatch, "The authorization callback state did not match this attempt.");
        }

        if (counts.ContainsKey("error"))
        {
            if (counts.ContainsKey("code"))
            {
                throw Fail(
                    OAuthAuthorizationAttemptError.AmbiguousCallback,
                    "The authorization callback carried both a code and an error.");
            }

            Transition(OAuthAuthorizationAttemptStatus.Denied);
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.ProviderDenied,
                "The authorization provider refused the request.");
        }

        if (!counts.ContainsKey("code"))
        {
            throw Fail(OAuthAuthorizationAttemptError.MissingCode, "The authorization callback carried no code.");
        }

        var code = Value(pairs, "code");
        if (code.Length == 0 || code.Length > MaximumCodeLength)
        {
            throw Fail(OAuthAuthorizationAttemptError.MissingCode, "The authorization callback code was not usable.");
        }

        return code;
    }

    private static string Value(List<KeyValuePair<string, string>> pairs, string name)
        => pairs.First(pair => string.Equals(pair.Key, name, StringComparison.Ordinal)).Value;

    /// <summary>
    /// Takes the one admission this attempt will ever grant, or refuses without changing anything.
    /// </summary>
    /// <remarks>
    /// Both completion paths run this first and nothing before it, so a replayed or late callback is
    /// refused before any value it carried is looked at. Admission is single-use: the state becomes
    /// <c>exchanging</c> here, so no second callback can complete the same attempt.
    /// </remarks>
    private void Admit()
    {
        lock (_gate)
        {
            if (_status != OAuthAuthorizationAttemptStatus.Pending)
            {
                throw new OAuthAuthorizationAttemptException(
                    OAuthAuthorizationAttemptError.AttemptNotPending,
                    "The authorization attempt cannot accept a callback in its current state.");
            }

            if (_timeProvider.GetUtcNow() >= _expiresAt)
            {
                _status = OAuthAuthorizationAttemptStatus.Expired;
                throw new OAuthAuthorizationAttemptException(
                    OAuthAuthorizationAttemptError.AttemptExpired,
                    "The authorization attempt expired before its callback arrived.");
            }

            _status = OAuthAuthorizationAttemptStatus.Exchanging;
        }
    }

    private async ValueTask<OAuthAuthorizationResult> ExchangeAsync(string code, CancellationToken cancellationToken)
    {
        var exchanged = await _tokenClient
            .ExchangeAsync(_configuration, _authenticationOrigins, CodeForm(code), _clientSecret, cancellationToken)
            .ConfigureAwait(false);

        if (string.IsNullOrEmpty(exchanged.RefreshToken))
        {
            throw Fail(
                OAuthAuthorizationAttemptError.RefreshTokenRequired,
                "The authorization provider returned no usable refresh token.");
        }

        lock (_gate)
        {
            // An operator may cancel the attempt while the provider request is in flight.
            // The provider's response cannot resurrect that cancelled attempt and hand its
            // credentials to the durable commit path.
            if (_status != OAuthAuthorizationAttemptStatus.Exchanging)
            {
                throw new OAuthAuthorizationAttemptException(
                    OAuthAuthorizationAttemptError.AttemptNotPending,
                    "The authorization attempt was cancelled before the exchange completed.");
            }

            _status = OAuthAuthorizationAttemptStatus.Committed;
        }

        return new OAuthAuthorizationResult(
            exchanged.AccessToken,
            exchanged.ExpiresAtUtc,
            exchanged.RefreshToken,
            Binding);
    }

    private string ReadForwardedCallback(string? state, string? code, string? error)
    {
        if (state is null)
        {
            throw Fail(OAuthAuthorizationAttemptError.MissingState, "The authorization callback carried no state.");
        }

        if (!MatchesState(state))
        {
            throw Fail(OAuthAuthorizationAttemptError.StateMismatch, "The authorization callback state did not match this attempt.");
        }

        // The forwarded callback preserves absent versus present query keys using null.
        // An explicitly empty error (or code) still has protocol meaning and must be
        // handled identically to the raw callback path.
        if (error is not null)
        {
            if (code is not null)
            {
                throw Fail(
                    OAuthAuthorizationAttemptError.AmbiguousCallback,
                    "The authorization callback carried both a code and an error.");
            }

            Transition(OAuthAuthorizationAttemptStatus.Denied);
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.ProviderDenied,
                "The authorization provider refused the request.");
        }

        if (code is not { Length: > 0 } usable || usable.Length > MaximumCodeLength)
        {
            throw Fail(OAuthAuthorizationAttemptError.MissingCode, "The authorization callback carried no usable code.");
        }

        return usable;
    }

    /// <summary>
    /// Compares a candidate state with this attempt's own value without leaking how much of a wrong
    /// value matched. The state is single-use rather than secret, but nothing is gained by making the
    /// comparison timing-dependent.
    /// </summary>
    private bool MatchesState(string candidate)
        => CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(candidate),
            Encoding.ASCII.GetBytes(State));

    private void Transition(OAuthAuthorizationAttemptStatus status)
    {
        lock (_gate)
        {
            if (!IsTerminalStatus(_status))
            {
                _status = status;
            }
        }
    }

    private OAuthAuthorizationAttemptException Fail(OAuthAuthorizationAttemptError error, string message)
    {
        Transition(OAuthAuthorizationAttemptStatus.Failed);
        return new OAuthAuthorizationAttemptException(error, message);
    }

    private static bool IsTerminalStatus(OAuthAuthorizationAttemptStatus status)
        => status is OAuthAuthorizationAttemptStatus.Committed
            or OAuthAuthorizationAttemptStatus.Denied
            or OAuthAuthorizationAttemptStatus.Failed
            or OAuthAuthorizationAttemptStatus.Cancelled
            or OAuthAuthorizationAttemptStatus.Expired;

    private static void ValidateRedirectUri(Uri? redirectUri)
    {
        // Uri.IsLoopback is true for localhost and for a literal loopback address family
        // (127.0.0.0/8 and ::1), and false for a wildcard such as 0.0.0.0 or [::].
        if (redirectUri is null
            || !redirectUri.IsAbsoluteUri
            || redirectUri.Scheme is not ("http" or "https")
            || redirectUri.UserInfo.Length != 0
            || redirectUri.Fragment.Length != 0
            || redirectUri.Query.Length != 0
            || !redirectUri.IsLoopback
            || redirectUri.IsDefaultPort
            || redirectUri.AbsolutePath is "" or "/")
        {
            throw new OAuthAuthorizationAttemptException(
                OAuthAuthorizationAttemptError.RedirectUriInvalid,
                "The OAuth callback URI must be an exact, explicitly ported loopback http(s) URI with a path.");
        }
    }
}

/// <summary>
/// Builds the authorization request URL and parses a callback query structurally. Both steps treat
/// parameter names as percent-decoded so an encoded spelling cannot smuggle a second protocol-owned
/// field past the reserved-name check.
/// </summary>
public static class OAuthAuthorizationRequest
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static readonly string[] ProtocolOwnedParameters =
    [
        "response_type",
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
        "state",
        "scope",
        "resource",
        "audience",
    ];

    /// <summary>The authorization parameter names the engine owns; an extension may never override one.</summary>
    public static IReadOnlyList<string> ReservedParameters { get; } = ProtocolOwnedParameters;

    /// <summary>
    /// Builds the authorization URL from the validated configuration. Protocol-owned parameters are
    /// emitted first and can never be overridden by an extension parameter, even under a
    /// percent-encoded or duplicate name.
    /// </summary>
    /// <param name="configuration">The projected profile configuration.</param>
    /// <param name="redirectUri">The validated loopback callback URI.</param>
    /// <param name="state">The attempt's one-time state.</param>
    /// <param name="challenge">The attempt's PKCE S256 challenge.</param>
    /// <returns>The absolute authorization URL to present to the operator.</returns>
    public static Uri Build(
        OAuthStrategyConfiguration configuration,
        Uri redirectUri,
        string state,
        string challenge)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(redirectUri);

        var endpoint = configuration.AuthorizationEndpoint
            ?? throw Refuse("The authorization endpoint is not configured.");

        var reserved = new HashSet<string>(ProtocolOwnedParameters, StringComparer.Ordinal);

        var existingQuery = endpoint.Query.Length > 0 ? endpoint.Query[1..] : string.Empty;
        if (existingQuery.Length > 0)
        {
            if (!TryParseQuery(existingQuery, out var endpointPairs))
            {
                throw Refuse("The authorization endpoint carries a malformed query.");
            }

            foreach (var pair in endpointPairs)
            {
                if (!reserved.Add(pair.Key))
                {
                    throw Refuse("The authorization endpoint already carries a protocol-owned or duplicate parameter.");
                }
            }
        }

        var query = new List<KeyValuePair<string, string>>
        {
            new("response_type", "code"),
            new("client_id", configuration.ClientId),
            new("redirect_uri", redirectUri.AbsoluteUri),
        };

        if (configuration.Scopes.Count > 0)
        {
            query.Add(new("scope", string.Join(' ', configuration.Scopes)));
        }

        if (configuration.Resource is { Length: > 0 } resource)
        {
            query.Add(new("resource", resource));
        }

        if (configuration.Audience is { Length: > 0 } audience)
        {
            query.Add(new("audience", audience));
        }

        query.Add(new("code_challenge", challenge));
        query.Add(new("code_challenge_method", "S256"));
        query.Add(new("state", state));

        foreach (var (name, value) in configuration.AuthorizationParameters)
        {
            if (!TryDecode(name, out var decoded) || decoded.Length == 0)
            {
                throw Refuse("An authorization extension parameter name is not a bounded wire name.");
            }

            if (!reserved.Add(decoded))
            {
                throw Refuse("An authorization extension parameter collides with a protocol-owned parameter.");
            }

            query.Add(new(decoded, value));
        }

        var builder = new StringBuilder(endpoint.GetLeftPart(UriPartial.Path));
        builder.Append('?');

        if (existingQuery.Length > 0)
        {
            builder.Append(existingQuery);
            builder.Append('&');
        }

        builder.Append(string.Join('&', query.Select(
            static pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}")));

        return new Uri(builder.ToString(), UriKind.Absolute);
    }

    /// <summary>
    /// Parses a query string into decoded name/value pairs, preserving order and duplicates. A
    /// malformed percent escape, an empty parameter name or an empty segment is refused. A literal
    /// <c>+</c> is not treated as a space: authorization-response values are opaque.
    /// </summary>
    /// <param name="rawQuery">The raw query string, with or without a leading <c>?</c>.</param>
    /// <param name="pairs">The decoded pairs in encounter order, when the query is well formed.</param>
    /// <returns>Whether the query is well formed.</returns>
    public static bool TryParseQuery(string rawQuery, out List<KeyValuePair<string, string>> pairs)
    {
        pairs = [];

        if (string.IsNullOrEmpty(rawQuery))
        {
            return true;
        }

        if (rawQuery[0] == '?')
        {
            rawQuery = rawQuery[1..];
        }

        foreach (var segment in rawQuery.Split('&'))
        {
            if (segment.Length == 0)
            {
                return false;
            }

            var separator = segment.IndexOf('=');
            var rawName = separator < 0 ? segment : segment[..separator];
            var rawValue = separator < 0 ? string.Empty : segment[(separator + 1)..];

            if (rawName.Length == 0
                || !TryDecode(rawName, out var name)
                || !TryDecode(rawValue, out var value))
            {
                return false;
            }

            pairs.Add(new(name, value));
        }

        return true;
    }

    private static OAuthAuthorizationAttemptException Refuse(string message)
        => new(OAuthAuthorizationAttemptError.AuthorizationParameterRefused, message);

    private static bool TryDecode(string raw, out string value)
    {
        value = string.Empty;

        if (raw.Length == 0)
        {
            return true;
        }

        var bytes = new List<byte>(raw.Length);
        var literalStart = -1;

        for (var index = 0; index < raw.Length; index++)
        {
            var character = raw[index];
            if (character == '%')
            {
                Flush(raw, literalStart, index, bytes);
                literalStart = -1;

                if (index + 2 >= raw.Length
                    || !char.IsAsciiHexDigit(raw[index + 1])
                    || !char.IsAsciiHexDigit(raw[index + 2]))
                {
                    return false;
                }

                bytes.Add((byte)((HexValue(raw[index + 1]) << 4) | HexValue(raw[index + 2])));
                index += 2;
            }
            else if (literalStart < 0)
            {
                literalStart = index;
            }
        }

        Flush(raw, literalStart, raw.Length, bytes);

        try
        {
            value = StrictUtf8.GetString(bytes.ToArray());
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static void Flush(string raw, int start, int end, List<byte> bytes)
    {
        if (start >= 0 && end > start)
        {
            bytes.AddRange(Encoding.UTF8.GetBytes(raw[start..end]));
        }
    }

    private static int HexValue(char character)
        => char.IsAsciiDigit(character)
            ? character - '0'
            : char.ToLowerInvariant(character) - 'a' + 10;
}
