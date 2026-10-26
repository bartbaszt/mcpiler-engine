using System.Security.Cryptography;

using MCPiler.Engine.Authentication.OAuth;

namespace MCPiler.Engine.Runtime;

/// <summary>Why a relay handle could not be used.</summary>
public enum StandaloneAuthorizationRelayRefusal
{
    /// <summary>No session answers to this handle, or it was already completed or abandoned.</summary>
    Unknown,

    /// <summary>The session is known but its bounded lifetime has passed.</summary>
    Expired,

    /// <summary>The session was opened with a different operator credential.</summary>
    CredentialMismatch,
}

/// <summary>
/// What an operator is given to drive one host-owned authorization: a handle, the URL to open, the
/// callback the attempt is registered for and the deadline.
/// </summary>
/// <remarks>
/// This is everything the caller may know about an attempt in progress. The PKCE verifier and the
/// protocol state stay inside the process; the handle stands for them.
/// </remarks>
/// <param name="Handle">The single-use handle this session answers to.</param>
/// <param name="MountPrefix">The mount the attempt authorizes.</param>
/// <param name="ProfileId">The profile the attempt authorizes.</param>
/// <param name="AuthorizationUrl">The authorization URL to present to the operator.</param>
/// <param name="RedirectUri">The exact loopback callback URI the attempt is registered for.</param>
/// <param name="ExpiresAtUtc">When the bounded attempt lifetime elapses.</param>
public sealed record StandaloneAuthorizationRelay(
    string Handle,
    string MountPrefix,
    string ProfileId,
    Uri AuthorizationUrl,
    Uri RedirectUri,
    DateTimeOffset ExpiresAtUtc);

/// <summary>
/// The bounded set of authorization sessions one process has presented to operators.
/// </summary>
/// <remarks>
/// <para>
/// Process-local and in-memory, for the same reason the attempts are: a half-finished authorization
/// is not durable state, and a restart should not resurrect one. Each session is single-use — taking
/// it removes it — so a relayed callback is admitted exactly once, and its attempt is single-use as
/// well.
/// </para>
/// <para>
/// Each session is bound to the credential fingerprint that opened it, and the binding is checked
/// before the session is taken, so a different credential cannot consume someone else's
/// half-finished authorization even when the handle is known.
/// </para>
/// <para>
/// The count is bounded because each session holds a live PKCE verifier. The set holds the attempts
/// themselves, so it is the only place that can answer with the authorization URL.
/// </para>
/// </remarks>
public sealed class StandaloneAuthorizationRelaySessions
{
    /// <summary>How many unfinished sessions may exist at once.</summary>
    public const int MaximumSessions = 8;

    private const int HandleBytes = 32;

    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _sessions = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;

    /// <summary>Creates the set.</summary>
    /// <param name="timeProvider">The clock the bounded lifetimes are measured against.</param>
    public StandaloneAuthorizationRelaySessions(TimeProvider? timeProvider = null)
        => _clock = timeProvider ?? TimeProvider.System;

    /// <summary>Open sessions, pruning the ones that have expired or reached a terminal state.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                Prune();
                return _sessions.Count;
            }
        }
    }

    /// <summary>
    /// Records a freshly built attempt and returns what the operator may know about it, or nothing
    /// when the process already holds its admitted number of unfinished authorizations.
    /// </summary>
    /// <remarks>
    /// The attempt is taken as the bound attempt and is not otherwise exposed: the handle returned
    /// here is the only way back to it, and the credential fingerprint is the only way to be allowed
    /// to use it.
    /// </remarks>
    /// <param name="mountPrefix">The mount the attempt authorizes.</param>
    /// <param name="profileId">The profile the attempt authorizes.</param>
    /// <param name="attempt">The bounded, memory-only protocol attempt.</param>
    /// <param name="credentialFingerprint">A non-secret identity for the credential that opened it.</param>
    /// <returns>The session summary, or null when the set is full.</returns>
    internal StandaloneAuthorizationRelay? Open(
        string mountPrefix,
        string profileId,
        OAuthAuthorizationAttempt attempt,
        string credentialFingerprint)
    {
        ArgumentException.ThrowIfNullOrEmpty(mountPrefix);
        ArgumentException.ThrowIfNullOrEmpty(profileId);
        ArgumentNullException.ThrowIfNull(attempt);
        ArgumentException.ThrowIfNullOrEmpty(credentialFingerprint);

        string handle = Convert.ToHexString(RandomNumberGenerator.GetBytes(HandleBytes));
        var relay = new StandaloneAuthorizationRelay(
            handle,
            mountPrefix,
            profileId,
            attempt.AuthorizationUrl,
            attempt.RedirectUri,
            attempt.ExpiresAtUtc);

        lock (_gate)
        {
            Prune();

            if (_sessions.Count >= MaximumSessions)
            {
                return null;
            }

            _sessions[handle] = new Entry(relay, attempt, credentialFingerprint);
            return relay;
        }
    }

    /// <summary>
    /// Takes the attempt a handle names, removing it so no second request can use it.
    /// </summary>
    /// <param name="handle">The handle the operator presented.</param>
    /// <param name="credentialFingerprint">The credential presenting the handle.</param>
    /// <param name="attempt">The taken attempt, when the handle was usable.</param>
    /// <param name="refusal">Why the handle could not be taken.</param>
    /// <returns>Whether a usable session was taken.</returns>
    internal bool TryTake(
        string handle,
        string credentialFingerprint,
        out OAuthAuthorizationAttempt attempt,
        out StandaloneAuthorizationRelayRefusal refusal)
    {
        attempt = null!;
        refusal = StandaloneAuthorizationRelayRefusal.Unknown;

        lock (_gate)
        {
            // The lookup happens before pruning, so a session that is present but past its deadline
            // is answered as expired rather than as an unknown handle. That difference is what tells
            // an operator to open a new attempt instead of wondering which handle they held.
            if (_sessions.TryGetValue(handle, out Entry? entry))
            {
                // The credential is checked before the session is taken, so a wrong credential cannot
                // consume another operator's half-finished authorization.
                if (!string.Equals(entry.CredentialFingerprint, credentialFingerprint, StringComparison.Ordinal))
                {
                    refusal = StandaloneAuthorizationRelayRefusal.CredentialMismatch;
                    return false;
                }

                if (entry.Attempt.ExpiresAtUtc <= _clock.GetUtcNow())
                {
                    _sessions.Remove(handle);
                    refusal = StandaloneAuthorizationRelayRefusal.Expired;
                    return false;
                }

                _sessions.Remove(handle);
                attempt = entry.Attempt;
                return true;
            }

            Prune();
            return false;
        }
    }

    /// <summary>
    /// Forgets a session without taking it, for an operator who will not finish it.
    /// </summary>
    /// <param name="handle">The handle the operator presented.</param>
    /// <param name="credentialFingerprint">The credential presenting the handle.</param>
    /// <returns>Whether a session was removed, and whether the credential matched.</returns>
    internal (bool Removed, bool Matched) Abandon(string handle, string credentialFingerprint)
    {
        lock (_gate)
        {
            if (_sessions.TryGetValue(handle, out Entry? entry))
            {
                if (!string.Equals(entry.CredentialFingerprint, credentialFingerprint, StringComparison.Ordinal))
                {
                    return (false, false);
                }

                // Abandoning is answered as done for an expired session too: the operator's intent —
                // this authorization will not be completed — already holds either way.
                _sessions.Remove(handle);
                entry.Attempt.Cancel();
                return (true, true);
            }

            Prune();
            return (false, true);
        }
    }

    private void Prune()
    {
        if (_sessions.Count == 0)
        {
            return;
        }

        DateTimeOffset now = _clock.GetUtcNow();
        List<string>? expired = null;

        foreach ((string handle, Entry entry) in _sessions)
        {
            if (entry.Attempt.ExpiresAtUtc <= now || entry.Attempt.IsTerminal)
            {
                (expired ??= []).Add(handle);
            }
        }

        if (expired is null)
        {
            return;
        }

        foreach (string handle in expired)
        {
            _sessions.Remove(handle);
        }
    }

    private sealed record Entry(
        StandaloneAuthorizationRelay Relay,
        OAuthAuthorizationAttempt Attempt,
        string CredentialFingerprint);
}

/// <summary>
/// Reads the three values a relayed callback carries, and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// A relay runs in a process that must not hold a raw callback query any longer than it takes to
/// read it: the query is parsed, and only the values the exchange needs are kept or forwarded. This
/// is that parse, so both sides of the relay agree on how a callback is read, including that a
/// repeated name is refused rather than resolved.
/// </para>
/// <para>
/// It decides no semantics. An absent state, a state that matches no attempt, an absent code, a
/// callback carrying both a code and an error — all of that is decided by the attempt that admits
/// the callback, in the process that owns the verifier.
/// </para>
/// </remarks>
/// <param name="rawQuery">The callback's raw query string, with or without a leading <c>?</c>.</param>
/// <param name="state">The decoded <c>state</c>, when present.</param>
/// <param name="code">The decoded <c>code</c>, when present.</param>
/// <param name="error">The decoded <c>error</c>, when present.</param>
/// <returns>Whether the query was well formed and carried no repeated parameter.</returns>
public static class StandaloneAuthorizationCallback
{
    /// <summary>Reads the minimal callback values, or refuses an unreadable one.</summary>
    public static bool TryRead(
        string rawQuery,
        out string? state,
        out string? code,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(rawQuery);

        state = null;
        code = null;
        error = null;

        if (!OAuthAuthorizationRequest.TryParseQuery(rawQuery, out List<KeyValuePair<string, string>> pairs))
        {
            return false;
        }

        HashSet<string> seen = new(StringComparer.Ordinal);

        foreach ((string name, string value) in pairs)
        {
            if (!seen.Add(name))
            {
                return false;
            }

            switch (name)
            {
                case "state":
                    state = value;
                    break;
                case "code":
                    code = value;
                    break;
                case "error":
                    error = value;
                    break;
                default:
                    break;
            }
        }

        return true;
    }
}

/// <summary>
/// What opening one relay session produced: the handle and URLs the operator drives with, or the
/// reasons it could not start.
/// </summary>
public sealed class StandaloneAuthorizationRelayStart
{
    private StandaloneAuthorizationRelayStart(
        StandaloneAuthorizationRelay? relay,
        IReadOnlyList<StartupRefusal> refusals)
    {
        Relay = relay;
        Refusals = refusals;
    }

    /// <summary>Whether a session was opened and may be presented.</summary>
    public bool Opened => Relay is not null;

    /// <summary>The session summary, when one was opened.</summary>
    public StandaloneAuthorizationRelay? Relay { get; }

    /// <summary>Every reason the session could not be opened. Empty on success.</summary>
    public IReadOnlyList<StartupRefusal> Refusals { get; }

    internal static StandaloneAuthorizationRelayStart Ready(StandaloneAuthorizationRelay relay)
        => new(relay, []);

    internal static StandaloneAuthorizationRelayStart Refused(string mount, string code, string message)
        => new(null, [new StartupRefusal(mount, code, message)]);
}
