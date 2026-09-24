namespace MCPiler.Engine.Manifest.Model;

/// <summary>
/// The <c>authentication</c> section: generic authentication profiles.
/// </summary>
/// <remarks>
/// <para>
/// A profile carries only non-secret configuration. It names the strategy kind, its bounded
/// configuration, the origins that may receive the credential, and references into the
/// <c>credentials</c> section. It never carries a Platform row id, a preset or product id, a
/// ciphertext, or a secret value: those are exactly the things the Manifest boundary exists to
/// keep out.
/// </para>
/// <para>
/// The section is optional. A manifest with no authentication section serves exactly as one
/// whose operations carry no credential references.
/// </para>
/// </remarks>
/// <param name="Profiles">The declared profiles.</param>
public sealed record AuthenticationSection(IReadOnlyList<AuthenticationProfile> Profiles = null!)
{
    /// <summary>The section format version this model represents.</summary>
    /// <remarks>
    /// Version 2 adds the <c>oauth1-authorization</c> kind with its bounded runtime
    /// configuration; older documents are refused rather than migrated.
    /// </remarks>
    public const int FormatVersion = 2;

    /// <summary>The declared profiles, never null.</summary>
    public IReadOnlyList<AuthenticationProfile> Profiles { get; init; } = Profiles ?? [];

    /// <summary>An empty section, which is the default when none is declared.</summary>
    public static AuthenticationSection Empty { get; } = new();

    /// <summary>Returns the profile with <paramref name="id"/>, or <c>null</c>.</summary>
    public AuthenticationProfile? Profile(string? id)
        => id is null
            ? null
            : Profiles.FirstOrDefault(profile => string.Equals(profile.Id, id, StringComparison.Ordinal));
}

/// <summary>One authentication profile.</summary>
/// <param name="Id">
/// The manifest-local identity referenced by an <c>http</c> binding's <c>authenticationRef</c>.
/// The id carries no runtime meaning beyond selecting the profile.
/// </param>
/// <param name="Kind">The closed strategy kind this profile executes.</param>
/// <param name="Configuration">
/// The bounded strategy configuration. Its member set is selected by
/// <paramref name="Kind"/>; unknown or executable members are refused.
/// </param>
/// <param name="AuthenticationOrigins">
/// The exact origins that may receive the credential while authenticating. Usually the token
/// or login endpoint's own origin.
/// </param>
/// <param name="DestinationOrigins">
/// The exact origins that may receive the request the credential is applied to.
/// </param>
/// <param name="CredentialRef">
/// The ids of the <c>credentials</c>-section entries this profile reveals.
/// </param>
/// <param name="ScopeFingerprint">
/// The producer's non-secret scope/config fingerprint. Engine compares it only for equality
/// when binding an existing local runtime record; it never derives identity from it.
/// </param>
/// <param name="Slots">Mutable-slot authority state, for kinds that own a writable slot.</param>
public sealed record AuthenticationProfile(
    string Id,
    AuthenticationKind Kind,
    System.Text.Json.Nodes.JsonObject Configuration,
    IReadOnlyList<string> AuthenticationOrigins,
    IReadOnlyList<string> DestinationOrigins,
    IReadOnlyList<string> CredentialRef,
    string? ScopeFingerprint = null,
    IReadOnlyList<AuthenticationSlot> Slots = null!)
{
    /// <summary>The longest permitted profile id.</summary>
    public const int MaxIdLength = 64;

    /// <summary>The longest permitted scope fingerprint, as lowercase hex SHA-256.</summary>
    public const int Sha256HexLength = 64;

    /// <summary>The declared origins, never null.</summary>
    public IReadOnlyList<string> AuthenticationOrigins { get; init; } = AuthenticationOrigins ?? [];

    /// <summary>The declared destination origins, never null.</summary>
    public IReadOnlyList<string> DestinationOrigins { get; init; } = DestinationOrigins ?? [];

    /// <summary>The referenced credential ids, never null.</summary>
    public IReadOnlyList<string> CredentialRef { get; init; } = CredentialRef ?? [];

    /// <summary>The declared mutable slots, never null.</summary>
    public IReadOnlyList<AuthenticationSlot> Slots { get; init; } = Slots ?? [];

    /// <summary>
    /// True when <paramref name="id"/> is a well-formed profile id, using the same charset as
    /// a credential id so one identity rule covers the whole format.
    /// </summary>
    public static bool IsValidId(string? id)
        => ManifestCredential.IsValidId(id);
}

/// <summary>
/// Authority state for one mutable runtime slot owned by an authentication profile.
/// </summary>
/// <param name="Slot">
/// The slot identity within the profile, for example <c>refreshToken</c>. It names a
/// runtime-owned mutable value, never a static or managed source credential.
/// </param>
/// <param name="AuthorityEpoch">
/// The non-secret authority epoch chosen by the authoring authority. An explicit Platform
/// reauthorization, clear, replacement or scope change advances it; ordinary runtime rotation
/// does not.
/// </param>
/// <param name="RuntimeRevision">
/// The monotonic runtime revision within one authority epoch. The generation input revision is
/// the floor a local runtime record must meet; a later rotation raises it.
/// </param>
public sealed record AuthenticationSlot(string Slot, long AuthorityEpoch, long RuntimeRevision = 0);

/// <summary>How a mutable-slot record is identified.</summary>
/// <param name="ProfileId">The owning profile id.</param>
/// <param name="Slot">The slot identity within the profile.</param>
/// <param name="AuthorityEpoch">The authority epoch the record belongs to.</param>
/// <param name="RuntimeRevision">The runtime revision the record records.</param>
public readonly record struct AuthenticationSlotKey(
    string ProfileId,
    string Slot,
    long AuthorityEpoch,
    long RuntimeRevision);
